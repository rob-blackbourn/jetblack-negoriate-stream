"""A more pythonic asyncio solution"""

import asyncio
from asyncio import (
    StreamReader,
    StreamWriter,
    IncompleteReadError,
    LimitOverrunError
)
import logging
import socket
import struct
from typing import Any, Iterable, List, Optional, Tuple, Union

import spnego
from spnego import Credential, NegotiateOptions

from .handshake import HandshakeRecord, HandshakeState

LOGGER = logging.getLogger(__name__)

_DEFAULT_LIMIT = 2 ** 16


class SpnegoClientContext:
    """The SPNEGO client context.

    This contains the handshake state and the SPNEGO client.
    """

    def __init__(
            self,
            username: Optional[Union[str, Credential, List[Credential]]],
            password: Optional[str],
            hostname: Optional[str],
            protocol: str,
            options: NegotiateOptions,
    ) -> None:
        self.handshake_state = HandshakeState.IN_PROGRESS

        if hostname is None:
            hostname = socket.gethostname()
        self.client = spnego.client(
            username,
            password,
            hostname,
            protocol=protocol,
            options=options
        )


class NegotiateStreamReader:
    """The reader for a negotiate stream.

    Note that data is sent as length delimited packets. This means that
    convenience methods like "readline" have no meaning in this layer.
    """

    def __init__(
            self,
            context: SpnegoClientContext,
            reader: StreamReader
    ) -> None:
        self._context = context
        self._reader = reader

    async def _read_data(self) -> bytes:
        header = await self._reader.readexactly(4)
        payload_size = struct.unpack('<I', header)[0]
        payload = await self._reader.readexactly(payload_size)
        unencrypted = self._context.client.unwrap(payload)
        return unencrypted.data

    async def _read_handshake(self) -> bytes:
        header_size = struct.calcsize(HandshakeRecord.FORMAT)
        buf = await self._reader.readexactly(header_size)
        handshake = HandshakeRecord.unpack(buf)

        self._context.handshake_state = handshake.state

        if self._context.handshake_state == HandshakeState.ERROR:

            if handshake.payload_size == 0:
                # No error information was provided.
                raise IOError("Negotiate error")
            else:
                # Unpack the error code.
                payload = await self._reader.readexactly(handshake.payload_size)
                _, error = struct.unpack('>II', payload)
                raise IOError(f"Negotiate error: {error}")

        return await self._reader.readexactly(handshake.payload_size)

    async def read(self) -> bytes:
        """Read data.

        As the data is length delimited, the size of each packet is determined
        by the sender.

        Returns:
            bytes: A packet of data.
        """
        if self._context.handshake_state == HandshakeState.DONE:
            return await self._read_data()
        else:
            return await self._read_handshake()


class NegotiateStreamWriter:
    """A writer for the negotiate stream protocol"""

    def __init__(
            self,
            context: SpnegoClientContext,
            writer: StreamWriter
    ) -> None:
        self._context = context
        self._writer = writer

    async def drain(self) -> None:
        """Wait until it is appropriate to resume writing to the stream.
        """
        await self._writer.drain()

    def close(self) -> None:
        """The method closes the stream and the underlying socket.

        The method should be used, though not mandatory, along with the
        wait_closed() method.
        """
        self._writer.close()

    async def wait_closed(self) -> None:
        """Wait until the stream is closed.
        """
        await self._writer.wait_closed()

    def _write_handshake(self, data: bytes) -> None:
        handshake = HandshakeRecord(
            self._context.handshake_state,
            1,
            0,
            len(data)
        )
        header = handshake.pack()
        self._writer.write(header + data)

    def _write_data(self, data: bytes) -> None:
        while data:
            chunk = self._context.client.wrap(data[:0xFC30])
            header = struct.pack('<I', len(chunk.data))
            self._writer.write(header + chunk.data)
            data = data[0xFC30:]

    def write(self, data: bytes) -> None:
        """The method attempts to write the data to the underlying socket
        immediately. If that fails, the data is queued in an internal write
        buffer until it can be sent.

        Args:
            data (bytes): The data to write.
        """
        if self._context.handshake_state == HandshakeState.IN_PROGRESS:
            self._write_handshake(data)
        else:
            self._write_data(data)

    def get_extra_info(self, name: str, default=None) -> Any:
        """Access optional transport information.

        Args:
            name (str): The name of the information to get.
            default (_type_, optional): The value to return if the information
                is not available. Defaults to None.

        Returns:
            Any: The equested information, or the default value.
        """
        if name == "negotiated_protocol":
            return self._context.client.negotiated_protocol
        else:
            return self._context.client.get_extra_info(name, default)


class StreamReaderWrapper:
    """A wrapper around the negotiate stream reader to implement StreamReader
    methods.

    The reader for negotiate stream is packet oriented, where each packet is
    size delimited. This wrapper provides methods like readline and readexactly.
    """

    def __init__(
            self,
            reader: NegotiateStreamReader,
            limit: int = _DEFAULT_LIMIT
    ) -> None:
        self._reader = reader
        self._limit = limit
        self._buffer = bytearray()
        self._eof = False

    async def _read_into_buffer(self) -> None:
        buf = await self._reader.read()
        if buf:
            self._buffer.extend(buf)
        else:
            self._eof = True

    def at_eof(self) -> bool:
        """Return True if the buffer is empty and feed_eof() was called.

        Returns:
            bool: True if the stream has reached the end of the file.
        """
        return self._eof and len(self._buffer) == 0

    async def read(self, n: int = -1) -> bytes:
        """Read up to n bytes from the stream.

        If n is not provided or set to -1, read until EOF, then return all
        read bytes. If EOF was received and the internal buffer is empty,
        return an empty bytes object.

        If n is 0, return an empty bytes object immediately.

        If n is positive, return at most n available bytes as soon as at least
         1 byte is available in the internal buffer. If EOF is received before
         any byte is read, return an empty bytes object.

        Args:
            n (int, optional): The number of bytes to read. Defaults to -1.

        Returns:
            bytes: The bytes read.
        """
        if n == 0:
            return b''

        if not self._buffer:
            await self._read_into_buffer()

        if n < 0 or self._eof:
            buf = bytes(self._buffer)
            self._buffer.clear()
        else:
            buf = bytes(self._buffer[:n])
            del self._buffer[:n]

        return buf

    async def readexactly(self, n: int) -> bytes:
        """Read exactly n bytes.

        Args:
            n (int): The number of bytes to read.

        Raises:
            ValueError: If the number of bytes is negative.
            IncompleteReadError: If the end of the file was reached before the
                requested number of bytes could be read.

        Returns:
            bytes: The data that was read.
        """
        if n < 0:
            raise ValueError('readexactly size can not be less than zero')

        while len(self._buffer) < n and not self._eof:
            await self._read_into_buffer()

        if self._eof:
            incomplete = bytes(self._buffer)
            self._buffer.clear()
            raise IncompleteReadError(incomplete, n)

        chunk = bytes(self._buffer[:n])
        del self._buffer[:n]
        return chunk

    async def readuntil(self, separator: bytes = b'\n') -> bytes:
        """Read data from the stream until separator is found.

        Args:
            separator (bytes, optional): The separator. Defaults to b'\n'.

        Raises:
            ValueError: If the separator is an empty byte.
            LimitOverrunError: If the amount of data read exceeds the configured
                stream limit.
            IncompleteReadError: If the end of the file was reached before the
                separator was found.

        Returns:
            bytes: The data that was read.
        """
        seplen = len(separator)
        if seplen == 0:
            raise ValueError('Separator should be at least one-byte string')

        offset = 0

        while True:
            buflen = len(self._buffer)

            if buflen - offset >= seplen:
                isep = self._buffer.find(separator, offset)

                if isep != -1:
                    break

                offset = buflen + 1 - seplen
                if offset > self._limit:
                    raise LimitOverrunError(
                        'Separator is not found, and chunk exceed the limit',
                        offset
                    )

            if self._eof:
                chunk = bytes(self._buffer)
                self._buffer.clear()
                raise IncompleteReadError(chunk, None)

            await self._read_into_buffer()

        if isep > self._limit:
            raise LimitOverrunError(
                'Separator is found, but chunk is longer than limit',
                isep
            )

        chunk = self._buffer[:isep + seplen]
        del self._buffer[:isep + seplen]
        return bytes(chunk)

    async def readline(self) -> bytes:
        """Read one line, where “line” is a sequence of bytes ending with \n.

        Raises:
            ValueError: If the amount of data read exceeds the configured
                stream limit.

        Returns:
            bytes: The bytes read.
        """
        sep = b'\n'

        try:

            line = await self.readuntil(sep)

        except IncompleteReadError as error:

            return error.partial

        except LimitOverrunError as error:

            if self._buffer.startswith(sep, error.consumed):
                del self._buffer[:error.consumed + len(sep)]
            else:
                self._buffer.clear()

            raise ValueError(error.args[0]) from error

        return line

    def __aiter__(self):
        return self

    async def __anext__(self):
        val = await self.readline()
        if val == b'':
            raise StopAsyncIteration
        return val


class StreamWriterWrapper:
    """A wrapper for the negotiate stream writer.

    As the protocol only writes length delimited packets a wrapper is required
    to implement convenience methods like writelines.
    """

    def __init__(self, writer: NegotiateStreamWriter) -> None:
        self._writer = writer

    def write(self, data: bytes) -> None:
        """The method attempts to write the data to the underlying socket
        immediately. If that fails, the data is queued in an internal write
        buffer until it can be sent.

        The method should be used along with the drain() method.

        Args:
            data (bytes): The data to write.
        """
        self._writer.write(data)

    def writelines(self, lines: Iterable[bytes]) -> None:
        """The method writes a list (or any iterable) of bytes to the underlying
        socket immediately. If that fails, the data is queued in an internal
         write buffer until it can be sent.

        Args:
            lines (Iterable[bytes]): An iterable of lines read.
        """
        for line in lines:
            self._writer.write(line)

    async def drain(self) -> None:
        """Wait until it is appropriate to resume writing to the stream.
        """
        await self._writer.drain()

    def close(self) -> None:
        """The method closes the stream and the underlying socket.
        """
        self._writer.close()

    async def wait_closed(self) -> None:
        """Wait until the stream is closed.
        """
        await self._writer.wait_closed()

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """Access optional transport information.

        Args:
            name (str): The name of the information to get.
            default (_type_, optional): The value to return if the information
                is not available. Defaults to None.

        Returns:
            Any: The equested information, or the default value.
        """
        return self._writer.get_extra_info(name, default)


async def _perform_handshake(
        reader: NegotiateStreamReader,
        writer: NegotiateStreamWriter,
        context: SpnegoClientContext
) -> None:
    in_token: Optional[bytes] = None
    while not context.client.complete:
        LOGGER.debug('Doing step')
        out_token = context.client.step(in_token)
        if not context.client.complete:
            assert out_token is not None, "a valid step should create a token"
            writer.write(out_token)
            await writer.drain()
            in_token = await reader.read()

    LOGGER.debug("Handshake complete")


async def open_negotiate_stream(
        host: str,
        port: int,
        *,
        username: Optional[Union[str, Credential, List[Credential]]] = None,
        password: Optional[str] = None,
        local_hostname: Optional[str] = None,
        protocol: str = "negotiate",
        options: NegotiateOptions = NegotiateOptions.none,
) -> Tuple[StreamReaderWrapper, StreamWriterWrapper]:
    """Establish a network connection and return a pair of (reader, writer)
    objects using the negotiate protocol for authentication.

    Args:
        host (str): The remote host.
        port (int): The port on the remote host.
        username (Optional[Union[str, Credential, List[Credential]]], optional):
            The username/credential(s) to authenticate with. Certain providers
            can use a cache if omitted. Defaults to None.
        password (Optional[str], optional): The password to authenticate with.
            Should only be specified when username is a string. Defaults to
            None.
        local_hostname (Optional[str], optional): The principal part of the SPN.
            Defaults to None.
        protocol (str, optional): The protocol to authenticate with, can be
            `ntlm`, `kerberos`, `negotiate`, or `credssp`. Defaults to "negotiate".
        options (NegotiateOptions, optional): The `spnego.NegotiateOptions`
            that define pyspnego specific options to control the negotiation.
            Defaults to `NegotiateOptions.none`.

    Returns:
        Tuple[StreamReaderWrapper, StreamWriterWrapper]: The reader and writer
            of the stream.
    """
    stream_reader, stream_writer = await asyncio.open_connection(host, port)

    context = SpnegoClientContext(
        username,
        password,
        local_hostname,
        protocol,
        options
    )
    reader = NegotiateStreamReader(context, stream_reader)
    writer = NegotiateStreamWriter(context, stream_writer)

    await _perform_handshake(reader, writer, context)

    return StreamReaderWrapper(reader), StreamWriterWrapper(writer)
