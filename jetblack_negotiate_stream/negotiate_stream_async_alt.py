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
from typing import Iterable, List, Optional, Tuple, Union

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
        await self._writer.drain()

    def close(self) -> None:
        self._writer.close()

    async def wait_closed(self) -> None:
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
        if self._context.handshake_state == HandshakeState.IN_PROGRESS:
            self._write_handshake(data)
        else:
            self._write_data(data)


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
        return self._eof and len(self._buffer) == 0

    async def read(self, n: int = -1) -> bytes:
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
        self._writer.write(data)

    def writelines(self, lines: Iterable[bytes]) -> None:
        for line in lines:
            self._writer.write(line)

    async def drain(self) -> None:
        await self._writer.drain()

    def close(self):
        self._writer.close()

    async def wait_closed(self) -> None:
        await self._writer.wait_closed()


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
