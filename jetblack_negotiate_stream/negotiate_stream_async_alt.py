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
from typing import Iterable, Optional, Tuple

import spnego

from .handshake import HandshakeRecord, HandshakeState

LOGGER = logging.getLogger(__name__)

_DEFAULT_LIMIT = 2 ** 16


class NegotiateStreamContext:

    def __init__(
            self,
            hostname: str,
    ) -> None:
        self.handshake_state = HandshakeState.IN_PROGRESS
        self.client = spnego.client(hostname=hostname)


class NegotiateStreamReader:

    def __init__(
            self,
            context: NegotiateStreamContext,
            reader: StreamReader
    ) -> None:
        self._context = context
        self._reader = reader

    async def read(self) -> bytes:
        if self._context.handshake_state == HandshakeState.DONE:

            header = await self._reader.readexactly(4)
            payload_size = struct.unpack('<I', header)[0]
            payload = await self._reader.readexactly(payload_size)
            unencrypted = self._context.client.unwrap(payload)
            return unencrypted.data

        header_size = struct.calcsize(HandshakeRecord.FORMAT)
        buf = await self._reader.readexactly(header_size)
        handshake = HandshakeRecord.unpack(buf)

        self._context.handshake_state = handshake.state

        if self._context.handshake_state != HandshakeState.ERROR:
            return await self._reader.readexactly(handshake.payload_size)

        if handshake.payload_size == 0:
            raise IOError("Negotiate error")

        payload = await self._reader.readexactly(handshake.payload_size)
        _, error = struct.unpack('>II', payload)
        raise IOError(f"Negotiate error: {error}")


class NegotiateStreamWriter:

    def __init__(
            self,
            context: NegotiateStreamContext,
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

    def write(self, data: bytes) -> None:
        if self._context.handshake_state == HandshakeState.IN_PROGRESS:
            handshake = HandshakeRecord(
                self._context.handshake_state,
                1,
                0,
                len(data)
            )
            header = handshake.pack()
            self._writer.write(header + data)
        else:
            while data:
                chunk = self._context.client.wrap(data[:0xFC30])
                header = struct.pack('<I', len(chunk.data))
                self._writer.write(header + chunk.data)
                data = data[0xFC30:]


class StreamReaderWrapper:

    def __init__(self, reader: NegotiateStreamReader, limit: int = _DEFAULT_LIMIT) -> None:
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

        except IncompleteReadError as e:

            return e.partial

        except LimitOverrunError as e:

            if self._buffer.startswith(sep, e.consumed):
                del self._buffer[:e.consumed + len(sep)]
            else:
                self._buffer.clear()

            raise ValueError(e.args[0])

        return line

    def __aiter__(self):
        return self

    async def __anext__(self):
        val = await self.readline()
        if val == b'':
            raise StopAsyncIteration
        return val


class StreamWriterWrapper:

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


async def open_negotiate_stream(
        host: str,
        port: int
) -> Tuple[StreamReaderWrapper, StreamWriterWrapper]:
    stream_reader, stream_writer = await asyncio.open_connection(host, port)

    context = NegotiateStreamContext(socket.gethostname())
    reader = NegotiateStreamReader(context, stream_reader)
    writer = NegotiateStreamWriter(context, stream_writer)

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

    return StreamReaderWrapper(reader), StreamWriterWrapper(writer)
