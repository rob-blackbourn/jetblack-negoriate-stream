"""Adds stream reader methods to the negotiate stream reader"""

from asyncio import IncompleteReadError, LimitOverrunError
from typing import Iterable

from .negotiate_stream_async_alt import (
    NegotiateStreamReader,
    NegotiateStreamWriter
)

_DEFAULT_LIMIT = 2 ** 16


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
