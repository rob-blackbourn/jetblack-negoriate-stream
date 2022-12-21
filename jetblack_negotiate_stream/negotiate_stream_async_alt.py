"""A more pythonic asyncio solution"""

import asyncio
from asyncio import StreamReader, StreamWriter
import logging
import struct
from typing import Optional, Tuple

import spnego

from .handshake import HandshakeRecord, HandshakeState

LOGGER = logging.getLogger(__name__)


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
        self._writer.drain()

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


async def open_negotiate_stream(
        host: str,
        port: int
) -> Tuple[NegotiateStreamReader, NegotiateStreamWriter]:
    stream_reader, stream_writer = await asyncio.open_connection(host, port)

    context = NegotiateStreamContext(host)
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

    return reader, writer
