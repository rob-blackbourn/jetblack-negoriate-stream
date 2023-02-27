"""An async version of NegotiateStream"""

from asyncio import StreamReader, StreamWriter
import logging
import socket
import struct
from typing import Optional

import spnego

from .handshake import HandshakeRecord, HandshakeState

LOGGER = logging.getLogger(__name__)


class NegotiateStreamAsync:

    def __init__(
            self,
            hostname: str,
            reader: StreamReader,
            writer: StreamWriter
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._handshake_state = HandshakeState.IN_PROGRESS
        self._client = spnego.client(hostname=socket.gethostname())

    def write(self, data: bytes) -> None:
        if self._handshake_state == HandshakeState.IN_PROGRESS:
            handshake = HandshakeRecord(self._handshake_state, 1, 0, len(data))
            header = handshake.pack()
            self._writer.write(header + data)
        else:
            while data:
                chunk = self._client.wrap(data[:0xFC30])
                header = struct.pack('<I', len(chunk.data))
                self._writer.write(header + chunk.data)
                data = data[0xFC30:]

    async def read(self) -> bytes:
        if self._handshake_state == HandshakeState.DONE:

            header = await self._reader.readexactly(4)
            payload_size = struct.unpack('<I', header)[0]
            payload = await self._reader.readexactly(payload_size)
            unencrypted = self._client.unwrap(payload)
            return unencrypted.data

        header_size = struct.calcsize(HandshakeRecord.FORMAT)
        buf = await self._reader.readexactly(header_size)
        handshake = HandshakeRecord.unpack(buf)

        self._handshake_state = handshake.state

        if self._handshake_state != HandshakeState.ERROR:
            return await self._reader.readexactly(handshake.payload_size)

        if handshake.payload_size == 0:
            raise IOError("Negotiate error")

        payload = await self._reader.readexactly(handshake.payload_size)
        _, error = struct.unpack('>II', payload)
        raise IOError(f"Negotiate error: {error}")

    async def drain(self) -> None:
        await self._writer.drain()

    async def authenticate_as_client(self) -> None:
        in_token: Optional[bytes] = None
        while not self._client.complete:
            LOGGER.debug('Doing step')
            out_token = self._client.step(in_token)
            if not self._client.complete:
                assert out_token is not None, "a valid step should create a token"
                self.write(out_token)
                await self.drain()
                in_token = await self.read()

        LOGGER.debug("Handshake complete")

    def close(self) -> None:
        self._writer.close()

    async def wait_closed(self) -> None:
        await self._writer.wait_closed()
