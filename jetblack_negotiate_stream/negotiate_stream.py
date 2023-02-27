"""NegotiateStream"""

import logging
import socket
import struct
from typing import Optional

import spnego

from .handshake import HandshakeRecord, HandshakeState
from .stream import Stream

LOGGER = logging.getLogger(__name__)


class NegotiateStream(Stream):

    def __init__(self, hostname: str, socket_: socket.socket) -> None:
        super().__init__(socket_)
        self._handshake_state = HandshakeState.IN_PROGRESS
        self._client = spnego.client(hostname=socket.gethostname())

    def write(self, data: bytes) -> None:
        if self._handshake_state == HandshakeState.IN_PROGRESS:
            handshake = HandshakeRecord(self._handshake_state, 1, 0, len(data))
            header = handshake.pack()
            self.send(header + data)
        else:
            while data:
                chunk = self._client.wrap(data[:0xFC30])
                header = struct.pack('<I', len(chunk.data))
                self.send(header + chunk.data)
                data = data[0xFC30:]

    def read(self) -> bytes:
        if self._handshake_state == HandshakeState.DONE:

            payload_size = struct.unpack('<I', self.recv(4))[0]
            payload = self.recv(payload_size)
            unencrypted = self._client.unwrap(payload)
            return unencrypted.data

        buf = self.recv(struct.calcsize(HandshakeRecord.FORMAT))
        handshake = HandshakeRecord.unpack(buf)

        self._handshake_state = handshake.state

        if self._handshake_state != HandshakeState.ERROR:
            return self.recv(handshake.payload_size)

        if handshake.payload_size == 0:
            raise IOError("Negotiate error")

        payload = self.recv(handshake.payload_size)
        _, error = struct.unpack('>II', payload)
        raise IOError(f"Negotiate error: {error}")

    def authenticate_as_client(self) -> None:
        in_token: Optional[bytes] = None
        while not self._client.complete:
            LOGGER.debug('Doing step')
            out_token = self._client.step(in_token)
            if not self._client.complete:
                assert out_token is not None, "a valid step should create a token"
                self.write(out_token)
                in_token = self.read()

        LOGGER.debug("Handshake complete")
