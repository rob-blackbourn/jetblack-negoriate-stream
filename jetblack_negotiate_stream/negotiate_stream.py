"""NegotiateStream"""

import logging
import socket
import struct
from typing import Optional

import spnego

from .handshake import HandshakeRecord, HandshakeState
from .stream import Stream

LOGGER = logging.getLogger(__name__)

_MAX_DATA_PACKET_LEN = 0xFC30


class NegotiateStream(Stream):
    """A synchronous negotiate stream handler"""

    def __init__(
            self,
            socket_: socket.socket,
            *,
            local_hostname: Optional[str] = None
    ) -> None:
        """Negotiate stream client.

        Wraps a socket and performs the handshake.

        Args:
            socket_ (socket.socket): The socket to wrap.
            local_hostname (Optional[str], optional): The hostname of the
                connecting client. Defaults to None.
        """
        super().__init__(socket_)

        self._handshake_state = HandshakeState.IN_PROGRESS

        if local_hostname is None:
            local_hostname = socket.gethostname()
        self._client = spnego.client(hostname=local_hostname)

    def _write_handshake(self, data: bytes) -> None:
        handshake = HandshakeRecord(self._handshake_state, 1, 0, len(data))
        header = handshake.pack()
        self.send(header + data)

    def _write_data(self, data: bytes) -> None:
        # Send in chunks in case the packet exceeds the maximum packet
        # length.
        while data:
            chunk = self._client.wrap(data[:_MAX_DATA_PACKET_LEN])
            header = struct.pack('<I', len(chunk.data))
            self.send(header + chunk.data)
            data = data[_MAX_DATA_PACKET_LEN:]

    def write(self, data: bytes) -> None:
        if self._handshake_state == HandshakeState.IN_PROGRESS:
            self._write_handshake(data)
        else:
            self._write_data(data)

    def _read_data(self) -> bytes:
        payload_size = struct.unpack('<I', self.recv(4))[0]
        payload = self.recv(payload_size)
        unencrypted = self._client.unwrap(payload)
        return unencrypted.data

    def _read_handshake(self) -> bytes:
        buf = self.recv(struct.calcsize(HandshakeRecord.FORMAT))
        handshake = HandshakeRecord.unpack(buf)

        self._handshake_state = handshake.state

        if self._handshake_state == HandshakeState.ERROR:

            if handshake.payload_size == 0:
                # No error information was provided.
                raise IOError("Negotiate error")
            else:
                # Unpack the error code from the payload.
                payload = self.recv(handshake.payload_size)
                _, error = struct.unpack('>II', payload)
                raise IOError(f"Negotiate error: {error}")

        # The state is either IN_PROGRESS or DONE.
        return self.recv(handshake.payload_size)

    def read(self) -> bytes:
        if self._handshake_state == HandshakeState.DONE:
            return self._read_data()
        else:
            return self._read_handshake()

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
