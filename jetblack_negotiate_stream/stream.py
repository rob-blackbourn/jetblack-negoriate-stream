"""Stream"""

import select
import socket


class Stream:

    def __init__(self, socket_: socket.socket) -> None:
        self._socket = socket_

    def recv(self, n: int = -1) -> bytes:
        if n == -1:
            self._socket.setblocking(False)
            readable, _, _ = select([self._socket], [], [])
            if self.socket not in readable:
                return b''
            return self._socket.recv(4096)
        else:
            self._socket.setblocking(True)
            data = b''
            while n:
                buf = self._socket.recv(n)
                n -= len(buf)
                data += buf
            return data

    def send(self, data: bytes) -> None:
        self._socket.setblocking(True)
        self._socket.sendall(data)
