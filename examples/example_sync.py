"""Example using a socket"""

import logging
import socket

from jetblack_negotiate_stream import NegotiateStream


def main():
    hostname = socket.gethostname()
    port = 8181

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((hostname, port))

        stream = NegotiateStream(hostname, sock)

        stream.authenticate_as_client()
        for data in (b'first line', b'second line', b'third line'):
            stream.write(data)
            response = stream.read()
            print("Received: ", response)

    print("Done")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
