"""Example using an async stream"""

import asyncio
import logging
import socket

from jetblack_negotiate_stream import NegotiateStreamAsync


async def main():
    hostname = socket.gethostname()
    port = 8181

    reader, writer = await asyncio.open_connection(hostname, port)

    stream = NegotiateStreamAsync(hostname, reader, writer)

    await stream.authenticate_as_client()
    for data in (b'first line', b'second line', b'third line'):
        stream.write(data)
        await stream.drain()
        response = await stream.read()
        print("Received: ", response)

    stream.close()
    await stream.wait_closed()

    print("Done")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())
