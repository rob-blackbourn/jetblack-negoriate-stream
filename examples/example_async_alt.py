"""Example using async readers and writers"""

import asyncio
import logging
import socket

from jetblack_negotiate_stream import open_negotiate_stream


async def main():
    hostname = socket.gethostname()
    port = 8181

    reader, writer = await open_negotiate_stream(hostname, port)

    for name in ["negotiated_protocol", "client_principal"]:
        value = writer.get_extra_info(name)
        print(f"{name}={value}")

    for data in (b'first line', b'second line', b'third line'):
        writer.write(data)
        await writer.drain()
        response = await reader.read()
        print("Received: ", response)

    writer.close()
    await writer.wait_closed()

    print("Done")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())
