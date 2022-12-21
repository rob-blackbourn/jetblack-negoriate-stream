# jetblack-negotiate-stream

A Python client for .Net
[NegotiateStream](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.negotiatestream).
It supports single sign on (SSO) and encryption.

This was tested using Python 3.8 on Windows 11.

## Installation

Install from pypi.

```bash
pip install jetblack-negotiate-stream
```

## Example

The following programs provide a simple echo server in C# and client in Python.

### Client

This is an example of a Python client using the synchronous
`NegotiateStream` class. Note the call to `authenticate_as_client` before
reading and writing.

```python
import socket

from jetblack_negotiate_stream import NegotiateStream

def main():
    hostname = socket.gethostname()
    port = 8181

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((hostname, port))

        stream = NegotiateStream(hostname, sock)

        # Do the client side negotiate handshake.
        stream.authenticate_as_client()

        for data in (b'first line', b'second line', b'third line'):
            # All reads and writes are encrypted.
            stream.write(data)
            response = stream.read()
            print("Received: ", response)

if __name__ == '__main__':
    main()
```

### Async Client

This program uses `NegotiateStreamAsync` which is simply an asynchronous
version of the `NegotiateStream` class demonstrated above.

```python
import asyncio
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

if __name__ == '__main__':
    asyncio.run(main())
```

### Alternative Async Client

The following client follows the patterns demonstrated in the asyncio library
using `open_negotiate_stream`. This follows the conventions of the asyncio
`open_connection` function. The negotiation happens before the function
returns, resulting in cleaner code. 

```python
import asyncio
import socket

from jetblack_negotiate_stream import open_negotiate_stream

async def main():
    hostname = socket.gethostname()
    port = 8181

    # Following the same pattern as asyncio.open_connection.
    reader, writer = await open_negotiate_stream(hostname, port)

    for data in (b'first line', b'second line', b'third line'):
        writer.write(data)
        await writer.drain()
        response = await reader.read()
        print("Received: ", response)

    writer.close()
    await writer.wait_closed()

if __name__ == '__main__':
    asyncio.run(main())
```

### Server

Here is a trivial C# echo server for the clients.

```csharp
using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace NegotiateStreamServer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var listener = new TcpListener(IPAddress.Any, 8181);
            listener.Start();

            while (true)
            {
                Console.WriteLine("Listening ...");
                var client = listener.AcceptTcpClient();

                try
                {
                    Console.WriteLine("... Client connected.");

                    Console.WriteLine("Authenticating...");
                    var stream = new NegotiateStream(client.GetStream(), false);
                    stream.AuthenticateAsServer();

                    Console.WriteLine(
                        "... {0} authenticated using {1}",
                        stream.RemoteIdentity.Name,
                        stream.RemoteIdentity.AuthenticationType);

                    var buf = new byte[4096];
                    for (var i = 0; i < 3; ++i)
                    {
                        var bytesRead = stream.Read(buf, 0, buf.Length);
                        var message = Encoding.UTF8.GetString(buf, 0, bytesRead);
                        Console.WriteLine(message);
                        stream.Write(buf, 0, bytesRead);
                    }
                    stream.Close();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
            }
        }
    }
}
```

## Acknowledgements

The library uses the [pyspnego](https://github.com/jborean93/pyspnego) library,
and takes many ideas from [net.tcp-proxy](https://github.com/ernw/net.tcp-proxy).
