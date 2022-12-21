# jetblack-negotiate-stream

A Python client for .Net [NegotiateStream](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.negotiatestream).
It supports single sign on (SSO) and encryption.

This was tested using Python 3.8 on Windows 11.

## Example

The following programs provide a simple echo server in C# and client in Python.

### Server

A trivial C# echo server.

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
                    for (var i = 0; i < 4; ++i)
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

### Client

A Python echo client.

```python
"""Example"""

import logging
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

    print("Done")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
```

## Acknowledgements

The library uses the [pyspnego](https://github.com/jborean93/pyspnego) library,
and takes many ideas from [net.tcp-proxy](https://github.com/ernw/net.tcp-proxy).
