# Copyright (c) 2025 Cloudflare, Inc.
# Licensed under the Apache 2.0 license found in the LICENSE file or at:
#     https://opensource.org/licenses/Apache-2.0

import asyncio
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration


class Http3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None
        self._response_complete = asyncio.Event()  # Event to signal end of stream
        self._body = []

    def quic_event_received(self, event):
        if getattr(self, "_http", None) is None:
            self._http = H3Connection(self._quic)

        for http_event in self._http.handle_event(event):
            self.http_event_received(http_event)

    def http_event_received(self, event):
        if isinstance(event, HeadersReceived):
            pass
            # print("Headers received: %s" % event.headers)
        elif isinstance(event, DataReceived):
            self._body.append(event.data)
            # print("Data received: %s" %event.data.decode("utf-8"))
            if event.stream_ended:
                self._response_complete.set()  # Signal the end of stream

    def get_body(self):
        return b''.join(self._body)


async def perform_get_request(ip, port, sni, path):
    # Create QUIC configuration
    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        server_name=sni,
        verify_mode=False,
    )

    # Connect to the server
    async with connect(
        host=ip,
        port=port,
        configuration=configuration,
        create_protocol=Http3Client
    ) as protocol:
        http = protocol._http
        stream_id = protocol._quic.get_next_available_stream_id()
        http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", sni.encode()),
                (b":path", path.encode()),
            ]
        )
        http.send_data(stream_id, b"", end_stream=True)
        await protocol._response_complete.wait()
        return protocol.get_body()

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: python http3_client.py <ip> <port> <sni>")
        sys.exit(1)

    hostname = sys.argv[1]
    port = int(sys.argv[2])
    sni = sys.argv[3]

    x = asyncio.run(perform_get_request(hostname, port, sni, '/'))
    print(x.decode().rstrip())
