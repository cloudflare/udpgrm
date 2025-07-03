# Copyright (c) 2025 Cloudflare, Inc.
# Licensed under the Apache 2.0 license found in the LICENSE file or at:
#     https://opensource.org/licenses/Apache-2.0

import argparse
import ipaddress
import aioquic
import asyncio
import socket
import os
import sys
import struct
from typing import Dict, Optional
from aioquic.asyncio import serve
from aioquic.h3.connection import H3_ALPN
from aioquic.h3.events import H3Event, HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, HandshakeCompleted
from socket import SOL_SOCKET, SO_DOMAIN, AF_INET, SOCK_DGRAM, SO_TYPE, SO_PROTOCOL, IPPROTO_UDP
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
import systemd
import systemd.daemon

import struct
import binascii

SO_COOKIE = 57


listenfds = int(os.environ.get('LISTEN_FDS', '0'))
fdnames = list(filter(bool, os.environ.get('LISTEN_FDNAMES', '').split(':')))


def get_inherited_sockets(listenfds=32, protocol=IPPROTO_UDP):
    SOCKETS = []
    for fd in range(3, listenfds+3):
        # In python we need socket object to call getsockopt
        try:
            tmp_sd = socket.fromfd(fd, 0, 0, 0)
        except OSError:
            continue
        try:
            domain = tmp_sd.getsockopt(SOL_SOCKET, SO_DOMAIN)
            type = tmp_sd.getsockopt(SOL_SOCKET, SO_TYPE)
            protocol = tmp_sd.getsockopt(SOL_SOCKET, SO_PROTOCOL)
        except OSError:
            # not a socket
            pass
        else:
            if protocol != IPPROTO_UDP:
                pass
            else:
                sd = MockSocket(domain, type, protocol, fileno=fd)
                SOCKETS.append(sd)
        # tmp_sd is a dup, we must close it
        tmp_sd.close()
    return SOCKETS


last_sock = None


class Http3Server(QuicConnectionProtocol):
    def quic_event_received(self, event):
        global last_sock
        last_sock = self._transport._sock
        if isinstance(event, HandshakeCompleted):
            fd = self._transport._sock
            self.so_cookie, = struct.unpack(
                'Q', fd.getsockopt(SOL_SOCKET, SO_COOKIE, 8))
            self.sni = self._quic.tls.client_server_name or b''
            self._http = H3Connection(self._quic)
        if getattr(self, "_http", None) is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    def http_event_received(self, event):
        if isinstance(event, HeadersReceived):
            hdr = dict(event.headers)
            print("%08x %s %s %s" %
                  (self.so_cookie, self.sni, hdr[b':authority'], hdr[b':path']))
            stream_id = event.stream_id

            self._http.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":status", b"200"),
                    (b"content-type", b"text/plain")
                ]
            )
            self._http.send_data(
                stream_id=stream_id,
                data=b"%08x %s Hello, HTTP/3!\n" % (
                    self.so_cookie, self.sni.encode()),
                end_stream=True
            )


def sock_to_str(s):
    so_cookie, = struct.unpack(
        'Q', s.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8))
    a, p = s.getsockname()
    if ':' in a:
        return '[%s]:%d (%08x)' % (a, p, so_cookie)
    return '%s:%d (%08x)' % (a, p, so_cookie)


UDP_GRM_SOCKET_GEN = 201


parser = argparse.ArgumentParser(
    prog='http3_simple_server',
    description='simple quic/http3 server')
parser.add_argument('--crt', help="crt file", default="examples/cert.crt")
parser.add_argument('--key', help="key file", default="examples/cert.key")
parser.add_argument('listen',
                    nargs='*',
                    help='Address and port to bind to (like: 127.0.0.1:443 or [::1]:443)')


class MockSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.captured_data = []

    def recv(self, *args, **kwargs):
        print("A")
        global last_sock
        last_sock = self
        return super().recv(*args, **kwargs)

    def recvfrom(self, *args, **kwargs):
        global last_sock
        last_sock = self
        return super().recvfrom(*args, **kwargs)

    def read(self, *args, **kwargs):
        print("C")
        global last_sock
        last_sock = self
        return super().read(*args, **kwargs)


async def main(args):
    sys.stdout.reconfigure(line_buffering=True)
    sd_inherited = get_inherited_sockets()
    sd_bound = []
    for addr in args.listen:
        ip, _, port = addr.rpartition(':')
        port = int(port)
        ip = ipaddress.ip_address(ip.strip("[]"))
        family = socket.AF_INET if ip.version == 4 else socket.AF_INET6

        sock = MockSocket(family, SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind((str(ip), port))
        sd_bound.append(sock)

    if sd_inherited:
        print('[*] Inherited %s' % ' '.join(sock_to_str(s)
              for s in sd_inherited))
    if sd_bound:
        print('[*] Bound to %s' % ' '.join(sock_to_str(s) for s in sd_bound))

    sockets = sd_inherited + sd_bound
    if not sockets:
        raise "Pass listen addr like 127.0.0.1:443, or use activate.py"

    def gen_cid():
        fcookie = b'XXX'
        if last_sock:
            try:
                _sock_gen, sock_idx, fcookie, _ = struct.unpack(
                    "IIHH", last_sock.getsockopt(socket.IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12))
                fcookie = socket.ntohs(fcookie)
            except OSError:
                print('err')
                pass
        cid = struct.pack("<BHHBHHH", 1, fcookie, 0xcafe, 0,
                          0, 0xdead, 0xbeef) + os.urandom(8)
        print(binascii.hexlify(cid))
        return cid

    config = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=False,
        connection_id_length=20,
        gen_connection_id=gen_cid,
    )
    config.load_cert_chain(args.crt, args.key)

    servers = [
        asyncio.create_task(serve(
            '127.0.0.1',
            0,
            sock=sock,
            configuration=config,
            create_protocol=Http3Server,
        ))
        for sock in sockets
    ]

    systemd.daemon.notify('READY=1')

    await asyncio.wait(servers)

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    asyncio.run(main(parser.parse_args(sys.argv[1:])))
