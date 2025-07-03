#!/bin/env -S python3 -u

# Copyright (c) 2025 Cloudflare, Inc.
# Licensed under the Apache 2.0 license found in the LICENSE file or at:
#     https://opensource.org/licenses/Apache-2.0

from systemd.daemon import notify
import argparse
import errno
import ipaddress
import re
import socket
import struct
import sys
import time

UDP_GRM_WORKING_GEN = 200
UDP_GRM_SOCKET_GEN = 201
UDP_GRM_DISSECTOR = 202
UDP_GRM_FLOW_ASSURE = 203
UDP_GRM_SOCKET_APP = 204

DISSECTOR_FLOW = 0
DISSECTOR_CBPF = 1
DISSECTOR_BESPOKE = 3
DISSECTOR_NOOP = 4
DISSECTOR_FLAG_VERBOSE = 0x8000
DISSECTOR_FLAG_READY = 0x10000
DISSECTOR_FLAG_FAILED = 0x20000

IP_FREEBIND = 15
IPV6_FREEBIND = 78

parser = argparse.ArgumentParser(
    prog='activate',
    description='Create unconnected UDP sockets and put them in systemd file descriptor store')

parser.add_argument('-4', '--also-ipv4', action='store_true',
                    help='Clear IPV6_V6ONLY flag. Allow IPv4 traffic on IPv6 socket.')
parser.add_argument('-c', '--count', default=1, type=int,
                    help='REUSEPORT group size - how many sockets to create')
parser.add_argument('--freebind', action='store_true',
                    help='set IP_FREEBIND / IPV6_FREEBIND')
parser.add_argument('--rcvbuf', default=16777216, type=int,
                    help='set SO_RCVBUF to use non-default receive buffer')
parser.add_argument('name', help='Systemd file descriptor name / FDNAME')
parser.add_argument('address',
                    help='Address and port to bind to (like: 127.0.0.1:443 or [::1]:443)')
parser.add_argument('-v', '--verbose', action='store_true',
                    help='Verbose output logging.')
parser.add_argument('--no-register', action='store_true',
                    help='Skip socket registration step. We register sockets by default as work_gen+1 generation.')
parser.add_argument('--advance-working-gen', action='store_true',
                    help='Advance working generation after registration is done. Not recomended. Should be done by the application.')

bpfparser = parser.add_argument_group('udpgrm cBPF related options')
bpfparser.add_argument('-b', '--bpf', dest='CBPFFILE',
                       help='Load cBPF from given file. Expecting format like from \'bpf_asm -c\'.')
bpfparser.add_argument('-a', '--app', dest='APPNO', type=int,
                       help='Application number')
bpfparser.add_argument('-m', '--apps-max', default=0, type=int,
                       help='Max application count')
bpfparser.add_argument('-t', '--tubular', default="", help='Tubular label')
bpfparser.add_argument('-f', '--flow-timeout', default=124,
                       type=int, help='For FLOW dissector, the flow timeout')
bpfparser.add_argument('-s', '--sni', dest='QUICHOSTNAME', action='append',
                       help='Parse QUIC hostname in format hostname:appnumber.')
bpfparser.add_argument('-d', '--digest', type=lambda x: int(x, 0), default=0,
                       help='select digest')
bpfparser.add_argument('-n', '--noop', action='store_true',
                       help='Use built-in NOOP dissector')

if '--' in sys.argv:
    idx = sys.argv.index('--')
    prog_args = sys.argv[1:idx]
    cmd = sys.argv[idx+1:]
else:
    prog_args = sys.argv[1:]
    cmd = []

args = parser.parse_args(prog_args)

if args.APPNO is not None and (not args.digest and args.CBPFFILE is None and args.QUICHOSTNAME is None):
    print("[!] You need to select --bpf, --digest or --sni before doing --app")
    sys.exit(1)

cbpf = []
if args.CBPFFILE:
    r = re.compile(
        r'^\w*{\s+([x0-9a-f]+),\s+([\d]+),\s+([\d]+),\s+([x0-9a-f]+)\s+},\w*$')
    for line in filter(lambda l: l and l[0] == '{', open(args.CBPFFILE)):
        m = r.match(line.strip())
        if not m:
            print("[!] Bad line %r" % (line, ))
            sys.exit(1)
        cbpf.append(tuple(int(t, 0) for t in m.groups()))
    if args.verbose:
        print("[ ] Loaded %d cBPF instructions from %r" %
              (len(cbpf), args.CBPFFILE))

quic_hostnames = []
if args.QUICHOSTNAME:
    quic_hostnames = [h.split(":") for h in args.QUICHOSTNAME]


def addr_to_str(addr):
    ip_s = addr[0] if ':' not in addr[0] else "[%s]" % (addr[0],)
    return "%s:%d" % (ip_s, addr[1])


def pack_hostname(host):
    hostname = host[0]
    app = int(host[1]) if len(host) > 1 else 0
    return struct.pack('BB', app, len(hostname)) + bytes(hostname, "utf-8")


def retrying_setsockopt(sd, level, optname, value):
    for i in range(8):
        try:
            return sd.setsockopt(level, optname, value)
        except OSError as e:
            if e.args[0] == errno.EAGAIN:
                # exponential backoff
                time.sleep(0.01 * (2 ** i))
            else:
                raise


def main(args):
    SOCKETS = []

    ip, separator, port = args.address.rpartition(':')
    port = int(port)
    ip = ipaddress.ip_address(ip.strip("[]"))
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6

    addr = (str(ip), port)
    for i in range(args.count):
        sd = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            sd.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY,
                          0 if args.also_ipv4 else 1)

        if args.freebind:
            if family == socket.AF_INET:
                sd.setsockopt(socket.IPPROTO_IP, IP_FREEBIND, 1)
            else:
                sd.setsockopt(socket.IPPROTO_IPV6, IPV6_FREEBIND, 1)

        sd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        if args.rcvbuf != 0:
            sd.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.rcvbuf)

        sd.bind(addr)
        if i == 0 and addr[1] == 0:
            addr = sd.getsockname()

        D_FLAGS = 0
        if args.verbose:
            D_FLAGS = DISSECTOR_FLAG_VERBOSE
        if i == 0 and (cbpf or args.digest or args.tubular or quic_hostnames or args.noop):
            if cbpf:
                v = struct.pack("IIII100sI512s", DISSECTOR_CBPF | D_FLAGS,
                                0, args.apps_max, 0, bytes(
                                    args.tubular, 'utf-8'),
                                len(cbpf), b''.join(struct.pack('HBBI', *sf) for sf in cbpf))
            elif args.digest:
                v = struct.pack("IIII100sI512s", DISSECTOR_BESPOKE | D_FLAGS,
                                0, args.apps_max, args.digest, bytes(
                                    args.tubular, 'utf-8'),
                                len(quic_hostnames), b''.join(
                                    struct.pack('BB62s', int(a), 0,
                                                bytes(h, "utf-8"))
                                    for h, a in quic_hostnames))
            elif args.noop:
                v = struct.pack("IIII100s", DISSECTOR_NOOP | D_FLAGS,
                                0, 0, 0, bytes(args.tubular, 'utf-8'))
            elif args.tubular:
                v = struct.pack("IIII100s", DISSECTOR_FLOW | D_FLAGS,
                                args.flow_timeout, 0, 0, bytes(
                                    args.tubular, 'utf-8'))
            try:
                retrying_setsockopt(sd, socket.IPPROTO_UDP,
                                    UDP_GRM_DISSECTOR, v)
            except OSError as e:
                if e.errno == 1:
                    print("[!] setsockopt(UDP_GRM_DISSECTOR) failed. Dissector conflict? Try 'udpgrm delete %s'." % (
                        args.address,))
                else:
                    print(
                        "[!] setsockopt(UDP_GRM_DISSECTOR) failed. is udpgrm loaded? Try 'udpgrm --self --install'. (errno=%d)" % (e.errno,))
                sys.exit(1)


        if args.APPNO or args.apps_max:
            try:
                retrying_setsockopt(sd, socket.IPPROTO_UDP,
                                    UDP_GRM_SOCKET_APP, args.APPNO or 0)
            except OSError as e:
                if e.errno == 75:
                    print("[!] setsockopt(UDP_GRM_SOCKET_APP) failed. Perhaps conflict with APPMAX? (errno=%d)" % (
                        e.errno,))
                else:
                    print("[!] setsockopt(UDP_GRM_SOCKET_APP) failed. is udpgrm loaded? (errno=%d)" % (
                        e.errno,))
                sys.exit(1)

        SOCKETS.append(sd)

    if args.verbose:
        print("[ ] FDNAME=%s deleting old entry from fd store" % (args.name,))
    notify("FDSTOREREMOVE=1\nFDNAME=%s" % (args.name,))

    if args.verbose:
        print("[ ] FDNAME=%s adding %d UDP %s sockets to fd store" %
              (args.name, args.count, addr_to_str(addr)))
    notify("FDSTORE=1\nFDNAME=%s" % (args.name, ),
           fds=[fd.fileno() for fd in SOCKETS])

    if not args.no_register:
        # Socket pre-registration, to avoid the service having to perform this dance itself.
        # Get the current working generation so we can set the correct number for the next generation
        try:
            working_gen = struct.unpack("i", SOCKETS[0].getsockopt(
                socket.IPPROTO_UDP, UDP_GRM_WORKING_GEN, 4))[0]
        except OSError:
            print(
                "[!] getsockopt(UDP_GRM_WORKING_GEN) failed. is udpgrm still running?")
            sys.exit(1)

        # Set the number of the new generation of sockets. This triggers a socket register
        # message in the udpgrm daemon.
        for fd in SOCKETS:
            try:
                retrying_setsockopt(fd, socket.IPPROTO_UDP,
                                    UDP_GRM_SOCKET_GEN, (working_gen + 1))
            except OSError:
                print(
                    "[!] setsockopt(UDP_GRM_SOCKET_GEN) failed. is udpgrm still running?")
                sys.exit(1)

        # Wait until socket registration is complete
        for fd in SOCKETS:
            for i in range(10):
                v = fd.getsockopt(socket.IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 8)
                sk_gen, sk_idx = struct.unpack('II', v)
                if sk_idx != 0xffffffff:
                    # valid registration found
                    break
                if i >= 7:
                    print("[!] pre-registration failed. is udpgrm still running?")
                    sys.exit(1)
                # exponential backoff
                time.sleep(0.1 * (2 ** i))

        # Service can now call setsockopt(UDP_GRM_WORKING_GEN) to steer new connections towards these sockets
        if args.advance_working_gen:
            try:
                retrying_setsockopt(fd, socket.IPPROTO_UDP,
                                    UDP_GRM_WORKING_GEN, working_gen + 1)
            except OSError:
                print(
                    "[!] setsockopt(UDP_GRM_SOCKET_GEN) failed. is udpgrm still running?")
                sys.exit(1)
    return SOCKETS


def clear_cloexec(fd):
    fd = fd.fileno()
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    fcntl.fcntl(fd, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)


if __name__ == '__main__':
    sockets = main(args)
    if cmd:
        # only lazy-import here, not on a hot path
        import fcntl
        import os
        import shutil

        for sd in sockets:
            clear_cloexec(sd)
        os.execve(shutil.which(cmd[0]), cmd, os.environ)
