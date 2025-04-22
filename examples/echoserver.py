#!/bin/env python3
'''
Example of DISSECTOR_FLOW.

$ sudo systemd-run \
        --unit echoserver \
	-p Type=notify \
        -p NotifyAccess=all \
        -p FileDescriptorStoreMax=128\
        -p ExecStartPre="$PWD/udpgrm --install --self" \
        -p ExecStartPre="$PWD/tools/udpgrm_activate.py \
                --no-register \
                --count=8 \
                xxx 0.0.0.0:4433" \
	-p KillMode=process \
        -p KillSignal=SIGTERM \
        -p Restart=always \
        -- $PWD/mmdecoy \
        	-- $PWD/examples/venv/bin/python3 $PWD/examples/echoserver.py

$ nc -u 127.0.0.1 4433
hello world
sk=0x0016876f data=b'hello wo'

$ sudo ./udpgrm flows
[ ] Retrievieng BPF progs from /sys/fs/bpf/udpgrm
0.0.0.0:4433
	so_cookie 0x16876f
		1807193a  age 18.1s 

'''

import subprocess
import socket
import select
from socket import (SOL_SOCKET, SO_DOMAIN, SO_TYPE, SO_PROTOCOL)

import os
import sys
import struct
import ipaddress
import itertools
import time
import signal
from systemd.daemon import notify


socket.IP_PKTINFO = 8
socket.SO_COOKIE = 57


SOCKETS = {}

RPCOUNT = 8

sys.stdout.reconfigure(line_buffering=True)


def sockets_from_activation():
    listenfds = int(os.environ.get('LISTEN_FDS', '0'))
    fdnames = os.environ.get('LISTEN_FDNAMES', None)
    if fdnames:
        fdnames = fdnames.split(':')
    else:
        fdnames = []

    if len(fdnames) != listenfds:
        raise OSError("LISTEN_FDS doesn't match LISTEN_FDNAMES")

    SOCKETS = []
    for fd, fdname in zip(range(3, listenfds+3), fdnames):
        # In python we need socket object to call getsockopt
        tmp_sd = socket.fromfd(fd, 0, 0, 0)
        try:
            domain = tmp_sd.getsockopt(SOL_SOCKET, SO_DOMAIN)
            type = tmp_sd.getsockopt(SOL_SOCKET, SO_TYPE)
            protocol = tmp_sd.getsockopt(SOL_SOCKET, SO_PROTOCOL)
        except OSError:
            # not a socket
            pass
        else:
            sd = socket.socket(domain, type, protocol, fileno=fd)
            SOCKETS.append((fdname, sd))
        # tmp_sd is a dup, we must close it
        tmp_sd.close()
    return SOCKETS


def addr_to_str(addr):
    ip_s = addr[0] if ':' not in addr[0] else "[%s]" % (addr[0],)
    return "%s:%d" % (ip_s, addr[1])


for addr in sys.argv[1:]:
    ip, separator, port = addr.rpartition(':')
    port = int(port)
    ip = ipaddress.ip_address(ip.strip("[]"))
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6

    addr = (str(ip), port)
    for i in range(RPCOUNT):
        sd = socket.socket(family, socket.SOCK_DGRAM)
        if ip.version == 4:
            sd.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
        else:
            sd.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
            sd.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        sd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

        sd.bind(addr)
        if i == 0 and addr[1] == 0:
            addr = sd.getsockname()
        if i == 0:
            print("%d [+] Opening %d sockets %s" %
                  (os.getpid(), RPCOUNT, addr_to_str(addr)))

        SOCKETS.setdefault(addr, []).append(sd)

for sdname, sd in sockets_from_activation():
    family = sd.getsockopt(SOL_SOCKET, SO_DOMAIN)
    assert sd.getsockopt(SOL_SOCKET, SO_TYPE), SOCK_DGRAM
    addr = sd.getsockname()

    print("%d [+] Socket from acivation %s: %s" %
          (os.getpid(), sdname, addr_to_str(addr,)))

    if family == socket.AF_INET:
        sd.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
    else:
        sd.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)

    SOCKETS.setdefault(addr, []).append(sd)


UDP_GRM_WORKING_GEN = 200
UDP_GRM_SOCKET_GEN = 201
UDP_GRM_DISSECTOR = 202

for addr, sockets in SOCKETS.items():
    sd = sockets[0]
    try:
        wrk_gen = sd.getsockopt(socket.IPPROTO_UDP, UDP_GRM_WORKING_GEN)
    except OSError:
        print("%d [!] Failed: udpgrm not loaded" % (os.getpid(),))
        break
    for s in sockets:
        try:
            s.setsockopt(socket.IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)
        except BlockingIOError:
            print("%d [ ] blocking" % (os.getpid(),))
            time.sleep(0.2)
            s.setsockopt(socket.IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)

    # max 1s wait
    t0 = time.time()
    for s in sockets:
        while t0 + 1 > time.time():
            v = s.getsockopt(socket.IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 8)
            sk_gen, sk_idx = struct.unpack('II', v)
            if sk_idx != 0xffffffff:
                break
            os.sched_yield()
            time.sleep(0.01)
        else:
            print('%d [!] Failed to sync with udpgrm' % (os.getpid(),))
    sd.setsockopt(socket.IPPROTO_UDP, UDP_GRM_WORKING_GEN, wrk_gen + 1)
    print("%d [ ] udpgrm: %s working gen %d -> %d" %
          (os.getpid(), addr_to_str(addr), wrk_gen, wrk_gen+1))


def unpack_cmsg(cmsg):
    addr = None
    for cmsg_level, cmsg_type, data in cmsg:
        if cmsg_level == socket.IPPROTO_IPV6 and cmsg_type == socket.IPV6_PKTINFO:
            # struct in6_pktinfo {
            #     struct in6_addr ipi6_addr; 16 bytes
            #     int             ipi6_ifindex; 4 bytes
            # };
            addr_bin, if_index = struct.unpack("16sI", data)
            addr = socket.inet_ntop(socket.AF_INET6, addr_bin)
            addr = (addr, 0, 0, if_index)
        elif cmsg_level == socket.IPPROTO_IP and cmsg_type == socket.IP_PKTINFO:
            # struct in_pktinfo {
            #     unsigned int   ipi_ifindex; 4 bytes
            #     struct in_addr ipi_spec_dst; 4 bytes
            #     struct in_addr ipi_addr; 4 bytes
            # };
            if_index, spec_dst_bin, addr_bin = struct.unpack("I4s4s", data)
            addr = socket.inet_ntop(socket.AF_INET, addr_bin)
            addr = (addr, 0, if_index)
        else:
            assert (0)
    return addr


def pack_pktinfo_cmsg(local_addr):
    if ':' not in local_addr[0]:
        local_addr_bin = socket.inet_pton(socket.AF_INET, local_addr[0])
        return (socket.IPPROTO_IP,
                socket.IP_PKTINFO,
                struct.pack("I4s4s", local_addr[2], local_addr_bin, b'\x00' * 4))
    else:
        local_addr_bin = socket.inet_pton(socket.AF_INET6, local_addr[0])
        return (socket.IPPROTO_IPV6,
                socket.IPV6_PKTINFO,
                struct.pack("16si", local_addr_bin, local_addr[3]))


sigint = 0
gracefull_quit = False

# Exit graceful when no msg after 15 sec
loop_in_seconds = 15

decoy_pid = os.getppid()


def sigint_handler(sig, frame):
    global sigint, gracefull_quit
    sigint += 1
    if sigint > 1:
        print("%d [!] SIG%d received second time, terminating" %
              (os.getpid(), sig))
        sys.exit(0)
    else:
        notify("STOPPING=1")
        print("%d [!] SIG%d received, gracefull stop (decoy=%d)" %
              (os.getpid(), sig, decoy_pid))
        # reload / restart
        os.kill(decoy_pid, signal.SIGURG)
        gracefull_quit = True


signal.signal(signal.SIGINT, sigint_handler)
signal.signal(signal.SIGTERM, sigint_handler)
signal.signal(signal.SIGHUP, sigint_handler)


LIST_OF_SOCKETS = list(itertools.chain(*SOCKETS.values()))

if not LIST_OF_SOCKETS:
    print("%d [!] no sockets, exiting" % (os.getpid(),))
    sys.exit(0)

notify("READY=1")

while True:
    rd, _, _ = select.select(LIST_OF_SOCKETS, [], [], loop_in_seconds)
    for sd in rd:
        data, cmsg, _flg, remote_addr = sd.recvmsg(1024*64, 256)
        local_addr = unpack_cmsg(cmsg)

        sk_cookie = sd.getsockopt(socket.SOL_SOCKET, socket.SO_COOKIE, 8)
        sk_cookie, = struct.unpack('Q', sk_cookie)
        cmsg = pack_pktinfo_cmsg(local_addr)
        buf = ("sk=0x%08x data=%s\n" % (sk_cookie, repr(data[:8]))).encode()
        sd.sendmsg([buf], [cmsg], 0, remote_addr)
    if not rd and gracefull_quit:
        print("%d [!] All flows drained, quitting" % (os.getpid(),))
        break
