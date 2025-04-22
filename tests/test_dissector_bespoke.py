from struct import pack, unpack
from . import base
from .lsocket import *
import random
import select
import shlex

TQCLIENT_BIN = "./client"
TQSERVER_BIN = "./tqserver --crt examples/cert.crt --key examples/cert.key"


def quic_client(port_or_addr, list_of_sni):
    if isinstance(port_or_addr, int) or ':' not in port_or_addr:
        addr = '127.0.0.1:%d' % (port_or_addr,)
    else:
        addr = port_or_addr
    argv0 = shlex.split(TQCLIENT_BIN)
    cmd = argv0 + ["--target", addr] + list_of_sni
    p = base.Process(cmd)
    r = p.collect_stdout()
    p.close()
    return '\n'.join(r).strip()


def set_apps(self, sni, apps_max=4, tubular=b''):
    digest = 0xDEAD
    socks = []
    port = 0
    for i in range(apps_max):
        s, port = self.bind(port=port)
        if i == 0:
            v = pack("IIII100sI512s", DISSECTOR_DIGEST,
                     0, apps_max, digest, tubular,
                     len(sni), b''.join(pack('BB62s', app, 0, bytes(name, "utf-8")) for name, app in sni))
            s.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        socks.append(s)
        s.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_APP, i)
        s.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 1)
        s.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 1)
        self.sync_socket_gen(s)

    # it's enough to sync last socket
    return socks, port


class TestDissectorDigest(base.TestCase):
    def h3_srv_run(self, argv1=[], pass_fds=[]):
        pass_fds = [fd.fileno() for fd in pass_fds]
        argv0 = shlex.split(TQSERVER_BIN)

        if isinstance(argv1, str):
            argv1 = shlex.split(argv1)

        cmd = argv0 + argv1
        p = base.Process(cmd, pass_fds=pass_fds)
        self._add_teardown(p)
        return p

    def test_digest(self):
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        sni = [('a.e.com', 1),
               ('b.e.com', 2),
               ('c.e.com', 3),
               ('e.com', 3),
               ('', 0)]
        list_of_fds, port = set_apps(self, sni)
        cookies = list(map(lambda fd: '#'+fd.cookie(), list_of_fds))
        snimap = dict(((n, cookies[i]) for n, i in sni))

        srv = self.h3_srv_run(pass_fds=list_of_fds)
        self.assertIn('from activation', srv.stdout_line())
        self.assertIn('from activation', srv.stdout_line())
        self.assertIn('from activation', srv.stdout_line())
        self.assertIn('from activation', srv.stdout_line())

        for hname in ['a.e.com', 'b.e.com', 'c.e.com', 'e.com', 'bad.com']:
            recv_cookie = quic_client(port, ['https://'+hname])
            self.assertEqual(recv_cookie, snimap.get(hname, cookies[0]))
