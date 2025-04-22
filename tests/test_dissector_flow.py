import os
import select

from . import base
from .lsocket import *
from struct import pack


class DissectorFlow(base.TestCase):
    def test_generations_stickiness(self):
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing message ring")[0])

        sa, port = self.bind('127.0.0.1')
        wrk_gen = sa.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, wrk_gen + 1)

        self.assertTrue(p.collect_stdout("Working gen")[0])

        # traffic goes to server
        old = self.socket()
        old.connect(('127.0.0.1', port))
        old.send(b'hello')
        # new flow is only created on response from srv
        self.assertEqual(sa.echo(), b'hello')

        # new server
        sb, _ = self.bind('127.0.0.1', port)
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 2)
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, wrk_gen + 2)
        self.assertTrue(p.collect_stdout("Working gen")[0])

        D, M = self.metrics_delta({})
        self.assertEqual(D, {'rx_processed_total': 1,
                             'rx_dissected_ok_total': 1,
                             'rx_flow_new_unseen': 1,
                             'rx_new_flow_total': 1,
                             'rx_new_flow_working_gen_dispatch_ok': 1,
                             'tx_total': 1,
                             'tx_flow_create_ok': 1})

        # old traffic goes to old server
        old.send(b'hello')
        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_processed_total': 1,
                             'rx_dissected_ok_total': 1,
                             'rx_flow_ok': 1})
        self.assertEqual(sa.recv(99), b'hello')

        # new traffic goes to new server
        new = self.socket()
        new.connect(('127.0.0.1', port))
        new.send(b'hello-new')
        self.assertEqual(sb.echo(99), b'hello-new')

        p = self.udpgrm_run("flows")
        self.assertIn("127.0.0.1", p.stdout_line())
        self.assertIn("so_cookie", p.stdout_line())
        self.assertIn("age", p.stdout_line())
        self.assertIn("so_cookie", p.stdout_line())
        self.assertIn("age", p.stdout_line())

    def test_reuseport_stickiness(self):
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing message ring")[0])

        sa0, port = self.bind('127.0.0.1')

        wrk_gen = sa0.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
        sa0.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)
        self.assertTrue(p.collect_stdout("socket found")[0])
        sa0.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, wrk_gen + 1)
        self.assertTrue(p.collect_stdout("Working gen")[0])

        # traffic goes to the only socket
        old = self.socket()
        old.connect(('127.0.0.1', port))
        old.send(b'hello')
        D, M = self.metrics_delta({})
        self.assertEqual(D, {'rx_processed_total': 1,
                             'rx_dissected_ok_total': 1,
                             'rx_flow_new_unseen': 1,
                             'rx_new_flow_total': 1,
                             'rx_new_flow_working_gen_dispatch_ok': 1})

        # new flow is only created on response from srv
        self.assertEqual(sa0.echo(), b'hello')
        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'tx_flow_create_ok': 1,
                             'tx_total': 1})

        # create more sockets in current gen
        sa1, _ = self.bind('127.0.0.1', port)
        sa1.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)
        sa2, _ = self.bind('127.0.0.1', port)
        sa2.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)

        # old flow still goes to the right reuseport socket
        old.send(b'hello')
        self.assertEqual(sa0.echo(), b'hello')
        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_flow_ok': 1,
                             'rx_dissected_ok_total': 1,
                             'rx_processed_total': 1,
                             'tx_flow_update_ok': 1,
                             'tx_total': 1})

        # create new socket group
        sb0, _ = self.bind('127.0.0.1', port)
        sb0.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 2)
        sb1, _ = self.bind('127.0.0.1', port)
        sb1.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 2)
        sb2, _ = self.bind('127.0.0.1', port)
        sb2.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 2)

        sb0.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, wrk_gen + 2)
        self.assertTrue(p.collect_stdout("Working gen ")[0])

        # old flow still goes to the right reuseport socket
        old.send(b'hello')
        self.assertEqual(sa0.echo(), b'hello')
        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_flow_ok': 1,
                             'rx_dissected_ok_total': 1,
                             'rx_processed_total': 1,
                             'tx_flow_update_ok': 1,
                             'tx_total': 1})

        x = self.socket()
        x.connect(('127.0.0.1', port))
        x.send(b'hello')

        sl, _, _ = select.select([sb0, sb1, sb2], [], [], 1)
        self.assertTrue(sl)
        for s in sl:
            self.assertEqual(s.echo(), b'hello')
        D, M = self.metrics_delta(M)
        self.assertEqual(D, {
            'rx_dissected_ok_total': 1,
            'rx_processed_total': 1,
            'rx_flow_new_unseen': 1,
            'rx_new_flow_total': 1,
            'rx_new_flow_working_gen_dispatch_ok': 1,
            'tx_flow_create_ok': 1,
            'tx_total': 1})

        x.send(b'hello')
        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_processed_total': 1,
                             'rx_dissected_ok_total': 1,
                             'rx_flow_ok': 1})

        # os.system('./udpgrm-test list')
        # os.system('./udpgrm-test flows')
        # os.system('ss -aenup dport = :%d or sport = :%d|cat' % (port,port))

    def test_flow_assure_v4(self):
        '''
        Test UDP_GRM_FLOW_ASSURE for ipv4
        '''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing message ring")[0])

        sa, port = self.bind('127.0.0.1')
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR,
                      pack("II", DISSECTOR_FLOW, 126))
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 34)

        sb, _ = self.bind('127.0.0.1', port)
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 35)
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 35)
        self.assertTrue(p.collect_stdout("Working gen")[0])

        D, M = self.metrics_delta({})
        self.assertEqual(D, {})

        for ss in (sa, sb, sa):
            for i in range(2):
                ca = self.connect()
                lip, lport = ca.getsockname()
                ss.setsockopt(IPPROTO_UDP, UDP_GRM_FLOW_ASSURE,
                              pack('HH4sII',
                                   socket.AF_INET,
                                   socket.htons(lport),
                                   socket.inet_pton(socket.AF_INET, lip),
                                   0, 0))
                D, M = self.metrics_delta(M)
                self.assertEqual(D, {'tx_flow_create_ok': 1, 'tx_total': 1})
                for j in range(2):
                    ca.send(b'hello')
                    self.assertEqual(ss.recv(32), b'hello')

                D, M = self.metrics_delta(M)
                self.assertEqual(D, {'rx_processed_total': 2,
                                     'rx_dissected_ok_total': 2,
                                     'rx_flow_ok': 2})

    def test_flow_assure_v6(self):
        '''
        Test UDP_GRM_FLOW_ASSURE for ipv6
        '''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing message ring")[0])

        sa, port = self.bind('::1')
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR,
                      pack("II", DISSECTOR_FLOW, 126))
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 34)

        sb, _ = self.bind('::1', port)
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 35)
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 35)
        self.assertTrue(p.collect_stdout("Working gen")[0])

        D, M = self.metrics_delta({})
        self.assertEqual(D, {})

        for ss in (sa, sb, sa):
            for i in range(2):
                ca = self.connect()
                lip, lport, flowinfo, scopeid = ca.getsockname()
                ss.setsockopt(IPPROTO_UDP, UDP_GRM_FLOW_ASSURE,
                              pack('HHI16sI',
                                   socket.AF_INET6,
                                   socket.htons(lport),
                                   socket.htonl(flowinfo),
                                   socket.inet_pton(socket.AF_INET6, lip),
                                   scopeid))
                D, M = self.metrics_delta(M)
                self.assertEqual(D, {'tx_flow_create_ok': 1, 'tx_total': 1})
                for j in range(2):
                    ca.send(b'hello')
                    self.assertEqual(ss.recv(32), b'hello')

                D, M = self.metrics_delta(M)
                self.assertEqual(D, {'rx_processed_total': 2,
                                     'rx_dissected_ok_total': 2,
                                     'rx_flow_ok': 2})

        # create flow entry
        v = pack('HHI16sI', socket.AF_INET6,
                 socket.htons(1234), socket.htonl(0),
                 socket.inet_pton(socket.AF_INET6, "::1"), 0)
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_FLOW_ASSURE, v)

        # check if setting flow on another socket fails
        with self.assertRaisesRegex(OSError, 'Errno 17. File exists'):
            sb.setsockopt(IPPROTO_UDP, UDP_GRM_FLOW_ASSURE, v)

    def test_flow_table_overflow(self):
        '''
        '''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing message ring")[0])

        sa, _ = self.bind('127.0.0.1')
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR,
                      pack("II", DISSECTOR_FLOW, 126))
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 34)

        D, M = self.metrics_delta({})
        self.assertEqual(D, {})

        for i in range(8192+100):
            sa.setsockopt(IPPROTO_UDP, UDP_GRM_FLOW_ASSURE,
                          pack('HH4sII',
                               socket.AF_INET,
                               socket.htons(1024+i),
                               socket.inet_pton(socket.AF_INET, '192.0.2.1'),
                               0, 0))

        D, M = self.metrics_delta(M)
        # All should be create, but on conflict update also +1's
        self.assertEqual(D['tx_flow_create_ok'] +
                         D.get('tx_flow_update_ok', 0), 8292)
        self.assertEqual(D['tx_total'], 8292)

        # new flows still are ok, and are yanking old flows
        for i in range(2):
            ca = self.connect()
            lip, lport = ca.getsockname()
            sa.setsockopt(IPPROTO_UDP, UDP_GRM_FLOW_ASSURE,
                          pack('HH4sII',
                               socket.AF_INET,
                               socket.htons(lport),
                               socket.inet_pton(socket.AF_INET, lip),
                               0, 0))
            D, M = self.metrics_delta(M)
            self.assertEqual(D, {'tx_flow_create_ok': 1, 'tx_total': 1})
            for j in range(2):
                ca.send(b'hello')
                self.assertEqual(sa.recv(32), b'hello')

            D, M = self.metrics_delta(M)
            self.assertEqual(D, {'rx_processed_total': 2,
                                 'rx_dissected_ok_total': 2,
                                 'rx_flow_ok': 2})
