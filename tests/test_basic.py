from . import base
from .lsocket import *
import os
import struct
import time


class BasicTest(base.TestCase):
    def test_help(self):
        """Basic test if -h prints stuff looking like help screen."""
        p = self.udpgrm_run("-h")
        self.assertIn("Usage: udpgrm ", p.stdout_line())
        self.assertIn("Options", p.stdout_line())
        self.assertIn(p.close(kill=False), (254,))

    def test_daemon(self):
        """Test basic empty --daemon run"""
        p = self.udpgrm_run("--daemon")
        self.assertIn("Loading BPF", p.stderr_line())
        self.assertIn("Pinning bpf programs ", p.stderr_line())
        self.assertIn("Tailing message ", p.stderr_line())
        self.assertEqual(p.close(), 0)

    def test_daemon_install(self):
        p = self.udpgrm_run("--daemon --install")
        self.assertIn("Loading BPF", p.stderr_line())
        self.assertIn("Pinning bpf programs ", p.stderr_line())
        self.assertIn("Installing BPF into ", p.stderr_line())
        self.assertIn("Tailing message ", p.stderr_line())
        self.assertEqual(p.close(), 0)

    def test_kill_cleanup(self):
        ''' Test if on exiting the cgroup hooks and bpffs is cleared '''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        self.assertEqual(p.graceful_stop(), 0)

        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        self.assertEqual(p.graceful_stop(), 0)

    def test_metrics_run(self):
        ''' Just validate 'udpgrm list' command '''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])

        sa = self.socket()
        sa.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        sa.bind(('127.0.0.1', 0))

        wrk_gen = sa.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
        if wrk_gen < 0:
            wrk_gen = 0
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, wrk_gen + 1)

        l = self.udpgrm_run("list -v")
        self.assertIn('127.0.0.1', l.stdout_line())
        self.assertIn('netns', l.stdout_line())
        self.assertIn('socket generations', l.stdout_line())
        self.assertIn('app 0', l.stdout_line())
        self.assertIn('metrics', l.stdout_line())

    def test_socket_registration(self):
        ''' Validate messages during socket group registration '''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing message ring")[0])

        sa = self.socket()
        sa.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        sa.bind(('127.0.0.1', 0))

        wrk_gen = sa.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)
        self.assertIn("socket group created", p.stdout_line())
        self.assertIn("registering socket", p.stdout_line())
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, wrk_gen + 1)
        self.assertIn("socket found", p.stdout_line())
        self.assertIn("setting working gen", p.stdout_line())
        self.assertIn("Working gen", p.stdout_line())

    def test_abi_check_loaded_daemon(self):
        ''' returns proto 92 with no loaded ebpf, and -1 with loaded '''
        sd = socket.socket(AF_INET, SOCK_DGRAM, 0)

        # Typically this means there is another --daemon working in the background
        with self.assertRaisesRegex(OSError, 'Errno 92. Protocol not available'):
            sd.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
        sd.close()

        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])

        # this is -1 with no socket group
        sd = socket.socket(AF_INET, SOCK_DGRAM, 0)
        x = sd.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
        self.assertEqual(x, -1)

        # this is -1 with socket group present but default value of -1
        sd.bind(('127.0.0.1', 0))
        x = sd.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
        self.assertEqual(x, -1)

        sd.close()

    def test_abi_grm_set_dissector(self):
        ''' basic dissector ABI'''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        sd, _ = self.bind()

        with self.assertRaisesRegex(OSError, 'Errno 77. File descriptor in bad state'):
            sd.getsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR)

        with self.assertRaisesRegex(OSError, 'Errno 77. File descriptor in bad state'):
            sd.getsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, 32)

        v = struct.pack("II", DISSECTOR_FLOW, 125)
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        # setting the same values doesnt fail
        v = struct.pack("IIII", DISSECTOR_FLOW, 125, 0, 0)
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        v = struct.pack("IIII", DISSECTOR_FLOW, 125, 0, 0)

        self.assertEqual(sd.getsockopt(
            IPPROTO_UDP, UDP_GRM_DISSECTOR, 4), v[:4])
        self.assertEqual(sd.getsockopt(
            IPPROTO_UDP, UDP_GRM_DISSECTOR, 8), v[:8])
        self.assertEqual(sd.getsockopt(
            IPPROTO_UDP, UDP_GRM_DISSECTOR, 12), v[:12])
        self.assertEqual(sd.getsockopt(
            IPPROTO_UDP, UDP_GRM_DISSECTOR, 16), v[:16])

        # setting different values fails
        with self.assertRaisesRegex(OSError, 'Errno 1. Operation not permitted'):
            v = struct.pack("IIII", DISSECTOR_FLOW, 124, 0, 0)
            sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        with self.assertRaisesRegex(OSError, 'Errno 1. Operation not permitted'):
            v = struct.pack("IIII", 1, 125, 0, 0)
            sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

    def test_abi_grm_set_dissector_dcid(self):
        ''' dissector ABI try changing dcid'''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        sd, _ = self.bind()

        v = struct.pack("IIII", DISSECTOR_FLOW, 125, 0, 0)
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        # compare result of getsockopt - should be identical
        v = struct.pack("IIII", DISSECTOR_FLOW, 125, 0, 0)

        self.assertEqual(sd.getsockopt(
            IPPROTO_UDP, UDP_GRM_DISSECTOR, 4), v[:4])
        self.assertEqual(sd.getsockopt(
            IPPROTO_UDP, UDP_GRM_DISSECTOR, 8), v[:8])
        self.assertEqual(sd.getsockopt(
            IPPROTO_UDP, UDP_GRM_DISSECTOR, 12), v[:12])
        self.assertEqual(sd.getsockopt(
            IPPROTO_UDP, UDP_GRM_DISSECTOR, 16), v[:16])

        # setting different values fails
        for t in [(DISSECTOR_CBPF, 125, 0, 0),
                  (DISSECTOR_FLOW, 124, 0, 0),
                  (DISSECTOR_FLOW, 125, 5, 0),
                  (DISSECTOR_FLOW, 125, 0, 17)]:
            with self.assertRaisesRegex(OSError, 'Errno 1. Operation not permitted'):
                v = struct.pack("IIII", *t)
                sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        # but the same values works just fine
        v = struct.pack("IIII", DISSECTOR_FLOW, 125, 0, 0)
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

    def test_socket_socket_gen_abi(self):
        ''' test error cases of UDP_GRM_SOCKET_GEN '''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        sd, _ = self.bind()

        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN)
        self.assertEqual(v, -1)
        # on socket register, the gen/idx are -1
        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12)
        self.assertEqual(v, struct.pack(
            'III', 0xffffffff, 0xffffffff, 0xff7f))

        # you can set arbitrary socket gen
        p.stop()
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 1)

        # now socket_gen = 1
        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12)
        self.assertEqual(v, struct.pack('III', 1, 0xffffffff, 0xffa1))

        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN)
        self.assertEqual(v, 1)
        p.cont()

        self.assertIn('socket group created', p.stdout_line())
        self.assertIn('registering socket', p.stdout_line())
        self.assertIn('socket found', p.stdout_line())
        self.sync_socket_gen(sd, prev=0xffa1)

        # now socket gen = 1 and socket idx = 1
        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12)
        self.assertEqual(v, struct.pack('III', 1, 0, 0xa1))

        # reset to another value is weird but totally ok
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 31)
        self.sync_socket_gen(sd, prev=0x01)

        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12)
        self.assertEqual(v, struct.pack('III', 31, 0, 0x7f))
        self.assertIn('registering socket', p.stdout_line())
        self.assertIn('weird', p.stdout_line())
        self.assertIn('socket found', p.stdout_line())
        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12)
        self.assertEqual(v, struct.pack('III', 31, 0, 0x7f))

        # second time in the same socket gen is also weird but fine
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 31)
        # if the same socket gen is used, the cookie will not change
        self.sync_socket_gen(sd)
        # in addition the socket will not be registered twice
        # self.assertIn('registering socket', p.stdout_line())
        # self.assertIn('weird', p.stdout_line())
        # self.assertIn('socket found', p.stdout_line())
        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12)
        self.assertEqual(v, struct.pack('III', 31, 0, 0x7f))

        # values above 31 are trimmed, but api still returns uncut value
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 99999)
        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN)
        self.assertEqual(v, 99999)

        # -1 is also fine
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, -1)
        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN)
        self.assertEqual(v, -1)

    def test_socket_gen_registering_delay(self):
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        sd, _ = self.bind()

        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN)
        self.assertEqual(v, -1)

        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 8)
        self.assertEqual(v, struct.pack('II', 0xffffffff, 0xffffffff))

        p.stop()
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)

        v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 8)
        self.assertEqual(v, struct.pack('II', 0, 0xffffffff))
        p.cont()

        # got socket index in < 3 seconds (without sync on stdout)
        t0 = time.time()
        i = 0
        while time.time() - t0 < 3:
            os.sched_yield()
            i += 1
            v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 8)
            if v != struct.pack('II', 0, 0xffffffff):
                self.assertEqual(v, struct.pack('II', 0, 0))
                break
        else:
            self.fail()

    def test_too_many_socket_groups_delete(self):
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        A = []
        while True:
            sd, _ = self.bind()
            try:
                sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
            except OSError:
                break
            self.assertTrue(p.collect_stdout("socket found")[0])
            A.append(sd)

        with self.assertRaisesRegex(OSError, 'Errno 9. Bad file descriptor'):
            sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)

        for s in A:
            ip, port = s.getsockname()
            p = self.udpgrm_run("delete %s:%d" % (ip, port))
            p.close(kill=False)

        # no error
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)

    def test_egain_on_setting_working_group(self):
        '''
        On UDP_GRM_SOCKET_GEN you can get EAGAIN when the internal queue is overfilled.
        '''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])

        sd, port = self.bind()
        S = [sd]
        for i in range(1, 256):
            sd, _ = self.bind(port=port)
            S.append(sd)
        self.assertEqual(len(S), 256)

        blocking = 0
        for s in S:
            try:
                s.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 1)
            except BlockingIOError:
                blocking += 1
                os.sched_yield()
                time.sleep(0.01)
                s.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 1)
        # Almost impossible to overflow ring buffer in test environment, even with more sockets!
        # If we find a way, revert this test to >=0.
        self.assertEqual(blocking, 0)

        self.sync_socket_gen(S[-1])
        a = p.fd_count()

        sd, _ = self.bind(port=port)
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 1)

        p.collect_stdout('too many sockets in the gen!')
        v = struct.unpack('ii', sd.getsockopt(
            IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 8))
        self.assertEqual(v, (1, -1))

        # dont leak fd
        self.assertEqual(p.fd_count(), a)

        # re-registering after random close is fine!
        pp = self.udpgrm_run("list -v")
        for line in pp.collect_stdout():
            if line.lstrip().startswith('gen '):
                a, _, b = line.partition('0:')
                b, _, _ = b.partition('<=')
                cookies = b.strip().split()
        self.assertEqual(len(cookies), 256)

        S[253].close()
        self._del_teardown(S[253])

        sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 1)
        self.sync_socket_gen(sd)
        v = struct.unpack('ii', sd.getsockopt(
            IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 8))
        self.assertEqual(v, (1, 253))

        # re-registering after random close is fine, still 256 sockets
        pp = self.udpgrm_run("list -v")
        cookies = None
        for line in pp.collect_stdout():
            if line.lstrip().startswith('gen '):
                a, _, b = line.partition('0:')
                b, _, _ = b.partition('<=')
                cookies = b.strip().split()

        self.assertEqual(len(cookies), 256)

    def test_metrics_duplicated(self):
        ''' Read old metrics on daemon restart '''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])

        # keep pointer to old map!
        if True:
            sx, _ = self.bind()

            wrk_gen = sx.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
            if wrk_gen < 0:
                wrk_gen = 0
            sx.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)
            sx.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, wrk_gen + 1)
            self.sync_socket_gen(sx)

        # in a moment we'll overwrite sa reuseport program, therfore
        # we'll loose the last reference to sk_reusepo map. Keep sx socket
        # to keep the reference
        if True:
            sa, port = self.bind()

            wrk_gen = sa.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
            if wrk_gen < 0:
                wrk_gen = 0
            sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)
            sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, wrk_gen + 1)
            self.sync_socket_gen(sa)

            old = self.connect()
            old.send(b'hello')
            self.assertEqual(sa.recv(1024), b'hello')
        p.close()

        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])

        if True:
            sb, _ = self.bind(port=port)

            wrk_gen = sb.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
            if wrk_gen < 0:
                wrk_gen = 0
            sb.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, wrk_gen + 1)
            sb.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, wrk_gen + 1)
            self.sync_socket_gen(sb)

            new = self.connect()
            new.send(b'hello')
            self.assertEqual(sb.recv(1024), b'hello')

        # The test is about metrics, +1 on each map
        D = self.metrics_rich()
        self.assertEqual(D['127.0.0.1:%s' % port]['metrics'], {
            'rx_processed_total': 1,
            'rx_dissected_ok_total': 1,
            'rx_flow_new_unseen': 1,
            'rx_new_flow_total': 1,
            'rx_new_flow_working_gen_dispatch_ok': 1})

        self.assertEqual(D['127.0.0.1:%s (old)' % port]['metrics'], {
            'rx_processed_total': 1,
            'rx_dissected_ok_total': 1,
            'rx_flow_new_unseen': 1,
            'rx_new_flow_total': 1,
            'rx_new_flow_working_gen_dispatch_ok': 1})

        # test selector
        D = self.metrics_rich('127.0.0.1:%s' % port)
        self.assertEqual(sorted(D.keys()), [
                         '127.0.0.1:%s' % port, '127.0.0.1:%s (old)' % port])

        # test empty
        D = self.metrics_rich('127.0.0.1:%s' % (port + 1,))
        self.assertEqual(sorted(D.keys()), [])

    def test_daemon_fail_start(self):
        """Test running daemon twice"""
        p = self.udpgrm_run("--daemon")
        self.assertTrue(p.collect_stderr("Tailing")[0])

        p2 = self.udpgrm_run("--daemon")
        self.assertIn("Loading BPF", p2.stderr_line())
        self.assertIn("Looks like /sys", p2.stderr_line())
        self.assertEqual(p2.close(kill=False), 255)

        # But --force is okay
        p2 = self.udpgrm_run("--daemon --force")
        self.assertTrue(p2.collect_stderr("Tailing")[0])
        self.assertEqual(p2.close(), 0)

        # p closes fine, even though it's in a bad state.
        self.assertEqual(p.close(), 0)
