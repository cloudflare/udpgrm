import select

from struct import pack, unpack
from . import base
from .lsocket import *


class DissectorCbpf(base.TestCase):
    def intro(self, cbpf, p=None, apps=0):
        if p is None:
            p = self.udpgrm_run("--daemon --install")
            self.assertTrue(p.collect_stderr("Tailing")[0])

        sa, port = self.bind()

        v = pack("IIII100sI256s", DISSECTOR_CBPF,
                 0, apps, 0, b'',
                 len(cbpf), b''.join(pack('HBBI', *sf) for sf in cbpf))
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
        self.assertTrue(p.collect_stdout("socket found")[0])

        # no need to update WORKING_GEN since it's zero anyway
        D, M = self.metrics_delta({}, port=port)
        self.assertEqual(D, {})

        x = self.connect()

        D, M = self.metrics_delta(M, port=port)
        self.assertEqual(D, {})

        return p, sa, x, M

    def outro(self, sd):
        addr = sd.getsockname()
        p = self.udpgrm_run("delete %s:%d" % (addr[0], addr[1]))

    def test_filter_minus_one(self):
        '''
        Return value of cBPF being -1 counts as "new_flow".
        '''

        '''
        $ echo "ret #-1" | bpf_asm -c | tr "{}" "()"
        ( 0x06,  0,  0, 0xffffffff ),
        '''
        cbpf = ((0x06,  0,  0, 0xffffffff),)

        p, sa, x, M = self.intro(cbpf)

        x.send(b'a' * 128)
        self.assertTrue(sa.recv(512))

        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_dissected_ok_total': 1,
                             'rx_flow_new_unseen': 1,
                             'rx_new_flow_total': 1,
                             'rx_new_flow_working_gen_dispatch_ok': 1,
                             'rx_processed_total': 1})

        x.send(b'hello'*4)
        self.assertTrue(sa.recv(512))

        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_dissected_ok_total': 1,
                             'rx_flow_new_unseen': 1,
                             'rx_new_flow_total': 1,
                             'rx_new_flow_working_gen_dispatch_ok': 1,
                             'rx_processed_total': 1})

    def test_filter_packet_too_short(self):
        '''
        Picking up data at beyond packet length results in "rx_packet_too_short_error"

        $ echo -e "ld [32]\nret #1" | bpf_asm -c |tr "{}" "()"
        ( 0x20,  0,  0, 0x00000020 ),
        ( 0x06,  0,  0, 0x00000001 ),
        '''
        cbpf = ((0x20,  0,  0, 0x00000020),
                (0x06,  0,  0, 0x00000001),)
        p, sa, x, M = self.intro(cbpf)

        # We're requesting 4 bytes at offset 32, so anything longer than 35 will work.
        for l in (31, 32, 33, 34, 35):
            x.send(b'a' * l)
            self.assertTrue(sa.recv(512))

            D, M = self.metrics_delta(M)
            self.assertEqual(
                D, {'rx_packet_too_short_error': 1, 'rx_processed_total': 1})

        for l in (36, 37, 38, 39, 40):
            x.send(b'a'*l)
            self.assertTrue(sa.recv(512))

            D, M = self.metrics_delta(M)
            self.assertEqual(D, {'rx_dissected_ok_total': 1,
                                 'rx_flow_new_bad_cookie': 1,
                                 'rx_flow_new_unseen': 1,
                                 'rx_new_flow_total': 1,
                                 'rx_new_flow_working_gen_dispatch_ok': 1,
                                 'rx_processed_total': 1})

    def test_basic_filter_cookie(self):
        '''
        echo -e "ldh [0]\nret a" | bpf_asm -c |tr "{}" "()"
        ( 0x28,  0,  0, 0000000000 ),
        ( 0x16,  0,  0, 0000000000 ),
        '''

        cbpf = ((0x28,  0,  0, 0x00000000),
                (0x16,  0,  0, 0x00000000),)
        p, sa, x, M = self.intro(cbpf)

        _, _, sa_cookie, _ = unpack('IIHH', sa.getsockopt(
            IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12))

        S = [(sa, pack(">H", sa_cookie))]
        for gen in (0, 3, 3):
            s, _ = self.bind(port=sa.getsockname()[1])
            s.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, gen)
            self.assertTrue(p.collect_stdout("socket found")[0])
            self.sync_socket_gen(s)
            _, _, s_cookie, _ = unpack('IIHH', s.getsockopt(
                IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12))

            # Notice: Big endian!
            S.append((s, pack(">H", s_cookie)))

        for i in range(2):
            # send to all 4 sockets, receive correctly on all of them
            for sd, s_cookie in S:
                x.send(s_cookie)
                self.assertEqual(sd.recv(512), s_cookie)

                D, M = self.metrics_delta(M)
                self.assertEqual(D, {'rx_dissected_ok_total': 1,
                                     'rx_flow_ok': 1,
                                     'rx_processed_total': 1})

        # unparsed cookies count as new flow
        x.send(b'hello world')
        sl, _, _ = select.select([S[0][0], S[1][0]], [], [], 1)
        self.assertTrue(sl)
        for s in sl:
            self.assertEqual(s.echo(), b'hello world')

        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_dissected_ok_total': 1,
                             'rx_flow_new_bad_cookie': 1,
                             'rx_flow_new_unseen': 1,
                             'rx_new_flow_total': 1,
                             'rx_new_flow_working_gen_dispatch_ok': 1,
                             'rx_processed_total': 1})

    def test_application_selection(self):
        '''

        Payload format is:
          0xAA <app>
        or
          0x00 <cookie>

        $ cat << EOF | bpf_asm -c | tr "{}" "()"

                ldb [0]
                jeq #0xaa, app, cookie
        app:
                ldb [1]
                or #0x80000000
                ret a
        cookie:
                ldh [1]
                ret a
        EOF
        ( 0x30,  0,  0, 0000000000 ),
        ( 0x15,  0,  3, 0x000000aa ),
        ( 0x30,  0,  0, 0x00000001 ),
        ( 0x44,  0,  0, 0x80000000 ),
        ( 0x16,  0,  0, 0000000000 ),
        ( 0x28,  0,  0, 0x00000001 ),
        ( 0x16,  0,  0, 0000000000 ),
        '''
        cbpf = ((0x30,  0,  0, 0000000000),
                (0x15,  0,  3, 0x000000aa),
                (0x30,  0,  0, 0x00000001),
                (0x44,  0,  0, 0x80000000),
                (0x16,  0,  0, 0000000000),
                (0x28,  0,  0, 0x00000001),
                (0x16,  0,  0, 0000000000),)
        p, sa, x, M = self.intro(cbpf, apps=4)

        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_APP, 0)
        _, _, sa_cookie, _ = unpack('IIHH', sa.getsockopt(
            IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12))

        S = [(sa, pack(">H", sa_cookie))]
        for (app_idx, gen) in ((1, 3), (2, 7), (2, 7)):
            s, _ = self.bind(port=sa.getsockname()[1])
            s.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_APP, app_idx)
            s.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, gen)
            self.assertTrue(p.collect_stdout("socket found")[0])
            self.sync_socket_gen(s)
            _, _, s_cookie, _ = unpack('IIHH', s.getsockopt(
                IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12))

            # Notice: Big endian!
            S.append((s, pack(">H", s_cookie)))

        # Test cookie routing since we are on it
        for i in range(4):
            for sd, s_cookie in S:
                x.send(b'\x00' + s_cookie)
                self.assertEqual(sd.recv(512), b'\x00' + s_cookie)
                D, M = self.metrics_delta(M)
                self.assertEqual(D, {'rx_dissected_ok_total': 1,
                                     'rx_flow_ok': 1,
                                     'rx_processed_total': 1})

        # Ok, we have tree gen 0, 3, and 7
        S[1][0].setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 3)
        S[2][0].setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 8)
        S[3][0].setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 7)
        for g, s in zip([0, 3, 7, 7], S):
            self.assertEqual(g, s[0].getsockopt(
                IPPROTO_UDP, UDP_GRM_WORKING_GEN))

        for app_idx, (sd, _) in zip([0, 1, 2, 2], S):
            got_idx = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_APP)
            self.assertEqual(app_idx, got_idx)

        # Now apps point to:
        #  app0 -> 0
        #  app1 -> 3
        #  app2 -> 7
        #  app3 -> [any] + rx_new_flow_working_gen_dispatch_error
        APPS = [(0, (S[0][0],)),
                (1, (S[1][0],)),
                (2, (S[2][0], S[3][0]))]

        # Test app routing
        for i in range(4):
            for app_idx, list_of_sk in APPS:
                v = b'\xaa' + pack('B', app_idx)
                x.send(v)
                sl, _, _ = select.select(list_of_sk, [], [], 1)
                self.assertTrue(sl)
                self.assertEqual(sl[0].recv(512), v)

                D, M = self.metrics_delta(M)
                self.assertEqual(D, {'rx_dissected_ok_total': 1,
                                     'rx_flow_new_unseen': 1,
                                     'rx_new_flow_total': 1,
                                     'rx_new_flow_working_gen_dispatch_ok': 1,
                                     'rx_processed_total': 1})
        v = b'\xaa' + pack('B', 3)
        x.send(v)
        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_dissected_ok_total': 1,
                             'rx_flow_new_unseen': 1,
                             'rx_new_flow_total': 1,
                             'rx_new_flow_working_gen_dispatch_error': 1,
                             'rx_processed_total': 1})

    def test_app_working_gen(self):
        '''
        Check if setting multiple working gens at the same time fails
        '''

        cbpf = ((0x06,  0,  0, 0xffffffff),)
        p, sa, x, M = self.intro(cbpf, apps=4)

        # default working gens point to zero
        self.assertEqual(0, sa.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN))

        # we can change one to arbitrary value
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 356)
        self.assertEqual(356, sa.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN))

        # we can change one to arbitrary value
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, -1)
        self.assertEqual(-1, sa.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN))

        # we can change one to arbitrary value
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 0)
        self.assertEqual(0, sa.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN))

    def test_invalid_cbpf_length(self):
        '''
        '''
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])

        sa, port = self.bind()
        cbpf = [(0, 0, 0, 0)]*32

        filter_len = 0
        v = pack("IIII100sI256s", DISSECTOR_CBPF,
                 0, 0, 0, b'',
                 filter_len, b''.join(pack('HBBI', *sf) for sf in cbpf))
        with self.assertRaisesRegex(OSError, 'Errno 1. Operation not permitted'):
            sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        filter_len = 65
        v = pack("IIII100sI256s", DISSECTOR_CBPF,
                 0, 0, 0, b'',
                 filter_len, b''.join(pack('HBBI', *sf) for sf in cbpf))
        with self.assertRaisesRegex(OSError, 'Errno 1. Operation not permitted'):
            sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        filter_len = 31
        # ret #1 should never be run, this is equal to bad cbpf - no ret.
        cbpf = [(0, 0, 0, 0)]*31 + [(0x06,  0,  0, 0x00000001)]
        v = pack("IIII100sI256s", DISSECTOR_CBPF,
                 0, 0, 0, b'',
                 filter_len, b''.join(pack('HBBI', *sf) for sf in cbpf))
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        # setting it second time should not raise an exception
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        # move socket to generation
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
        self.assertTrue(p.collect_stdout("socket found")[0])
        self.sync_socket_gen(sa)

        x = self.connect()

        x.send(b'a' * 128)
        self.assertTrue(sa.recv(512))

        D, M = self.metrics_delta({})
        self.assertEqual(D, {'rx_cbpf_prog_error': 1,
                             'rx_processed_total': 1})

    def test_invalid_cbpf(self):
        '''Test for invalid cbpf opcode or lack of 'ret' statement.'''
        # invalid instruction
        cbpf = [(999, 0, 0, 0)] + [(0x06,  0,  0, 0x00000001)]
        p, sa, x, M = self.intro(cbpf)

        x.send(b'a' * 128)
        self.assertTrue(sa.recv(512))

        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_cbpf_prog_error': 1,
                             'rx_processed_total': 1})

        self.outro(sa)

        # no 'ret'
        cbpf = [(0, 0, 0, 0)]
        p, sa, x, M = self.intro(cbpf, p=p)

        x.send(b'a' * 128)
        self.assertTrue(sa.recv(512))

        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_cbpf_prog_error': 1,
                             'rx_processed_total': 1})
        self.outro(sa)

        # no 'ret'
        cbpf = [(0, 0, 0, 0)] * 32
        p, sa, x, M = self.intro(cbpf, p=p)

        x.send(b'a' * 128)
        self.assertTrue(sa.recv(512))

        D, M = self.metrics_delta(M)
        self.assertEqual(D, {'rx_cbpf_prog_error': 1,
                             'rx_processed_total': 1})
        self.outro(sa)
