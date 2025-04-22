import struct

from . import base
from .lsocket import *


class DissectorQuic(base.TestCase):
    '''
            ldb [0]
            and #0x80
            jeq #0x80, long_form, short_form

    long_form:
            ldb [5]
            jneq #16, bad_length
            ldx #6
            jmp parse_dcid

    bad_length:
            ret #-1

    short_form:
            ldx #1
            jmp parse_dcid

    parse_dcid:
           ldh [x + 0]
           ret a

    '''
    test_quic_cbpf = [
        (0x30,  0,  0, 0000000000),
        (0x54,  0,  0, 0x00000080),
        (0x15,  0,  5, 0x00000080),
        (0x30,  0,  0, 0x00000005),
        (0x15,  0,  2, 0x00000010),
        (0x01,  0,  0, 0x00000006),
        (0x05,  0,  0, 0x00000003),
        (0x06,  0,  0, 0xffffffff),
        (0x01,  0,  0, 0x00000001),
        (0x05,  0,  0, 0000000000),
        (0x48,  0,  0, 0000000000),
        (0x16,  0,  0, 0000000000),
    ]

    def test_quic_not_quic_hdr(self):
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        sa, port = self.bind()

        cbpf = self.test_quic_cbpf
        v = struct.pack("IIII100sI256s", DISSECTOR_CBPF,
                        124, 0, 0, b'',
                        len(cbpf), b''.join(struct.pack('HBBI', *sf) for sf in cbpf))
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
        self.sync_socket_gen(sa)
        self.assertTrue(p.collect_stdout("socket found")[0])

        v = sa.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12)
        self.assertEqual(v, struct.pack('III', 0, 0, 0x80))
        quic_cookie = struct.unpack('IIHH', v)[2]

        # Too short packet for Quic -> _error
        old = self.socket()
        old.connect(('127.0.0.1', port))
        old.send(b'\xffhell')
        self.assertEqual(sa.echo(), b'\xffhell')

        D, M = self.metrics_delta({})
        # TEST: D == {}
        self.assertEqual(D, {'rx_processed_total': 1,
                             'rx_packet_too_short_error': 1})

        NEW_FLOW_COUNTERS = {'rx_processed_total': 1,
                             'rx_new_flow_total': 1,
                             'rx_new_flow_working_gen_dispatch_ok': 1,
                             'rx_dissected_ok_total': 1,
                             'rx_flow_new_unseen': 1}

        VALID_RX_FLOW_COUNTERS = {'rx_processed_total': 1,
                                  'rx_dissected_ok_total': 1,
                                  'rx_flow_ok': 1}

        # Short QUIC packet, wrong quic_cookie data -> new flow
        old.send(b'\x01'*128)
        self.assertEqual(sa.echo(), b'\x01'*128)
        D, M = self.metrics_delta(M)
        self.assertEqual(D, NEW_FLOW_COUNTERS | {'rx_flow_new_bad_cookie': 1})

        # Short QUIC packet, correct quic_cookie data -> just RX
        v = struct.pack(">BHHIII", 0x00, quic_cookie, 0, 0, 0, 0)
        old.send(v)
        self.assertEqual(sa.echo(), v)
        D, M = self.metrics_delta(M)
        self.assertEqual(D, VALID_RX_FLOW_COUNTERS)

        # Long packet ->  new flow
        old.send(b'\xff'*128)
        self.assertEqual(sa.echo(), b'\xff'*128)
        D, M = self.metrics_delta(M)
        self.assertEqual(D, NEW_FLOW_COUNTERS)

        # Valid long packet -> just as RX
        # type, version, dcid_len, dcid
        v = struct.pack(">BIBHHIII", 0x80, 1, 16,
                        quic_cookie, 0, 0, 0, 0)
        old.send(v)
        self.assertTrue(sa.recv(99))
        D, M = self.metrics_delta(M)
        self.assertEqual(D, VALID_RX_FLOW_COUNTERS)

        # invalid long packet -> new flow
        v = struct.pack(">BIBIIII", 0x80, 1, 16, 0x000f0, 0, 0, 0)
        old.send(v)
        self.assertTrue(sa.recv(99))
        D, M = self.metrics_delta(M)
        self.assertEqual(D, NEW_FLOW_COUNTERS | {'rx_flow_new_bad_cookie': 1})
