from struct import pack, unpack
from . import base
from .lsocket import *
import random
import select

'''
        ; First bit determines QUIC long vs short format
        ldb [0]
        and #0x80
        jeq #0x80, long_form, short_form

long_form:
        ; struct long_quic_pkt {
	;     uint8_t type;
	;     int8_t version[4];
        ;     uint8_t dcid_len: 8;
	;     struct cf_connection_id dcid; // 20 for us, but specified by dcid_len
        ; } __attribute__((packed));
        ;
        ldb [5]
        jneq #20, bad_length
        ldx #6
        jmp parse_dcid

bad_length:
        ret #-1

short_form:
	; struct short_quic_pkt {
	;     unsigned char type;
	;     struct cf_connection_id dcid; // we always assgin 20 bytes DCID
        ; } __attribute__((packed));
        ldx #1
        jmp parse_dcid

parse_dcid:
	; %x is an offset to QUIC DCID
        ;
        ; struct cf_connection_id {
	;     uint8_t version;
	;     uint16_t colo_id;
	;     uint16_t metal;
        ;     uint16_t cookie;
        ;     uint8_t _reserved[2];
	;     uint8_t nonce[8];
        ;     uint8_t _unused[3];
        ; } __attribute__((packed));
        ;
        ldb [x + 0]
	jneq #1, bad_version
        ldh [x + 5]
        st M[0]
        ldh [x + 13]
        tax
        ld M[0]
        xor x
        ret a

bad_version:
       ret #-2
'''


class CfCID(base.TestCase):
    def test_cfcid(self):
        cbpf = [(0x30,  0,  0, 0000000000),
                (0x54,  0,  0, 0x00000080),
                (0x15,  0,  5, 0x00000080),
                (0x30,  0,  0, 0x00000005),
                (0x15,  0,  2, 0x00000014),
                (0x01,  0,  0, 0x00000006),
                (0x05,  0,  0, 0x00000003),
                (0x06,  0,  0, 0xffffffff),
                (0x01,  0,  0, 0x00000001),
                (0x05,  0,  0, 0000000000),
                (0x50,  0,  0, 0000000000),
                (0x15,  0,  7, 0x00000001),
                (0x48,  0,  0, 0x00000005),
                (0x02,  0,  0, 0000000000),
                (0x48,  0,  0, 0x0000000d),
                (0x07,  0,  0, 0000000000),
                (0x60,  0,  0, 0000000000),
                (0xac,  0,  0, 0000000000),
                (0x16,  0,  0, 0000000000),
                (0x06,  0,  0, 0xfffffffe), ]
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        sa, port = self.bind()
        sb, _ = self.bind(port=port)

        v = pack("IIII100sI256s", DISSECTOR_CBPF,
                 124, 0, 0, b'',
                 len(cbpf), b''.join(pack('HBBI', *sf) for sf in cbpf))
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
        self.assertTrue(p.collect_stdout("socket found")[0])
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
        self.assertTrue(p.collect_stdout("socket found")[0])

        # no need to update WORKING_GEN since it's zero anyway
        x = self.connect()
        D, M = self.metrics_delta({})
        self.assertEqual(D, {})

        sa_cookie = unpack('IIHH', sa.getsockopt(
            IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12))[2]
        sb_cookie = unpack('IIHH', sb.getsockopt(
            IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12))[2]
        self.assertNotEqual(sa_cookie, 0)
        self.assertNotEqual(sb_cookie, 0)

        for ss, cookie in ((sa, sa_cookie), (sb, sb_cookie), (sa, sa_cookie)):
            # version, colo, metal, cookie, resered, nonce, reserved
            # struct.pack does enforce C alignment, no no way to say
            # __attribute__((packed))
            cid = b'\x01' + pack('HHHHQ', 2, 3, socket.htons(cookie), 0,
                                 random.getrandbits(64)) + b'\x00\x00\x00'
            self.assertEqual(len(cid), 20)
            cid = list(cid)
            for off in range(1, 9):
                cid[off] ^= cid[off+8]
            x.send(b'\x00' + bytes(cid) + b'some payload')
            D, M = self.metrics_delta(M)
            self.assertEqual(len(ss.recv(512)), 33)
            self.assertEqual(D, {'rx_dissected_ok_total': 1,
                             'rx_flow_ok': 1, 'rx_processed_total': 1})


'''
        ; First bit determines QUIC long vs short format
        ldb [0]
        and #0x80
        jeq #0x80, long_form, short_form

long_form:
        ; struct long_quic_pkt {
	;     uint8_t type;
	;     int8_t version[4];
        ;     uint8_t dcid_len: 8;
	;     struct cf_connection_id dcid; // 20 for us, but specified by dcid_len
        ; } __attribute__((packed));
        ;
        ldb [5]
        jneq #20, bad_length
        ldx #6
        jmp parse_dcid

bad_length:
        ret #-1

short_form:
	; struct short_quic_pkt {
	;     unsigned char type;
	;     struct cf_connection_id dcid; // we always assgin 20 bytes DCID
        ; } __attribute__((packed));
        ldx #1
        jmp parse_dcid

parse_dcid:
	; %x is an offset to QUIC DCID
        ;
        ; struct cf_connection_id {
	;     uint8_t version;
	;     uint16_t colo_id;
	;     uint16_t metal;
        ;     uint16_t cookie;
        ;     uint8_t app;
        ;     uint8_t _reserved;
	;     uint8_t nonce[8];
        ;     uint8_t _unused[3];
        ; } __attribute__((packed));
        ;
        ldb [x + 0]
        jneq #1, bad_version
        ldh [x + 5]
        st M[0]
        ldh [x + 13]
        tax
        ld M[0]
        xor x
        jeq #0, fetch_app
        ret a

bad_version:
       ret #-2

fetch_app:
        ldb [x + 7]
        st M[0]
        ldb [x + 15]
        tax
        ld M[0]
        xor x
        and #3
        or #0x80000000
        ret a
'''


class CfCIDApp(base.TestCase):
    def test_cfcid_app(self):
        cbpf = [
            (0x30,  0,  0, 0000000000),
            (0x54,  0,  0, 0x00000080),
            (0x15,  0,  5, 0x00000080),
            (0x30,  0,  0, 0x00000005),
            (0x15,  0,  2, 0x00000014),
            (0x01,  0,  0, 0x00000006),
            (0x05,  0,  0, 0x00000003),
            (0x06,  0,  0, 0xffffffff),
            (0x01,  0,  0, 0x00000001),
            (0x05,  0,  0, 0000000000),
            (0x50,  0,  0, 0000000000),
            (0x15,  0,  9, 0x00000001),
            (0x48,  0,  0, 0x00000005),
            (0x03,  0,  0, 0x00000001),
            (0x02,  0,  0, 0000000000),
            (0x48,  0,  0, 0x0000000d),
            (0x07,  0,  0, 0000000000),
            (0x60,  0,  0, 0000000000),
            (0xac,  0,  0, 0000000000),
            (0x15,  2,  0, 0000000000),
            (0x16,  0,  0, 0000000000),
            (0x06,  0,  0, 0xfffffffe),
            (0x61,  0,  0, 0x00000001),
            (0x50,  0,  0, 0x00000007),
            (0x02,  0,  0, 0000000000),
            (0x50,  0,  0, 0x0000000f),
            (0x07,  0,  0, 0000000000),
            (0x60,  0,  0, 0000000000),
            (0xac,  0,  0, 0000000000),
            (0x54,  0,  0, 0x00000003),
            (0x44,  0,  0, 0x80000000),
            (0x16,  0,  0, 0000000000),
        ]
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])
        sa, port = self.bind()
        sb, _ = self.bind(port=port)

        v = pack("IIII100sI512s", DISSECTOR_CBPF,
                 124, 4, 0, b'',
                 len(cbpf), b''.join(pack('HBBI', *sf) for sf in cbpf))
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

        # app=1, gen=1
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_APP, 1)
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 1)
        self.assertTrue(p.collect_stdout("socket found")[0])
        # app=3, gen=1
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_APP, 3)
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 2)
        self.assertTrue(p.collect_stdout("socket found")[0])

        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 1)
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 2)

        # WORKING_GEN on app=0 is zero whcih is an empty group. see
        # the dispatch falls back to basics
        x = self.connect()
        D, M = self.metrics_delta({})
        self.assertEqual(D, {})

        x.send(b'\x00' + (b'\xff' * 20) + b'some payload')
        for ss in select.select([sa, sb], [], [])[0]:
            self.assertEqual(len(ss.recv(512)), 33)

        D, M = self.metrics_delta(M)
        self.assertEqual(D, {
            'rx_dissected_ok_total': 1,
            'rx_flow_new_unseen': 1,
            'rx_new_flow_total': 1,
            'rx_new_flow_working_gen_dispatch_error': 1,
            'rx_processed_total': 1})

        # Test cookie-based dispatch
        sa_cookie = unpack('IIHH', sa.getsockopt(
            IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12))[2]
        sb_cookie = unpack('IIHH', sb.getsockopt(
            IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12))[2]
        self.assertNotEqual(sa_cookie, 0)
        self.assertNotEqual(sb_cookie, 0)

        def cid(cookie, app):
            # version, colo, metal, cookie, resered, nonce, reserved
            # struct.pack does enforce C alignment, no no way to say
            # __attribute__((packed))
            cid = b'\x01' + pack('HHHBBQ', 2, 3, socket.htons(cookie), app, 0,
                                 random.getrandbits(64)) + b'\x00\x00\x00'
            self.assertEqual(len(cid), 20)
            cid = list(cid)
            for off in range(1, 9):
                cid[off] ^= cid[off+8]
            return bytes(cid)

        for ss, cookie in ((sa, sa_cookie), (sb, sb_cookie), (sa, sa_cookie)):
            x.send(b'\x00' + cid(cookie, 0) + b'some payload')
            self.assertEqual(len(ss.recv(512)), 33)
            D, M = self.metrics_delta(M)
            self.assertEqual(D, {'rx_dissected_ok_total': 1,
                             'rx_flow_ok': 1, 'rx_processed_total': 1})

        # Test app dispatch
        for ss, app in [(sa, 1), (sb, 3), (sa, 1)]:
            x.send(b'\x00' + cid(0, app) + b'some payload')
            self.assertEqual(len(ss.recv(512)), 33)
            D, M = self.metrics_delta(M)
            self.assertEqual(D, {
                'rx_dissected_ok_total': 1,
                'rx_flow_new_unseen': 1,
                'rx_new_flow_total': 1,
                'rx_new_flow_working_gen_dispatch_ok': 1,
                'rx_processed_total': 1})

        # app with no sockets
        x.send(b'\x00' + cid(0, 0) + b'some payload')
        for ss in select.select([sa, sb], [], [])[0]:
            self.assertEqual(len(ss.recv(512)), 33)
        D, M = self.metrics_delta(M)
        self.assertEqual(D, {
            'rx_dissected_ok_total': 1,
            'rx_flow_new_unseen': 1,
            'rx_new_flow_total': 1,
            'rx_new_flow_working_gen_dispatch_error': 1,
            'rx_processed_total': 1})
