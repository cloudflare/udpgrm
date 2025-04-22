from . import base
from .lsocket import *
import socket
import struct


def tubular_recv(uds):
    cd, _ = uds.accept()
    msg, ancdata, _, _ = cd.recvmsg(
        4096, socket.CMSG_LEN(struct.calcsize("i")))
    cd.send(b'OK')
    cd.close()

    if not ancdata:
        raise RuntimeError("No file descriptor received")

    cmsg_level, cmsg_type, cmsg_data = ancdata[0]

    if cmsg_level != socket.SOL_SOCKET or cmsg_type != socket.SCM_RIGHTS:
        raise RuntimeError("Unexpected control message")

    received_fd = struct.unpack("i", cmsg_data)[0]
    tmp_sd = socket.fromfd(received_fd, 0, 0, 0)
    domain = tmp_sd.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN)
    type = tmp_sd.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    protocol = tmp_sd.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL)
    fd = base._socket(domain, type, protocol, fileno=received_fd)
    tmp_sd.close()
    return msg, fd


class BasicTubular(base.TestCase):
    def test_one(self):
        uds, uds_fname = self.uds()
        p = self.udpgrm_run("--daemon --install --tubular=%s" % (uds_fname,))
        self.assertTrue(p.collect_stderr("Tubular path")[0])
        self.assertTrue(p.collect_stderr("Tailing")[0])

        fd_a = p.fd_count()

        sa, port = self.bind()

        label = b'udp_server'
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR,
                      struct.pack("IIII100s",
                                  DISSECTOR_FLOW, 126, 0, 0,
                                  label + b'\x00' * (100-len(label))))

        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
        self.assertTrue(p.collect_stdout("socket found")[0])

        self.assertEqual(fd_a+1, p.fd_count())

        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 0)
        self.assertTrue(p.collect_stdout("Working gen app=0 0")[0])

        cd, _ = uds.accept()
        self.assertEqual(cd.recv(99), b"udp_server#")
        cd.send(b'OK')
        cd.close()

        # no message
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 0)
        self.assertTrue(p.collect_stdout("Working gen app=0 0")[0])

        self.assertTrue(p.collect_stdout(
            "No new sockets to register to tubular")[0])

        self.assertEqual(fd_a, p.fd_count())

        self.assertIn(
            "Tubular register failed: Bad file descriptor", p.stdout_line())

        self.assertEqual(fd_a, p.fd_count())

    def test_sockets_leak(self):
        uds_fname = '/bad_path'
        p = self.udpgrm_run("--daemon --install --tubular=%s" % (uds_fname,))
        self.assertTrue(p.collect_stderr("Tubular path")[0])
        self.assertTrue(p.collect_stderr("Tailing")[0])
        fd_a = p.fd_count()

        sa, port = self.bind()

        label = b'udp_server'
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR,
                      struct.pack("IIII100s",
                                  DISSECTOR_FLOW, 126, 0, 0,
                                  label + b'\x00' * (100-len(label))))
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
        self.sync_socket_gen(sa)
        self.assertEqual(fd_a+1, p.fd_count())

        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 0)
        self.assertTrue(p.collect_stdout("Tubular register failed")[0])

        self.assertEqual(fd_a, p.fd_count())

    def test_good_sockets_registered(self):
        # we used to register wrong sockets when two groups were set
        # concurrently
        uds, uds_fname = self.uds()
        p = self.udpgrm_run("--daemon --install --tubular=%s" % (uds_fname,))
        self.assertTrue(p.collect_stderr("Tubular path")[0])
        self.assertTrue(p.collect_stderr("Tailing")[0])
        fd_a = p.fd_count()

        # one
        sa, port_a = self.bind()
        label_a = b'udp_server_a'
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR,
                      struct.pack("IIII100s",
                                  DISSECTOR_FLOW, 126, 0, 0,
                                  label_a + b'\x00' * (100-len(label_a))))
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
        self.sync_socket_gen(sa)
        self.assertEqual(fd_a+1, p.fd_count())

        # two
        sb, port_b = self.bind()
        self.assertNotEqual(port_a, port_b)
        label_b = b'udp_server_b'
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR,
                      struct.pack("IIII100s",
                                  DISSECTOR_FLOW, 126, 0, 0,
                                  label_b + b'\x00' * (100-len(label_b))))
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
        self.sync_socket_gen(sb)

        self.assertEqual(fd_a+2, p.fd_count())

        # one
        sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 0)
        self.assertTrue(p.collect_stdout("Working gen app=0 0")[0])

        msg, recv_sd = tubular_recv(uds)
        self.assertEqual(msg, b"udp_server_a#")
        self.assertEqual(sa.cookie(), recv_sd.cookie())
        recv_sd.close()

        # two
        sb.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 0)
        self.assertTrue(p.collect_stdout("Working gen app=0 0")[0])

        msg, recv_sd = tubular_recv(uds)
        self.assertEqual(msg, b"udp_server_b#")
        self.assertEqual(sb.cookie(), recv_sd.cookie())
        recv_sd.close()

        # test leaked fds
        self.assertEqual(fd_a, p.fd_count())
