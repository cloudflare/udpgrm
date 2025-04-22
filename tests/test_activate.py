from . import base
from .lsocket import *
import os
import socket
import tempfile


class ActivateTest(base.TestCase):
    def test_activate_usage(self):
        p = base.Process(["python3", "examples/activate.py"], close_fds=True)
        self.assertTrue(p.collect_stderr("usage")[0])
        p.close()

    def test_activate_simple(self):
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing")[0])

        notify_sock_dir = tempfile.mkdtemp()
        notify_sock_path = os.path.join(notify_sock_dir, "notify.sock")
        notify_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notify_sock.bind(notify_sock_path)

        p = base.Process(["python3", "examples/activate.py", "--quic", "-c", "1", "udp_test",
                         "127.0.0.1:21000"], close_fds=True, env={"NOTIFY_SOCKET": notify_sock_path})
        # Check that no errors are raised
        self.assertFalse(p.collect_stderr())
        # Check that systemd receives socket store notifications
        self.assertEqual(b"FDSTOREREMOVE=1\nFDNAME=udp_test",
                         notify_sock.recvmsg(1024)[0])
        self.assertEqual(b"FDSTORE=1\nFDNAME=udp_test",
                         notify_sock.recvmsg(1024)[0])
        p.close()
        notify_sock.close()
        os.unlink(notify_sock_path)
        os.rmdir(notify_sock_dir)
