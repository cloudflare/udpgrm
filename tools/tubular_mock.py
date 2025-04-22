import socket
import struct
import stat
import os
import signal

SO_COOKIE = 57

signal.signal(signal.SIGPIPE, signal.SIG_DFL)

s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)

path = "/tmp/a"
if path and path[0] != '\x00':
    try:
        if stat.S_ISSOCK(os.stat(path).st_mode):
            os.remove(path)
    except FileNotFoundError:
        pass

s.bind(path)
s.listen(10)
while True:
    c, _ = s.accept()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO,
                 struct.pack("ll", 1, 0))
    c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO,
                 struct.pack("ll", 1, 0))

    while True:
        try:
            p, ctrl, _flags, _addr = c.recvmsg(1024, 4096)
            print("in=%r" % (p, ))
        except BlockingIOError:
            pass

        fds = []
        for cmsg_level, cmsg_type, cmsg_data in ctrl:
            if cmsg_level == socket.SOL_SOCKET:
                if cmsg_type == socket.SCM_RIGHTS:
                    # Parse SCM_RIGHTS message
                    fds = struct.unpack('i' * (len(cmsg_data) // 4), cmsg_data)
                else:
                    print(f"Unknown cmsg_type {cmsg_type}")
            else:
                print(f"Unknown cmsg_level {cmsg_level}")

        cookies = []
        for fd in fds:
            sd = socket.fromfd(fd, 0, 0, 0)
            so_cookie, = struct.unpack(
                'Q', sd.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8))
            sd.close()
            cookies.append("0x%x" % so_cookie)
        print("Received sockets with cookies: %s" % (', '.join(cookies)))
        if not p or p.rstrip()[-1] == ord(b'#'):
            break
    try:
        c.send(b"OK")
    except BrokenPipeError:
        pass
    c.close()
