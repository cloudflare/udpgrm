# Copyright (c) 2025 Cloudflare, Inc.
# Licensed under the Apache 2.0 license found in the LICENSE file or at:
#     https://opensource.org/licenses/Apache-2.0

import os
import shlex
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time
import re
import unittest

from . import utils
from . import lsocket

SO_COOKIE = 57

UDPGRMBIN = os.environ.get("UDPGRMBIN")


class Process(object):
    def __init__(self, argv, close_fds=True, env=None, pass_fds=()):
        self.command = utils.encode_shell(argv)

        stdin_r, stdin_w = os.pipe()

        _env = dict(os.environ)
        if env:
            _env.update(env)
        self.p = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=close_fds,
            pass_fds=pass_fds,
            stdin=stdin_r,
            env=_env,
        )
        os.close(stdin_w)
        self.stdin_r = stdin_r
        self.rc = None
        self.pidfd = os.pidfd_open(self.p.pid)
        self.pid = self.p.pid

    def stdout_line(self):
        while True:
            o = self.p.stdout.readline().decode().rstrip()
            if o == "PASS\n" or o.startswith("coverage: "):
                continue
            return o

    def stderr_line(self):
        return self.p.stderr.readline().decode().rstrip()

    def close(self, kill=True):
        """Returns process return code."""
        if self.p:
            if kill:
                # Ensure the process registers two signals by sending
                # a combo of SIGINT and SIGTERM. Sending the same
                # signal two times is racy because the process can't
                # reliably detect how many times the signal was sent.
                try:
                    signal.pidfd_send_signal(self.pidfd, signal.SIGINT)
                except ProcessLookupError:
                    pass
                # Avoid hard kill - the code coverage will not be reported.
            try:
                self.rc = self.p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                while True:
                    l = self.stderr_line() or self.stdout_line()
                    if l:
                        print('>>>', l)
                    else:
                        raise

            os.close(self.stdin_r)
            self.p.stdin_r = None
            self.p.stderr.close()
            self.p.stdout.close()
        self.p = None
        if self.pidfd:
            os.close(self.pidfd)
            self.pidfd = None
        return self.rc

    def graceful_stop(self, wait=True):
        try:
            signal.pidfd_send_signal(self.pidfd, signal.SIGINT)
        except ProcessLookupError:
            print("pid already dead")
            pass
        if wait:
            try:
                return self.p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                while True:
                    l = self.stderr_line() or self.stdout_line()
                    if l:
                        print('>>>', l)
                    else:
                        raise

    def kill(self):
        self.p.kill()

    def collect_stderr(self, breakword=None):
        s = []
        while True:
            line = self.stderr_line()
            if not line:
                break
            s.append(line)
            if breakword and breakword in line:
                return s, True
        if not breakword:
            return s
        else:
            return s, False

    def collect_stdout(self, breakword=None):
        s = []
        while True:
            line = self.stdout_line()
            if not line:
                break
            s.append(line)
            if breakword and breakword in line:
                return s, True
        if not breakword:
            return s
        else:
            return s, False

    def fd_count(self):
        # Give the daemon a chance to free file descriptors after
        # sending the uds message.
        self.do_yield()
        return len(os.listdir('/proc/%d/fd' % (self.pid,)))

    def stop(self):
        try:
            signal.pidfd_send_signal(self.pidfd, signal.SIGSTOP)
        except ProcessLookupError:
            pass

    def cont(self):
        try:
            signal.pidfd_send_signal(self.pidfd, signal.SIGCONT)
        except ProcessLookupError:
            pass

    def do_yield(self):
        for i in range(100):
            d = b""
            with open('/proc/%d/wchan' % (self.pid,), 'rb') as fd:
                d = fd.read()
            if d.strip() != b"0":
                break
            os.sched_yield()
            time.sleep(0.001)
        else:
            raise Exception("failed to get process to sleep")


class _socket(socket.socket):
    def echo(self, bufsize=4096):
        (b, addr) = self.recvfrom(bufsize)
        self.sendto(b, addr)
        return b

    def cookie(self):
        so_cookie, = struct.unpack(
            'Q', self.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8))
        return '%08x' % (so_cookie,)


def parse_metrics(text, ignore_zero_metrics=True):
    results = {}
    data = None

    for line in text.splitlines():
        if not line.strip():
            continue

        if ':' in line and not line.startswith('\t'):
            addr = line.strip()
            assert addr not in results

            data = {
                'addr': addr,
                'flags': {},
                'socket_generations': [],
                'metrics': {}
            }
            results[addr] = data  # data is mutable

        elif line.startswith('netns'):
            # Parse netns line
            for k_v in line.strip().split("  "):
                k, _, v = line.partition(" ")
                data['flags'][k] = v

        elif line.startswith('socket generations:') or line.startswith('metrics:'):
            continue  # Skip header

        elif line.strip().startswith('gen '):
            data['socket_generations'].append(line.strip())

        elif line.startswith('\t\t'):
            k, _, v = line.strip().partition(' ')
            if int(v):
                data['metrics'][k] = int(v)

    return results


class TestCase(unittest.TestCase):
    cleanups = None

    def _add_teardown(self, item):
        if not self.cleanups:
            self.cleanups = []
        self.cleanups.append(item)

    def _del_teardown(self, item):
        self.cleanups.remove(item)

    def udpgrm_run(self, argv1=[]):
        argv0 = shlex.split(UDPGRMBIN)

        if isinstance(argv1, str):
            argv1 = shlex.split(argv1)

        p = Process(argv0 + argv1)
        self._add_teardown(p)
        return p

    def udpgrm_metrics(self, port=None):
        if port:
            selector = " 127.0.0.1:%d" % (port,)
        else:
            selector = ""

        # only supports single active socket group
        p = self.udpgrm_run("list -v%s" % selector)
        all_lines = '\n'.join(p.collect_stdout())
        blocks = re.split(r"\n(?!\t)", all_lines)
        if len(blocks) > 1 and " (old)\n" not in blocks[1]:
            print(all_lines)
            self.fail(
                "Only one group supported in tests metrics. Make sure you dont have stale udpgrm daemons or REUSEPORT groups.")

        _, _, lines = blocks[0].partition('metrics:')
        M = {}
        for line in lines.split('\n'):
            line = line.strip()
            k, _, v = line.partition(' ')
            v = int(v) if v.isdecimal() else v
            if k or v:
                M[k] = v
        p.close()
        self._del_teardown(p)
        return M

    def metrics_rich(self, selector=""):
        p = self.udpgrm_run("list -v %s" % (selector,))
        all_lines = '\n'.join(p.collect_stdout())
        p.close()
        self._del_teardown(p)
        return parse_metrics(all_lines)

    def metrics_delta(self, A, port=None):
        B = self.udpgrm_metrics(port=port)
        C = {}
        for k, v in B.items():
            d = v - A.get(k, 0)
            if d:
                C[k] = d
        return C, B

    def socket(self, *args, **kwargs):
        if len(args) < 1 and 'family' not in kwargs:
            kwargs['family'] = socket.AF_INET
        if len(args) < 2 and 'type' not in kwargs:
            kwargs['type'] = socket.SOCK_DGRAM
        sd = _socket(*args, **kwargs)
        sd.settimeout(1)
        self._add_teardown(sd)
        return sd

    def bind(self, ip='127.0.0.1', port=0):
        kwargs = {}
        kwargs['family'] = socket.AF_INET if ':' not in ip else socket.AF_INET6
        kwargs['type'] = socket.SOCK_DGRAM
        sd = _socket(**kwargs)
        sd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sd.bind((ip, port))
        sd.settimeout(1)
        self._add_teardown(sd)
        addr = sd.getsockname()
        self.last_bind_family = kwargs['family']
        self.last_bind_addr = addr
        return sd, addr[1]

    def connect(self, addr=None, port=None):
        if not addr:
            addr = list(self.last_bind_addr)
        if port:
            addr[1] = port
        sd = self.socket(family=self.last_bind_family)
        sd.connect(tuple(addr))
        return sd

    def uds(self):
        fname = self.tempname()
        ud = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        if os.access(fname, 0) and stat.S_ISSOCK(os.stat(fname).st_mode):
            os.unlink(fname)
        ud.bind(fname)
        ud.listen(1)
        self._add_teardown(ud)
        return ud, fname

    def _testFailed(self):
        """
        I hate python
        https://stackoverflow.com/questions/4414234/getting-pythons-unittest-results-in-a-teardown-method

        I hate python #2
        https://github.com/pytest-dev/pytest/issues/10631
        """
        if hasattr(self._outcome, "errors"):  # Python 3.4-3.10
            result = self.defaultTestResult()  # these 2 methods have no side effects
            self._feedErrorsToResult(result, self._outcome.errors)
        else:  # Python 3.11+
            result = self._outcome.result

        def list2reason(exc_list):
            if exc_list and exc_list[-1][0] is self:
                return exc_list[-1][1]

        error = list2reason(result.errors)
        failure = list2reason(result.failures)
        return error or failure

    def tearDown(self):
        failed = self._testFailed()
        if failed:
            print("\n[!] Test Failed.")
        while self.cleanups:
            item = self.cleanups.pop()
            if isinstance(item, subprocess.Popen):
                item.send_signal(signal.SIGINT)
                item.wait(timeout=5)
            elif isinstance(item, Process):
                if failed:
                    print("[!] Output from: %s" % (item.command,))
                o = True
                so = ""
                if getattr(item, "stdout", None):
                    while o:
                        o = item.stdout.read()
                        so += o
                o = True
                se = ""
                if getattr(item, "stderr", None):
                    while o:
                        o = item.stderr_line()
                        se += o
                if failed:
                    print(so)
                    print(se)
                self.assertNotIn("Traceback", so)
                self.assertNotIn("Traceback", se)
                item.close()
                if getattr(item, "stdout", None):
                    item.stdout.close()
                if getattr(item, "stderr", None):
                    item.stderr.close()
            elif isinstance(item, tempfile._TemporaryFileWrapper):
                item.close()
            elif isinstance(item, socket.socket) or isinstance(item, _socket):
                if item.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX:
                    fname = item.getsockname()
                    if os.access(fname, 0) and stat.S_ISSOCK(os.stat(fname).st_mode):
                        os.unlink(fname)
                item.close()
            else:
                print("[!] Unknown cleanup type")
                print(type(item))

    def tempname(self):
        tf = tempfile.NamedTemporaryFile(delete=True)
        tf.close()
        return tf.name

    def tempfile(self, content, close_fd=False):
        tf = tempfile.NamedTemporaryFile(delete=True)
        tf.write(content.encode())
        tf.flush()
        if close_fd:
            tf.file.close()
        self._add_teardown(tf)
        return tf.name

    def sync_socket_gen(self, sb, prev=None):
        t0 = time.time()
        while time.time() < t0+1:
            gen, idx, sb_cookie = struct.unpack('III', sb.getsockopt(
                socket.IPPROTO_UDP, lsocket.UDP_GRM_SOCKET_GEN, 12))
            if prev is None and (gen != 0xffffffff and idx != 0xffffffff):
                break
            elif prev is not None and sb_cookie != prev:
                break
            os.sched_yield()
        else:
            self.fail("socket gen sync failed %r" % (sb_cookie,))
