# Copyright (c) 2025 Cloudflare, Inc.
# Licensed under the Apache 2.0 license found in the LICENSE file or at:
#     https://opensource.org/licenses/Apache-2.0

import os
import select
import threading
import time

from . import base
from .lsocket import *
from struct import pack


class DissectorNoop(base.TestCase):
    def test_noop(self):
        p = self.udpgrm_run("--daemon --install")
        self.assertTrue(p.collect_stderr("Tailing message ring")[0])

        sd, port = self.bind()
        v = pack("I", DISSECTOR_NOOP)
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 0)
        self.sync_socket_gen(sd)
        sd.setblocking(False)
        sd.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, 0)

        cd = self.connect()

        def sender_loop(var):
            while not var[0]:
                time.sleep(0.0005)
                cd.send(b"hello")
                var[1] += 1

        var = [False, 0]
        thread = threading.Thread(target=sender_loop, args=(var,))
        thread.daemon = True
        thread.start()

        count = 0
        # Make the timeouts to send >1k packets and ~1s roughly
        for i in range(1, 65):
            sa, _ = self.bind(port=port)
            sa.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, i)
            self.sync_socket_gen(sa)
            sa.setblocking(False)
            sa.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, i)
            time.sleep(0.01)
            while True:
                try:
                    sd.recvmsg(1024, 0, socket.MSG_DONTWAIT)
                except (TimeoutError, BlockingIOError):
                    break
                count += 1
            sd.close()
            self._del_teardown(sd)
            sd = sa

        var[0] = True
        thread.join()

        while True:
            try:
                sd.recvmsg(1024, 0, socket.MSG_DONTWAIT)
            except (TimeoutError, BlockingIOError):
                break
            count += 1

        # the packet count must match exactly, not even one packet lost
        self.assertEqual(var[1], count)
        D, M = self.metrics_delta({})

        # The metrics are arguably boring
        self.assertEqual(D, {'rx_dissected_ok_total': count,
                             'rx_flow_new_unseen': count,
                             'rx_new_flow_total': count,
                             'rx_new_flow_working_gen_dispatch_ok': count,
                             'rx_processed_total': count})
