# Copyright (c) 2025 Cloudflare, Inc.
# Licensed under the Apache 2.0 license found in the LICENSE file or at:
#     https://opensource.org/licenses/Apache-2.0

import socket
from socket import AF_INET, AF_INET6, SOCK_DGRAM, SOL_SOCKET, SO_REUSEPORT, IPPROTO_UDP
UDP_GRM_WORKING_GEN = 200
UDP_GRM_SOCKET_GEN = 201
UDP_GRM_DISSECTOR = 202
UDP_GRM_FLOW_ASSURE = 203
UDP_GRM_SOCKET_APP = 204

DISSECTOR_FLOW = 0
DISSECTOR_CBPF = 1
DISSECTOR_DIGEST = 3
DISSECTOR_NOOP = 4
DISSECTOR_FLAG_VERBOSE = 0x8000
