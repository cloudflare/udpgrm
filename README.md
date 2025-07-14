UDP Graceful Restart Marshal
=============================

It's difficult to support zero-downtime, graceful restarts in modern UDP application.

Historically, UDP was designed for simple single-packet request/response protocols like DNS or NTP, where graceful restarts were not a problem. Modern UDP services like QUIC, Masque, WireGuard, SIP, or games hold flow state that shouldn't be lost on restart. Passing state between application instances is usually hard to do safely.

One solution is to borrow semantics from TCP servers: when an application restarts, new flows are sent to the new instance, while old flows keep going to the old one and gradually drain. After a timeout or when all flows end, the old instance exits. There are two ways to achieve this.

The first is [the established-over-unconnected technique](https://blog.cloudflare.com/everything-you-ever-wanted-to-know-about-udp-sockets-but-were-afraid-to-ask-part-1/). It has two major issues: it is racy for some protocols (when the handshake uses more than one packet), and it has a performance cost (kernel hash table conflicts are likely at scale, as the hash bucket is based only on the local two-tuple).

Another solution is to utilize Linux REUSEPORT API. A REUSEPORT socket group can contain sockets from both old and new application instances. A correctly set REUSEPORT eBPF program can, based on some flow tracking logic, direct packets to an appropriate UDP socket and maintain flow stickiness. This is what *udpgrm* does.

What is a reuseport group
=========================

Sockets with the SO_REUSEPORT flag can share a local port tuple, like 192.0.2.0:443.

```
┌───────────────────────────────────────────┐
│ reuseport group 192.0.2.0:443             │
│ ┌───────────┐ ┌───────────┐ ┌───────────┐ │
│ │ socket #1 │ │ socket #2 │ │ socket #3 │ │
│ └───────────┘ └───────────┘ └───────────┘ │
└───────────────────────────────────────────┘
```

For sockets to create a reuseport group, they need to share:

 - ip:port pair
 - BINDTODEVICE, SO_REUSEPORT and `ipv6_only` settings
 - network namespace
 - owner id

Udpgrm
======

Udpgrm is a lightweight software daemon that sets up REUSEPORT group eBPF program and cgroup hooks on getsockopt, setsockopt and sendmsg syscalls. It has two main goals:

-	steer new flows to sockets belonging to a "new application" instance
-	preserve flow affinity, to avoid disturbing the old flows


An eBPF program can be installed on a REUSEPORT group to implement custom load balancing logic with SO_ATTACH_REUSEPORT_EBPF. It can direct packets to specific sockets within the group. udpgrm builds on this and loads its own custom REUSEPORT eBPF program.

Udpgrm concepts
===============

Before we can explain the API we need to discuss some udpgrm concepts.

Generations
-----------

Within REUSEPORT, udpgrm groups sockets into sets called "generations", identified by an unsigned integer. Each generation represents one instance of the application. If a generation contains multiple UDP sockets, new flows are balanced across them like in a standard REUSEPORT setup. A socket may also have no assigned generation number.


```
┌───────────────────────────────────────────────────┐
│ reuseport group 192.0.2.0:443                     │
│  ┌─────────────────────────────────────────────┐  │
│  │ socket generation 0                         │  │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐  │  │
│  │  │ socket #1 │ │ socket #2 │ │ socket #3 │  │  │
│  │  └───────────┘ └───────────┘ └───────────┘  │  │
│  └─────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────┐  │
│  │ socket generation 1                         │  │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐  │  │
│  │  │ socket #4 │ │ socket #5 │ │ socket #6 │  │  │
│  │  └───────────┘ └───────────┘ └───────────┘  │  │
│  └─────────────────────────────────────────────┘  │
│     sockets with unassigned generation            │
│   ┌───────────┐ ┌───────────┐                     │
│   │ socket #0 │ │ socket #8 │                     │
│   └───────────┘ └───────────┘                     │
└───────────────────────────────────────────────────┘
```

Udpgrm maintains a pointer to generation that is accepting new flows, this is called "working generation". This is supposed to point to sockets belonging to the newest application instance.

```
┌──────────────────────────────────────────────┐
│ reuseport group 192.0.2.0:443                │
│                                              │
│   ...                                        │
│                                              │
│   Working generation ────┐                   │
│                          │                   │
│           ┌──────────────▼────────────────┐  │
│           │ socket generation 1           │  │
│           │  ┌───────────┐ ┌──────────┐   │  │
│           │  │ socket #4 │ │ ...      │   │  │
│           │  └───────────┘ └──────────┘   │  │
│           └───────────────────────────────┘  │
│                                              │
│   ...                                        │
└──────────────────────────────────────────────┘
```

The application assigns a socket generation and a working generation with setsockopt syscalls.

Dissectors
----------

The REUSEPORT group can change over time: sockets can come and go as the application is being restarted. To keep the stickiness of existing flows, udpgrm must preserve the flow-to-socket mapping.

Udpgrm supports three flow state management models:

-	Udpgrm can maintain a flow table. Indexed by a flow hash, it contains a target socket identifier. The size of the flow table is fixed - there is a limit to the number of concurrent flows supported by this mode.

-	A cookie-based model, where the target socket identifier - cookie - is encoded in each ingress UDP packet. For example in QUIC this identifier can be stored as part of the connection ID. The dissection logic can be expressed as cBPF code. This model does not require a flow table in udpgrm, but is harder to integrate - it requires protocol support.

-	A no-op null mode, with no state tracking at all. Useful for traditional UDP services like DNS.

These modes are called "dissectors" and are named DISSECTOR_FLOW, DISSECTOR_CBPF, DISSECTOR_NOOP accordingly.

Udpgrm API reference
====================

Probing for udpgrm cgroup hooks
-------------------------------

Before the application does anything useful, it shall check if udpgrm daemon is working properly. There are three conditions that must be met: cgroup hooks must be installed, pid and network namespaces must match.

The first condition - cgroup hooks - can be verified by calling getsockopt(UDP_GRM_WORKING_GEN) on a UDP socket:

```
sd = socket.socket(AF_INET, SOCK_DGRAM, 0)
sd.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
```

This getsockopt will fail with ENOPROTOOPT if udpgrm cgroup hooks are not loaded. Otherwise, it will succeed with -1 if the reuseport group is not yet set up, or will succeed and return the current working generation value - 0 by default.

If the application detects udpgrm is not loaded, it may choose to error or to continue. It's totally fine to keep on going without udpgrm - it's just graceful restarts and socket stickiness will not work. This may be totally acceptable for local development or testing setups.

Basic socket creation
---------------

Udpgrm supports unconnected UDP / SOCK_DGRAM sockets with SO_REUSEPORT bit set. Typically an unconnected socket is created by the application on startup - this may require CAP_NET_ADMIN if binding to lower ports (for alternatives see below), like this:

```
sd = socket.socket(AF_INET, SOCK_DGRAM, 0)
sd.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
sd.bind(("192.0.2.1", 5201))
```

At this point the socket is working in the same way as if it were without udpgrm.

Reuseport group setup
---------------------

After the bind() is called, it's possible (but optional) to set dissector parameters:

```
v = struct.pack("II", DISSECTOR_FLOW, 124)
sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)
```

This is a simplified example, setting the dissector to FLOW and flow timeout of 124 seconds. Full definition of the passed struct:

```
struct udp_grm_dissector {
    uint32_t dissector_type;
    uint32_t flow_entry_timeout_sec;
    uint32_t _res1;
    uint32_t _res2;
    char label[LABEL_SZ];
    uint32_t filter_len;
    struct sock_filter filter[MAX_INSTR];
} __attribute__((packed));
```

You can set UDP_GRM_DISSECTOR only once, at the time of the first socket creating a reuseport group. You can call UDP_GRM_DISSECTOR later, but it will only succeed if all parameters match current values. Attempts to change this struct during the lifetime of the reuseport group will fail with EPERM.

If you wish to clear udpgrm state for a reuseport group you can do that with "udpgrm delete" CLI like:

```
$ udpgrm delete 0.0.0.0:5201
```

Socket generation assignment
----------------------------

After creating a new server instance, we should retrieve the current working generation number:

```
work_gen = sd.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
```

With that handy, enroll one or more of our new reuseport sockets into subsequent generation:

```
for s in [sockets]:
    s.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, work_gen + 1)
```

Setting the socket generation number is instantaneous. However, the socket must go via udpgrm daemon to get the index value within a generation. Application could poll on the return value of getsockopt to ensure the socket has been successfully registered:

```
for i in range(8):
    v = s.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 8);
    sk_gen, sk_idx = struct.unpack('II', v)
    if sk_idx != 0xffffffff:
        break
    time.sleep(0.1 * (2 ** i))
else:
    print("[!] pre-registration failed. is udpgrm still running?")
    sys.exit(1)
```

On rare occasions when dealing with dozens of sockets, setsockopt(UDP_GRM_SOCKET_GEN) might return EAGAIN.

After the setsockopt(UDP_GRM_SOCKET_GEN), when the application boots successfully, it can bump the working generation value and route new traffic to our new sockets:

```
sd.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, work_gen + 1)
```

At this point the new application instance might communicate with the old instance to let it know it's supposed to enter graceful restart mode and slowly drain traffic.

Dissector modes
===============

Udpgrm supports three dissector modes:

-	`DISSECTOR_FLOW` - Socket identifier is saved in flow table hashed by a 3-tuple.
-	`DISSECTOR_CBPF` - Socket identifier is retrieved from a 2-byte cookie extracted from a packet.
-	`DISSECTOR_NOOP` - No socket identifier needed, useful for fire-and-forget UDP services like DNS.

DISSECTOR_FLOW
==============

In this mode the flow state is saved in a flow table indexed by a 3-tuple hash of {remote IP, remote port, reuseport group ID}. We can't use the traditional 4-tuple, since we don't know local source IP on sendmsg() layer - source IP is selected later on routing. Additionally in the context of REUSEPORT eBPF we're sure what the local tuple is, so there is no point in hashing it.

This is a default dissector and can be set on first socket explicitly with UDP_GRM_DISSECTOR:

```
struct udpgrm_dissector_flow {
        uint32_t dissector_type;
        uint32_t flow_entry_timeout_sec;
};
```

Like:

```
sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR,
            struct.pack("II", DISSECTOR_FLOW, 125))
```

Flow entries lifetime
---------------------

Flow entries are created and updated on sendmsg() hook. This is important - flow entry is only created when the application responds, resembling an "assured" state in conntrack. Each flow entry is preserved for 125 seconds by default. In other words, to keep the flow entry your application must transmit a packet more often than every 125 seconds.

Sometimes relying on sendmsg() hooks is undesirable. This may be due to performance concerns, or a complex scenario when the tx is done from a socket on a different local port. This may happen for TPROXY or sk_lookup deployments. For such situations please call UDP_GRM_FLOW_ASSURE syscall like:

```
sd.setsockopt(IPPROTO_UDP, UDP_GRM_FLOW_ASSURE, remote_addr)
```

Where remote_addr is struct sockaddr_in or struct sockaddr_in6. This setsockopt will create a flow entry or update a timeout on an existing flow entry for a given remote address. On flow entry conflict EEXIST is returned.

Note, the application shall call the UDP_GRM_FLOW_ASSURE often enough to ensure the flow entry doesn't timeout.

Flow table overflow
-------------------

Flow table has a fixed size, 8192 entries at the time of writing. On overflow, LRU semantics are used to evict hopefully stale flow entries.

Notice - flow table is shared across all reuseport groups handled by udpgrm. As a key/hash we use a 32-bit value. It's possible for flows to have conflicting hashes. To illustrate this, if there are 8k concurrent flows, there is a 1 in 524288 chance for a new flow hash to hit a conflicting flow entry.

However, conflicts in the flow table are not catastrophic. There are two variants of a possible hash conflict.

First conflict case is when a flow hits a flow entry pointing to a socket in the right reuseport group. Such a new flow is indistinguishable from an existing flow. This slightly violates the contract that no new flows should be routed draining sockets - however this case is not catastrophic. The old instance would perhaps need to handle the flow and take longer to drain. If the flow entry points to a dead socket, the typical new flow dispatch is used. On tx / sendmsg the `tx_flow_update_conflict` metric is increased until the flow entry expires and a new flow entry can be created.

Second conflict case is when a flow hits an entry pointing to a socket from an incorrect reuseport group. This isn't a big deal - udpgrm would try the socket from an incorrect reuseport group, fail with `rx_flow_rg_conflict` metric, and fall back to new flow dispatch logic. On tx / sendmsg the flow entry will be prevented from flapping and the `tx_flow_update_conflict` metric would increase. The socket would remain sticky as long as the working generation doesn't change.

Neither cases should cause big problems in practice, but beware: an application should be capable of accepting new flows even in draining mode.

DISSECTOR_CBPF
==============

For some protocols it's possible to avoid the flow table at all. This can be done by storing a cookie - a value that internally can be mapped onto a socket - in a packet. For example in QUIC a server can affect the client connection ID and stuff arbitrary data there.

Udpgrm in DISSECTOR_CBPF mode can run arbitrary classic BPF bytecode to extract a 16-bit cookie value from the packet.

Notice:

-	"udpgrm cookie" - is a 16-bit value that points to a socket generation and socket index as managed by udpgrm.
-	"socket cookie" - is a 64-bit value uniquely identifying a socket on Linux, can be retrieved with SO\_COOKIE.

We need the full C structure definition for UDP_GRM_DISSECTOR:

```
struct udp_grm_dissector {
    uint32_t dissector_type;
    uint32_t flow_entry_timeout_sec;
    uint32_t app_max;
    uint32_t _res2;
    char label[LABEL_SZ];
    uint32_t filter_len;
    struct sock_filter filter[MAX_INSTR];
} __attribute__((packed));
```

The CBPF dissector uses the "filter" member to store a program. First we need to design the cBPF program. Let's say the 16-bit cookie lives in first two bytes of the UDP datagram, which can be expressed by this cBPF assembly:

```
    ldh [0]
    ret a
```

To compile cBPF:

```
$ echo -e "ldh [0]\nret a" | bpf_asm -c |tr "{}" "()"
( 0x28,  0,  0, 0000000000 ),
( 0x16,  0,  0, 0000000000 ),
```

To load it as part of dissector setup:

```
cbpf = [( 0x28,  0,  0, 0000000000 ),
        ( 0x16,  0,  0, 0000000000 )]

v = pack("IIII100sI256s", DISSECTOR_CBPF,
         124, 0, 0, b'',
         len(cbpf), b''.join(pack('HBBI', *sf) for sf in cbpf))
sa.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)
```

The sockets registered with UDP_GRM_SOCKET_GEN have a 16-bit cookie assigned. It can be retrieved with getsockopt which returns such struct:

```
struct udpgrm {
    uint32_t sk_gen;
    uint32_t sk_idx;
    uint16_t cookie;
    uint16_t _padding;
};
```

Here's an example:

```
v = sd.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 12)
sk_gen, sk_idx, cookie, _pad = struct.unpack("IIHH", v)
```

Notice, as described above, there is a delay before setting socket generation and retrieving valid sk_idx. Retry this call as long as sk_idx is equal to 0xffffffff.

For our example such a cookie should be put into ingress packets as the first two bytes. Notice, that the cBPF operates in big-endian mode, so a correct packet sent by the client might look like:

```
cd.send( pack(">H", cookie) + b' hello world' )
```

The 16-bit value cookie contains 5 bits for socket generation, 8 bits for socket index, and 3 bits of naive checksum. The cBPF runs on each ingress packet, and its main role is to extract the cookie. There are four available outputs of the cBPF program:

1.	Udpgrm cookie - an integer in the range from 0 to 0xffff. If the checksum from that 16-bit value doesn't match, the `rx_flow_new_bad_cookie` is increased. Otherwise, if the cookie is valid but no socket is found, the typical new flow dispatch is followed.

2.	Values in the special range 0x80000000 - 0x80000003 go to application dispatch logic. More on this below.

3.	Values outside of the ranges, like -1 indicate new flow.

4.	Error - fetching data from outside of the packet or invalid cBPF bytecode. In this case metrics rx_packet_too_short_error or rx_cbpf_prog_error are increased. The packet is dispatched using classic REUSEPORT group logic. These errors are considered critical and should be investigated.

There is an upper limit of max 64 cBPF instructions. Remember, this bytecode is interpreted on every ingress packet and slow. If you need more instructions you probably should write a custom dissector.

DISSECTOR_NOOP
==============

Udpgrm shines for stateful UDP services like QUIC. However, it is also useful for stateless traditional fire-and-forget servers like DNS or NTP. For these, while state tracking is not important - actually it's harmful - udpgrm can still be useful in order to ensure no packet is lost during service upgrade.

Typically, a service like DNS is not easy to upgrade in a "graceful" way that guarantees no packet loss. Either one can use a "stop the world" model, where old server stops, closes listening sockets, and later new server starts opening fresh sockets. This of course has a race condition problem and it's possible for inbound packets to be lost.

Another option is to allow new instance to take over the sockets from the parent server. The old instance needs to keep on holding to the sockets in order to be able to respond using them. This setup is not terrible, but hard to get right, especially for a case when the new instance needs to roll back due to some problem like configuration error.

Finally, the last option is to create new sets of sockets with SO_REUSEPORT, and just allow the new instance to hold onto these. This is best, but requires some sort of eBPF reuseport program that can steer the new requests to either old or new server instance. This is where udpgrm comes in.

All that is required is for the new instance to register the REUSEPORT socket, and change the "working generation" pointer, like so:

```
v = pack("I", DISSECTOR_NOOP)
sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)

work_gen = sd.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)
sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, work_gen + 1);

for i in range(8):
    v = s.getsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 8);
    sk_gen, sk_idx = struct.unpack('II', v)
    if sk_idx != 0xffffffff:
        break
    time.sleep(0.1 * (2 ** i))
else:
    print("[!] pre-registration failed. is udpgrm still running?")
    sys.exit(1)

sd.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, work_gen + 1);
```

This will ensure all new packets go to the freshest socket, and no packet is lost during the server transition.

Application selection
---------------------

As an extension to DISSECTOR_CBPF, we support udpgrm dispatching packets across multiple applications. Think about setup with two QUIC applications behind port 443, each wanting to support graceful restart. The supported scenario is as follows:

-	The 16-bit udpgrm cookie is in the packet header.
-	For packets belonging to established flows, this value is extracted from the UDP packet by cBPF code.
-	For new flows, the cBPF can extract the application number from the UDP packet - for example by inspecting TLS SNI.

Basically, the idea is that the UDP header contains enough information to dispatch the flow to a specific application, for the new flows case. Internally, we split the generations pool across applications. Here's how to use it with "udpgrm_activate.py" wrapper.

First, we need to set up the cbpf and max-applications parameters for the socket group:

```
udpgrm_activate.py --bpf cbpf-instr.sh --max-apps=4 --app-no=0 quic-app-0 0.0.0.0:443
```

Notice that we set three things here. First, we set the dissector to DISSECTOR_CBPF and load relevant cbpf from a file. We also set the max of 4 concurrent applications. This limits the generation limit per application to 32/4 = 8. Then we set the application number for our socket to zero. Finally we store the sockets in systemd socket store.

If you wanted to do that without udpgrm_activate.py, then after setting dissector, but before setting socket or working group you would need to assign the socket to specific application number with:

```
sd.setsockopt(socket.IPPROTO_UDP, UDP_GRM_SOCKET_APP, appno)
```

The application number assigned to a specific socket can be retrieved similarly with:

```
sd.getsockopt(socket.IPPROTO_UDP, UDP_GRM_SOCKET_APP)
```

Finally, all this requires cBPF support. For a new flow, to select a specific application, the cBPF can return values from 0x80000000 to 0x80000003, mapped to application numbers 0..3.

udpgrm daemon lifetime
======================

udpgrm needs to run as a daemon. The daemon needs to run as root:

```
$ udpgrm --daemon
```

It will load the eBPF programs, pin them to /sys/fs/bpf/udpgrm/, but it won't install them into the cgroup. Udpgrm will stay in the foreground and print debugging info on the screen. After that you need to install the cgroup hooks in one or more cgroups:

```
$ udpgrm --install=/sys/fs/cgroup/system.slice
```

This will create the hooks BPF links and pin them to /sys/fs/bpf/udpgrm/<cgroup_id>\_<hook>. Skipping the parameter from `--install` will cause it to look for main cgroup. Passing `--self` will cause udpgrm to inspect /proc/self/cgroup and attach to current cgroup, like:

```
$ udpgrm --install --self
```

You can verify where the hooks are loaded with `bpftool`:

```
$ bpftool cgroup tree
```

Alternatively, for ease of use you can run this CLI to both run the daemon and install the cgroups - in the main cgroup by default:

```
$ udpgrm --daemon --install
```

This is useful for development and debugging.

Upgrading udpgrm daemon
-----------------------

If udpgrm is used as recommended in this guide - for example hooks installed with systemd `udpgrm --install --self` command - then the udpgrm contract can be upheld during the daemon restart.

Generally, udpgrm daemon should outlive the application. In a rare situation when udpgrm daemon needs to be restarted, however, this shouldn't be a big problem. You don't generally need to immediately restart the application.

If udpgrm daemon is restarted, then it creates new pins in /sys/fs/bpf/udpgrm. The old ebpf programs, loaded in REUSEPORT_EBPF and cgroup hooks, remain active. The only problem is that `udpgrm list` stops seeing the old installation - since it points to new maps. This should not interfere with normal operation though.

If later the application is restarted, the new hooks should be re-installed in the application cgroup, and REUSEPORT_EBPF program re-loaded. Therefore all old ebpf state should be lost. This again, is fine. The only problem is with `DISSECTOR_FLOW` where of course the flow state might be lost.

In summary, udpgrm daemon might be restarted, just bear in mind that metrics and flow state for old app using FLOW dissector are lost.

Tubular integration
-------------------

Since the udpgrm daemon has access to the sockets, it's possible to hook it to an external application requiring socket access. For example Cloudflare Tubular (sk_lookup) daemon requires access to listening sockets.

We accept the `--tubular=PATH` option for the udpgrm daemon. With this option, when the socket group is configured with a non-empty `label` field, then on `setsockopt(UDP_GRM_WORKING_GEN)` the sockets are passed to the Tubular unix domain socket.

Three requirements must be met for that to work:

-	`--tubular` option must point to SEQPACKET unix domain socket
-	non-empty `label` field must be passed during `UDP_GRM_DISSECTOR` phase
-	the `setsockopt(UDP_GRM_WORKING_GEN)` must be called

`Label` is a zero-terminated string of max length 100 bytes, like this:

```
label = b"udp_server"
sd.setsockopt(socket.IPPROTO_UDP, UDP_GRM_DISSECTOR,
            struct.pack("IIII100s",
                DISSECTOR_FLOW, 125, 0, 0,
                label + b'\x00'))
```

Reuseport group metrics
-----------------------

You can see reuseport group metrics with:

```
$ udpgrm list
192.0.2.1:5201
 netns 0x0  dissector flow
 socket generations:
     gen 0  0x7015 0x7016  <= wrk_gen % 2
 metrics:
     rx_processed_total 4
     rx_flow_ok 3
     rx_flow_new_unseen 1
     rx_new_flow_total 1
     rx_new_flow_working_gen_dispatch_ok 1
     tx_total 4
     tx_flow_create_ok 1
     tx_flow_update_ok 3
```

You can supply `-v` to see some more details. Generally, there is one list per reuseport group, but there are exceptions. For example, if you restart udpgrm daemon, the `udpgrm list` will be able to query metrics from old/stale udpgrm groups. This can result in one ip/port being reported multiple times, like:

```
$ udpgrm list
192.0.2.1:5201
 netns 0x0  dissector flow
 socket generations:
     gen 0  0x7015 0x7016  <= wrk_gen % 2
 metrics:
     rx_processed_total 4

192.0.2.1:5201 (old)
 netns 0x0  dissector flow
 metrics:
     rx_processed_total 4
```

Metrics are grouped, hopefully in an intelligent way.

![Metrics chart](tools/flow-chart.png)

First, there is a management section for misc metrics, right now it contains:

-	`setup_critical` - number of critical errors, mostly around socket setup. Things like failure to extract socket, or register it with Tubular are logged here. A non-zero number here is critical and has a matching CRITICAL line in the `udpgrm` output.
-	`setup_critical_gauge` - a boolean showing if last `setsockopt(UDP_GRM_WORKING_GEN)` succeeded.

The rest of the metrics are dataplane - counting packets or syscalls. We collect these metrics in two places - on the REUSEPORT program and sendmsg hook.

REUSEPORT program contains three separate stages of packet processing. Each stage counts the number of total processed *packets*. A single packet can be accounted for in every stage, but within a stage it is accounted for exactly once. The stages are:

-	packet parsing
-	existing flow dispatch
-	new flow dispatch

(1) Packet parsing metrics:

-	`rx_processed_total` - total packets going into the reuseport group
-	error: `rx_internal_state_error` - something is deeply wrong with our maps or data in maps.
-	error: `rx_cbpf_prog_error` - Running cBPF failed. Either encountered invalid instruction, or finished without 'ret' statement.
-	error: `rx_packet_too_short_error` - failed to fetch data from packet that is needed to compute flow hash or flow cookie.

On error we can't continue processing in this stage. These errors are hard and fallback to classic reuseport group processing.

(2) Existing flow dispatch:

-	`rx_dissected_ok_total` - total packets that went through previous stage.
-	success: `rx_flow_ok` - Flow entry or socket cookie found, dispatch went fine.
-	fallback: `rx_flow_rg_conflict` - Found socket had wrong reuseport group. Looks like conflict in flow table, or cookie spraying for flowtable-less dissectors.
-	fallback: `rx_flow_other_error` - Flow entry or socket cookie pointing to a dead socket.
-	fallback: `rx_flow_new_unseen` - Flow / packet looks like new, and should have a new flow created for it.
-	supporting: `rx_flow_new_had_expired` - For flow table dissectors, flow entry was found but was expired. Can be indicative of too short flow entry timeout. This counter is a subset of `rx_flow_new_unseen` flows.
-	supporting: `rx_flow_new_bad_cookie` - For cookie dissectors, packet was parsed, but extracted cookie had bad checksum

On success, we're done processing the packet. On error, packets fall through to the next section.

(3) New flow dispatch:

-	`rx_new_flow_total` - total packets that went to this stage.
-	success: `rx_new_flow_working_gen_dispatch_ok` - packets that went to the working generation of sockets and succeeded in the dispatch.
-	error: `rx_new_flow_working_gen_dispatch_error` - packets that failed to be dispatched to working gen sockets.

On success, the working group socket gets a packet. On error we fall-through to classic reuseport group dispatch semantics. This should be considered critical.

Then we're collecting metrics from `sendmsg` *calls* (notice: this is not about packets, with UDP_SEGMENT it's possible to send multiple packets with one syscall):

-	`tx_total` - number of total sendmsg calls for the reuseport group sockets.
-	`tx_flow_create_ok` - flow entries are only created on sendmsg. This counter shows number of created flow entries for the reuseport group.
-	supporting: `tx_flow_create_from_expired_ok` - subset of previous counter, showing number of found/conflicting flow entries that were expired and updated. Might be indicative of flow timeout.
-	`tx_flow_create_error` - For some reason flow creation failed. Shouldn't happen.
-	`tx_flow_update_ok` - When sendmsg is done on existing flow, we update the timeout. This counter indicates successes.
-	`tx_flow_update_conflict` - When updating the timeout we also validate if the flow cookie matches our sendmsg socket. If that's not the case, we have a problem. Was the flow migrated to another socket? This counter counts that. Notice: we do not move the flow. The flow entry will keep on pointing to old socket until the flow expires. This counter increases if the application dies prematurely, since we're unable to keep stickiness.

Listing flow table contents
---------------------------

To show the status of flow table:

```
$ udpgrm flows
```

Note on namespaces
------------------

The cgroup hooks (setsockopt/getsockopt/sendmsg) are scoped to a cgroup. The sockets are tied to a network namespace. We perform socket stealing which is keyed by a process pid, which lives in pid namespace.

Currently, the UDP application must:

-	live in a pid namespace shared with udpgrm.
-	live in the same mount namespace, access to /sys/bpf filesystem.
-	live in a cgroup with installed cgroup hooks - see below on how to do that.
-	not do messy stuff across net namespaces. Internally we key the reuseport group by IP and port, so you can't have separate reuseport groups in different namespaces with the same IP/port. Similarly, BINDTODEVICE (bound device) ifnumber is not taken into account when keying reuseport groups. Also `ipv6_only` flag should be verified.

Systemd integration
-------------------

To integrate with systemd you're supposed to create a `udpgrm.service` that starts the udpgrm daemon, and then stuff the dependency inside your application service like so:

```
[Service]
...
    ExecStartPre=/usr/local/bin/udpgrm --install --self
```

Note: The sendmsg hooks are optional. They are only needed for a FLOW dissector without application use of UDP_GRM_FLOW_ASSURE. If that works you can check it with:

```
$ bpftool cgroup tree /sys/fs/cgroup/system.slice/application.service
/sys/fs/cgroup/system.slice/application.service
108     cgroup_device   multi
107     cgroup_inet4_bind multi     _bpf_bind4
106     cgroup_inet6_bind multi     _bpf_bind6
105     cgroup_udp4_sendmsg multi   _udp4_sendmsg
104     cgroup_udp6_sendmsg multi   _udp6_sendmsg
103     cgroup_getsockopt multi     _getsockopt
102     cgroup_setsockopt multi     _setsockopt
```

Alternatively, you can manually install the cgroup handlers into a cgroup like this:

```
$ udpgrm --install=/sys/fs/cgroup/system.slice/application.service
```

Typically an application creates the UDP sockets by itself. This might require CAP_NET_BIND, like:

```
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

An alternative is to create a socket in the privileged ExecStartPre program, and pass it down to an application with the use of Systemd File Descriptor Store. This is similar to using Systemd Socket Activation. Note: classical socket activation is not very useful with UDP unconnected sockets. We're shipping the "udpgrm_activate.py" script to support such deployments. An example systemd service might look like:

```
[Service]
Type=notify                 # Enable access to fd store
NotifyAccess=all            # Allow access to fd store from ExecStartPre
FileDescriptorStoreMax=128  # Limit of stored sockets must be set

ExecStartPre=/udpgrm_activate.py test-port 0.0.0.0:5201
ExecStart=mmdecoy examples/echoserver.py

Restart=always               # if pid dies, restart it.
KillMode=porcess             # Send signal only to decoy
KillSignal=SIGTERM           # Make signal explicit
```

When using `KillMode=process`, the  `mmdecoy` program can be used to fool systemd that our daemon exited. You can experiment with commandline systemd-run:

```
sudo systemd-run \
        --unit echoserver \
	-p Type=notify \
        -p NotifyAccess=all \
        -p FileDescriptorStoreMax=128\
        -p ExecStartPre="$PWD/udpgrm --install --self" \
        -p ExecStartPre="$PWD/tools/udpgrm_activate.py \
                --no-register \
                --count=8 \
                xxx 0.0.0.0:4433" \
	-p KillMode=process \
        -p KillSignal=SIGTERM \
        -p Restart=always \
        -- $PWD/mmdecoy \
        	-- $PWD/examples/venv/bin/python3 $PWD/examples/echoserver.py

```

Then you can see it in action with:
```
$ sudo systemctl status echoserver
$ sudo systemctl restart echoserver
```


Testing
-------

The tests require loading BPF programs, and bumping RLIMIT_MEMLOCK, so unfortunately they must be run as root. Here's how to run a specific test:

```
CLANG_BIN=clang-18 \
    make test \
    TEST=tests.test_basic.BasicTest.test_metrics_duplicated
```

GRO considerations
------------------

In case of GRO/GSO/UDP_SEGMENT packet trains, only the first packet in the train is visible by SO\_REUSEPORT program. Therefore the counters reported by udpgrm will only show this. Linux's `sk_reuseport_md` does not contain gso_segs/gso_size so it's not even possible to know if the packet is long.

Examples
--------

quic/digest
===========

We have implementations of QUIC servers and clients in Python and Rust. The servers are able to inherit sockets from `udpgrm_activate.py`. With DIGEST dissector it's possible to decrypt the initial QUIC packet and dispatch connections to different applications based on SNI.

First, set up the daemon on one terminal:

```
sudo ./udpgrm --daemon
```

On other terminals run two rust servers, one with `-a0` another with `-a1`:

```
sudo ./udpgrm --install --self
./examples/venv/bin/python3 tools/udpgrm_activate.py \
	--advance-working-gen -a0 -m4 \
        --digest 0xdead --sni example.com:1 --sni example.pl:1 \
        xxx 127.0.0.1:4433 -- \
        ./tqserver \
        	--crt examples/cert.crt --key examples/cert.key
```

Or the python server:

```
sudo ./udpgrm --install --self
./examples/venv/bin/python3 tools/udpgrm_activate.py \
	--advance-working-gen -a1 -m4 \
        --digest 0xdead --sni example.com:1 --sni example.pl:1 \
        xxx 127.0.0.1:4433 -- \
        ./examples/venv/bin/python3 examples/http3_simple_server.py \
		--crt examples/cert.crt --key examples/cert.key
```

Clients:

```
./client --target 127.0.0.1:4433 http://example.com/
```

or

```
./examples/venv/bin/python3 examples/http3_simple_client.py \
	127.0.0.1 4433 example.com
```

Rust API
========

Some very basic code using rust api is under simple-flip.rs:

```
$ sudo ./udpgrm --daemon
$ sudo ./udpgrm --install --self
$ (cd crates/udpgrm; cargo run --example simple-flip)
Yay, it worked!
```

Performance considerations
==========================

Unless you're using DISSECTOR_FLOW, consider installing udpgrm without sendmsg hooks, by passing `--without-sendmsg`:

```
$ sudo ./udpgrm --install --self --without-sendmsg
```

Apart from that, note that any SO_ATTACH_REUSEPORT_EBPF program will add about cost to packet processing (see also "GRO considerations" section).

The cost of the eBPF depends on the settings, but the ballpark is

 - about 10ns of fixed cost for just calling an empty eBPF REUSEPORT program
 - about 20ns is due to our eBPF HASH map lookup of `reuseport_storage_map`
 - about 8ns could be shaved if we replaced SOCKMAP with SOCKHASH
 - about 22ns is caused by doing incr on metrics
 - loads of cycles can be wasted in the DISSECTOR_CBPF on the interpreter

For example, on one machine the fast path for the DISSECTOR_BESPOKE takes on average 80ns per packet train.

Raw performance is not udpgrm's strongest point, but this only matters if the workload is ingress-heavy. In most cases, routing and firewall processing take more time. Still, there is room for improvement.

Hacking ebpf
============

When modifying the eBPF consider running "make info"

```
$ make info
**** stack usage by function ****
ebpf/ebpf_aes128.c:180  AES_ECB_encrypt        32   static
ebpf/ebpf_sha256.c:34   sha256_calc_chunk      64   static
ebpf/ebpf_sha256.c:123  sha256_hmac            40   static
...
**** verifier instruction count ****
udpgrm_reuseport_prog  processed  103486  insns  (limit  1000000)  max_states_per_insn  54  total_states  5658  peak_states  1827  mark_read  64
udpgrm_setsockopt      processed  9931    insns  (limit  1000000)  max_states_per_insn  2   total_states  172   peak_states  172   mark_read  42
udpgrm_getsockopt      processed  4215    insns  (limit  1000000)  max_states_per_insn  1   total_states  38    peak_states  38    mark_read  5
```

It will show stack usage by function and verifier instruction count. These can be very usefull when hitting verifier stack or instruction limits.


Random ideas
============

Since udpgrm knows which packet is "new", belonging to a fresh flow, it could save it and provide something like `TCP_SAVED_SYN`, I guess `UDP_SAVED_SYN`.

We could implement something resembling SYN cookies but for QUIC, kicking in on queue overflow or rate limit. For  Retry packets, udpgrm could be used to validate the token.

License
=======

The eBPF programs that udpgrm loads into the kernel at runtime, which consist of the files in
the `ebpf/` subdirectory, are licensed under the [GPLv2](ebpf/LICENSE). Header files that are
shared between eBPF and userland code are found in `include/` and are dual-licensed under the
[GPLv2](ebpf/LICENSE) and the [Apache 2.0 license](LICENSE) at your option. All code not listed
otherwise is licensed exclusively under the [Apache 2.0 license](LICENSE).
