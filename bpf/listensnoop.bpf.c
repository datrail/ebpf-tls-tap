// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 DatRail
//
// Report every TCP, UDP or ICMP-echo socket that starts accepting inbound
// traffic. An agent that opens a port is offering a service nobody declared;
// the TLS uprobes in sslsniff.bpf.c cannot see it because no TLS call is ever
// made.
//
// - inet_csk_listen_start(sk) runs only when a socket moves into LISTEN,
//   never for a repeated listen() that merely resizes the backlog, so each
//   listening socket is reported once. It also covers listen() with no prior
//   bind(), where the kernel picks the port here.
// - inet_bind_sk/inet6_bind_sk(sk, ...) are where every AF_INET/AF_INET6
//   bind() lands since Linux 6.6, MPTCP's included: it binds its subflow
//   there directly, bypassing inet_bind. Before 6.6 they don't exist and
//   every bind, MPTCP's too, goes through inet_bind/inet6_bind; the loader
//   attaches exactly one of each pair. TCP binds are skipped (the listen hook reports the ones that
//   become servers); a UDP bind is the only signal a UDP server gives, since
//   UDP has no listen(). An unprivileged ICMP "ping" socket (SOCK_DGRAM,
//   IPPROTO_ICMP) binds an echo identifier the same way and then receives
//   every echo reply carrying it, so it is reported too, the identifier as
//   its port.
// - inet_send_prepare(sk) binds an unbound socket on its first sendto(). An
//   unconnected datagram socket bound that way receives from anyone, so it
//   is a listener too. connect() autobinds through a different path and is
//   not reported: a connected socket only hears its peer.
// - inet_csk_accept(sk, ...) hands a TCP listener's next connection to the
//   process serving it. The first time a given remote address is accepted on
//   a given process's listener port, that peer is reported: who actually
//   connects in, not just that a door is open.
//
// fentry/fexit, not kprobes: fexit sees the arguments and the return value
// together, so there is no entry-to-return map that a burst of concurrent
// calls could overflow (a kretprobe has a fixed number of slots, and a missed
// return used to leave an entry behind until the map was full and every
// later event was dropped). A call the trampoline skips because the program
// was already running on that CPU is counted by the kernel in the program's
// recursion_misses, which userspace adds to its "lost" count. The return
// value comes from bpf_get_func_ret(), so it does not depend on how many
// arguments this kernel's version of the function takes.
//
// Address and port are read on return, after the kernel assigned them, so a
// bind to port 0 reports the port actually chosen, and the event says whether
// the kernel chose it (ephemeral): a bind that asked for port 0, a listen()
// on an unbound socket, or an autobind. A consumer comparing listeners over
// time needs that, since a chosen port differs on every run while an asked-for
// one is the service's identity, whatever range it falls in.
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "listensnoop.h"
#include "pidns.bpf.h"

#define AF_INET 2
#define AF_INET6 10
#define SOCK_DGRAM 2
#define IPPROTO_ICMP 1
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58
#define IPPROTO_UDPLITE 136

/* A ring buffer, not a perf buffer: a perf buffer reports its losses only
 * when the next event fits, so the last event of a flood (the one listen()
 * the flood was hiding) could vanish without a trace. Here every event that
 * does not fit is counted in dropped, which userspace polls on its own. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} listen_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped SEC(".maps");

/* The unbound datagram socket a thread is sending on, from fentry to fexit of
 * inet_send_prepare. Task storage lives and dies with the task, so it has no
 * capacity to exhaust. */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u64);
} unbound_send SEC(".maps");

/* Whether the kernel picked the socket's current port: written on every
 * successful bind() (1 if it asked for port 0, else 0) and set by listen()
 * on a socket with no port. Never only set: a kernel-chosen port is released
 * when the socket disconnects (connect(AF_UNSPEC)), and the same socket can
 * then bind a port it asks for, which must not read as ephemeral. Read when
 * the socket starts listening; lives and dies with the socket. */
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u8);
} kernel_chose SEC(".maps");

/* Peers already reported: one event per (process, listener, remote
 * address), so a busy server costs an event per new peer, not one per
 * connection. LRU, so it can't fill: an evicted peer is only reported again
 * when it next connects, which a consumer that keeps a set absorbs. The
 * process is its host PID plus its start time and exec count, so a reused
 * PID or an exec() into another program is a new process, whose peers are
 * new. Not comm: that is per thread and settable, and a server whose
 * worker threads have names would report each peer once per worker. */
struct peer_key {
    __u64 start_time; /* the thread group leader's, monotonic ns */
    __u64 exec_id;    /* its self_exec_id: one more on every exec() */
    __u32 tgid;       /* host PID: stable whatever namespace listensnoop is in */
    __u16 family;
    __u16 port;
    __u8 addr[16];    /* the listener's: two on one port are two listeners */
    __u8 peer[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct peer_key);
    __type(value, __u8);
} peers_seen SEC(".maps");

const volatile pid_t targ_pid = 0;
const volatile uid_t targ_uid = -1;
/* The inode of listensnoop's own PID namespace. PIDs are reported as that
 * namespace sees them, so they mean what they mean to the user and to -p
 * whether it runs on the host or in a container. */
const volatile __u32 pidns_ino = 0;
/* --own-namespace: drop events from processes listensnoop's namespace cannot
 * see, rather than report them with pid 0. */
const volatile bool own_ns_only = false;

static __always_inline u16 sk_protocol(struct sock *sk)
{
    return BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
}

/* Datagram sockets that start receiving once bound: UDP and ICMP echo. A raw
 * socket of the same protocol is excluded: it receives everything whether
 * bound or not, and its "port" would be the protocol number. */
static __always_inline bool is_datagram(struct sock *sk)
{
    u16 protocol = sk_protocol(sk);

    if (BPF_CORE_READ_BITFIELD_PROBED(sk, sk_type) != SOCK_DGRAM)
        return false;
    return protocol == IPPROTO_UDP || protocol == IPPROTO_UDPLITE ||
           protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6;
}

static __always_inline void count_drop(void)
{
    u32 zero = 0;
    u64 *drops = bpf_map_lookup_elem(&dropped, &zero);

    if (drops)
        __sync_fetch_and_add(drops, 1);
}

static __always_inline void mark_kernel_chose(struct sock *sk, bool chose)
{
    __u8 *flag;

    if (!chose) {
        /* Only clear an existing mark; no mark already reads as asked-for. */
        flag = bpf_sk_storage_get(&kernel_chose, sk, 0, 0);
        if (flag)
            *flag = 0;
        return;
    }
    flag = bpf_sk_storage_get(&kernel_chose, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (flag)
        *flag = 1;
    else
        count_drop(); /* out of memory: the port would read as asked-for */
}

static __always_inline bool kernel_chose_port(struct sock *sk)
{
    __u8 *flag = bpf_sk_storage_get(&kernel_chose, sk, 0, 0);

    return flag && *flag;
}

/* Whether the current process is one to report, with its IDs. */
static __always_inline bool wanted(u16 family, u32 *pid, u32 *tid, u32 *uid)
{
    *uid = bpf_get_current_uid_gid();
    ns_pid_tid(pidns_ino, pid, tid);
    if (own_ns_only && !*pid)
        return false;
    if (targ_pid && targ_pid != *pid)
        return false;
    if (targ_uid != (uid_t)-1 && targ_uid != *uid)
        return false;
    return family == AF_INET || family == AF_INET6;
}

static __always_inline void fill(struct listen_event_t *e, struct sock *sk, u8 kind,
                                 bool ephemeral, u32 pid, u32 tid, u32 uid, u16 family)
{
    __builtin_memset(e, 0, sizeof(*e));
    e->pid = pid;
    e->tid = tid;
    e->uid = uid;
    e->family = family;
    if (family == AF_INET)
        BPF_CORE_READ_INTO(&e->addr, sk, __sk_common.skc_rcv_saddr);
    else
        BPF_CORE_READ_INTO(&e->addr, sk, __sk_common.skc_v6_rcv_saddr);
    e->port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->protocol = sk_protocol(sk);
    e->kind = kind;
    e->ephemeral = ephemeral;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->host_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void emit(void *ctx, struct sock *sk, u8 kind, bool ephemeral)
{
    struct listen_event_t *e;
    u32 pid, tid, uid;
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (!wanted(family, &pid, &tid, &uid))
        return;
    e = bpf_ringbuf_reserve(&listen_events, sizeof(*e), 0);
    if (!e) {
        count_drop();
        return;
    }
    fill(e, sk, kind, ephemeral, pid, tid, uid, family);
    bpf_ringbuf_submit(e, 0);
}

static __always_inline bool succeeded(void *ctx)
{
    u64 ret;

    return bpf_get_func_ret(ctx, &ret) == 0 && (int)ret == 0;
}

/* listen() on a socket with no port: the kernel picks one in here. */
SEC("fentry/inet_csk_listen_start")
int BPF_PROG(listen_start_enter, struct sock *sk)
{
    if (!sk->__sk_common.skc_num)
        mark_kernel_chose(sk, true);
    return 0;
}

SEC("fexit/inet_csk_listen_start")
int BPF_PROG(listen_start_exit, struct sock *sk)
{
    if (succeeded(ctx))
        emit(ctx, sk, LISTEN_KIND_LISTEN, kernel_chose_port(sk));
    return 0;
}

static __always_inline int bind_exit(void *ctx, struct sock *sk)
{
    __u64 uaddr = 0;
    __be16 asked = 0;

    if (!sk || !succeeded(ctx))
        return 0;
    /* The port bind() asked for: sin_port and sin6_port share offset 2. */
    if (bpf_get_func_arg(ctx, 1, &uaddr) ||
        bpf_probe_read_kernel(&asked, sizeof(asked), (void *)uaddr + 2))
        return 0;
    mark_kernel_chose(sk, !asked); /* read by a TCP socket's later listen() */
    /* IP_BIND_ADDRESS_NO_PORT binds an address but no port yet; the first
     * sendto() reports it as an autobind once it has one. */
    if (is_datagram(sk) && BPF_CORE_READ(sk, __sk_common.skc_num))
        emit(ctx, sk, LISTEN_KIND_BIND, !asked);
    return 0;
}

SEC("fexit/inet_bind_sk")
int BPF_PROG(inet_bind_sk_exit, struct sock *sk)
{
    return bind_exit(ctx, sk);
}

SEC("fexit/inet6_bind_sk")
int BPF_PROG(inet6_bind_sk_exit, struct sock *sk)
{
    return bind_exit(ctx, sk);
}

/* Kernels before 6.6, which have no inet_bind_sk: every bind comes here. */
SEC("fexit/inet_bind")
int BPF_PROG(inet_bind_exit, struct socket *sock)
{
    return bind_exit(ctx, sock->sk);
}

SEC("fexit/inet6_bind")
int BPF_PROG(inet6_bind_exit, struct socket *sock)
{
    return bind_exit(ctx, sock->sk);
}

SEC("fentry/inet_send_prepare")
int BPF_PROG(send_prepare_enter, struct sock *sk)
{
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 *slot;

    if (BPF_CORE_READ(sk, __sk_common.skc_num) || !is_datagram(sk))
        return 0;
    slot = bpf_task_storage_get(&unbound_send, task, 0,
                                BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (slot)
        *slot = (__u64)sk;
    else
        count_drop(); /* out of memory: this autobind can't be followed */
    return 0;
}

SEC("fexit/inet_send_prepare")
int BPF_PROG(send_prepare_exit, struct sock *sk)
{
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 *slot = bpf_task_storage_get(&unbound_send, task, 0, 0);

    if (!slot || *slot != (__u64)sk)
        return 0;
    *slot = 0;
    if (succeeded(ctx) && BPF_CORE_READ(sk, __sk_common.skc_num))
        emit(ctx, sk, LISTEN_KIND_AUTOBIND, true);
    return 0;
}

/* accept() and every other way of taking a connection off a TCP listener's
 * queue (accept4, io_uring, MPTCP's first subflow) returns the new socket
 * here, in the context of the process taking it: the one serving the peer.
 * The handshake itself completes in softirq, with no process to attribute it
 * to, so a connection nobody accepts is not reported, and neither is an
 * MPTCP join: a later subflow, possibly from another address, that the
 * kernel adds to an accepted connection without another accept. Address, port and
 * family are the listener's, so a consumer can join the peer to the listener
 * it reported; on a dual-stack IPv6 listener an IPv4 peer is IPv4-mapped. */
#define EEXIST 17

SEC("fexit/inet_csk_accept")
int BPF_PROG(accept_exit, struct sock *sk)
{
    struct listen_event_t *e;
    struct peer_key key = {};
    struct task_struct *leader;
    struct sock *child;
    u32 pid, tid, uid;
    u16 family;
    u8 seen = 1;
    u64 ret;

    if (bpf_get_func_ret(ctx, &ret) || !ret)
        return 0;
    child = (struct sock *)ret;
    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (!wanted(family, &pid, &tid, &uid))
        return 0;
    leader = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), group_leader);
    key.start_time = BPF_CORE_READ(leader, start_time);
    key.exec_id = BPF_CORE_READ(leader, self_exec_id);
    key.tgid = bpf_get_current_pid_tgid() >> 32;
    key.family = family;
    key.port = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (family == AF_INET)
        BPF_CORE_READ_INTO((__be32 *)key.addr, sk, __sk_common.skc_rcv_saddr);
    else
        BPF_CORE_READ_INTO((struct in6_addr *)key.addr, sk, __sk_common.skc_v6_rcv_saddr);
    /* Into a field of the source's own type: BPF_CORE_READ_INTO copies
     * sizeof(*dst), and 16 bytes from skc_daddr run on into the client's
     * port, which would make every connection a new peer. */
    if (family == AF_INET)
        BPF_CORE_READ_INTO((__be32 *)key.peer, child, __sk_common.skc_daddr);
    else
        BPF_CORE_READ_INTO((struct in6_addr *)key.peer, child, __sk_common.skc_v6_daddr);
    /* NOEXIST makes the check and the insert one step: of two CPUs taking
     * the same new peer at once, exactly one reports it. Any other failure
     * reports anyway; a duplicate is harmless, a gap is not. */
    if (bpf_map_update_elem(&peers_seen, &key, &seen, BPF_NOEXIST) == -EEXIST)
        return 0;
    e = bpf_ringbuf_reserve(&listen_events, sizeof(*e), 0);
    if (!e) {
        /* Forget it, so the next connection from this peer is reported. */
        bpf_map_delete_elem(&peers_seen, &key);
        count_drop();
        return 0;
    }
    fill(e, sk, LISTEN_KIND_PEER, kernel_chose_port(sk), pid, tid, uid, family);
    __builtin_memcpy(e->peer, key.peer, sizeof(e->peer));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
