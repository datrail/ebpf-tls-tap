// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DatRail
#ifndef __LISTENSNOOP_H
#define __LISTENSNOOP_H

#define LISTEN_COMM_LEN 16

/* How the socket started accepting traffic. */
#define LISTEN_KIND_LISTEN 1 /* a stream socket moved to LISTEN */
#define LISTEN_KIND_BIND 2   /* a datagram socket bound a local port */
#define LISTEN_KIND_AUTOBIND 3 /* an unbound datagram socket's first sendto() */

struct listen_event_t {
    __u64 timestamp_ns;
    __u32 pid;      /* in listensnoop's PID namespace; 0 if not visible there */
    __u32 tid;
    __u32 host_pid; /* in the initial PID namespace */
    __u32 uid;
    __u16 family;   /* AF_INET or AF_INET6 */
    __u16 protocol; /* IPPROTO_* of the socket */
    __u16 port;     /* host byte order */
    __u8 kind;      /* LISTEN_KIND_* */
    __u8 ephemeral; /* 1 if the kernel chose the port, not the caller */
    __u8 addr[16];  /* IPv4 in the first 4 bytes, else IPv6 */
    char comm[LISTEN_COMM_LEN];
};

#endif /* __LISTENSNOOP_H */
