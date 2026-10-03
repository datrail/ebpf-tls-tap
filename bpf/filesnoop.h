// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DatRail
#ifndef __FILESNOOP_H
#define __FILESNOOP_H

#define FILE_COMM_LEN 16
#define FILE_PATH_LEN 4096 /* PATH_MAX, terminating NUL included */

/* How the file was opened: bits of file_event_t.access. */
#define FILE_ACCESS_READ 1
#define FILE_ACCESS_WRITE 2
#define FILE_ACCESS_EXEC 4 /* opened by execve() to run it */

struct file_event_t {
    __u64 timestamp_ns;
    __u64 ino;
    __u32 dev;      /* the kernel's dev_t: major << 20 | minor */
    __u32 pid;      /* in filesnoop's PID namespace; 0 if not visible there */
    __u32 tid;
    __u32 host_pid; /* in the initial PID namespace */
    __u32 uid;
    __u32 flags;    /* open(2) flags as the caller passed them */
    __u8 access;    /* FILE_ACCESS_* */
    __u8 layer;     /* 1: opened on an overlay layer's internal mount */
    __s16 path_err; /* bpf_d_path's error, 0 if path holds the path */
    char comm[FILE_COMM_LEN];
    /* Only the used part, NUL included, is sent: the event's size says
     * how long it is. */
    char path[FILE_PATH_LEN];
};

#endif /* __FILESNOOP_H */
