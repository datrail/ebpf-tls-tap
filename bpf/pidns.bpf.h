// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 DatRail
//
// PIDs as the probe's own PID namespace sees them, shared by listensnoop and
// filesnoop. The including program defines pidns_ino, the inode of that
// namespace, which userspace fills in before load.
#ifndef __PIDNS_BPF_H
#define __PIDNS_BPF_H

/* The kernel's MAX_PID_NS_LEVEL is 32, so levels run 0..32. */
#define MAX_PIDNS_LEVEL 33

/* p's number in the probe's PID namespace: 0 if p is not visible there. */
static __always_inline u32 nr_in_ns(struct pid *p, __u32 ns_ino)
{
    unsigned int level = BPF_CORE_READ(p, level);
    void *numbers = (void *)p + bpf_core_field_offset(struct pid, numbers);
    struct upid upid;

    for (int i = 0; i < MAX_PIDNS_LEVEL; i++) {
        if (i > level)
            break;
        if (bpf_probe_read_kernel(&upid, sizeof(upid),
                                  numbers + i * bpf_core_type_size(struct upid)))
            break;
        if (BPF_CORE_READ(upid.ns, ns.inum) == ns_ino)
            return upid.nr;
    }
    return 0;
}

static __always_inline void ns_pid_tid(__u32 ns_ino, u32 *pid, u32 *tid)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    *pid = nr_in_ns(BPF_CORE_READ(task, group_leader, thread_pid), ns_ino);
    *tid = nr_in_ns(BPF_CORE_READ(task, thread_pid), ns_ino);
}

#endif /* __PIDNS_BPF_H */
