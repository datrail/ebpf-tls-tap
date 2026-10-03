// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 DatRail
//
// Report the regular files a process opens, and whether to read, write or
// run them. An agent that reads ~/.ssh/id_rsa or rewrites a file outside its
// workspace does it with open(); its tool calls only say what it asked for,
// and the TLS uprobes in sslsniff.bpf.c see neither.
//
// - security_file_open(file) runs for every open that reaches a file, from
//   open(), openat(), openat2(), io_uring, execve() and the kernel's own
//   opens on a process's behalf, after the path is resolved and before any
//   data moves. fexit reports only the opens the LSMs allowed. O_PATH opens
//   never get here: they can't read or write.
// - One event per (process, file, access): a process that reads a file a
//   thousand times costs one event, and one that later opens it to write is
//   reported again. Like listensnoop's peers, the set is an LRU, so it can't
//   fill; an evicted file is only reported again on its next open.
// - overlayfs (every container's root) opens files in its layers on the
//   opener's behalf: the file beneath the one the process asked for, and the
//   lower file when a write copies it up. Those opens go through
//   security_file_open too, on a private mount of the layer that belongs to
//   no mount namespace (MNT_NS_INTERNAL). For an overlay mounted from the
//   initial user namespace, which is how a container runtime mounts a
//   container's root, they are skipped while the process's own open of the
//   overlay file is in progress: they are that open, under a path the
//   process never named. Any other open on an internal mount is reported,
//   marked "layer". An unprivileged process can mount its own overlay in a
//   user namespace, over any directory it can read, and choose the path it
//   reads through; the layer event names the file actually read.
// - Only regular files: devices, FIFOs and directories carry no file content
//   to read or write.
//
// The path is the one the process would see (bpf_d_path resolves it against
// the opener's root, so a container's /etc is its own). An unlinked file's
// path ends in " (deleted)", as in /proc/<pid>/fd.
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "filesnoop.h"
#include "pidns.bpf.h"

#define S_IFMT 00170000
#define S_IFREG 0100000
#define PF_KTHREAD 0x00200000
#define FMODE_READ 0x1
#define FMODE_WRITE 0x2
/* execve()'s open says so in the open flags, __FMODE_EXEC: 040000000 until
 * Linux 6.x, now the same bit as FMODE_EXEC, which older kernels also set
 * in f_mode before this hook. Values are the asm-generic ones (x86, arm64);
 * any of the three marks an exec. */
#define FMODE_EXEC 0x20
#define FMODE_EXEC_FLAG_OLD 040000000
#define EEXIST 17
#define EINVAL 22
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define PROC_USER_INIT_INO 0xEFFFFFFDU /* the initial user namespace */

/* A ring buffer, for the reason listensnoop's is: a loss is always counted,
 * in dropped, even when nothing follows it. Events are variable-length, so
 * a burst of short paths fits far more than 4 MB / sizeof(event). */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 << 20);
} file_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped SEC(".maps");

/* Where an event is built before only its used part is copied out. Per CPU
 * is enough: a program that would preempt itself on the same CPU is skipped
 * by the kernel, and counted in recursion_misses. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_event_t);
} scratch SEC(".maps");

/* The overlay file the current task is opening, while it is being opened,
 * if a container runtime (the initial user namespace) mounted the overlay;
 * else 0. Set by every open on a mount in a namespace, so a value left by an
 * open whose do_dentry_open exit was skipped lasts only until the task's
 * next open. Task storage lives and dies with the task. */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u64);
} overlay_open SEC(".maps");

/* Files already reported. The process is its host PID plus its start time
 * and exec count, as in listensnoop's peers_seen, so a reused PID or an
 * exec() into another program is a new process. The file is its mount and
 * dentry (the path it was opened by) plus its inode number, so a dentry
 * freed and reused for another file reads as new. */
struct open_key {
    __u64 start_time;
    __u64 exec_id;
    __u64 mnt;
    __u64 dentry;
    __u64 ino;
    __u32 tgid;
    __u32 access;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct open_key);
    __type(value, __u8);
} opens_seen SEC(".maps");

const volatile pid_t targ_pid = 0;
const volatile uid_t targ_uid = -1;
/* The inode of filesnoop's own PID namespace; see pidns.bpf.h. */
const volatile __u32 pidns_ino = 0;
/* --own-namespace: drop processes filesnoop's namespace cannot see. */
const volatile bool own_ns_only = false;
/* filesnoop's own PID in its namespace: its own opens are not news. */
const volatile pid_t self_pid = 0;

static __always_inline void count_drop(void)
{
    u32 zero = 0;
    u64 *drops = bpf_map_lookup_elem(&dropped, &zero);

    if (drops)
        __sync_fetch_and_add(drops, 1);
}

/* A mount that belongs to no namespace: a layer of an overlay, or a
 * kernel-internal mount. */
static __always_inline bool internal_mount(struct vfsmount *vfs)
{
    struct mount *m = (void *)vfs - bpf_core_field_offset(struct mount, mnt);

    return (long)BPF_CORE_READ(m, mnt_ns) == -EINVAL; /* MNT_NS_INTERNAL */
}

static __always_inline bool runtime_overlay(struct super_block *sb)
{
    return BPF_CORE_READ(sb, s_magic) == OVERLAYFS_SUPER_MAGIC &&
           BPF_CORE_READ(sb, s_user_ns, ns.inum) == PROC_USER_INIT_INO;
}

/* Whether an open on an internal mount is overlayfs working for the
 * task's open of a runtime overlay's file; on any other mount, note
 * whether this open is one. */
static __always_inline bool layer_open_to_skip(struct file *file, bool internal)
{
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 *outer;

    if (internal) {
        outer = bpf_task_storage_get(&overlay_open, task, 0, 0);
        return outer && *outer;
    }
    if (runtime_overlay(BPF_CORE_READ(file, f_path.dentry, d_sb))) {
        outer = bpf_task_storage_get(&overlay_open, task, 0,
                                     BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (outer)
            *outer = (__u64)file;
        /* Out of memory: its layer opens are reported, marked as such. */
    } else {
        outer = bpf_task_storage_get(&overlay_open, task, 0, 0);
        if (outer)
            *outer = 0;
    }
    return false;
}

/* The overlay file's open is over: anything else on an internal mount is
 * not part of it. */
SEC("fexit/do_dentry_open")
int BPF_PROG(dentry_open_exit, struct file *file)
{
    struct task_struct *task = bpf_get_current_task_btf();
    __u64 *outer = bpf_task_storage_get(&overlay_open, task, 0, 0);

    if (outer && *outer == (__u64)file)
        *outer = 0;
    return 0;
}

SEC("fexit/security_file_open")
int BPF_PROG(file_open_exit, struct file *file)
{
    struct file_event_t *e;
    struct open_key key = {};
    struct task_struct *task, *leader;
    struct inode *inode;
    bool layer;
    u32 zero = 0, pid, tid, uid, mode, flags;
    u16 access = 0;
    u8 seen = 1;
    long len;
    u64 ret;

    if (bpf_get_func_ret(ctx, &ret) || (int)ret)
        return 0;
    if ((BPF_CORE_READ(file, f_path.dentry, d_inode, i_mode) & S_IFMT) != S_IFREG)
        return 0;
    task = (struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(task, flags) & PF_KTHREAD)
        return 0;
    layer = internal_mount(BPF_CORE_READ(file, f_path.mnt));
    if (layer_open_to_skip(file, layer))
        return 0;
    uid = bpf_get_current_uid_gid();
    ns_pid_tid(pidns_ino, &pid, &tid);
    if (own_ns_only && !pid)
        return 0;
    if (self_pid && pid == self_pid)
        return 0;
    if (targ_pid && targ_pid != pid)
        return 0;
    if (targ_uid != (uid_t)-1 && targ_uid != uid)
        return 0;

    mode = BPF_CORE_READ(file, f_mode);
    flags = BPF_CORE_READ(file, f_flags);
    if (mode & FMODE_READ)
        access |= FILE_ACCESS_READ;
    if (mode & FMODE_WRITE)
        access |= FILE_ACCESS_WRITE;
    if ((mode & FMODE_EXEC) || (flags & (FMODE_EXEC | FMODE_EXEC_FLAG_OLD)))
        access |= FILE_ACCESS_EXEC;

    leader = BPF_CORE_READ(task, group_leader);
    key.start_time = BPF_CORE_READ(leader, start_time);
    key.exec_id = BPF_CORE_READ(leader, self_exec_id);
    key.tgid = bpf_get_current_pid_tgid() >> 32;
    key.mnt = (u64)BPF_CORE_READ(file, f_path.mnt);
    key.dentry = (u64)BPF_CORE_READ(file, f_path.dentry);
    /* The inode the path names, not f_inode: before 6.8, overlayfs's open
     * of the file beneath carries the overlay path with the layer's inode,
     * and must read as the open already reported. */
    inode = BPF_CORE_READ(file, f_path.dentry, d_inode);
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.access = access;
    /* NOEXIST makes the check and the insert one step, as for listensnoop's
     * peers: of two threads opening the same new file at once, exactly one
     * reports it. Any other failure reports anyway. */
    if (bpf_map_update_elem(&opens_seen, &key, &seen, BPF_NOEXIST) == -EEXIST)
        return 0;

    e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        goto lost;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->ino = key.ino;
    e->dev = BPF_CORE_READ(inode, i_sb, s_dev);
    e->pid = pid;
    e->tid = tid;
    e->host_pid = key.tgid;
    e->uid = uid;
    e->flags = flags;
    e->access = access;
    e->layer = layer;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    len = bpf_d_path(&file->f_path, e->path, sizeof(e->path));
    if (len < 1 || len > FILE_PATH_LEN) {
        e->path_err = len < 0 ? len : -1;
        e->path[0] = 0;
        len = 1;
    } else {
        e->path_err = 0;
    }
    if (bpf_ringbuf_output(&file_events, e,
                           offsetof(struct file_event_t, path) + len, 0))
        goto lost;
    return 0;

lost:
    /* Forget it, so the next open of this file is reported. */
    bpf_map_delete_elem(&opens_seen, &key);
    count_drop();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
