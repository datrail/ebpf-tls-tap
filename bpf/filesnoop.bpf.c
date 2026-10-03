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
// - overlayfs opens files in its layers on the opener's behalf: the file
//   beneath the one the process asked for, the lower file when a write,
//   chmod, truncate or similar copies it up, and the upper one again when a
//   read follows a copy-up. Those opens go through security_file_open too.
//   They run with the credentials of whoever mounted the overlay, and the
//   file keeps them (f_cred). A container runtime mounts a container's root
//   from the initial user namespace: those layer opens are skipped, since
//   they only repeat (or make up, for a chmod) an open under a path the
//   process never named. Any other layer open is reported, marked "layer":
//   an unprivileged process can mount its own overlay in a user namespace,
//   over any directory it can read, and choose the path it reads through;
//   the layer event names the file actually read. A layer open is one whose
//   path is on a layer's private mount, which belongs to no mount namespace
//   (6.8 and later), or one whose file's inode is not its path's (before
//   6.8, the file beneath carries the overlay's path).
// - Only regular files: devices, FIFOs and directories carry no file content
//   to read or write, and neither do pidfds and namespace files, which are
//   regular files on kernel-internal filesystems.
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
#define SB_KERNMOUNT (1 << 22)
#define NSFS_MAGIC 0x6e736673
#define PID_FS_MAGIC 0x50494446
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

/* An overlay layer's private mount: no mount namespace (MNT_NS_INTERNAL),
 * and not a kern_mount() like shmem's, whose files (a memfd reopened through
 * /proc) a process opens itself. */
static __always_inline bool layer_mount(struct vfsmount *vfs, struct super_block *sb)
{
    struct mount *m = (void *)vfs - bpf_core_field_offset(struct mount, mnt);

    return (long)BPF_CORE_READ(m, mnt_ns) == -EINVAL &&
           !(BPF_CORE_READ(sb, s_flags) & SB_KERNMOUNT);
}

SEC("fexit/security_file_open")
int BPF_PROG(file_open_exit, struct file *file)
{
    struct file_event_t *e;
    struct open_key key = {};
    struct task_struct *task, *leader;
    struct inode *inode;
    struct super_block *sb;
    unsigned long magic;
    bool layer;
    u32 zero = 0, pid, tid, uid, mode, flags;
    u16 access = 0;
    u8 seen = 1;
    long len;
    u64 ret;

    if (bpf_get_func_ret(ctx, &ret) || (int)ret)
        return 0;
    inode = BPF_CORE_READ(file, f_inode);
    if ((BPF_CORE_READ(inode, i_mode) & S_IFMT) != S_IFREG)
        return 0;
    sb = BPF_CORE_READ(inode, i_sb);
    magic = BPF_CORE_READ(sb, s_magic);
    if (magic == NSFS_MAGIC || magic == PID_FS_MAGIC)
        return 0;
    task = (struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(task, flags) & PF_KTHREAD)
        return 0;
    layer = layer_mount(BPF_CORE_READ(file, f_path.mnt), sb) ||
            inode != BPF_CORE_READ(file, f_path.dentry, d_inode);
    if (layer && BPF_CORE_READ(file, f_cred, user_ns, ns.inum) == PROC_USER_INIT_INO)
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
    key.ino = BPF_CORE_READ(inode, i_ino);
    /* Before 6.8 a layer open has the overlay's mount and dentry, and
     * overlayfs gives its inode the real one's number: only this keeps it
     * from reading as the process's own open, already reported. */
    key.access = access | (layer << 8);
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
    e->dev = BPF_CORE_READ(sb, s_dev);
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
