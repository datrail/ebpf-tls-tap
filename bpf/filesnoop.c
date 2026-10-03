// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DatRail
//
// Print one JSON line the first time each process opens each regular file
// for each kind of access (read, write, exec), and a "lost" line for any
// event dropped.
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "filesnoop.h"
#include "filesnoop.skel.h"
#include "snoop_util.h"

#define POLL_TIMEOUT_MS 100
#define INVALID_UID -1
#define INVALID_PID -1

static volatile sig_atomic_t exiting = 0;

static struct env {
	pid_t pid;
	uid_t uid;
	bool verbose;
	bool own_namespace;
	long heartbeat; /* seconds; 0 is off */
} env = {
	.uid = INVALID_UID,
	.pid = INVALID_PID,
};

const char *argp_program_version = "filesnoop 0.1";
const char *argp_program_bug_address = "https://github.com/datrail/ebpf-tls-tap/issues";
const char argp_program_doc[] =
	"Report the regular files processes open, to read, write or run.\n"
	"\n"
	"USAGE: filesnoop [-h] [-p PID] [-u UID] [-n] [-H SECONDS] [-v]\n"
	"\n"
	"Prints one JSON object per line, \"kind\":\"open\", the first time a\n"
	"process opens a file for a given access: \"read\", \"write\" and\n"
	"\"exec\" say which. Opening it again the same way prints nothing; opening\n"
	"it another way prints again. \"path\" is the path as the process sees\n"
	"it; with \"layer\":true, overlayfs opened it in a layer beneath, and the\n"
	"path is the layer's. A \"kind\":\"lost\" line means events were dropped. Files already\n"
	"open when it starts are not reported.\n"
	"PIDs, and -p, are as filesnoop's own PID namespace sees them; a process\n"
	"it cannot see has pid 0 and only its host_pid, or is left out with -n.\n"
	"A \"kind\":\"start\" line marks each attach; with -H, a \"kind\":\"alive\"\n"
	"line follows about every SECONDS. Both carry the wall-clock time.\n"
	"\n"
	"EXAMPLES:\n"
	"    ./filesnoop             # every process\n"
	"    ./filesnoop -p 181      # only PID 181\n";

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Trace this PID only."},
	{"uid", 'u', "UID", 0, "Trace this UID only."},
	{"own-namespace", 'n', NULL, 0, "Leave out processes outside filesnoop's PID namespace."},
	{"heartbeat", 'H', "SECONDS", 0, "Print an alive line every SECONDS."},
	{"verbose", 'v', NULL, 0, "Verbose libbpf debug output."},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	char *end;
	long val;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'n':
		env.own_namespace = true;
		break;
	case 'H':
		errno = 0;
		val = strtol(arg, &end, 10);
		if (errno || *end || val < 1 || val > 86400) {
			fprintf(stderr, "invalid heartbeat: %s (1..86400 seconds)\n", arg);
			argp_usage(state);
		}
		env.heartbeat = val;
		break;
	case 'p':
	case 'u':
		errno = 0;
		val = strtol(arg, &end, 10);
		if (errno || *end || val < 0 || val > (long)INT32_MAX) {
			fprintf(stderr, "invalid %s: %s\n",
				key == 'p' ? "PID" : "UID", arg);
			argp_usage(state);
		}
		if (key == 'p')
			env.pid = val;
		else
			env.uid = val;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = {
	opts,
	parse_arg,
	NULL,
	argp_program_doc
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

/* Length of the valid UTF-8 sequence at s, or 0 if there is none. */
static size_t utf8_len(const unsigned char *s, size_t n)
{
	size_t len;
	unsigned int cp;

	if (s[0] < 0x80)
		return 1;
	if (s[0] >= 0xc2 && s[0] <= 0xdf)
		len = 2, cp = s[0] & 0x1f;
	else if (s[0] >= 0xe0 && s[0] <= 0xef)
		len = 3, cp = s[0] & 0x0f;
	else if (s[0] >= 0xf0 && s[0] <= 0xf4)
		len = 4, cp = s[0] & 0x07;
	else
		return 0;
	if (len > n)
		return 0;
	for (size_t i = 1; i < len; i++) {
		if ((s[i] & 0xc0) != 0x80)
			return 0;
		cp = cp << 6 | (s[i] & 0x3f);
	}
	/* Overlong forms, surrogates and past U+10FFFF are not UTF-8. */
	if ((len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000) ||
	    (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff)
		return 0;
	return len;
}

/* A path is any bytes but '\0'. Valid UTF-8 is printed as text; each byte
 * that isn't becomes U+FFFD, and the exact bytes follow as "path_hex", so
 * two paths that differ only there still read as two. Returns whether the
 * path was valid UTF-8. */
static bool print_json_path(const char *p, size_t n)
{
	const unsigned char *s = (const unsigned char *)p;
	bool valid = true;

	putchar('"');
	for (size_t i = 0; i < n;) {
		size_t len = utf8_len(s + i, n - i);

		if (!len) {
			fputs("\\ufffd", stdout);
			valid = false;
			i++;
		} else if (len > 1) {
			fwrite(s + i, 1, len, stdout);
			i += len;
		} else if (s[i] == '"' || s[i] == '\\') {
			printf("\\%c", s[i++]);
		} else if (s[i] < 0x20 || s[i] == 0x7f) {
			printf("\\u%04x", s[i++]);
		} else {
			putchar(s[i++]);
		}
	}
	putchar('"');
	return valid;
}

static void print_alive(const char *kind)
{
	char stamp[32];
	struct tm tm;
	time_t now = time(NULL);

	if (!gmtime_r(&now, &tm) ||
	    !strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm))
		return;
	printf("{\"kind\":\"%s\",\"time\":\"%s\",\"every\":%ld}\n",
	       kind, stamp, env.heartbeat);
	fflush(stdout);
}

static const char *json_bool(bool b)
{
	return b ? "true" : "false";
}

static int handle_event(void *ctx, void *data, size_t data_size)
{
	const struct file_event_t *e = data;
	size_t head = offsetof(struct file_event_t, path), n;

	if (data_size <= head)
		return 0;
	n = strnlen(e->path, data_size - head);

	printf("{\"timestamp_ns\":%llu,\"kind\":\"open\",\"pid\":%u,\"tid\":%u,"
	       "\"host_pid\":%u,\"uid\":%u,\"comm\":",
	       (unsigned long long)e->timestamp_ns,
	       e->pid, e->tid, e->host_pid, e->uid);
	print_json_string(e->comm, sizeof(e->comm));
	printf(",\"path\":");
	if (!print_json_path(e->path, n)) {
		printf(",\"path_hex\":\"");
		for (size_t i = 0; i < n; i++)
			printf("%02x", (unsigned char)e->path[i]);
		putchar('"');
	}
	if (e->path_err)
		printf(",\"path_error\":%d", e->path_err);
	/* Opened on a layer's internal mount: path is relative to the layer,
	 * dev and ino are the file actually read or written. */
	if (e->layer)
		printf(",\"layer\":true");
	/* creat/trunc/append are what the caller asked for: O_CREAT on a file
	 * that already exists opens it without creating anything. */
	printf(",\"read\":%s,\"write\":%s,\"exec\":%s,"
	       "\"creat\":%s,\"trunc\":%s,\"append\":%s,"
	       "\"dev\":\"%u:%u\",\"ino\":%llu}\n",
	       json_bool(e->access & FILE_ACCESS_READ),
	       json_bool(e->access & FILE_ACCESS_WRITE),
	       json_bool(e->access & FILE_ACCESS_EXEC),
	       json_bool(e->flags & O_CREAT),
	       json_bool(e->flags & O_TRUNC),
	       json_bool(e->flags & O_APPEND),
	       e->dev >> 20, e->dev & ((1U << 20) - 1),
	       (unsigned long long)e->ino);
	fflush(stdout);
	return 0;
}

static bool kernel_has_func(const struct btf *vmlinux, const char *name)
{
	return vmlinux && btf__find_by_name_kind(vmlinux, name, BTF_KIND_FUNC) >= 0;
}

int main(int argc, char **argv)
{
	struct filesnoop_bpf *obj = NULL;
	struct ring_buffer *rb = NULL;
	__u64 drops_reported = 0;
	struct timespec now, last_report = {}, last_alive = {};
	struct stat ns;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = filesnoop_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}
	obj->rodata->targ_uid = env.uid;
	obj->rodata->targ_pid = env.pid == INVALID_PID ? 0 : env.pid;
	if (stat("/proc/self/ns/pid", &ns)) {
		err = -errno;
		fprintf(stderr, "can't read own PID namespace: %s\n",
			strerror(errno));
		goto cleanup;
	}
	obj->rodata->pidns_ino = ns.st_ino;
	obj->rodata->own_ns_only = env.own_namespace;
	obj->rodata->self_pid = getpid();

	/* do_dentry_open is static, so a kernel may have inlined it. Without
	 * its exit, the overlay open in progress is only replaced by the
	 * task's next open, which skips at most the layer opens in between. */
	struct btf *vmlinux = btf__load_vmlinux_btf();

	bpf_program__set_autoload(obj->progs.dentry_open_exit,
				  kernel_has_func(vmlinux, "do_dentry_open"));
	btf__free(vmlinux);

	err = filesnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = filesnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(obj->maps.file_events),
			      handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "failed to open ring buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR ||
	    signal(SIGTERM, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* Stdout carries only events; readiness goes to stderr. */
	fprintf(stderr, "filesnoop: attached\n");
	print_alive("start");
	clock_gettime(CLOCK_MONOTONIC, &last_alive);

	while (!exiting) {
		err = ring_buffer__poll(rb, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling ring buffer: %s\n",
				strerror(-err));
			goto cleanup;
		}
		err = 0;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (env.heartbeat &&
		    (now.tv_sec - last_alive.tv_sec) * 1000 +
		    (now.tv_nsec - last_alive.tv_nsec) / 1000000 >= env.heartbeat * 1000) {
			print_alive("alive");
			last_alive = now;
		}
		if ((now.tv_sec - last_report.tv_sec) * 1000 +
		    (now.tv_nsec - last_report.tv_nsec) / 1000000 < POLL_TIMEOUT_MS)
			continue;
		last_report = now;
		err = report_drops(obj->obj, bpf_map__fd(obj->maps.dropped),
				   &drops_reported);
		if (err) {
			fprintf(stderr, "can't read drop counters: %s\n",
				strerror(-err));
			goto cleanup;
		}
	}
	ring_buffer__consume(rb);
	err = report_drops(obj->obj, bpf_map__fd(obj->maps.dropped),
			   &drops_reported);

cleanup:
	ring_buffer__free(rb);
	filesnoop_bpf__destroy(obj);
	return err != 0;
}
