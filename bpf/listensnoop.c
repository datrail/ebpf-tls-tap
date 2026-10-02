// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DatRail
//
// Print one JSON line for every socket that starts accepting inbound traffic
// (a TCP socket entering LISTEN, a datagram socket binding a port, or one
// bound by its first sendto()), and a "lost" line for any event dropped.
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>

#include "listensnoop.h"
#include "listensnoop.skel.h"

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

const char *argp_program_version = "listensnoop 0.1";
const char *argp_program_bug_address = "https://github.com/datrail/ebpf-tls-tap/issues";
const char argp_program_doc[] =
	"Report sockets that start accepting inbound traffic.\n"
	"\n"
	"USAGE: listensnoop [-h] [-p PID] [-u UID] [-n] [-H SECONDS] [-v]\n"
	"\n"
	"Prints one JSON object per line: a TCP socket entering LISTEN\n"
	"(\"kind\":\"listen\"), a UDP or ICMP-echo socket binding a port\n"
	"(\"kind\":\"bind\"), or an unbound one's first sendto()\n"
	"(\"kind\":\"autobind\"). A \"kind\":\"lost\" line means events were\n"
	"dropped. Sockets already listening when it starts are not reported.\n"
	"PIDs, and -p, are as listensnoop's own PID namespace sees them; a\n"
	"process it cannot see has pid 0 and only its host_pid, or is left out\n"
	"with -n. A \"kind\":\"start\" line marks each attach; with -H, a\n"
	"\"kind\":\"alive\" line follows about every SECONDS. Both carry the\n"
	"wall-clock time, so a consumer can tell a quiet probe from a stopped or\n"
	"restarted one.\n"
	"\n"
	"EXAMPLES:\n"
	"    ./listensnoop           # every new listening socket\n"
	"    ./listensnoop -p 181    # only PID 181\n";

static const struct argp_option opts[] = {
	{"pid", 'p', "PID", 0, "Trace this PID only."},
	{"uid", 'u', "UID", 0, "Trace this UID only."},
	{"own-namespace", 'n', NULL, 0, "Leave out processes outside listensnoop's PID namespace."},
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

/* comm is attacker-chosen (prctl PR_SET_NAME), so escape it fully. */
static void print_json_string(const char *s, size_t max)
{
	putchar('"');
	for (size_t i = 0; i < max && s[i]; i++) {
		unsigned char c = s[i];

		if (c == '"' || c == '\\')
			printf("\\%c", c);
		else if (c < 0x20 || c >= 0x7f)
			printf("\\u%04x", c);
		else
			putchar(c);
	}
	putchar('"');
}

static const char *protocol_name(__u16 protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_UDPLITE:
		return "udplite";
	case IPPROTO_ICMP:
		return "icmp";
	case IPPROTO_ICMPV6:
		return "icmpv6";
	case 262: /* IPPROTO_MPTCP, missing from older libc headers */
		return "mptcp";
	default:
		return NULL;
	}
}

static const char *kind_name(__u8 kind)
{
	switch (kind) {
	case LISTEN_KIND_BIND:
		return "bind";
	case LISTEN_KIND_AUTOBIND:
		return "autobind";
	case LISTEN_KIND_LISTEN:
		return "listen";
	default:
		return "unknown";
	}
}

/* Wall-clock, not the events' boot-relative timestamp_ns: the consumer
 * compares it with its own clock to see whether the probe is still running.
 * `kind` is "start" once, at attach, and "alive" for each heartbeat. A
 * consumer that sees two starts knows the probe was down in between: it
 * does not report sockets already listening when it attaches, so whatever
 * opened in that gap is missing. */
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

static int handle_event(void *ctx, void *data, size_t data_size)
{
	const struct listen_event_t *e = data;
	char addr[INET6_ADDRSTRLEN];
	const char *proto;
	int af = e->family == AF_INET6 ? AF_INET6 : AF_INET;

	if (data_size < sizeof(*e))
		return 0;
	if (!inet_ntop(af, e->addr, addr, sizeof(addr)))
		return 0;

	printf("{\"timestamp_ns\":%llu,\"kind\":\"%s\",\"pid\":%u,\"tid\":%u,"
	       "\"host_pid\":%u,\"uid\":%u,\"comm\":",
	       (unsigned long long)e->timestamp_ns,
	       kind_name(e->kind),
	       e->pid, e->tid, e->host_pid, e->uid);
	print_json_string(e->comm, sizeof(e->comm));
	proto = protocol_name(e->protocol);
	if (proto)
		printf(",\"protocol\":\"%s\"", proto);
	else
		printf(",\"protocol\":\"%u\"", e->protocol);
	printf(",\"family\":\"%s\",\"addr\":\"%s\",\"port\":%u,\"ephemeral\":%s}\n",
	       af == AF_INET6 ? "ipv6" : "ipv4", addr, e->port,
	       e->ephemeral ? "true" : "false");
	fflush(stdout);
	return 0;
}

/* Report events missed since the last check: those the ring buffer had no
 * room for, and calls a program skipped because it was already running on
 * that CPU (the kernel's recursion_misses; a preempted program blocks its
 * own next run there, and an unprivileged process can arrange that). On
 * stdout, not just stderr: a consumer must know it has a gap, or an agent
 * could hide the one listen() that matters. */
static int report_drops(struct listensnoop_bpf *obj, __u64 *reported)
{
	int ncpus = libbpf_num_possible_cpus();
	struct bpf_program *prog;
	__u32 zero = 0;
	__u64 total = 0;

	if (ncpus <= 0)
		return ncpus;
	__u64 counts[ncpus];
	if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.dropped), &zero, counts))
		return -errno;
	for (int i = 0; i < ncpus; i++)
		total += counts[i];
	bpf_object__for_each_program(prog, obj->obj) {
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info);
		int fd = bpf_program__fd(prog);

		if (fd < 0)
			continue; /* not loaded, e.g. inet6_bind without IPv6 */
		if (bpf_prog_get_info_by_fd(fd, &info, &len))
			return -errno;
		total += info.recursion_misses;
	}
	if (total > *reported) {
		printf("{\"kind\":\"lost\",\"count\":%llu}\n",
		       (unsigned long long)(total - *reported));
		fflush(stdout);
		fprintf(stderr, "lost %llu events\n",
			(unsigned long long)(total - *reported));
		*reported = total;
	}
	return 0;
}

/* What an fexit program needs: the function in the kernel's BTF. */
static bool vmlinux_has_func(const struct btf *vmlinux, const char *name)
{
	return vmlinux && btf__find_by_name_kind(vmlinux, name, BTF_KIND_FUNC) >= 0;
}

/* inet6_bind lives in the ipv6 module when IPv6 is not built in. */
static bool kernel_has_symbol(const char *name)
{
	char line[256], sym[128];
	bool found = false;
	FILE *f = fopen("/proc/kallsyms", "r");

	if (!f)
		return true; /* let the load decide */
	while (!found && fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%*s %*s %127s", sym) == 1 && !strcmp(sym, name))
			found = true;
	}
	fclose(f);
	return found;
}

int main(int argc, char **argv)
{
	struct listensnoop_bpf *obj = NULL;
	struct ring_buffer *rb = NULL;
	__u64 drops_reported = 0;
	struct timespec now, last_report = {}, last_alive = {};
	struct stat ns;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = listensnoop_bpf__open();
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
	/* One bind hook per family, never both: inet_bind calls inet_bind_sk,
	 * so attaching both would report every bind twice. From 6.6, MPTCP's
	 * binds reach only the _sk form; before, there is no _sk form and they
	 * go through inet_bind like the rest. */
	struct btf *vmlinux = btf__load_vmlinux_btf();
	bool v4_sk = vmlinux_has_func(vmlinux, "inet_bind_sk");
	/* An ipv6 module's functions are in its own BTF, which libbpf attaches
	 * to when the module is loaded; kallsyms says whether it is. */
	bool v6_sk = vmlinux_has_func(vmlinux, "inet6_bind_sk") ||
		     kernel_has_symbol("inet6_bind_sk");
	bool v6 = v6_sk || vmlinux_has_func(vmlinux, "inet6_bind") ||
		  kernel_has_symbol("inet6_bind"); /* or the ipv6 module's BTF */

	btf__free(vmlinux);

	bpf_program__set_autoload(obj->progs.inet_bind_sk_exit, v4_sk);
	bpf_program__set_autoload(obj->progs.inet_bind_exit, !v4_sk);
	bpf_program__set_autoload(obj->progs.inet6_bind_sk_exit, v6_sk);
	bpf_program__set_autoload(obj->progs.inet6_bind_exit, v6 && !v6_sk);
	if (!v6)
		fprintf(stderr, "warning: inet6_bind not found (IPv6 not loaded); "
			"IPv6 UDP binds will not be reported\n");

	err = listensnoop_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = listensnoop_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(obj->maps.listen_events),
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
	fprintf(stderr, "listensnoop: attached\n");
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
		/* Poll returns as soon as anything is queued, so under load this
		 * loop spins; one "lost" line per interval is enough. */
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
		err = report_drops(obj, &drops_reported);
		if (err) {
			fprintf(stderr, "can't read drop counters: %s\n",
				strerror(-err));
			goto cleanup;
		}
	}
	/* Print what was queued before the signal, and any last gap. */
	ring_buffer__consume(rb);
	err = report_drops(obj, &drops_reported);

cleanup:
	ring_buffer__free(rb);
	listensnoop_bpf__destroy(obj);
	return err != 0;
}
