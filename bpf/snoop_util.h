// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DatRail
//
// Output helpers shared by listensnoop and filesnoop.
#ifndef __SNOOP_UTIL_H
#define __SNOOP_UTIL_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>

/* comm is attacker-chosen (prctl PR_SET_NAME), so escape it fully. */
static inline void print_json_string(const char *s, size_t max)
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

/* Report events missed since the last check: those the ring buffer had no
 * room for (counted per CPU in the map behind dropped_fd), and calls a
 * program skipped because it was already running on that CPU (the kernel's
 * recursion_misses; a preempted program blocks its own next run there, and
 * an unprivileged process can arrange that). On stdout, not just stderr: a
 * consumer must know it has a gap, or an agent could hide the one event
 * that matters. */
static inline int report_drops(struct bpf_object *obj, int dropped_fd,
			       __u64 *reported)
{
	int ncpus = libbpf_num_possible_cpus();
	struct bpf_program *prog;
	__u32 zero = 0;
	__u64 total = 0;

	if (ncpus <= 0)
		return ncpus;
	__u64 counts[ncpus];
	if (bpf_map_lookup_elem(dropped_fd, &zero, counts))
		return -errno;
	for (int i = 0; i < ncpus; i++)
		total += counts[i];
	bpf_object__for_each_program(prog, obj) {
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info);
		int fd = bpf_program__fd(prog);

		if (fd < 0)
			continue; /* not loaded on this kernel */
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

#endif /* __SNOOP_UTIL_H */
