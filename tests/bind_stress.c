// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DatRail
//
// Native-thread load for tests/listensnoop_test.py. Python's GIL cannot keep
// enough threads inside bind() at once to reproduce these, so they are in C.
//
//   bind_stress contend THREADS BINDS
//     THREADS threads spin on bind() of one already-bound UDP socket (each
//     call fails, but runs the kernel's inet_bind), while the main thread
//     binds BINDS fresh UDP sockets to port 0 and prints each port. A
//     kretprobe-based probe has max(10, 2 x CPUs) return slots and misses
//     most of these binds; every one must be reported. The main thread gets
//     the first CPU it may use to itself and the spinners the rest, so a
//     spinner preempted inside the probe never makes the kernel skip one of
//     its binds; the slots a kretprobe would exhaust are host-wide, so that
//     contention remains. The first line printed is "isolated 1", or
//     "isolated 0" when there was only one CPU to use or pinning failed.
//
//   bind_stress oversubscribe THREADS ITERS
//     THREADS threads, all pinned to CPUs 0 and 1, each doing ITERS rounds of
//     a UDP bind and a TCP listen on fresh sockets; prints how many
//     succeeded. Preempted programs make the trampoline skip others on the
//     same CPU (recursion_misses); each skipped call must count as lost.
//
//   bind_stress flood BINDS
//     Binds and closes BINDS fresh UDP sockets as fast as possible, to
//     overflow the event buffer while nobody reads it.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int busy;
static volatile int stop;

static void loopback(struct sockaddr_in *a)
{
	memset(a, 0, sizeof(*a));
	a->sin_family = AF_INET;
	a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static void *spin(void *arg)
{
	struct sockaddr_in a;

	loopback(&a);
	while (!stop)
		bind(busy, (struct sockaddr *)&a, sizeof(a));
	return NULL;
}

static int bind_one(int keep_open)
{
	struct sockaddr_in a;
	socklen_t len = sizeof(a);
	int s = socket(AF_INET, SOCK_DGRAM, 0);

	loopback(&a);
	if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof(a)) ||
	    getsockname(s, (struct sockaddr *)&a, &len)) {
		perror("bind_one");
		exit(1);
	}
	if (!keep_open)
		close(s);
	return ntohs(a.sin_port);
}

static long iters, succeeded;

static void *churn(void *arg)
{
	struct sockaddr_in a = { .sin_family = AF_INET };
	cpu_set_t cpus;
	long ok = 0;

	CPU_ZERO(&cpus);
	CPU_SET((long)arg % 2, &cpus);
	sched_setaffinity(0, sizeof(cpus), &cpus);
	for (long i = 0; i < iters; i++) {
		int u = socket(AF_INET, SOCK_DGRAM, 0);
		int t = socket(AF_INET, SOCK_STREAM, 0);

		if (!bind(u, (struct sockaddr *)&a, sizeof(a)))
			ok++;
		if (!listen(t, 1))
			ok++;
		close(u);
		close(t);
	}
	__atomic_add_fetch(&succeeded, ok, __ATOMIC_RELAXED);
	return NULL;
}

int main(int argc, char **argv)
{
	if (argc == 4 && !strcmp(argv[1], "oversubscribe")) {
		int threads = atoi(argv[2]);
		pthread_t *t = calloc(threads, sizeof(*t));

		iters = atol(argv[3]);
		for (long i = 0; i < threads; i++)
			pthread_create(&t[i], NULL, churn, (void *)i);
		for (int i = 0; i < threads; i++)
			pthread_join(t[i], NULL);
		printf("%ld\n", succeeded);
		return 0;
	}
	if (argc == 4 && !strcmp(argv[1], "contend")) {
		int threads = atoi(argv[2]), binds = atoi(argv[3]);
		pthread_t *t = calloc(threads, sizeof(*t));
		struct sockaddr_in a;

		loopback(&a);
		busy = socket(AF_INET, SOCK_DGRAM, 0);
		if (busy < 0 || bind(busy, (struct sockaddr *)&a, sizeof(a))) {
			perror("busy socket");
			return 1;
		}
		cpu_set_t allowed, rest, first;
		int isolated = 0, main_cpu = -1;

		CPU_ZERO(&rest);
		CPU_ZERO(&first);
		if (!sched_getaffinity(0, sizeof(allowed), &allowed) &&
		    CPU_COUNT(&allowed) > 1) {
			for (int c = 0; c < CPU_SETSIZE; c++) {
				if (!CPU_ISSET(c, &allowed))
					continue;
				if (main_cpu < 0)
					main_cpu = c;
				else
					CPU_SET(c, &rest);
			}
			CPU_SET(main_cpu, &first);
			isolated = 1;
		}
		for (int i = 0; i < threads; i++) {
			pthread_create(&t[i], NULL, spin, NULL);
			if (isolated &&
			    pthread_setaffinity_np(t[i], sizeof(rest), &rest))
				isolated = 0;
		}
		if (isolated && sched_setaffinity(0, sizeof(first), &first))
			isolated = 0;
		printf("isolated %d\n", isolated);
		usleep(300000);
		/* Kept open so no port repeats within the run. */
		for (int i = 0; i < binds; i++) {
			printf("%d\n", bind_one(1));
			usleep(1000);
		}
		stop = 1;
		for (int i = 0; i < threads; i++)
			pthread_join(t[i], NULL);
		return 0;
	}
	if (argc == 3 && !strcmp(argv[1], "flood")) {
		for (int i = 0, n = atoi(argv[2]); i < n; i++)
			bind_one(0);
		return 0;
	}
	fprintf(stderr, "usage: %s contend THREADS BINDS | "
		"oversubscribe THREADS ITERS | flood BINDS\n", argv[0]);
	return 2;
}
