/*
 * Copyright (C) 2012 Luigi Rizzo. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * $Id: pkt-gen.c 10189 2012-01-12 10:56:43Z luigi $
 *
 * Test program to study various concurrency issues.
 * Create multiple threads, possibly bind to cpus, and run a workload.
 */

#include <errno.h>
#include <pthread.h>	/* pthread_* */
#include <pthread_np.h>	/* pthread w/ affinity */
#include <signal.h>	/* signal */
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>	/* PRI* macros */
#include <string.h>	/* strcmp */
#include <fcntl.h>	/* open */
#include <unistd.h>	/* close */

#include <sys/types.h>
#include <machine/atomic.h>

#include <sys/poll.h>
#include <sys/param.h>
#include <sys/cpuset.h>	/* cpu_set */
#include <sys/sysctl.h>	/* sysctl */
#include <sys/time.h>	/* timersub */

static inline int min(int a, int b) { return a < b ? a : b; }

/* debug support */
#define D(format, ...)				\
	fprintf(stderr, "%s [%d] " format "\n", 	\
	__FUNCTION__, __LINE__, ##__VA_ARGS__)

int verbose = 0;

#if 1
/* Wrapper around `rdtsc' to take reliable timestamps flushing the pipeline */ 
#define my_rdtsc(t) \
	do { \
		u_int __regs[4];					\
									\
		do_cpuid(0, __regs);					\
		(t) = rdtsc();						\
	} while (0)

static __inline void
do_cpuid(u_int ax, u_int *p)
{
	__asm __volatile("cpuid"
			 : "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3])
			 :  "0" (ax));
}

static __inline uint64_t
rdtsc(void)
{
	uint64_t rv;

	__asm __volatile("rdtsc" : "=A" (rv));
	return (rv);
}
#endif /* 1 */

#if 0

struct multi_ring {
	uint32_t	prod_idx;
	uint32_t	cons_idx;
	uint32_t	release_idx_1;
	uint32_t	release_idx_2;
	uint32_t	ring_size;

	/* other stuff */
};

/*
 * get_prod_idx()
 *	return the index of a free slot for the producer, can block
 * get_cons_idx()
 *	return the index of a full slot for the consumer, can block
 * release_data()
 *	releases an object, non blocking
 */
uint32_t
get_prod_idx(struct multi_ring *r, int blocking)
{
}

uint32_t
get_cons_idx(struct multi_ring *r)
{
}

void
release_obj(struct multi_ring *r)
{
}
#endif /* acquire/release */

/*
 * global arguments for all threads
 */
struct glob_arg {
	int m_cycles;	/* million cycles */
	int nthreads;
	int cpus;
	struct {
		uint64_t	ctr __attribute__ ((__aligned__(64) ));
	} v[10];
};

/*
 * Arguments for a new thread. The same structure is used by
 * the source and the sink
 */
struct targ {
	struct glob_arg *g;
	int used;
	int completed;
	uint64_t count;
	struct timeval tic, toc;
	int me;
	pthread_t thread;
	int affinity;
};


static struct targ *targs;
static int global_nthreads;

/* control-C handler */
static void
sigint_h(__unused int sig)
{
	for (int i = 0; i < global_nthreads; i++) {
		/* cancel active threads. */
		if (targs[i].used == 0)
			continue;

		D("Cancelling thread #%d\n", i);
		pthread_cancel(targs[i].thread);
		targs[i].used = 0;
	}

	signal(SIGINT, SIG_DFL);
}


/* sysctl wrapper to return the number of active CPUs */
static int
system_ncpus(void)
{
	int mib[2], ncpus;
	size_t len;

	mib[0] = CTL_HW;
	mib[1] = HW_NCPU;
	len = sizeof(mib);
	sysctl(mib, 2, &ncpus, &len, NULL, 0);

	return (ncpus);
}

/* set the thread affinity. */
static int
setaffinity(pthread_t me, int i)
{
	cpuset_t cpumask;

	if (i == -1)
		return 0;

	/* Set thread affinity affinity.*/
	CPU_ZERO(&cpumask);
	CPU_SET(i, &cpumask);

	if (pthread_setaffinity_np(me, sizeof(cpuset_t), &cpumask) != 0) {
		D("Unable to set affinity");
		return 1;
	}
	return 0;
}

static void *
td_body(void *data)
{
	struct targ *targ = (struct targ *) data;
	int m, i;

	if (setaffinity(targ->thread, targ->affinity))
		goto quit;
	/* main loop.*/
	gettimeofday(&targ->tic, NULL);
	for (m = 0; m < targ->g->m_cycles; m++) {
		// struct timeval t = { 0, 1000};
		// select(0, NULL, NULL, NULL, &t);// usleep(1500);
		for (i = 0; i < 1000000; i++) {
			atomic_add_64(&(targ->g->v[targ->me].ctr), 1);
			targ->count ++;
		}
	}
	gettimeofday(&targ->toc, NULL);
	targ->completed = 1;
	//targ->count = 0;
quit:
	/* reset the ``used`` flag. */
	targ->used = 0;

	return (NULL);
}


static void
usage(void)
{
	const char *cmd = "pkt-gen";
	fprintf(stderr,
		"Usage:\n"
		"%s arguments\n"
		"\t-t threads		total threads\n"
		"\t-c cores		cores to use\n"
		"\t-a 			force affinity\n"
		"\t-n cycles		(millions) of cycles\n"
		"\t-w report_ms		milliseconds between reports\n"
		"",
		cmd);

	exit(0);
}


int
main(int arc, char **argv)
{
	int i;

	struct glob_arg g;

	int ch;
	int report_interval = 1000;	/* report interval */
	int affinity = 0;

	bzero(&g, sizeof(g));

	g.nthreads = 1;
	g.cpus = 1;
	g.m_cycles = 10;

	while ( (ch = getopt(arc, argv,
			"a:n:w:c:t:v")) != -1) {
		switch(ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;
		case 'a':	/* force affinity */
			affinity = atoi(optarg);
			break;
		case 'n':	/* cycles */
			g.m_cycles = atoi(optarg);
			break;
		case 'w':	/* report interval */
			report_interval = atoi(optarg);
			break;
		case 'c':
			g.cpus = atoi(optarg);
			break;
		case 't':
			g.nthreads = atoi(optarg);
			break;

		case 'v':
			verbose++;
			break;
		}
	}

	{
		int n = system_ncpus();
		if (g.cpus < 0 || g.cpus > n) {
			D("%d cpus is too high, have only %d cpus", g.cpus, n);
			usage();
		}
		if (g.cpus == 0)
			g.cpus = n;
	}

	/* validate provided nthreads. */
	if (g.nthreads < 1) {
		D("bad nthreads %d", g.nthreads);
		// continue, fail later
	}

	/* Install ^C handler. */
	global_nthreads = g.nthreads;
	signal(SIGINT, sigint_h);

	targs = calloc(g.nthreads, sizeof(*targs));
	/*
	 * Now create the desired number of threads, each one
	 * using a single descriptor.
 	 */
	D("start %d threads on %d cores", g.nthreads, g.cpus);
	for (i = 0; i < g.nthreads; i++) {

		/* start threads. */
		bzero(&targs[i], sizeof(targs[i]));
		targs[i].g = &g;
		targs[i].used = 1;
		targs[i].completed = 0;
		targs[i].me = i;
		targs[i].affinity = affinity ? (affinity*i) % g.cpus : -1;
		if (pthread_create(&targs[i].thread, NULL, td_body,
				   &targs[i]) == -1) {
			D("Unable to create thread %d", i);
			targs[i].used = 0;
		}
	}

    {
	uint64_t my_count = 0, prev = 0;
	uint64_t count = 0;
	double delta_t;
	struct timeval tic, toc;

	gettimeofday(&toc, NULL);
	for (;;) {
		struct timeval now, delta;
		uint64_t pps;
		int done = 0;

		delta.tv_sec = report_interval/1000;
		delta.tv_usec = (report_interval%1000)*1000;
		select(0, NULL, NULL, NULL, &delta);
		gettimeofday(&now, NULL);
		timersub(&now, &toc, &toc);
		my_count = 0;
		for (i = 0; i < g.nthreads; i++) {
			my_count += targs[i].count;
			if (targs[i].used == 0)
				done++;
		}
		pps = toc.tv_sec* 1000000 + toc.tv_usec;
		if (pps < 10000)
			continue;
		pps = (my_count - prev)*1000000 / pps;
		D("%" PRIu64 " mctr", pps/1000000);
		prev = my_count;
		toc = now;
		if (done == g.nthreads)
			break;
	}

	timerclear(&tic);
	timerclear(&toc);
	for (i = 0; i < g.nthreads; i++) {
		/*
		 * Join active threads, unregister interfaces and close
		 * file descriptors.
		 */
		pthread_join(targs[i].thread, NULL);

		if (targs[i].completed == 0)
			continue;

		/*
		 * Collect threads o1utput and extract information about
		 * how log it took to send all the packets.
		 */
		count += targs[i].count;
		if (!timerisset(&tic) || timercmp(&targs[i].tic, &tic, <))
			tic = targs[i].tic;
		if (!timerisset(&toc) || timercmp(&targs[i].toc, &toc, >))
			toc = targs[i].toc;
	}

	/* print output. */
	timersub(&toc, &tic, &toc);
	delta_t = toc.tv_sec + 1e-6* toc.tv_usec;
    }

	return (0);
}
/* end of file */
