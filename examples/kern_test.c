/*
 * performance testing code
 */
#ifndef _KERNEL
/*
 * glue code to build this in userspace
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>
#define	SYSCTL_HANDLER_ARGS	struct oidp *oidp, struct req *req
#define SYSCTL_NODE(_1, _2, _3, _4, _5, _6)
#define SYSCTL_ULONG(_1, _2, _3, _4, _5, _6, _7)
#define SYSCTL_STRING(_1, _2, _3, _4, _5, _6, _7)
#define SYSCTL_PROC(_1, _2, _3, _4, _5, _6, _7, _8, _9)
struct oidp;
struct req {
	void *newptr;
};

int sysctl_handle_int(struct oidp *, int *value, int mode, struct req *); 
#endif
// kern_test.c

static __inline uint64_t
rdtsc(void)
{
        uint64_t rv;

        __asm __volatile("rdtscp" : "=A" (rv) : : "%rax");
        return (rv);
}

#include <sys/sysctl.h>
static uint64_t test_count, t_start, t_end, t_delta;
static char test_name[128];

static int test_run(SYSCTL_HANDLER_ARGS);

// SYSCTL_DECL(_kern);
SYSCTL_NODE(_kern, OID_AUTO, test, CTLFLAG_RW, 0, "kernel testing");
SYSCTL_ULONG(_kern_test, OID_AUTO, count,
    CTLFLAG_RW, &test_count, 0, "number of test cycles");
SYSCTL_ULONG(_kern_test, OID_AUTO, cycles,
    CTLFLAG_RW, &t_delta, 0, "runtime");
SYSCTL_STRING(_kern_test, OID_AUTO, name,
	CTLFLAG_RW, &test_name, sizeof(test_name), "");
SYSCTL_PROC(_kern_test, OID_AUTO, run,
    CTLTYPE_U64 | CTLFLAG_RW, 0, 0, test_run,
    "U64", "run the test");


struct targ {
	uint64_t count;
};
struct entry {
        void (*fn)(struct targ *);
        char *name;
        uint64_t scale;
};

static void test_nop(struct targ *a) {
	uint64_t i, count = a->count;
	volatile int x = 0;
	for (i = 0; i < count; i++) {
		x = i;
	}
}
struct entry tests[] = {
#if 0
        { test_sel, "select", 1 },
        { test_poll, "poll", 1 },
        { test_usleep, "usleep", 1 },
        { test_time, "time", 1 },
        { test_gettimeofday, "gettimeofday", 1 },
        { test_bcopy, "bcopy", 1 },
        { test_add, "add", ONE_MILLION },
        { test_atomic_add, "atomic-add", ONE_MILLION },
        { test_cli, "cli", ONE_MILLION },
        { test_rdtsc, "rdtsc", ONE_MILLION },   // unserialized
        { test_rdtsc1, "rdtsc1", ONE_MILLION }, // serialized
        { test_atomic_cmpset, "cmpset", ONE_MILLION },
#endif
	{ test_nop, "nop", 1 },
	{ NULL, NULL, 0 }
};

static int test_run_val;
static int
test_run(SYSCTL_HANDLER_ARGS)
{
        int error, value;
	struct entry *i;

        value = test_run_val;
        error = sysctl_handle_int(oidp, &value, 0, req);
        if (error != 0 || req->newptr == NULL)
                return (error);
        printf("new value is %d, string %s\n", value, test_name);
        test_run_val = value;
	for (i = 0; i->name; i++) {
		printf("compare .%s. .%s.\n", test_name, i->name);
		if (!strcmp(test_name, i->name))
			break;
	}
	if (i->name) {
		struct targ a;
		a.count = test_count;
		printf("try to run test %s\n", test_name);
		t_start = rdtsc();
		i->fn(&a);
		t_end = rdtsc();
	}
        return (0);
}
