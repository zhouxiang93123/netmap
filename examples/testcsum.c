/*
 * test checksum
 *
 * In summary:
 * - on new cpus (AMD X2, i5, i7) alignment is not very important.
 * - on old P4, the unrolling is not very useful
 * - the assembly version is uniformly slower
 *
 * In summary the 32-bit version with unrolling is quite fast.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

volatile uint16_t res;

#define REDUCE16(_x)	({ uint32_t x = _x;	\
	x = (x & 0xffff) + (x >> 16);		\
	x = (x & 0xffff) + (x >> 16);		\
	x; } )

#define REDUCE32(_x)	({ uint64_t x = _x;	\
	x = (x & 0xffffffff) + (x >> 32);	\
	x = (x & 0xffffffff) + (x >> 32);	\
	x; } )

uint32_t
dummy(const unsigned char *addr __unused, int count __unused)
{
	return 0;
}

/*
 * Base mechanism, 16 bit at a time, not unrolled
 */
uint32_t
sum16(const unsigned char *addr, int count)
{
	uint32_t sum = 0;
	uint16_t *d = (uint16_t *)addr;

	for (;count >= 2; count -= 2)
		sum += *d++;

	/* Add left-over byte, if any */
	if (count & 1)
		sum += *(uint8_t *)d;
	return REDUCE16(sum);
}

/*
 * Better mechanism, 32 bit at a time, not unrolled
 */
uint32_t
sum32(const unsigned char *addr, int count)
{
	uint64_t sum = 0;
	const uint32_t *d = (const uint32_t *)addr;

	for (; count >= 4; count -= 4)
		sum += *d++;
	addr = (const uint8_t *)d;
	if (count >= 2) {
		sum += *(const uint16_t *)addr;
		addr += 2;
	}
	/* Add left-over byte, if any */
	if (count & 1)
		sum += *addr;
	sum = REDUCE32(sum);
	return REDUCE16(sum);
}

uint32_t
sum32u(const unsigned char *addr, int count)
{
	uint64_t sum = 0;
	const uint32_t *p = (uint32_t *)addr;

	for (; count >= 32; count -= 32) {
		sum += (uint64_t)p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7];
		p += 8;
	}
	if (count & 0x10) {
		sum += (uint64_t)p[0] + p[1] + p[2] + p[3];
		p += 4;
	}
	if (count & 8) {
		sum += (uint64_t)p[0] + p[1];
		p += 2;
	}
	if (count & 4)
		sum += *p++;
	addr = (const unsigned char *)p;
	if (count & 2) {
		sum += *(uint16_t *)addr;
		addr += 2;
	}
	if (count & 1)
		sum += *addr;
	sum = REDUCE32(sum);
	return REDUCE16(sum);
}

uint32_t
sum32a(const unsigned char *addr, int count)
{
        uint32_t sum32 = 0;
        uint64_t sum;
	const uint32_t *p = (const uint32_t *)addr;

	for (;count >= 32; count -= 32) {
	    __asm(
		"add %1, %0\n"
		"adc %2, %0\n"
		"adc %3, %0\n"
		"adc %4, %0\n"
		"adc %5, %0\n"
		"adc %6, %0\n"
		"adc %7, %0\n"
		"adc %8, %0\n"
		"adc $0, %0"
		: "+r" (sum32)
		: "g" (p[0]),
		  "g" (p[1]),
		  "g" (p[2]),
		  "g" (p[3]),
		  "g" (p[4]),
		  "g" (p[5]),
		  "g" (p[6]),
		  "g" (p[7])
		: "cc"
	    );
	    p += 8;
	}
	sum = sum32;
	for (;1 &&  count >= 16; count -= 16) {
		sum += (uint64_t)p[0] + p[1] + p[2] + p[3];
		p += 4;
	}
	for (; count >= 4; count -= 4) {
		sum += *p++;
	}
	addr = (unsigned char *)p;
	if (count > 1) {
		sum += *(uint16_t *)addr;
		addr += 2;
	}
	if (count & 1)
		sum += *addr;
	sum = REDUCE32(sum);
	return REDUCE16(sum);
}


struct ftab {
	char *name;
	uint32_t (*fn)(const unsigned char *, int);
};

struct ftab f[] = {
	{ "dummy", dummy },
	{ "sum16", sum16 },
	{ "sum32", sum32 },
	{ "sum32u", sum32u },
	{ "sum32a", sum32a },
	{ NULL, NULL }
};

int
main(int argc, char *argv[])
{
	int i, n;
	int lim = argc > 1 ? atoi(argv[1]) : 100;
	int len = argc > 2 ? atoi(argv[2]) : 1024;
	char *fn = argc > 3 ? argv[3] : "sum16";
	char buf0[2048], *buf = buf0;
	uint32_t (*fnp)(const unsigned char *, int) = NULL;

	for (i = 0; f[i].name; i++) {
		if (!strcmp(f[i].name, fn)) {
			fnp = f[i].fn;
			break;
		}
	}
	if (fnp == NULL) {
		fnp = sum16;
		fn = "sum16-default";
	}
	if (len > (int)sizeof(buf0))
		len = sizeof(buf0);
	buf = buf0;
	for (i = 0; i < len; i++)
		buf[i] = i *i - i + 5;
	fprintf(stderr, "function %s len %d count %dM\n",
		fn, len, lim);
	for (n = 0; n < lim; n++) {
		for (i = 0; i < 1000000; i++) {
			res = fnp((unsigned char *)buf, len);
		}
	}
	fprintf(stderr, "%s %u sum16 %u sum32 %d sum32u %u\n",
		fn, res,
		sum16((unsigned char *)buf, len),
		sum32((unsigned char *)buf, len),
		sum32u((unsigned char *)buf, len));
	return 0;
}
