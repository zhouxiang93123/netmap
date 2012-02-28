/*
 * test checksum
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

volatile uint16_t res;

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
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
        return sum;
}

uint32_t
sum32(const unsigned char *addr, int count)
{
        uint64_t sum = 0;
        int i;
                          
        for (i = 0; i < count; i += 4)
                sum += * (uint32_t *) (addr + i);
	if (count - i > 1) {
                sum += *(uint16_t *) (addr + i);
		i += 2;
	}
        /* Add left-over byte, if any */
        if (++i == count)
                sum += *(addr + i);
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
        return sum;
}

uint32_t
sum32u(const unsigned char *addr, int count)
{
        uint64_t sum = 0;
	const uint32_t *p = (uint32_t *)addr;
	//const uint8_t *c = addr;

	for (; count >= 32; count -= 32) {
		sum += (uint64_t)p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7];
		p += 8;
	}
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
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);
	sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);
	return sum;
}

int
main(int argc, char *argv[])
{
	int lim = argc > 1 ? atoi(argv[1]) : 100;
	int len = argc > 2 ? atoi(argv[2]) : 1024;
	int i, n;
	char buf[2048];
	// uint32_t (*fn)(const unsigned char *addr, int count);

	if (len > (int)sizeof(buf))
		len = sizeof(buf);
	for (i = 0; i < len; i++)
		buf[i] = i *i - i + 5;
	for (n = 0; n < lim; n++) {
		for (i = 0; i < 1000000; i++) {
			res = sum32u((unsigned char *)buf, len);
		}
	}
	fprintf(stderr, "csum 32 %u csum16 %d csum32u %u\n",
		sum16((unsigned char *)buf, len),
		sum32((unsigned char *)buf, len),
		sum32u((unsigned char *)buf, len));
	return 0;
}
