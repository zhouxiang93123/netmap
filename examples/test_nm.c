/* simple test program for netmap library */
#include <stdio.h>
#include <stdlib.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <poll.h>

void my_cb(u_char *arg, const struct nm_hdr_t *h, const u_char *buf)
{
	fprintf(stderr, "received %d bytes at %p arg %p\n",
		h->len, buf, arg);
}

int main(int argc, char *argv[])
{
	struct nm_desc_t *d;
	struct pollfd pfd;
	int i, cnt;
	uintptr_t tot = 0;

	bzero(&pfd, sizeof(pfd));

	d = nm_open(argv[1], NULL, 0, 0);
	if (d == NULL) {
		fprintf(stderr, "no netmap\n");
		exit(0);
	}
	pfd.fd = d->fd;
	pfd.events = POLLIN;

	for (cnt = 0; cnt < 10; tot += i) {
		i = poll(&pfd, 1, 1000);
		if (i == 0)
			fprintf(stderr, "no data %d\n", cnt++);
		else
			i = nm_dispatch(d, 0, my_cb, (void *)tot);
	}
	nm_close(d);
	return 0;
}
