#include <errno.h>
#include <stdio.h>
#include <inttypes.h>	/* PRI* macros */
#include <string.h>	/* strcmp */
#include <fcntl.h>	/* open */
#include <unistd.h>	/* close */
#include <sys/ioctl.h>	/* ioctl */
#include <sys/param.h>
#include <net/if.h>	/* ifreq */
#include <net/netmap.h>
#include <net/netmap_user.h>

static int
bdgconfig(const char *name, int cmd)
{
	int error = 0, fd = open("/dev/netmap", O_RDWR);
	struct nmreq nmr;

	if (fd == -1) {
		fprintf(stderr, "Unable to open /dev/netmap");
		return -1;
	}
	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	strncpy(nmr.nr_name, name, sizeof(nmr.nr_name));
	if (cmd == 0) { /* GINFO */
		error = ioctl(fd, NIOCGINFO, &nmr);
		if (error) {
			fprintf(stdout, "Unable to get if info for %s\n", name);
			close(fd);
			return error;
		} else
			fprintf(stdout, "%s: %d queues.\n", name, nmr.nr_rx_rings);
	} else {
		nmr.nr_cmd = cmd;
		error = ioctl(fd, NIOCREGIF, &nmr);
		if (error == -1)
			fprintf(stdout, "Unable to %s %s to the bridge\n",
			    cmd & NETMAP_BDG_DETACH?"detach":"attach", name);
		else
			fprintf(stdout, "Success to %s %s to the bridge\n",
			    cmd & NETMAP_BDG_DETACH?"detach":"attach", name);
	}
	close(fd);
	return error;
}

int
main(int argc, char **argv)
{
	int ch;
	const char *cmd = "nic2bridge";

	if (argc != 3) {
usage:
		fprintf(stderr,
			"Usage:\n"
			"%s arguments\n"
			"\t-g interface	interface name to get info\n"
			"\t-d interface	interface name to be detached\n"
			"\t-a interface	interface name to be attached\n"
			"\t-h interface	interface name to be attached with the host stack\n"
			"", cmd);
		return 0;
	}
	while ((ch = getopt(argc, argv, "d:a:h:g:")) != -1) {
		switch (ch) {
		default:
			fprintf(stderr, "bad option %c %s", ch, optarg);
			goto usage;

		case 'd':
			bdgconfig(optarg, NETMAP_BDG_DETACH);
			break;

		case 'a':
			bdgconfig(optarg, NETMAP_BDG_ATTACH);
			break;
		case 'h':
			bdgconfig(optarg, NETMAP_BDG_ATTACH | NETMAP_BDG_HOST);
			break;
		case 'g':
			bdgconfig(optarg, 0 /* GINFO */);
			break;
		}
	}
	return 0;
}
