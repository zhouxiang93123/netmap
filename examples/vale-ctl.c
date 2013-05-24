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

/* debug support */
#define ND(format, ...)	do {} while(0)
#define D(format, ...)					\
	fprintf(stderr, "%s [%d] " format "\n",		\
	__FUNCTION__, __LINE__, ##__VA_ARGS__)

static int
bdg_ctl(const char *name, int nr_cmd, int nr_arg)
{
	int error = 0, fd = open("/dev/netmap", O_RDWR);
	struct nmreq nmr;

	if (fd == -1) {
		D("Unable to open /dev/netmap");
		return -1;
	}

	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	if (name != NULL) /* might be NULL */
		strncpy(nmr.nr_name, name, sizeof(nmr.nr_name));
	nmr.nr_cmd = nr_cmd;

	switch (nr_cmd) {
	case NETMAP_BDG_ATTACH:
	case NETMAP_BDG_DETACH:
		if (nr_arg && nr_arg != NETMAP_BDG_HOST)
			nr_arg = 0;
		nmr.nr_arg1 = nr_arg;
		error = ioctl(fd, NIOCREGIF, &nmr);
		if (error == -1)
			D("Unable to %s %s to the bridge", nr_cmd ==
			    NETMAP_BDG_DETACH?"detach":"attach", name);
		else
			D("Success to %s %s to the bridge\n", nr_cmd ==
			    NETMAP_BDG_DETACH?"detach":"attach", name);
		break;
	case NETMAP_BDG_LIST:
		if (strlen(nmr.nr_name)) { /* name to bridge/port info */
			error = ioctl(fd, NIOCGINFO, &nmr);
			if (error)
				D("Unable to obtain info for %s", name);
			else
				D("%s at bridge:%d port:%d", name, nmr.nr_arg1,
				    nmr.nr_arg2);
			break;
		}

		/* scan all the bridges and ports */
		nmr.nr_arg1 = nmr.nr_arg2 = 0;
		for (; !ioctl(fd, NIOCGINFO, &nmr); nmr.nr_arg2++) {
			D("bridge:%d port:%d %s", nmr.nr_arg1, nmr.nr_arg2,
			    nmr.nr_name);
			nmr.nr_name[0] = '\0';
		}

		break;
	default: /* GINFO */
		nmr.nr_cmd = nmr.nr_arg1 = nmr.nr_arg2 = 0;
		error = ioctl(fd, NIOCGINFO, &nmr);
		if (error)
			D("Unable to get if info for %s", name);
		else
			D("%s: %d queues.", name, nmr.nr_rx_rings);
		break;
	}
	close(fd);
	return error;
}

int
main(int argc, char **argv)
{
	int ch, nr_cmd = 0, nr_arg = 0;
	const char *command = "nic2bridge";
	char *name = NULL;

	if (argc != 3 && argc != 1 /* list all */ ) {
usage:
		fprintf(stderr,
			"Usage:\n"
			"%s arguments\n"
			"\t-g interface	interface name to get info\n"
			"\t-d interface	interface name to be detached\n"
			"\t-a interface	interface name to be attached\n"
			"\t-h interface	interface name to be attached with the host stack\n"
			"\t-l list all or specified bridge's interfaces\n"
			"", command);
		return 0;
	}

	while ((ch = getopt(argc, argv, "d:a:h:g:l:")) != -1) {
		switch (ch) {
		default:
			fprintf(stderr, "bad option %c %s", ch, optarg);
			goto usage;
		case 'd':
			nr_cmd = NETMAP_BDG_DETACH;
			break;
		case 'a':
			nr_cmd = NETMAP_BDG_ATTACH;
			break;
		case 'h':
			nr_cmd = NETMAP_BDG_ATTACH;
			nr_arg = NETMAP_BDG_HOST;
			break;
		case 'g':
			nr_cmd = 0;
			break;
		case 'l':
			nr_cmd = NETMAP_BDG_LIST;
			break;
		}
		name = optarg;
	}
	if (argc == 1)
		nr_cmd = NETMAP_BDG_LIST;
	bdg_ctl(name, nr_cmd, nr_arg);
	return 0;
}
