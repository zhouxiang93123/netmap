#include "nm_util.h"

static int
bdgconfig(const char *ifname, int cmd)
{
	int error = 0, fd = open("/dev/netmap", O_RDWR);
	struct nmreq hwnmr;

	if (fd == -1)
		D("Unable to open /dev/netmap");
	else {
		bzero(&hwnmr, sizeof(hwnmr));
		hwnmr.nr_version = NETMAP_API;
		strncpy(hwnmr.nr_name, ifname, sizeof(hwnmr.nr_name));
		hwnmr.spare1 = cmd;
		error = ioctl(fd, NIOCREGIF, &hwnmr);
		if (error == -1)
			D("Unable to %s %s to the bridge", cmd == NETMAP_BDG_DETACH?"detach":"attach", ifname);
		else
			D("Success to %s %s to the bridge", cmd == NETMAP_BDG_DETACH?"detach":"attach", ifname);
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
			"\t-d interface	interface name to be detached\n"
			"\t-a interface	interface name to be attached\n"
			"", cmd);
		return 0;
	}
	while ((ch = getopt(argc, argv, "d:a:")) != -1) {
		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			goto usage;

		case 'd':
			bdgconfig(optarg, NETMAP_BDG_DETACH);
			break;

		case 'a':
			bdgconfig(optarg, NETMAP_BDG_ATTACH);
			break;
		}
	}
	return 0;
}
