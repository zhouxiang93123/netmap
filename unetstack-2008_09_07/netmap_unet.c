/*
 * netmap interface for unetstack
 *
 * BSD license
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sys.h"
#include <errno.h>
#include <sys/poll.h>


struct nc_buff *
ncb_alloc(unsigned int size)
{
	return NULL;
}

void ncb_free(struct nc_buff *ncb)
{
}



int packet_index = 1;
unsigned char packet_edst[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


int netchannel_send_raw(struct nc_buff *ncb)
{
	//sendto(ncb->nc->fd, ncb->head, ncb->len);

	return 0;
}

int netchannel_recv_raw(struct netchannel *nc, unsigned int tm)
{
	struct nc_buff *ncb;
	int err, received = 0;
	struct pollfd pfd;

	pfd.fd = nc->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	syscall_recv += 1;

	err = poll(&pfd, 1, tm);
	if (err < 0) {
		ulog_err("%s: failed to poll", __func__);
		return err;
	}
	if (!(pfd.revents & POLLIN) || !err) {
		ulog("%s: no data, revents: %x.\n", __func__, pfd.revents);
		return -EAGAIN;
	}

	syscall_recv += 1;

	do {
		ncb = ncb_alloc(4096);
		if (!ncb)
			return -ENOMEM;
		ncb->nc = nc;

		//err = recvfrom(nc->fd, ncb->head, ncb->len, 0, (struct sockaddr *)&sa, &len);
		if (err < 0) {
			ulog_err("%s: failed to read", __func__);
			err = -errno;
			goto err_out_free;
		}

		ncb_trim(ncb, err);

		err = packet_ip_process(ncb);
		if (err) {
			err = 1;
			ncb_put(ncb);
		}
		++received;
	} while (err > 0 && ++received < 50);

	return 0;

err_out_free:
	ncb_put(ncb);
	return err;
}

static int netchannel_create_raw(struct netchannel *nc)
{
	// open a netmap descriptor
	return -1;
}


void netchannel_remove(struct netchannel *nc)
{
	close(nc->fd);
}

struct netchannel *netchannel_create(struct netchannel_control *ctl, unsigned int state)
{
	int err;
	struct common_protocol *proto;
	struct netchannel *nc;

	if (ctl->saddr.proto == IPPROTO_TCP)
		proto = &atcp_common_protocol;
	else if (ctl->saddr.proto == IPPROTO_UDP)
		proto = &udp_common_protocol;
	else
		return NULL;

	nc = malloc(sizeof(struct netchannel) + proto->size);
	if (!nc)
		return NULL;

	memset(nc, 0, sizeof(struct netchannel) + proto->size);
	ncb_queue_init(&nc->recv_queue);

	nc->proto = (struct common_protocol *)(nc + 1);
	nc->state = state;
	nc->header_size = MAX_HEADER_SIZE;

	memcpy(nc->proto, proto, sizeof(struct common_protocol));
	memcpy(&nc->ctl, ctl, sizeof(struct netchannel_control));

	nc->fd = netchannel_create_raw(nc);
	if (nc->fd < 0) {
		ulog_err("Failed to create netchannel");
		goto err_out_free;
	}

	err = nc->proto->create(nc);
	if (err)
		goto err_out_free;

	return nc;

err_out_free:
	free(nc);
	return NULL;
}

int netchannel_send(struct netchannel *nc, void *buf, unsigned int size)
{
	return nc->proto->process_out(nc, buf, size);
}

int netchannel_recv(struct netchannel *nc, void *buf, unsigned int size)
{
	return nc->proto->process_in(nc, buf, size);
}
