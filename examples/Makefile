# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	pkt-gen bridge testpcap libnetmap.so
#PROGS += pingd
PROGS	+= testlock testcsum test_select kern_test

CLEANFILES = $(PROGS) pcap.o
NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra

LDFLAGS += -lpthread -lpcap
#SRCS = pkt-gen.c

.include <bsd.prog.mk>
.include <bsd.lib.mk>

all: $(PROGS)

testpcap: pcap.c libnetmap.so
	$(CC) $(CFLAGS) -o ${.TARGET} pcap.c $(LDFLAGS)

kern_test: testmod/kern_test.c

pkt-gen.o bridge.o libnetmap.so pcap.o: nm_util.h
libnetmap.so:	pcap.c
	$(CC) $(CFLAGS) -fpic -c ${.ALLSRC}
	$(CC) -shared -o ${.TARGET} ${.ALLSRC:.c=.o}
