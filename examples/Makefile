# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	pkt-gen bridge testpcap libnetmap.so
#PROGS += pingd
PROGS	+= testlock testcsum test_select kern_test

CLEANFILES = $(PROGS) pcap.o nm_util.o
NO_MAN=
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall
CFLAGS += -I ../sys # -I/home/luigi/FreeBSD/head/sys -I../sys
CFLAGS += -Wextra

LDFLAGS += -lpthread -lpcap
#SRCS = pkt-gen.c

.include <bsd.prog.mk>
.include <bsd.lib.mk>

all: $(PROGS)

testpcap: pcap.c libnetmap.so nm_util.o
	$(CC) $(CFLAGS) -DTEST -o ${.TARGET} pcap.c nm_util.o $(LDFLAGS)

kern_test: testmod/kern_test.c

nm_util.o pkt-gen.o bridge.o libnetmap.so pcap.o: nm_util.h

pkt-gen: pkt-gen.o nm_util.o
	$(CC) $(LDFLAGS) -o ${.TARGET} ${.ALLSRC}

bridge: bridge.o nm_util.o
	$(CC) $(LDFLAGS) -o ${.TARGET} ${.ALLSRC}

libnetmap.so:	pcap.c nm_util.o
	$(CC) $(CFLAGS) -fpic -c pcap.c
	$(CC) -shared -o ${.TARGET} pcap.o nm_util.o
