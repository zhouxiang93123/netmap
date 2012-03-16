#KDIR	:= /lib/modules/$(shell uname -r)/build
KDIR	:= /home/zbr/aWork/git/linux-2.6/linux-2.6.netchannels
PWD	:= $(shell pwd)
CC	:= gcc

CFLAGS	:= -I$(KDIR)/include -W -Wall -g -O1 -Werror
LDFLAGS := -lc

OBJS := atcp.o udp.o ip.o packet.o stat.o
DEPS := sys.h Makefile

USE_PCAP=1
ifdef USE_PCAP
CFLAGS += -DUSE_PCAP -DUDEBUG
CFLAGS += -include glue.h
CFLAGS += -I../sys -Imy_inc
LDFLAGS += -lpcap
DEPS += glue.h
OBJS += netmap_unet.o ncbuff.o
endif
ifdef USE_NETMAP
CFLAGS += -DUSE_NETMAP
CFLAGS += -include glue.h
CFLAGS += -I../sys -Imy_inc
DEPS += glue.h
OBJS += netmap_unet.o
endif

ifdef NETCHANNEL
CFLAGS += -DKERNEL_NETCHANNEL
OBJS += netchannel.o ncbuff.o
endif

ifdef DEBUG
CFLAGS += -DUDEBUG
endif

TARGETS	:= stack

all: $(OBJS) $(TARGETS)
	@echo "Compilation has been successfully finished."

stack: $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

$(OBJS): $(DEPS)
atcp.o:		atcp.c sys.h Makefile
udp.o:		udp.c sys.h Makefile
ip.o:		ip.c sys.h Makefile
netchannel.o:	netchannel.c sys.h Makefile
netmap_unet.o: netmap_unet.c sys.h Makefile
ncbuff.o:	ncbuff.c sys.h Makefile
packet.o:	packet.c sys.h Makefile
stat.o:		stat.c stat.h sys.h Makefile

%.o:$(patsubst %.o,%.c,$<)
	$(CC) $(CFLAGS) $(patsubst %.o,%.c,$@) -c -o $@

clean:
	rm -f *.o *~ $(TARGETS) $(LIB_OBJS)

%: $(patsubst %,%.c,$<)
