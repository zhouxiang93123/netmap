# $Id$
# targets to build tarballs and diffs

# build a distribution
DIST_NAME := netmap-0.9-20120730.tar.gz
DIST_SRCS := ./sys/net ./sys/modules ./Makefile ./LINUX
DIST_SRCS += ./sys/dev
DIST_SRCS += ./examples ./test

RELEASE_SRCS := ./sys/net ./sys/dev ./sys/modules ./examples
RELEASE_SRCS += ./README ./LINUX
RELEASE_EXCL := --exclude .svn --exclude sys/dev/\*/i\*.c --exclude examples/testmod
RELEASE_EXCL += --exclude connlib\* --exclude netmap_vale.c

all:
	@echo "What do you want to do ?"

tgz:
	tar cvzf /usr/ports/distfiles/${DIST_NAME} \
		-s'/^./netmap/' --exclude .svn $(DIST_SRCS)

diff-head:
	(cd ~/FreeBSD/head ; \
	svn diff sys/conf sys/dev sbin/ifconfig ) > head-netmap.diff

# XXX remember to patch sbin/ifconfig if not done yet
diff-r8:
	(cd ~/FreeBSD/RELENG_8 ; \
	svn diff sys/conf sys/dev sbin/ifconfig ) > r8-netmap.diff

release:
	tar cvzf /tmp/netmap.tgz \
		-s'/^./netmap/' $(RELEASE_EXCL) $(RELEASE_SRCS)
