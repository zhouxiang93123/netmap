SUBDIR= examples test

.include <bsd.subdir.mk>

# build a distribution
DIST_NAME := netmap-0.4-20110704.tar.gz
DIST_SRCS := ./sys/net ./sys/modules ./Makefile 
DIST_SRCS += ./sys/dev
DIST_SRCS += ./examples ./test

RELEASE_SRCS := ./sys/net ./sys/modules ./examples
RELEASE_SRCS += ./sys/dev
RELEASE_SRCS += ./head-netmap.diff ./README # ./NOTES
RELEASE_EXCL := --exclude .svn --exclude sys/dev/\*/i\*.c

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
