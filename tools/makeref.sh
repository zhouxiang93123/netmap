#!/usr/bin/bash

# create a reference tree
DEVS="ixgbe e1000 bge nfe re"
MODULES="ixgbe em bge nfe re"
url='http://svn.freebsd.org/base/head/sys/'
revision='217746'

set -e
set -u

mkdir -p head/sys/dev head/sys/modules
cd head/sys
for i in $DEVS ; do
	mkdir -p dev/$i
	(cd dev && svn co "${url}dev/${i}@${revision}")
done

for i in $MODULES ; do
	mkdir -p modules/$i
	(cd modules && svn co "${url}modules/${i}@${revision}")
done
mkdir -p pci
(cd . && svn co "${url}pci@${revision}")
cd ../..
tar cvzf head-dev-base.tgz --exclude .svn head

trap - INT TERM EXIT
