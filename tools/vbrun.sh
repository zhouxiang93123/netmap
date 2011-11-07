#!/bin/bash

set -u
set -e


PORT=2222
HOST=matteo@localhost

PICOBSD="/mnt/workspace/freebsd/src/release/picobsd/build/build_dir-netmap/"
PICOBSD_IMG="picobsd.bin"

VBOX="/cygdrive/c/Documents and Settings/Matteo/.VirtualBox/HardDisks"
VBOX_IMG="PicoBSD#.vdi"


# how many vm to start.
end=$1

cd "${VBOX}"

# copy picobsd image locally.
scp -P ${PORT} ${HOST}:${PICOBSD}/${PICOBSD_IMG} .

for i in `eval echo \{1..${end}\}`; do
    # replace "#.vdi" symbol with the current iteration number.
    vm=${VBOX_IMG/'#.vdi'/${i}}
    # replace "#" symbol with the current iteration number.
    img=${VBOX_IMG/'#'/${i}}

    # remove old hdd.
    if [ -f ${img} ]; then
        rm ${img}
    fi

    # specifyc vbox commands.
    VBoxManage convertfromraw ${PICOBSD_IMG} ${img}
    VBoxManage modifyvm ${vm} --hda none
    VBoxManage closemedium disk ${img}
    VBoxManage modifyvm ${vm} --hda ${img}
    VBoxManage startvm ${vm}
done

