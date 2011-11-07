[ x"${KERNELTREE}" == x ] && {
    echo picobsd.sh: KERNELTREE is not set: press enter to continue...
    read
}

PICOTREE=${KERNELTREE}/release/picobsd
PICOTYPE=netmap-qemu


alias cdp='cd ${PICOTREE}'

function preminder
{
    local ixgbe=${KERNELTREE}/sys/dev/ixgbe/ixgbe.c
    local netmap=${KERNELTREE}/sys/dev/netmap/netmap_kern.h

    grep 'static int ixgbe_enable_aim' ${ixgbe}
    grep 'static int ixgbe_max_interrupt_rate' ${ixgbe}

    grep '#define NETMAP_SKIP_POLL' ${netmap}
    grep '#define NETMAP_SLOW_POLL' ${netmap}
    grep '#define NETMAP_DOUBLE_PACKETS' ${netmap}
    grep '#define NETMAP_LATENCY_TIMESTAMPS' ${netmap}
}

function pbuilddep
{
    local netmap=~/workspace/n/examples

    echoandexec make -C ${netmap}
}

function pbuild
{
    local type_=${1:-${PICOTYPE}}

    preminder
    pbuilddep
    [ $? -ne 0 ] && return;
    echo Press ENTER to continue...
    read

    (
        echoandexec cd ${PICOTREE}/build
        echoandexec ./picobsd --src ${KERNELTREE} -n ${type_}
    )
}

function ptest
{
    local id=${1:-0}
    local image=${2:-${PICOTREE}/build/build_dir-${PICOTYPE}/picobsd.bin}

    echoandexec qemu ${image} \
           -net nic,model=e1000,macaddr=52:54:00:12:34:5${id} \
           -net tap,ifname=tap${id},script=no
}

function pdeploy
{
    local usb=${1:-/dev/da0}
    local image=${2:-${PICOTREE}/build/build_dir-${PICOTYPE}/picobsd.bin}
    local command=""

    echoandexec sudo dd if=${image} of=${usb}
}
