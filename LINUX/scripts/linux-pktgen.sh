#!/bin/bash

#set -x


function pgset() {
    local result

    echo $1 > ${PGDEV}

    result=$(cat $PGDEV | fgrep "Result: OK:")
    if [ "$result" = "" ]; then
        cat $PGDEV | fgrep "Result:"
    fi
}

# What can we do with this function?
function pg() {
    echo inject > $PGDEV
    cat $PGDEV
}


# Script configuration
IF="enp6s0"
DST_IP="10.216.1.36"
DST_MAC="14:da:e9:b8:5a:85"
CPU="1"
PKT_COUNT="3000000"
PKT_SIZE="60"


# Load pktgen kernel module
modprobe pktgen


# Thread-CPU configuration
PGDEV="/proc/net/pktgen/kpktgend_${CPU}"
echo "Removing all devices"
pgset "rem_device_all"
echo "Adding $IF"
pgset "add_device $IF"


# Packets/mode configuration
PGDEV="/proc/net/pktgen/$IF"
echo "Configuring $PGDEV"
pgset "count ${PKT_COUNT}"
pgset "clone_skb 0"
pgset "pkt_size ${PKT_SIZE}"
pgset "delay 0"
pgset "dst $DST_IP"
pgset "dst_mac $DST_MAC"


# Run
PGDEV="/proc/net/pktgen/pgctrl"
echo "Running... Ctrl-C to stop"
pgset "start"
echo "Done."

# Show results
cat /proc/net/pktgen/$IF

