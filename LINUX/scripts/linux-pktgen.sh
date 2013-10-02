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


# Sanitize command-line parameters
CPU="$1"
QUEUE="$2"  # {0, 1, 2}
if [ -z "$CPU" ]; then
    CPU="1"
fi
if [ -z "$QUEUE"]; then
    QUEUE="0"
fi

# Script configuration
IF="enp1s0f1"
DST_IP="10.216.8.1"
DST_MAC="00:1b:21:80:e7:d9"
PKT_COUNT="40000000"
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

