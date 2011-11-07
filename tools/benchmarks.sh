#!/bin/bash

set -u
set -e

# simulation
program=$1
ifname=ix0
npackets=40960000
packetsize=60
destaddr=ff:ff:ff:ff:ff:ff


parse_speed()
{

	local pair=$1
	local speed
	local unit
	local k

	speed=${pair##*:}
	speed=${speed%[KM]pps.}
	unit=${pair: -5:1}
	if [ ${unit} = 'M' ]; then
		k=1
	elif [ ${unit} = 'K' ]; then
		k=1000
	fi

	echo "${speed} / ${k}" | bc
}


simulate()
{
	local burst=$1
	local threads=$2
	local cores=$3
	local speed

	cmd="${program} ${ifname} ${burst} ${threads} ${cores}"
	# comment the following line to test receiver
	cmd="${cmd} ${npackets} ${packetsize} ${destaddr}"

	speed=`${cmd} | grep pps | cut -d ' ' -f 2`

	echo `parse_speed ${speed}`
}


for que in 1 2 4; do
	# use the highest freq value for module operations
	sysctl dev.cpu.0.freq=2934 > /dev/null

	# load the module with the right number of queues
	kldunload ixgbe
	kenv hw.ixgbe.num_queues=${que} > /dev/null
	kldload ixgbe

	for freq in 150 300 600 1200 2400 2800 2934 ; do
		# set the core speed
		sysctl dev.cpu.0.freq=${freq} > /dev/null

		for burst in 1 2 4 8 16 32 64 128 256 512 1024 2048; do
			for thread in 1 ${que}; do
				for core in 1 ${thread}; do
					speed=`simulate ${burst} ${thread} ${core}`
					echo "${que} ${freq} ${core} ${thread} ${burst} ${speed}"

					if [ ${thread} -eq 1 ]; then
						break
					fi
				done

				if [ ${que} -eq 1 ]; then
					break
				fi
			done
		done
	done

done
