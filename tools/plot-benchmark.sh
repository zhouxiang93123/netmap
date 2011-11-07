#!/bin/bash

# tipical usage:
#   cat data.log | bash plot-benchmarks.sh 

set -e
set -u


function usage()
{
        echo "Usage: $0 QUEUE FREQ BURST"
        echo "Use a single escaped \`*\` as widlcard."
        exit 1
}


if [ $# -ne 3 ]; then
    usage $0
fi


que=$1
freq=$2
burst=$3
if [ "${que}" == '*' ]; then
        title="Cpu Freq: ${freq}, Burst Size: ${burst}"
        xlabel="Queues"
elif [ "${freq}" == '*' ]; then
        title="Queues = ${que}, Burst Size: ${burst}"
        xlabel="Cpu Freq (Hz)"
elif [ "${burst}" == '*' ]; then
        title="Queues = ${que}, Cpu Freq: ${freq}"
        xlabel="Burst Size (packets)"
else
        usage $0
fi

ylabel="Speed (pps)"


values="`mktemp`"
trap "rm -rf ${values}; exit $?" INT TERM EXIT

while read line; do
        set - $line

        if [ "${que}" == '*' ]; then
                if [ ${freq} -ne $2 -o ${burst} -ne $3 ] ; then
                        continue
                fi
                echo $1 $4 >> "${values}"
        elif [ "${freq}" == '*' ]; then
                if [ ${que} -ne $1 -o ${burst} -ne $3 ] ; then
                        continue
                fi
                echo $2 $4 >> "${values}"
        elif [ "${burst}" == '*' ]; then
                if [ ${que} -ne $1 -o ${freq} -ne $2 ] ; then
                        continue
                fi
                echo $3 $4 >> "${values}"
        fi
done


echo "set title \"${title}\""
echo "set xlabel \"${xlabel}\""
echo "set ylabel \"${ylabel}\""
echo "set grid"
echo "plot \"${values}\" with lines"
echo "pause mouse key"

#rm -rf "${values}"
trap - INT TERM EXIT
