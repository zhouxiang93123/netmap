#!/usr/bin/env bash

# repeat a command a specified number of times, plus sleep a certain
# amount of time at the end of each iteration.
#
# For example, the following invocation:
#
#   bash repeat.sh 100 1s echo yes
#
# will produced 100 yes messages, one per second.

set -u
set -e


ntimes=$1
sleepint=$2
shift
shift
cmd="$*"

for i in eval echo {1..${ntimes}}; do
    echo ${cmd}
    sleep ${sleepint}
done
