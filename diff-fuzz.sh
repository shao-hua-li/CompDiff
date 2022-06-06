#!/bin/bash
set -e
export AFFINITY
export EXTRA_ARGS
source "/$TARGET/args.sh"
source "/$FUZZER/diff-fuzz-M.sh" &

sleep 5
for i in `seq 1 $SLAVES`
do
    AFFINITY=$((AFFINITY+1))
    export SLAVEID=$i
    source "/$FUZZER/diff-fuzz-S.sh" &
    sleep 2
done
sleep $TIMEOUT

