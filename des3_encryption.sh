#!/bin/bash

trap "exit" INT TERM ERR
trap "kill 0" EXIT

powerstat -R -c -z &
PID=$!

/usr/bin/time -f "%e sec" -o ./time.log ./des3.py --num 8

kill -INT $PID

sleep 1
echo

cat ./time.log
rm ./time.log

wait
