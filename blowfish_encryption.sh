#!/bin/bash

trap "exit" INT TERM ERR
trap "kill 0" EXIT

powerstat -R -c -z &
PID=$!

./blowfish.py --num 8

kill -INT $PID

wait
