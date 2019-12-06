#!/bin/bash

trap "exit" INT TERM ERR
trap "kill 0" EXIT

powerstat -R -c -z &
PID=$!

sleep 10

kill -INT $PID

wait
