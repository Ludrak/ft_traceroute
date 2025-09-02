#!/bin/bash
cd /dist
echo "Starting parallel test..."
echo "Instance 1 starting..."
TRACEROUTE_DEBUG=1 ./ft_traceroute 127.0.0.1 > /tmp/par1.log 2>&1 &
PID1=$!
sleep 0.2
echo "Instance 2 starting..."
TRACEROUTE_DEBUG=1 ./ft_traceroute 127.0.0.1 > /tmp/par2.log 2>&1 &
PID2=$!

wait $PID1
wait $PID2

echo "=== PARALLEL INSTANCE 1 (PID $PID1) ==="
head -25 /tmp/par1.log
echo "=== PARALLEL INSTANCE 2 (PID $PID2) ==="
head -25 /tmp/par2.log
