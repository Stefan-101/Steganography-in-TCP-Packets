#!/bin/bash

# the warden acts as a router
# we could potentially capture stuff in this container
iptables -A FORWARD -j ACCEPT

# reorder packets (reordering percentage controlled by REORDER_PCT env var, default 25)
tc qdisc add dev eth0 root netem delay 50ms reorder ${REORDER_PCT:-25}% 50%

# capture packets
tcpdump -i eth0 tcp port 80 -w /scripts/warden_capture.pcap &

# drop packets
# tc qdisc add dev eth0 root netem loss 10%