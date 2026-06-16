#!/bin/bash
set -x

# make warden container the default router  - ENABLE THESE ON LOCAL DOCKER ENVIRONMENT
ip route del default
ip route add default via 172.7.0.254
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

# drop the kernel reset of hand-coded tcp connections
# https://stackoverflow.com/a/8578541
# iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# capture packets in netfilterqueue
iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1
iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 1

cd scripts
ALICE_FLAGS=""
[ "$JITTER_ENABLED" = "0" ] && ALICE_FLAGS="$ALICE_FLAGS --no-jitter"
[ "$EXECUTE_COMMANDS" = "0" ] && ALICE_FLAGS="$ALICE_FLAGS --no-exec"
python3 alice.py $ALICE_FLAGS $( [ "$MITIGATED" = "1" ] && echo "--mitigated" ) &

cd ..
wget http://172.8.0.3/carrier_file.bin
echo "ALICE_WGET_DONE"