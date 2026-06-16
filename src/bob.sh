#!/bin/bash
set -x

# make warden container the default router  - ENABLE THESE ON LOCAL DOCKER ENVIRONMENT
ip route del default
ip route add default via 172.8.0.254
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

# we need to drop the kernel reset of hand-coded tcp connections
# https://stackoverflow.com/a/8578541
# iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

# capture packets in netfilterqueue
iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1
iptables -A OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num 1

cd scripts
# head -c 5K </dev/urandom > ./secret/bobs_secret.txt
# head -c 50M </dev/urandom > large_file.bin
python3 -m http.server 80 --directory /http_server &
python3 bob.py --file ./secret/bobs_secret.txt $( [ "$MITIGATED" = "1" ] && echo "--mitigated" ) &
