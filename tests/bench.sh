#!/bin/bash

set -ex -o pipefail

[[ $UID != 0 ]] && exec sudo -E "$(readlink -f "$0")" "$@"

NETNS="narans"

OUTER_DEVICE="wg1"
INNER_DEVICE="wg2"

OUTER_IP="10.10.10.1"
INNER_IP="10.10.10.2"

OUTER_PORT=1111
INNER_PORT=2222

OUTER_KEY="$(mktemp --suffix ".outer.key")"
INNER_KEY="$(mktemp --suffix ".inner.key")"

trap "killall nara iperf3 || true; ip netns del \"$NETNS\" || true" INT TERM EXIT

wg genkey > "$OUTER_KEY"
wg genkey > "$INNER_KEY"

nara "$OUTER_DEVICE"
nara "$INNER_DEVICE"
ip netns add "$NETNS"

wg set "$OUTER_DEVICE" private-key "$OUTER_KEY" listen-port "$OUTER_PORT" \
    peer "$(wg pubkey < "$INNER_KEY")" endpoint 127.0.0.1:"$INNER_PORT" allowed-ips "$INNER_IP"/32

wg set "$INNER_DEVICE" private-key "$INNER_KEY" listen-port "$INNER_PORT" \
    peer "$(wg pubkey < "$OUTER_KEY")" endpoint 127.0.0.1:"$OUTER_PORT" allowed-ips "$OUTER_IP"/32

sleep 1

ip link set "$INNER_DEVICE" netns "$NETNS"

ip addr add dev "$OUTER_DEVICE" "$OUTER_IP/24"
ip -netns "$NETNS" addr add dev "$INNER_DEVICE" "$INNER_IP/24"

ip link set up "$OUTER_DEVICE"
ip -netns "$NETNS" link set up "$INNER_DEVICE"


ip netns exec "$NETNS" iperf3 -s -1 -B "$INNER_IP" 2>&1 1>/dev/null &

sleep 1

iperf3 -n 100M -4 -Z -B "$OUTER_IP" -c "$INNER_IP"

ping -q -c 1000 -i 0.001 -I "$OUTER_IP" "$INNER_IP"
