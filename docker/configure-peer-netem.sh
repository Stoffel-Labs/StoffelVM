#!/bin/sh
set -eu

# Add RTT only to traffic whose destination is another MPC party. Each endpoint
# contributes half of NET_RTT_MS to a round trip. A deliberately slow endpoint
# contributes all of NET_EXTRA_RTT_MS on its own egress, so the measured RTT is:
#
#   NET_RTT_MS + source extra RTT + destination extra RTT

interface=${NET_INTERFACE:-eth0}
global_rtt_ms=${NET_RTT_MS:-0}
extra_rtt_ms=${NET_EXTRA_RTT_MS:-0}
peer_ips=${NET_PEER_IPS:-}
loss=${NET_LOSS:-}
bandwidth=${NET_BANDWIDTH:-}

validate_milliseconds() {
    name=$1
    value=$2
    case "$value" in
        ''|*[!0-9]*)
            echo "ERROR: $name must be a non-negative integer number of milliseconds (got '$value')." >&2
            exit 2
            ;;
    esac
}

strip_leading_zeroes() {
    value=$1
    while [ "${value#0}" != "$value" ]; do
        value=${value#0}
    done
    printf '%s\n' "${value:-0}"
}

validate_milliseconds NET_RTT_MS "$global_rtt_ms"
validate_milliseconds NET_EXTRA_RTT_MS "$extra_rtt_ms"
global_rtt_ms=$(strip_leading_zeroes "$global_rtt_ms")
extra_rtt_ms=$(strip_leading_zeroes "$extra_rtt_ms")

if [ "$global_rtt_ms" -eq 0 ] \
    && [ "$extra_rtt_ms" -eq 0 ] \
    && [ -z "$loss" ] \
    && [ -z "$bandwidth" ]; then
    exit 0
fi

if [ -z "$peer_ips" ]; then
    echo "ERROR: NET_PEER_IPS must list the MPC party IPs when peer shaping is enabled." >&2
    exit 2
fi

if ! command -v tc >/dev/null 2>&1; then
    echo "ERROR: tc is required for peer shaping; install iproute2 in the image." >&2
    exit 2
fi

# A packet sees half the global RTT and all of this node's extra RTT. The echo
# or protocol response sees the corresponding delay configured by its sender.
delay_us=$((global_rtt_ms * 500 + extra_rtt_ms * 1000))

set -- netem
if [ "$delay_us" -gt 0 ]; then
    set -- "$@" delay "${delay_us}us"
fi
if [ -n "$loss" ]; then
    set -- "$@" loss "${loss}%"
fi
if [ -n "$bandwidth" ]; then
    set -- "$@" rate "${bandwidth}mbit"
fi

# Send ordinary traffic through the unshaped second band. Explicit destination
# filters select only peer-party traffic for the netem first band.
if ! tc qdisc replace dev "$interface" root handle 1: prio bands 2 \
    priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1; then
    echo "ERROR: could not install the peer shaper on $interface (is NET_ADMIN enabled?)." >&2
    exit 2
fi
if ! tc qdisc replace dev "$interface" parent 1:1 handle 10: "$@"; then
    echo "ERROR: could not configure netem on $interface." >&2
    exit 2
fi

# Loss and rate were whole-network controls before peer RTT shaping existed.
# Apply them to the ordinary band as well so that behavior remains compatible.
set -- netem
if [ -n "$loss" ]; then
    set -- "$@" loss "${loss}%"
fi
if [ -n "$bandwidth" ]; then
    set -- "$@" rate "${bandwidth}mbit"
fi
if [ "$#" -gt 1 ] \
    && ! tc qdisc replace dev "$interface" parent 1:2 handle 20: "$@"; then
    echo "ERROR: could not configure loss/bandwidth on $interface." >&2
    exit 2
fi

normalized_peer_ips=$(printf '%s\n' "$peer_ips" | tr ',' ' ')
for peer_ip in $normalized_peer_ips; do
    case "$peer_ip" in
        ''|*[!0-9.]*)
            echo "ERROR: NET_PEER_IPS contains an invalid IPv4 address ('$peer_ip')." >&2
            exit 2
            ;;
    esac
    if ! tc filter add dev "$interface" protocol ip parent 1: prio 1 u32 \
        match ip dst "${peer_ip}/32" flowid 1:1; then
        echo "ERROR: could not add the peer filter for $peer_ip on $interface." >&2
        exit 2
    fi
done

echo "Network shaping enabled on $interface: global_peer_rtt=${global_rtt_ms}ms node_extra_peer_rtt=${extra_rtt_ms}ms peer_egress_delay=${delay_us}us peers='$normalized_peer_ips'${loss:+ global_loss=${loss}%}${bandwidth:+ global_bandwidth=${bandwidth}mbit}"
