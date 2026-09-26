#!/bin/sh
# shellcheck shell=busybox disable=1091,3043
#
# Watches the settings quectel-cm reports for a data call and hands every change
# to netifd. This runs as the proto task of the interface, so netifd tears the
# interface down and brings it up again by itself once this exits.

. /lib/functions.sh
. /lib/netifd/netifd-proto.sh
INCLUDE_ONLY=1 . /lib/netifd/proto/quectel.sh

interface="$1"
ifname="$2"
ipcfg="$3"
cm_pid="$4"
grace="$5"
defaultroute="$6"
peerdns="$7"
sourcefilter="$8"
prefixlifetime="$9"
# ${10} onwards, not $10: that is $1 followed by a literal zero.
passthrough="${10}"
device="${11}"
nat64="${12}"
nat64prefix="${13}"

seen="$(cat "$ipcfg" 2>/dev/null)"
lost=0

while :; do
	# A handover replaces the settings in well under a second, so poll tightly
	# enough that the window in which netifd still holds the previous address
	# stays short.
	sleep 2

	[ -d "/proc/$cm_pid" ] || {
		echo "quectel-cm for $interface is gone"
		exit 1
	}

	# quectel-cm survives some resets on its own, waiting for the modem to come
	# back and dialling again, so the grace period below is what a reset would
	# otherwise cost before netifd rebuilds the interface. The control device
	# leaving the bus is not a data call that might return in a moment - it is the
	# whole modem gone - so hand it straight back to netifd instead.
	[ -z "$device" ] || [ -c "$device" ] || {
		echo "The control device of $interface is gone"
		exit 1
	}

	current="$(cat "$ipcfg" 2>/dev/null)"

	[ -n "$current" ] || {
		# A dropped data call normally comes back within seconds, and sitting it
		# out is far cheaper than having netifd rebuild the interface and the
		# modem session, so only give up once it stays away.
		lost=$((lost + 2))
		[ "$lost" -lt "$grace" ] && continue

		echo "The data call of $interface stayed down for ${lost}s"
		exit 1
	}

	lost=0
	[ "$current" = "$seen" ] && continue
	seen="$current"

	echo "Reconfiguring $interface, the network handed out new settings"
	quectel_send_ipcfg "$interface" "$ifname" "$ipcfg" "$passthrough"

	# A re-established data call can land on a different network, so the prefix
	# its IPv4 has to be translated to is worth asking about again rather than
	# assuming it survived the handover.
	quectel_nat64_update "$interface" "$ifname" "$ipcfg" "$nat64" "$nat64prefix"
done
