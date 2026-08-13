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

seen="$(cat "$ipcfg" 2>/dev/null)"
lost=0

while :; do
	sleep 5

	[ -d "/proc/$cm_pid" ] || {
		echo "quectel-cm for $interface is gone"
		exit 1
	}

	current="$(cat "$ipcfg" 2>/dev/null)"

	[ -n "$current" ] || {
		# A dropped data call normally comes back within seconds, and sitting it
		# out is far cheaper than having netifd rebuild the interface and the
		# modem session, so only give up once it stays away.
		lost=$((lost + 5))
		[ "$lost" -lt "$grace" ] && continue

		echo "The data call of $interface stayed down for ${lost}s"
		exit 1
	}

	lost=0
	[ "$current" = "$seen" ] && continue
	seen="$current"

	echo "Reconfiguring $interface, the network handed out new settings"
	quectel_send_ipcfg "$interface" "$ifname" "$ipcfg"
done
