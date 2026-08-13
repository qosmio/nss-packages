#!/bin/sh
# shellcheck shell=busybox disable=1091,3043,2166,3037,3036

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

QUECTEL_CM="/usr/bin/quectel-cm"
QUECTEL_QMI_PROXY="/usr/bin/quectel-qmi-proxy"
QUECTEL_RUN_DIR="/var/run/quectel"

# Send a single AT command, discarding the response. sms_tool enforces its own
# read timeout, so a silent or wrong port costs a couple of seconds instead of
# blocking the setup script forever.
quectel_at() {
	local atdevice="$1" cmd="$2"

	[ -c "$atdevice" ] || return 1

	if command -v sms_tool >/dev/null; then
		sms_tool -d "$atdevice" at "$cmd" >/dev/null 2>&1
	else
		printf '%s\r\n' "$cmd" >"$atdevice" 2>/dev/null
	fi
}

# The AT port cannot be derived from the QMI control device, so probe the ports
# in the order Quectel modules usually expose them. Without sms_tool there is no
# way to read a reply, so fall back to the port AT sits on for nearly all of them.
quectel_find_at_device() {
	local atdevice

	command -v sms_tool >/dev/null || {
		[ -c /dev/ttyUSB2 ] && echo "/dev/ttyUSB2"
		return
	}

	for atdevice in /dev/ttyUSB2 /dev/ttyUSB3 /dev/ttyUSB1 /dev/ttyUSB0 /dev/ttyACM0; do
		[ -c "$atdevice" ] || continue
		quectel_at "$atdevice" "AT" && {
			echo "$atdevice"
			return 0
		}
	done

	return 1
}

# quectel-cm locates the proxy by scanning /proc for the process holding the
# cdc-wdm descriptor, so the proxy has to own the device before it is started.
quectel_proxy_ready() {
	local device="$1" pid fd

	for pid in $(pidof quectel-qmi-proxy 2>/dev/null); do
		for fd in "/proc/$pid/fd/"*; do
			[ "$(readlink -f "$fd" 2>/dev/null)" = "$device" ] && return 0
		done
	done

	return 1
}

quectel_start_proxy() {
	local device="$1" waited=0

	quectel_proxy_ready "$device" && return 0

	if ! pidof quectel-qmi-proxy >/dev/null; then
		"$QUECTEL_QMI_PROXY" &
	fi

	while [ "$waited" -lt 10 ]; do
		sleep 1
		waited=$((waited + 1))
		quectel_proxy_ready "$device" && return 0
	done

	return 1
}

# Only touch the processes started for this interface: a second modem, driven by
# another interface, has its own quectel-cm that has to keep running.
quectel_stop_instances() {
	local interface="$1"
	local pidfile="$QUECTEL_RUN_DIR/$interface.pids" pid

	[ -f "$pidfile" ] && {
		for pid in $(cat "$pidfile"); do
			[ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$QUECTEL_CM" ] || continue
			kill "$pid" 2>/dev/null
		done
		rm -f "$pidfile"
	}

	rm -f "$QUECTEL_RUN_DIR/$interface".ipcfg*

	return 0
}

# quectel-cm parses the operands of -s positionally and bails out with its usage
# screen on an empty argument, so append only what is actually configured and
# keep -s last so its operands stay contiguous.
quectel_start_cm() {
	local interface="$1" apn="$2"

	shift 2

	[ -n "$apn" ] && {
		set -- "$@" -s "$apn"
		[ "$auth" != "none" ] && [ -n "$username" ] &&
			set -- "$@" "$username" "$password" "$auth"
	}

	"$QUECTEL_CM" "$@" &
	QUECTEL_CM_PID="$!"

	mkdir -p "$QUECTEL_RUN_DIR"
	echo "$QUECTEL_CM_PID" >>"$QUECTEL_RUN_DIR/$interface.pids"
	echo "Started quectel-cm ($QUECTEL_CM_PID): $*"
}

# quectel-cm writes the settings the network handed out once the data call is up
# and removes them again when it drops, so the file is both the readiness signal
# and the configuration source.
quectel_wait_ipcfg() {
	local ipcfg="$1" timeout="$2" pid="$3" waited=0

	while [ "$waited" -lt "$timeout" ]; do
		[ -f "$ipcfg" ] && return 0
		[ -d "/proc/$pid" ] || return 1

		sleep 1
		waited=$((waited + 1))
	done

	return 1
}

# Apply what the modem negotiated to the interface itself. Everything lands on
# the one netifd interface, so ifstatus, the firewall and the routing metric all
# refer to the same thing instead of to a dynamically spawned side interface.
quectel_send_ipcfg() {
	local interface="$1" ifname="$2" ipcfg="$3"
	local IFNAME IPV4_ADDRESS IPV4_NETMASK IPV4_PREFIX IPV4_GATEWAY IPV4_MTU IPV4_DNS
	local IPV6_ADDRESS IPV6_PREFIX IPV6_GATEWAY IPV6_MTU IPV6_DNS
	local dns

	[ -f "$ipcfg" ] || return 1
	. "$ipcfg"

	proto_init_update "$ifname" 1
	proto_set_keep 1

	[ -n "$IPV4_ADDRESS" ] && {
		proto_add_ipv4_address "$IPV4_ADDRESS" "$IPV4_PREFIX"
		# Carriers routinely place the gateway outside the assigned subnet, so
		# give it a host route of its own before relying on it as the next hop.
		proto_add_ipv4_route "$IPV4_GATEWAY" 32
		[ "$defaultroute" = 0 ] || proto_add_ipv4_route "0.0.0.0" 0 "$IPV4_GATEWAY"
		[ "$peerdns" = 0 ] || for dns in $IPV4_DNS; do proto_add_dns_server "$dns"; done
	}

	[ -n "$IPV6_ADDRESS" ] && {
		proto_add_ipv6_address "$IPV6_ADDRESS" 128
		# RFC 7278: hand the /64 the modem got on to the LAN
		proto_add_ipv6_prefix "$IPV6_ADDRESS/$IPV6_PREFIX"
		proto_add_ipv6_route "$IPV6_GATEWAY" 128
		[ "$defaultroute" = 0 ] || {
			# Restricting the default route to the delegated prefix keeps a
			# second wan from picking it up, at the cost of the router itself
			# no longer finding a route when it has not bound a source yet.
			if [ "$sourcefilter" = 0 ]; then
				proto_add_ipv6_route "::" 0 "$IPV6_GATEWAY"
			else
				proto_add_ipv6_route "::" 0 "$IPV6_GATEWAY" "" "" \
					"$IPV6_ADDRESS/$IPV6_PREFIX"
			fi
		}
		[ "$peerdns" = 0 ] || for dns in $IPV6_DNS; do proto_add_dns_server "$dns"; done
	}

	proto_send_update "$interface"
}

proto_quectel_init_config() {
	available=1
	no_device=1
	proto_config_add_string "device:device"
	proto_config_add_string "atdevice"
	proto_config_add_boolean "multiplexing"
	proto_config_add_string "apn"
	proto_config_add_string "apnv6"
	proto_config_add_string "pdnindex"
	proto_config_add_string "pdnindexv6"
	proto_config_add_string "auth"
	proto_config_add_string "username"
	proto_config_add_string "password"
	proto_config_add_string "pincode"
	proto_config_add_int "delay"
	proto_config_add_int "timeout"
	proto_config_add_string "pdptype"
	proto_config_add_boolean "sourcefilter"
	proto_config_add_boolean "delegate"
	proto_config_add_int "mtu"
	proto_config_add_array 'cell_lock_4g:list(string)'
	proto_config_add_defaults
}

proto_quectel_setup() {
	local interface="$1"
	local device atdevice apn apnv6 auth username password pincode delay timeout
	local pdptype pdnindex pdnindexv6 multiplexing
	# shellcheck disable=2034,2086 # allow unused and word splitting
	local cell_lock_4g sourcefilter delegate mtu $PROTO_DEFAULT_OPTIONS
	local ip6table zone
	local devname devpath ifname ifname4 ifname6
	local want_v4 want_v6 ipcfg ipcfg6 link_ifname link_pid
	local idx cell_lock cell_ids pci earfcn

	json_get_vars device atdevice apn apnv6 auth username password pincode delay timeout
	json_get_vars pdnindex pdnindexv6 multiplexing
	json_get_vars pdptype sourcefilter delegate ip6table
	# shellcheck disable=2086 # allow word splitting
	json_get_vars mtu $PROTO_DEFAULT_OPTIONS

	[ -n "$delay" ] || delay="5"
	[ -n "$timeout" ] || timeout="60"
	[ -n "$auth" ] || auth="none"
	[ -z "$ctl_device" ] || device="$ctl_device"

	# LuCI leaves out an option that still holds its form default, so an empty
	# pdptype is the "IPv4/IPv6" the user selected, not an unconfigured modem.
	# Treating it as neither used to leave the interface without any address.
	[ -n "$pdptype" ] || pdptype="ipv4v6"

	[ -n "$device" ] || {
		echo "No control device specified"
		proto_notify_error "$interface" NO_DEVICE
		proto_set_available "$interface" 0
		return 1
	}

	device="$(readlink -f "$device")"
	[ -c "$device" ] || {
		echo "The specified control device does not exist"
		proto_notify_error "$interface" NO_DEVICE
		proto_set_available "$interface" 0
		return 1
	}

	devname="$(basename "$device")"
	devpath="$(readlink -f "/sys/class/usbmisc/$devname/device/")"
	# shellcheck disable=2012
	ifname="$(ls "$devpath/net" 2>"/dev/null" | head -n 1)"
	[ -n "$ifname" ] || {
		echo "The interface could not be found."
		proto_notify_error "$interface" NO_IFACE
		proto_set_available "$interface" 0
		return 1
	}

	sleep "$delay"

	[ -n "$atdevice" ] || atdevice="$(quectel_find_at_device)"
	if [ -c "$atdevice" ]; then
		quectel_at "$atdevice" "AT+CFUN=1"
	else
		echo "No AT port found, skipping modem initialisation"
	fi

	if json_is_a cell_lock_4g array; then
		echo "4G Cell ID Locking"
		json_select cell_lock_4g
		idx=1
		cell_ids=""

		while json_is_a ${idx} string; do
			json_get_var cell_lock $idx
			# shellcheck disable=2154 # cell_lock is assigned and used
			pci="${cell_lock%%,*}"
			earfcn="${cell_lock##*,}"
			cell_ids="$cell_ids,$earfcn,$pci"
			idx=$((idx + 1))
		done
		idx=$((idx - 1))
		json_select ..

		if [ "$idx" -gt 0 ]; then
			quectel_at "$atdevice" "AT+QNWLOCK=\"COMMON/4G\",${idx}${cell_ids}" ||
				echo "Failed to apply the 4G cell lock"
		fi
	else
		quectel_at "$atdevice" 'AT+QNWLOCK="COMMON/4G",0'
	fi

	case "$pdptype" in
	ipv4) want_v4=1 ;;
	ipv6) want_v6=1 ;;
	*) want_v4=1; want_v6=1 ;;
	esac

	# The data call lands on the QMAP/RMNET child when data aggregation is on.
	# Modems running without it (qmap_mode=0) carry it on the base netdev.
	ifname4="$ifname"
	[ -r "/sys/class/net/${ifname}_1" ] && ifname4="${ifname}_1"
	ifname6="$ifname4"

	if [ "$multiplexing" = 1 ]; then
		if [ -r "/sys/class/net/${ifname}_2" ]; then
			ifname6="${ifname}_2"
		else
			echo "IP multiplexing needs a second QMAP channel, load the driver with qmap_mode=2 or higher"
			proto_notify_error "$interface" NO_IFACE
			return 1
		fi
	fi

	quectel_start_proxy "$device" || {
		echo "quectel-qmi-proxy did not take ownership of $device"
		proto_notify_error "$interface" NO_DEVICE
		return 1
	}

	quectel_stop_instances "$interface"
	mkdir -p "$QUECTEL_RUN_DIR"
	ipcfg="$QUECTEL_RUN_DIR/$interface.ipcfg"
	ipcfg6="$QUECTEL_RUN_DIR/$interface.ipcfg6"

	# Build the argument list positionally. Passing "$ipv4opt"/"$ipv6opt" the way
	# this script used to handed quectel-cm an empty argument for every unused
	# family, which it answers with its usage screen and an immediate exit, so no
	# data call was ever set up for a single-stack pdptype.
	#
	# -N keeps quectel-cm from configuring the host itself; its built-in udhcpc
	# would install a second address and a metric-less default route that netifd
	# can neither order nor clean up again. -w has it report what it negotiated
	# instead, which is what gets applied to the interface below.
	set -- -i "$ifname" -N
	[ -n "$pincode" ] && set -- "$@" -p "$pincode"

	if [ "$multiplexing" = 1 ]; then
		[ -n "$pdnindex" ] || pdnindex="1"
		[ -n "$pdnindexv6" ] || pdnindexv6="2"

		if [ "$want_v4" = 1 ]; then
			quectel_start_cm "$interface" "$apn" "$@" -4 \
				-n "$pdnindex" -m 1 -w "$ipcfg"
			link_ifname="$ifname4"
			link_pid="$QUECTEL_CM_PID"
		fi
		if [ "$want_v6" = 1 ]; then
			# whichever call the interface itself carries writes $ipcfg; a
			# second one lands on its own QMAP channel and reports separately
			[ -n "$link_ifname" ] || ipcfg6="$ipcfg"

			quectel_start_cm "$interface" "${apnv6:-$apn}" "$@" -6 \
				-n "$pdnindexv6" -m 2 -w "$ipcfg6"
			[ -n "$link_ifname" ] || {
				link_ifname="$ifname6"
				link_pid="$QUECTEL_CM_PID"
			}
		fi
	else
		[ "$want_v4" = 1 ] && set -- "$@" -4
		[ "$want_v6" = 1 ] && set -- "$@" -6

		quectel_start_cm "$interface" "$apn" "$@" -w "$ipcfg"
		link_pid="$QUECTEL_CM_PID"
		[ "$want_v4" = 1 ] && link_ifname="$ifname4" || link_ifname="$ifname6"
	fi

	quectel_wait_ipcfg "$ipcfg" "$timeout" "$link_pid" || {
		echo "The modem did not establish a data call within ${timeout}s"
		quectel_stop_instances "$interface"
		proto_notify_error "$interface" CALL_FAILED
		return 1
	}

	if [ -n "$mtu" ]; then
		echo "Setting MTU to $mtu"
		ip link set dev "$ifname4" mtu "$mtu"
		[ "$ifname6" = "$ifname4" ] || ip link set dev "$ifname6" mtu "$mtu"
	fi

	echo "Setting up $link_ifname"
	quectel_send_ipcfg "$interface" "$link_ifname" "$ipcfg" || {
		echo "The modem reported no usable settings"
		quectel_stop_instances "$interface"
		proto_notify_error "$interface" CALL_FAILED
		return 1
	}

	# Hand netifd a proto task that watches for further changes. Without a dhcp
	# client of its own on this interface there is nothing else that would
	# notice a data call re-established on a different address, and letting
	# netifd own the watcher means its exit drives the teardown and the retry.
	proto_run_command "$interface" /usr/share/quectel/quectel-monitor \
		"$interface" "$link_ifname" "$ipcfg" "$link_pid" "$timeout" \
		"$defaultroute" "$peerdns" "$sourcefilter"

	# A netifd interface has exactly one l3 device, so the second data call of a
	# multiplexed setup, which lands on its own QMAP channel, still needs an
	# interface of its own to carry its addresses.
	[ "$multiplexing" = 1 ] && [ "$want_v4" = 1 ] && [ "$want_v6" = 1 ] && {
		zone="$(fw3 -q network "$interface" 2>/dev/null)"

		json_init
		json_add_string name "${interface}_6"
		json_add_string device "$ifname6"
		json_add_string proto "dhcpv6"
		proto_add_dynamic_defaults
		[ -z "$ip6table" ] || json_add_string ip6table "$ip6table"
		json_add_string extendprefix 1
		[ "$delegate" = "0" ] && json_add_boolean delegate "0"
		[ "$sourcefilter" = "0" ] && json_add_boolean sourcefilter "0"
		[ -z "$zone" ] || json_add_string zone "$zone"
		json_close_object
		ubus call network add_dynamic "$(json_dump)"
	}

	return 0
}

proto_quectel_teardown() {
	local interface="$1"
	local waited=0

	echo "Stopping network $interface"

	# netifd has already stopped the monitor it owns by the time it gets here
	quectel_stop_instances "$interface"

	proto_init_update "*" 0
	proto_send_update "$interface"

	while [ "$waited" -lt 5 ] && pidof quectel-cm >/dev/null; do
		sleep 1
		waited=$((waited + 1))
	done

	# The proxy is shared by every modem on the box, so it may only be stopped
	# once the last quectel-cm that could be using it is gone.
	pidof quectel-cm >/dev/null || killall quectel-qmi-proxy 2>/dev/null

	return 0
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol quectel
}
