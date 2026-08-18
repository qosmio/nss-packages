#!/bin/sh
# shellcheck shell=busybox disable=1091,3043,2166,3037,3036

[ -n "$INCLUDE_ONLY" ] || {
	. /lib/functions.sh
	. ../netifd-proto.sh
	init_proto "$@"
}

QUECTEL_CM="/usr/bin/quectel-cm"
QUECTEL_QMI_PROXY="/usr/bin/quectel-qmi-proxy"
# The control device quectel-qmi-proxy opens when it is not told which one to use.
QUECTEL_QMI_PROXY_DEV="/dev/cdc-wdm0"
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
#
# A modem that has just come back from a reset exposes its ports before its
# firmware answers on them, so a single sweep finds nothing and the initialisation
# below is skipped on exactly the run that needs it most. Keep sweeping until one
# of them replies. Each unanswered port costs a read timeout of its own, so the
# deadline is measured rather than counted in iterations.
quectel_find_at_device() {
	local timeout="$1" atdevice deadline

	command -v sms_tool >/dev/null || {
		[ -c /dev/ttyUSB2 ] && echo "/dev/ttyUSB2"
		return
	}

	deadline="$(($(date +%s) + timeout))"

	while :; do
		for atdevice in /dev/ttyUSB2 /dev/ttyUSB3 /dev/ttyUSB1 /dev/ttyUSB0 /dev/ttyACM0; do
			[ -c "$atdevice" ] || continue
			quectel_at "$atdevice" "AT" && {
				echo "$atdevice"
				return 0
			}
		done

		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 1
	done
}

# Same for a port named in the configuration: it is gone for as long as the modem
# is, and it accepts commands later still.
quectel_wait_at_device() {
	local atdevice="$1" timeout="$2" deadline

	deadline="$(($(date +%s) + timeout))"

	while :; do
		[ -c "$atdevice" ] && quectel_at "$atdevice" "AT" && return 0
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 1
	done
}

# quectel-cm reaches the proxy over an abstract socket named after the last
# character of the control device, so the instance that serves this modem is the
# one holding *this* node - not just any quectel-qmi-proxy that happens to run.
quectel_proxy_holds() {
	local pid="$1" device="$2" fd

	for fd in "/proc/$pid/fd/"*; do
		[ "$(readlink -f "$fd" 2>/dev/null)" = "$device" ] && return 0
	done

	return 1
}

quectel_proxy_ready() {
	local device="$1" pid

	for pid in $(pidof quectel-qmi-proxy 2>/dev/null); do
		quectel_proxy_holds "$pid" "$device" && return 0
	done

	return 1
}

# An instance left from before a reset keeps reopening the node it was given every
# few seconds and keeps serving the socket name derived from it, so it both holds
# the device away from its replacement and answers under its name. It has to go.
# An instance driving a second modem has a device of its own and is left alone.
quectel_stop_proxy() {
	local device="$1" pid args

	for pid in $(pidof quectel-qmi-proxy 2>/dev/null); do
		args=" $(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null)"

		case "$args" in
		*" -d $device "*) ;;
		*" -d "*) quectel_proxy_holds "$pid" "$device" || continue ;;
		# Started without -d, so it is on the built-in default: what older
		# versions of this script left running, and still this modem's proxy
		# when this modem is the one that default names.
		*)
			[ "$device" = "$QUECTEL_QMI_PROXY_DEV" ] ||
				quectel_proxy_holds "$pid" "$device" || continue
			;;
		esac

		kill "$pid" 2>/dev/null
	done
}

# Name the device explicitly. Started without it the proxy opens /dev/cdc-wdm0
# whatever this modem actually is, so a second modem - or a first one that came
# back from a reset on a different node - was served under a socket name
# quectel-cm never looks for, and setup waited out its timeout and failed.
quectel_start_proxy() {
	local device="$1" waited=0

	quectel_proxy_ready "$device" && return 0

	quectel_stop_proxy "$device"
	"$QUECTEL_QMI_PROXY" -d "$device" &

	while [ "$waited" -lt 10 ]; do
		sleep 1
		waited=$((waited + 1))
		quectel_proxy_ready "$device" && return 0
	done

	return 1
}

# Only touch the processes started for this interface: a second modem, driven by
# another interface, has its own quectel-cm that has to keep running.
#
# Wait for them to be gone rather than merely signalled. The kernel hands a
# cdc-wdm minor back only once the last descriptor on it is closed, so a
# quectel-cm that outlives the modem's reset keeps the old node allocated and the
# modem returns as the *next* one up - leaving the node named in the
# configuration missing for good. One that lost its modem mid-transaction is also
# the one most likely to take its time going, so do not let it take forever.
quectel_stop_instances() {
	local interface="$1"
	local pidfile="$QUECTEL_RUN_DIR/$interface.pids" pids="" pid alive waited=0

	[ -f "$pidfile" ] && {
		for pid in $(cat "$pidfile"); do
			[ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$QUECTEL_CM" ] || continue
			kill "$pid" 2>/dev/null
			pids="$pids $pid"
		done
		rm -f "$pidfile"
	}

	while [ "$waited" -lt 5 ]; do
		alive=""
		for pid in $pids; do
			[ -d "/proc/$pid" ] && alive=1
		done
		[ -n "$alive" ] || break

		sleep 1
		waited=$((waited + 1))
	done

	for pid in $pids; do
		[ -d "/proc/$pid" ] && {
			echo "quectel-cm ($pid) did not stop, killing it"
			kill -9 "$pid" 2>/dev/null
		}
	done

	rm -f "$QUECTEL_RUN_DIR/$interface".ipcfg*

	return 0
}

# ------------------------------------------------------------ modem probing ---

# The netcard is a sibling of the control device - both hang off the same USB
# interface - so walk up from the node rather than guessing a name. Going through
# whichever class the node belongs to rather than through /sys/class/usbmisc also
# covers the GobiQMI nodes of the out-of-tree driver.
quectel_netdev() {
	local device="$1" devname sysdev netdev

	devname="$(basename "$device")"

	for sysdev in "/sys/class/"*"/$devname/device"; do
		[ -e "$sysdev" ] || continue

		# shellcheck disable=2012 # ls is what busybox has for reading a dir
		netdev="$(ls "$(readlink -f "$sysdev")/net" 2>/dev/null | head -n 1)"
		[ -n "$netdev" ] || continue

		echo "$netdev"
		return 0
	done

	return 1
}

# A reset - "AT+CFUN=1,1", a firmware crash, the modem being power cycled - takes
# the device off the bus and puts it back the better part of a minute later.
# netifd runs setup again as soon as the interface goes down, which is long before
# that, so this is what decides whether a reset is a reconnect or a dead
# interface. Both the control node and the netcard appear when the driver binds,
# but not necessarily in the same instant, so wait for the pair.
quectel_wait_modem() {
	local device="$1" timeout="$2" waited=0 ifname

	while :; do
		ifname="$(quectel_netdev "$device")" && [ -c "$device" ] && {
			echo "$ifname"
			return 0
		}

		[ "$waited" -lt "$timeout" ] || return 1
		[ "$waited" = 0 ] &&
			echo "Waiting up to ${timeout}s for the modem on $device" >&2

		sleep 1
		waited=$((waited + 1))
	done
}

# The kernel hands out the lowest free cdc-wdm minor, so as long as nothing holds
# the old node open the modem comes back as the same one, and everything this
# proto starts is stopped before the wait for exactly that reason. It cannot do
# anything about the rest of the system though, and a node held by something else
# moves the modem one along, leaving the configured name pointing at nothing.
# Recognise that rather than reporting a modem that is plainly there as missing -
# but only when there is a single candidate, because with two modems on the box
# guessing would attach this interface to the wrong one.
quectel_find_control_device() {
	local candidate found=""

	for candidate in /dev/cdc-wdm*; do
		[ -c "$candidate" ] || continue
		quectel_netdev "$candidate" >/dev/null || continue
		[ -n "$found" ] && return 1
		found="$candidate"
	done

	[ -n "$found" ] || return 1

	echo "$found"
}

# With data aggregation on, the data call lands on a QMAP child of the netcard,
# and the driver creates it a moment after the parent. Deciding before it is there
# sends the call to the base netdev, where it comes up and carries nothing, so ask
# the driver whether there is a child to wait for at all.
quectel_wait_qmap() {
	local ifname="$1" timeout="$2" param mode waited=0

	for param in \
		"/sys/class/net/$ifname/qmap_mode" \
		"/sys/class/net/$ifname/device/driver/module/parameters/qmap_mode"; do
		[ -r "$param" ] && break
	done

	# No such knob: a driver that does not aggregate, so the base netdev is where
	# the call lands and there is nothing to wait for.
	[ -r "$param" ] || return 1

	mode="$(cat "$param" 2>/dev/null)"
	case "$mode" in
	"" | 0 | *[!0-9]*) return 1 ;;
	esac

	while [ "$waited" -lt "$timeout" ]; do
		[ -r "/sys/class/net/${ifname}_1" ] && return 0

		sleep 1
		waited=$((waited + 1))
	done

	echo "The driver aggregates data but never created ${ifname}_1"

	return 1
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

# ------------------------------------------------------------- passthrough ---
#
# The carrier's single address belongs to the one host behind the modem, not to
# this router. It is handed over by *routing* it to the host rather than bridging:
# a raw-IP cellular link has no ethernet to be transparent about, so nothing is
# really lost, and the QMAP netcard keeps the raw-IP form that the rmnet-nss fast
# path requires - which a Linux bridge would have taken away from it.

# Rebuilding the passthrough - a dhcp server that hands the host this address,
# and whatever has to happen to the port it sits on - is not this package's
# business, and hardcoding the name of the thing that does it would be worse.
# Announce that there is something to rebuild and let whoever subscribed do it.
quectel_notify() {
	local action="$1" interface="$2" datadev="$3" ipcfg="$4"

	[ -x /sbin/hotplug-call ] || return 0

	ACTION="$action" INTERFACE="$interface" DEVICE="$datadev" IPCFG="$ipcfg" \
		/sbin/hotplug-call quectel
}

# The one thing that must not happen is assigning the address here. It belongs to
# the host; put it on this interface as well and the kernel delivers packets for it
# locally instead of forwarding them on, which looks like the passthrough silently
# swallowing all inbound traffic.
quectel_send_passthrough() {
	local interface="$1" datadev="$2" ipcfg="$3" address="$4"

	[ -n "$address" ] || {
		echo "The data call came up without an IPv4 address, so there is nothing to pass through"
		return 1
	}

	echo "Passing $address through to the host, routed"

	proto_init_update "$datadev" 1

	# No gateway: the modem link is raw IP with no L2 and the netcard is NOARP, so
	# the device *is* the next hop. And no dns, because with no address of its own
	# this router cannot originate traffic anyway - the host resolves for itself
	# from the servers the dhcp server hands it.
	[ "$defaultroute" = 0 ] || proto_add_ipv4_route "0.0.0.0" 0

	proto_send_update "$interface"

	quectel_notify passthrough "$interface" "$datadev" "$ipcfg"
}

# Apply what the modem negotiated to the interface itself. Everything lands on
# the one netifd interface, so ifstatus, the firewall and the routing metric all
# refer to the same thing instead of to a dynamically spawned side interface.
quectel_send_ipcfg() {
	local interface="$1" ifname="$2" ipcfg="$3" passthrough="$4"
	local IFNAME IPV4_ADDRESS IPV4_NETMASK IPV4_PREFIX IPV4_GATEWAY IPV4_MTU IPV4_DNS
	local IPV6_ADDRESS IPV6_PREFIX IPV6_GATEWAY IPV6_MTU IPV6_DNS
	local dns

	[ -f "$ipcfg" ] || return 1
	. "$ipcfg"

	# Both the first setup and every handover after it come through here, so the
	# passthrough only has to be taught once.
	[ "$passthrough" = 1 ] && {
		quectel_send_passthrough "$interface" "$ifname" "$ipcfg" "$IPV4_ADDRESS"
		return $?
	}

	# Deliberately no proto_set_keep here. This runs again for every data call
	# the modem re-establishes, and "keep" tells netifd to hold on to what it
	# configured last time, so a handover would leave the address and the routes
	# of every previous call behind instead of replacing them.
	proto_init_update "$ifname" 1

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
		# RFC 7278: hand the /64 the modem got on to the LAN.
		#
		# The carrier issues a fresh /64 for every data call, and a prefix that
		# stops being advertised is kept alive for the rest of its valid
		# lifetime so that clients can migrate off it gracefully. Announcing the
		# multi-hour default for a prefix that only lasts until the next
		# handover therefore parks one deprecated prefix per reconnect on the
		# LAN, so announce only what a link that renumbers this often can
		# actually promise.
		#
		# proto_add_ipv6_prefix names its two lifetimes "valid" then
		# "preferred", but the string it builds is read back as
		# addr/length,preferred,valid, so the shorter one goes first.
		proto_add_ipv6_prefix "$IPV6_ADDRESS/$IPV6_PREFIX" \
			"$((prefixlifetime / 2))" "$prefixlifetime"
		proto_add_ipv6_route "$IPV6_GATEWAY" 128
		[ "$defaultroute" = 0 ] || {
			# A default route restricted to the delegated prefix is one the
			# router cannot use itself: the route lookup of a socket that has
			# not bound a source yet matches nothing and fails outright with
			# "network unreachable", even though the link is perfectly fine.
			# The modem is normally the only way off this box, so restrict the
			# route only when asked, for setups where a second wan needs the
			# source prefix to decide which uplink a packet leaves by.
			if [ "$sourcefilter" = 1 ]; then
				proto_add_ipv6_route "::" 0 "$IPV6_GATEWAY" "" "" \
					"$IPV6_ADDRESS/$IPV6_PREFIX"
			else
				proto_add_ipv6_route "::" 0 "$IPV6_GATEWAY"
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
	proto_config_add_int "devicetimeout"
	proto_config_add_int "timeout"
	proto_config_add_string "pdptype"
	proto_config_add_boolean "passthrough"
	proto_config_add_boolean "sourcefilter"
	proto_config_add_int "prefixlifetime"
	proto_config_add_boolean "delegate"
	proto_config_add_int "mtu"
	proto_config_add_array 'cell_lock_4g:list(string)'
	proto_config_add_defaults
}

proto_quectel_setup() {
	local interface="$1"
	local device atdevice apn apnv6 auth username password pincode delay timeout
	local pdptype pdnindex pdnindexv6 multiplexing prefixlifetime passthrough
	# shellcheck disable=2034,2086 # allow unused and word splitting
	local cell_lock_4g sourcefilter delegate mtu $PROTO_DEFAULT_OPTIONS
	local ip6table zone devicetimeout
	local ifname ifname4 ifname6 moved
	local want_v4 want_v6 ipcfg ipcfg6 link_ifname link_pid
	local idx cell_lock cell_ids pci earfcn

	json_get_vars device atdevice apn apnv6 auth username password pincode delay timeout
	json_get_vars pdnindex pdnindexv6 multiplexing devicetimeout
	json_get_vars pdptype passthrough sourcefilter delegate ip6table prefixlifetime
	# shellcheck disable=2086 # allow word splitting
	json_get_vars mtu $PROTO_DEFAULT_OPTIONS

	[ -n "$delay" ] || delay="5"
	[ -n "$timeout" ] || timeout="60"
	[ -n "$devicetimeout" ] || devicetimeout="40"
	[ -n "$auth" ] || auth="none"
	[ -n "$prefixlifetime" ] || prefixlifetime="1800"
	[ -z "$ctl_device" ] || device="$ctl_device"

	# LuCI leaves out an option that still holds its form default, so an empty
	# pdptype is the "IPv4/IPv6" the user selected, not an unconfigured modem.
	# Treating it as neither used to leave the interface without any address.
	[ -n "$pdptype" ] || pdptype="ipv4v6"

	# IPv4 only, for now, because that is all the routed passthrough hands over: the
	# host route, the /32 and the dhcp offer are all v4. Unlike the old bridge mode
	# this is a limit of *this code* rather than of the hardware - the carrier's /64
	# could be delegated to the host's port the way the proto already delegates it
	# to the LAN - so ask the network for one family rather than dialling a second
	# call whose address nothing would yet use.
	if [ "$passthrough" = 1 ]; then
		[ "$pdptype" = "ipv4" ] || {
			echo "The passthrough is IPv4 only; asking for an IPv4 data call"
			pdptype="ipv4"
		}

		# One address, one host, one channel: a second data call would land on a
		# netcard the passthrough does not route to, so it would come up and carry
		# nothing.
		[ "$multiplexing" = 1 ] && {
			echo "The passthrough drives the first QMAP channel only; ignoring IP multiplexing"
			multiplexing=0
		}
	fi

	# The one genuinely unrecoverable case: nothing was configured, so there is
	# nothing to wait for and no event that could ever make this interface work.
	# Everything below is instead a modem that is on its way back, and marking the
	# interface unavailable for one of those is what turned a reset into a dead
	# interface: netifd refuses to set up an unavailable interface, and with
	# no_device=1 nothing ever marks it available again, so not even "ifup" got
	# the modem back - only reloading the network configuration did.
	[ -n "$device" ] || {
		echo "No control device specified"
		proto_notify_error "$interface" NO_DEVICE
		proto_set_available "$interface" 0
		return 1
	}

	# Not with -f: the node is routinely absent at this point, and canonicalising
	# a path that is not there fails and yields nothing at all.
	[ -e "$device" ] && device="$(readlink -f "$device")"

	mkdir -p "$QUECTEL_RUN_DIR"

	# Before waiting, not after: while one of these still holds the old node open
	# the kernel cannot hand its minor back, and the modem returns as the next
	# node up instead of as the one named in the configuration.
	quectel_stop_instances "$interface"

	ifname="$(quectel_wait_modem "$device" "$devicetimeout")"

	# The configured node never came back. Before reporting the modem missing,
	# check whether it is on the box under a different one.
	[ -n "$ifname" ] || {
		moved="$(quectel_find_control_device)"
		[ -n "$moved" ] && ifname="$(quectel_netdev "$moved")"

		[ -n "$ifname" ] && {
			echo "The modem came back as $moved, not as the configured $device"
			device="$moved"
		}
	}

	# Return without marking the interface unavailable: netifd sets an interface
	# whose setup failed up again, so this is what retries, at the pace of the
	# wait above, until the modem is back.
	[ -n "$ifname" ] || {
		echo "No modem on $device after ${devicetimeout}s"
		proto_notify_error "$interface" NO_DEVICE
		return 1
	}

	sleep "$delay"

	if [ -n "$atdevice" ]; then
		quectel_wait_at_device "$atdevice" "$delay" ||
			echo "The configured AT port $atdevice is not answering"
	else
		atdevice="$(quectel_find_at_device "$delay")"
	fi

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
	# Modems running without it (qmap_mode=0) carry it on the base netdev. The
	# child is created a moment after its parent, so ask the driver whether one is
	# coming rather than reading the answer off a directory that is still filling
	# up - which after a reset gave the base netdev and a data call that came up
	# on a device carrying nothing.
	ifname4="$ifname"
	quectel_wait_qmap "$ifname" 10 && ifname4="${ifname}_1"
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
	quectel_send_ipcfg "$interface" "$link_ifname" "$ipcfg" "$passthrough" || {
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
		"$defaultroute" "$peerdns" "$sourcefilter" "$prefixlifetime" \
		"$passthrough" "$device"

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
	local device

	json_get_vars device
	[ -e "$device" ] && device="$(readlink -f "$device")"

	echo "Stopping network $interface"

	# netifd has already stopped the monitor it owns by the time it gets here.
	# This waits for quectel-cm to be gone rather than just signalled.
	quectel_stop_instances "$interface"

	proto_init_update "*" 0
	proto_send_update "$interface"

	# Release the control device here rather than leaving it to whoever comes
	# next. A teardown is most often a modem that has just reset, and the kernel
	# hands a cdc-wdm minor back only once the last descriptor on it is closed -
	# so a proxy still holding it makes the modem reappear one node along, under a
	# name no configuration mentions. The proxy is per device, so a second modem
	# keeps the instance serving its own node.
	[ -n "$device" ] && quectel_stop_proxy "$device"

	return 0
}

[ -n "$INCLUDE_ONLY" ] || {
	add_protocol quectel
}
