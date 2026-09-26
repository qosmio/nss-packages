#!/bin/sh
# shellcheck shell=busybox disable=1091,3043
#
# Announce the carrier's NAT64 prefix to the LAN as the PREF64 option of the
# router advertisements (RFC 8781), which is what lets a client switch on the
# CLAT it already ships with. Android, iOS, macOS and Windows 11 all do; each of
# them then translates its own IPv4 traffic into the carrier's NAT64 and this
# router keeps forwarding plain IPv6, so nothing is inserted into the datapath
# and the NSS fast path is untouched.
#
# This is the subscriber to what the quectel proto announces, kept apart from it
# so that a setup with its own idea of how the LAN should be told - or with no
# use for being told at all - can replace or delete this file without patching
# the protocol handler.

[ "$ACTION" = nat64 ] || [ "$ACTION" = nat64_stop ] || exit 0

. /lib/functions.sh

# nat64_stop withdraws the prefix, and so does an announcement that carries none.
prefix=""
[ "$ACTION" = nat64 ] && prefix="$PREFIX"

changed=0

# odhcpd reads ra_pref64 from the dhcp configuration, and only interfaces that
# actually send router advertisements can carry the option, so leave the rest
# alone. The interface the modem is on is one of the rest: the announcement
# describes what lies beyond it, not something to advertise back into it.
handle_dhcp() {
	local section="$1" prefix="$2"
	local network ra current

	config_get network "$section" interface
	config_get ra "$section" ra
	config_get current "$section" ra_pref64

	[ -n "$network" ] || return 0
	[ "$network" = "$INTERFACE" ] && return 0

	case "$ra" in
	server | hybrid) ;;
	*) return 0 ;;
	esac

	[ "$current" = "$prefix" ] && return 0

	# Only when it differs. This runs again on every reconnect, and a carrier
	# does not change its NAT64 prefix between them, so writing unconditionally
	# would spend a flash erase on saying the same thing.
	if [ -n "$prefix" ]; then
		uci -q set "dhcp.$section.ra_pref64=$prefix"
		logger -t quectel-nat64 "announcing NAT64 prefix $prefix on $network"
	else
		uci -q delete "dhcp.$section.ra_pref64"
		logger -t quectel-nat64 "withdrawing the NAT64 prefix from $network"
	fi

	changed=1
}

config_load dhcp
config_foreach handle_dhcp dhcp "$prefix"

[ "$changed" = 1 ] || exit 0

uci -q commit dhcp
/etc/init.d/odhcpd reload

exit 0
