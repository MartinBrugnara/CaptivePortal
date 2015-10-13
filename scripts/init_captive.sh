

# TODO: check how to do that via 'echo >'
# net.ipv4.ip_forward=1

# Captive portal IP
CAPTIVE_IP="10.0.0.1" #that should be me

# Active device 
GW_DEV="eth0"
IN_DEV="eth1"

# Flush tables
iptables -F 
iptables -X

# Default filter policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD ALLOW

# enable captive portal website
iptables -A INPUT -i $IN_DEV -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $IN_DEV -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# enable nat
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -A POSTROUTING -t nat -o $GW_DEV -j MASQUERADE

# captive portal filter
iptables -t mangle -N internet 
iptables -t mangle -A internet -p tcp -m tcp --dport 80 -j MARK --set-mark 99 
iptables -t mangle -A internet -m mark ! --mark 99 -j MARK --set-mark 100 

# for each dev to manage
iptables -t mangle -I PREROUTING -i $IN_DEV -j internet 
iptables -t nat -I PREROUTING -i $IN_DEV -p tcp -m mark --mark 99 -m tcp --dport 80 -j DNAT --to-destination $CAPTIVE_IP
iptables -A FORWARD -i $IN_DEV -m mark --mark 100 -j REJECT
# allow DNS, DHCP, NTP
iptables -I FORWARD -p udp -i $IN_DEV -m multiport --dports 53,67,123 -j ACCEPT
iptables -I FORWARD -p udp -i $IN_DEV -m multiport --sports 53,67,123 -j ACCEPT
# end for each

# ------------------------------------------------------------------------------
# User management:
# allow
iptables -t mangle -I internet 1 -m mac --mac-source $USER_MAC_ADDRESS -s $USER_IP -j RETURN

# block
iptables -t mangle -D internet  -m mac --mac-source $USER_MAC_ADDRESS -s $USER_IP -j RETURN

