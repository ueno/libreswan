../../guestbin/ping-once.sh --down 10.0.10.1
ipsec whack --trafficstatus
iptables -t nat -L -n
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
