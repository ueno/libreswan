# trigger OE
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# wait for IKE SA to expire due to inactivity.
../../guestbin/wait-for.sh --timeout 180 --no-match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
# establish a new one
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
echo done
