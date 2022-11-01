#!/bin/ksh

daemon="@@LIBEXECDIR@@/pluto"
daemon_flags="--logfile @@LOGDIR@@/pluto.log --config @@SYSCONFDIR@@/ipsec.conf --leak-detective"

. /etc/rc.d/rc.subr

#pidfile="@@RUNDIR@@/${name}.pid"
#required_files="@@SYSCONFDIR@@/ipsec.conf"

case $1 in
onestart ) set start ;;
onestop ) set stop ;;
esac

rc_pre()
{
    @@SBINDIR@@/ipsec checknss
}

rc_cmd $1
