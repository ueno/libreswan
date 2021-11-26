#!/bin/sh

set -e

# chop everything off after testing; assume this is run from topdir?
topdir=$(realpath $0 | sed "s;testing/.*;;")

# check NFS is installed and start it (no need to enable it).
if test -f /lib/systemd/system/nfs-server.service ; then
    echo "starting NFS ..."
    sudo systemctl start nfs-server
#elif some other os ...
else
    echo "is NFS installed?" 1>&2
    exit 1
fi

# export the testing directory
if sudo exportfs | grep ${topdir} ; then
    echo ${topdir} already exported
else
    echo "exporting ${topdir} ..."
    #sudo exportfs -r
    sudo exportfs -o rw,no_root_squash 192.168.234.0/24:${topdir}
fi

# poke a hole in the firewall; see systemctl EXIT CODE 0 indicates it is running
if test -f /lib/systemd/system/firewalld.service && systemctl status firewalld > /dev/null ; then
    echo "configuring firewall ..."
    # add the zone swandefault; replace old
    #
    # problem is that libvirt screws around with the firewall zones so
    # add these to the libvirt zone
    #
    # sudo firewall-cmd --permanent --delete-zone=swandefault || true
    # sudo firewall-cmd --permanent --new-zone=swandefault
    # sudo firewall-cmd --permanent --zone=swandefault --add-interface=swandefault
    # sudo firewall-cmd --permanent --zone=swandefault --add-service=nfs
    # sudo firewall-cmd --permanent --zone=swandefault --add-service=mountd
    # sudo firewall-cmd --permanent --zone=swandefault --add-service=rpc-bind
    sudo firewall-cmd --permanent --zone=libvirt --add-service=nfs
    sudo firewall-cmd --permanent --zone=libvirt --add-service=mountd
    sudo firewall-cmd --permanent --zone=libvirt --add-service=rpc-bind
    sudo firewall-cmd --reload
else
    echo "assuming firewall is disabled"
fi
