#!/usr/bin/env python3

from select import poll, POLLIN, POLLOUT, POLLERR 
from pyroute2 import IPRoute
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg
import socket

from .helper import *
from .dhcp_packet_mgr import process_dhcp_packet
from .database_manager import *

#  If there is a new NL msg, add the new interface to poll if it's create 
#  and remove the intf from poll if it's delete

def process_nlmsg(poller_obj: poll, nlmsg: ifinfmsg) -> None:
    nl_event = nlmsg['event']
    if nl_event not in ['RTM_NEWLINK', 'RTM_DELLINK']:
        return

    ifname = nlmsg.IFLA_IFNAME.value
    state = nlmsg.IFLA_OPERSTATE.value

    if not is_served_intf(ifname):
        return

    if nl_event == 'RTM_NEWLINK' and state == 'UP':
        print("Interface UP notif: ", ifname)
        register_with_poll(poller_obj, ifname)
    else:
        print("Interface delete notif: ", ifname)
        deregister_with_poll(poller_obj, ifname)


def start_server():
    init_dhcp_db()

# 1. Create an NL socket and bind

    nlsock = IPRoute()
    try:
        nlsock.bind(groups=rtnl.RTMGRP_LINK)
    except OSError as err:
        print("{}: Failed to bind netlink socket".format(err))
        raise

# 2. Poll on the NL socket

    poller_obj = poll()
    poller_obj.register(nlsock)
    print("Registered Netlink socket for polling...")


# 3. Add any existing served interfaces to the poll list (to handle cases of process restart)

    for intf in nlsock.get_links():
        ifname = intf.IFLA_IFNAME.value
        state = intf.IFLA_OPERSTATE.value
        if is_served_intf(ifname) and state == 'UP':
            print("Adding an existing interface: ", ifname)
            register_with_poll(poller_obj, ifname)

# 4. Keep checking for any events on the polled FDs and process them
    while True:
        fdEvent = poller_obj.poll(1024)
        for fd, event in fdEvent:
            if event & POLLIN:                    #TODO: Add code to handle other events
                if fd == socket_to_fd(nlsock):
                    for nlmsg in nlsock.get():
                        process_nlmsg(poller_obj, nlmsg)
                else:
                    intf_sock = fd_to_socket(fd)
                    if intf_sock:
                        msg, saddr = intf_sock.recvfrom(1024)
                        print("Received DHCP packet")
                        process_dhcp_packet(fd, msg)
                    else:
                        print("Received POLLIN event on fd=", fd, " not in list")
    
    # When should sql connection be closed?


