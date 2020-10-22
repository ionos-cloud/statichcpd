#!/usr/bin/env python3

from select import poll, POLLIN, POLLOUT, POLLERR 
from pyroute2 import IPRoute
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg
import socket
from dpkt import dhcp
import sqlite3

from database_manager import database
from helper import register_with_poll, deregister_with_poll, is_served_intf
from helper import fd_to_socket, socket_to_fd
from dhcp_packet_mgr import fetch_dhcp_opt, fetch_dhcp_type, fetch_dhcp_req_ip, fetch_offer_ip
from dhcp_packet_mgr import construct_dhcp_opt_list 
from dhcp_packet_mgr import construct_dhcp_offer, construct_dhcp_ack, construct_dhcp_nak  
from dhcp_packet_mgr import process_dhcp_packet, dhcp_db 

db_handler = dhcp_db.db_handler

#  If there is a new NL msg, add the new interface to poll if it's create 
#  and remove the intf from poll if it's delete

def process_nlmsg(poller_obj: poll, nlmsg: ifinfmsg) -> None:
    if nlmsg['event'] == 'RTM_NEWLINK' or nlmsg['event'] == 'RTM_DELLINK':
        ifname = nlmsg.IFLA_IFNAME.value
        state = nlmsg.IFLA_OPERSTATE.value
        if is_served_intf(ifname):
            if nlmsg['event']=='RTM_NEWLINK' and state == 'UP':
                print("Interface UP notif: ", ifname)
                register_with_poll(poller_obj, ifname)
            else:
                print("Interface delete notif: ", ifname)
                deregister_with_poll(poller_obj, ifname)


def main():
    
# 1. Create an NL socket and bind

    nlsock = IPRoute()
    nlsock.bind(groups=rtnl.RTMGRP_LINK) 

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
                        process_dhcp_packet(fd, msg, dhcp_db.host_ip_config_tab_name)

    if (sqliteConnection):
        sqliteConnection.close()
        print("The SQLite connection is closed")


if __name__ == "__main__":
    main()
