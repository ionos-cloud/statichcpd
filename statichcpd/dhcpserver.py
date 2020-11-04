#!/usr/bin/env python3

from select import poll, POLLIN, POLLOUT, POLLERR 
from pyroute2 import IPRoute
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg
from pyroute2.netlink.rtnl.ifaddrmsg import ifaddrmsg
import socket
from logging import Logger
from typing import Dict, List, Any, Tuple, TypeVar
import netifaces as ni
from dpkt import dhcp

from .dhcp_packet_mgr import process_dhcp_packet
from .database_manager import *
from .logmgr import logger

#  If there is a new NL msg, add the new interface to poll if it's create 
#  and remove the intf from poll if it's delete

any_nlmsg = TypeVar('any_nlmsg', ifinfmsg, ifaddrmsg)

class ifstate(Enum):
    UP = 1
    DOWN = 2

ifname_to_sock: Dict = {}
fd_to_ifname: Dict = {}
intf_state: Dict = {}
serverip: Dict = {}
intf_prefix: List[str] = ['veth0dummy']

# Socket Helper Functions

def socket_to_fd(sock: socket.socket) -> int:
    try:
        return sock.fileno()
    except AttributeError as err:
        logger.error("{}: Failed to fetch file descriptor for socket {}".format(err, sock))
        

def ifname_to_socket(ifname: str) -> socket.socket:
        return ifname_to_sock.get(ifname, None)

def fd_to_socket(fd: int) -> socket.socket:
    ifname = fd_to_ifname.get(fd, None)
    if ifname:
        return ifname_to_socket(ifname)

def is_served_intf(ifname: str) -> bool:
    return bool(list(filter(ifname.startswith, intf_prefix)))

def add_sock_binding(poller_obj: poll, ifname: str, intf_sock: socket.socket) -> bool:
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            intf_sock.bind(('', 67))
        except OSError:
            logger.error("Failed to bind to the socket for ".format(ifname))
            intf_sock.close()   # No entry is added to internal datastructs at this point and not registered with poll
            return False

        ifname_to_sock[ifname] = intf_sock
        fd_to_ifname[socket_to_fd(intf_sock)] = ifname
        return True

def del_sock_binding(ifname: str, intf_sock: socket.socket) -> None:
    if intf_sock:
        fd = socket_to_fd(intf_sock)
        if fd in fd_to_ifname:
            del fd_to_ifname[fd]
        if ifname in ifname_to_sock:
            del ifname_to_sock[ifname]
        intf_sock.close()

# Poll helper functions

def register_with_poll(poller_obj: poll, ifname: str, interface_ip: str) -> None:
    if ifname_to_socket(ifname) != None:
        if interface_ip == serverip.get(ifname):
	           logger.debug("Ignoring already exisitng intf: ".format(ifname))
	           return
        # Case of IP updation: Update the IP address mapping for the interface
        serverip[ifname] = interface_ip
        logger.debug("Updated serverip for intf {} : {}".format(ifname, serverip))

    
    # Create a socket
    try:
        intf_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        logger.error("Failed to open socket for {}. Skipping poll registration".format(ifname))
        return
    
    # Bind the socket and set socket options
    add_success = add_sock_binding(poller_obj, ifname, intf_sock)
    if not add_success:
        logger.error("Failed to add socket binding for {}. Not registering intf with poll".format(ifname))
        return

    # Case of new IP addition: Add the IP address mapping for the interface
    serverip[ifname] = interface_ip
    logger.debug("Created serverip for intf {} : {} ".format(ifname, serverip))

    # Register with poller object
    logger.debug("Polling on interface ".format(ifname))
    try:
        poller_obj.register(socket_to_fd(intf_sock))
    except AttributeError as err:
        logger.error("{}: Registering with poll failed for {}".format(err, ifname))
        intf_sock = ifname_to_socket(ifname)
        # Cleanup the socket binding and IP address mapping from internal datastructures
        del_sock_binding(ifname, intf_sock)
        del serverip[ifname]

def deregister_with_poll(poller_obj: poll, ifname: str) -> None:
    intf_sock = ifname_to_socket(ifname)
    if not intf_sock:
	       logger.debug("Ignoring non-exisitng intf: {}".format(ifname))
	       return
    try:
        poller_obj.unregister(socket_to_fd(intf_sock))
    except KeyError as err:
        logger.error("{}: Deregistering with poll failed for {}".format(err, ifname))
    del_sock_binding(ifname, intf_sock)
    del serverip[ifname]
def process_nlmsg(poller_obj: poll, nlmsg: any_nlmsg) -> None:
    nl_event = nlmsg['event']
    if nl_event not in ['RTM_NEWLINK', 'RTM_DELLINK', 'RTM_NEWADDR', 'RTM_DELADDR']:
        return
    if nl_event == 'RTM_NEWLINK':
        ifname = nlmsg.IFLA_IFNAME.value
        state = nlmsg.IFLA_OPERSTATE.value
        if is_served_intf(ifname):
            if state == 'LOWERLAYERDOWN' or state == 'DOWN':
                intf_state[ifname] = ifstate.DOWN.value
                logger.debug("Set state down for {} ".format(ifname))
                return
            # Case where interface state is UP
            intf_state[ifname] = ifstate.UP.value
            logger.debug("{} notif for {} ".format(nl_event, ifname))
            try:
                interface_ip = ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']
            except:
                logger.error("No IP address configuration found on {}. Skipping poll registration".format(ifname))
                return
            else:
                register_with_poll(poller_obj, ifname, interface_ip)
    elif nl_event == 'RTM_DELLINK':
        ifname = nlmsg.IFLA_IFNAME.value
        logger.debug("{} notif for {} ".format(nl_event, ifname))
        if is_served_intf(ifname):
            if ifname in intf_state:
                logger.debug("Deleting state entry for {} val {}".format(ifname, intf_state[ifname]))
                del intf_state[ifname]
            deregister_with_poll(poller_obj, ifname)
    elif nl_event == 'RTM_NEWADDR':
        ifname = nlmsg.IFA_LABEL.value
        if is_served_intf(ifname):
            logger.debug("ifname {}".format(ifname))
            upstate = bool(ifname in intf_state and intf_state[ifname] == ifstate.UP.value) 
            if not upstate:
                logger.error("{} notif for intf {} in DOWN state. Skipping poll registration".format(nl_event, ifname))
                return
            ifaddr = nlmsg.IFA_ADDRESS.value
            logger.debug("{} notif for {} IP {}".format(nl_event, ifname, ifaddr))
            # Fetch IP address and update internal DB and register with poll
            register_with_poll(poller_obj, ifname, ifaddr)
    else: # Case of RTM_DELADDR
        ifname = nlmsg.IFA_LABEL.value
        if is_served_intf(ifname):
            logger.debug("{} notif for {} ".format(nl_event, ifname))
            deregister_with_poll(poller_obj, ifname)

def start_server():
    init_dhcp_db()

# 1. Create an NL socket and bind

    nlsock = IPRoute()
    try:
        nlsock.bind(groups=(rtnl.RTMGRP_LINK | rtnl.RTMGRP_IPV4_IFADDR))
    except OSError as err:
        logger.exception("Exception binding netlink socket")

# 2. Poll on the NL socket

    poller_obj = poll()
    poller_obj.register(nlsock)
    logger.debug("Registered Netlink socket for polling...")


# 3. Add any existing served interfaces with IP address to the poll list if it's UP (to handle cases of process restart)

    for intf in nlsock.get_links():
        state = intf.IFLA_OPERSTATE.value
        ifname = intf.IFLA_IFNAME.value
        if is_served_intf(ifname) and state == 'UP':
            for addr in nlsock.get_addr():   ## Look for more efficient way
                if ifname == addr.IFA_LABEL.value:
                    ifaddr = addr.IFA_ADDRESS.value
                    logger.debug("Adding an existing interface: {} addr: {}".format(ifname, ifaddr))
                    intf_state[ifname] = ifstate.UP.value
                    register_with_poll(poller_obj, ifname, ifaddr)
                    break

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
                        ifname = fd_to_ifname[fd]
                        msg, saddr = intf_sock.recvfrom(1024)
                        logger.debug("Received DHCP packet on {} from {}".format(ifname, saddr))
                        (data, address) = process_dhcp_packet(ifname, serverip.get(ifname), msg)
                        if data is None or address is None:
                            logger.debug("No DHCP response sent for packet on {}".format(ifname))
                            continue
                        intf_sock.sendto(data, (address, 68))

                    else:
                        logger.debug("Received POLLIN event on fd={}, not in list".format(fd))
    
    # When should sql connection be closed?


