#!/usr/bin/env python3

import socket
from select import poll 
from dpkt.compat import compat_ord
import ipaddress
from dpkt import dhcp
from typing import Dict, List, Any, Tuple
import struct

from .logmgr import logger

ifname_to_sock: Dict = {}
fd_to_ifname: Dict = {}
serverip: Dict = {}
intf_state: Dict = {}
intf_prefix: List[str] = ['veth0dummy']

dhcp_type_to_str: Dict = {dhcp.DHCPDISCOVER : "DHCPDISCOVER",
                        dhcp.DHCPOFFER : "DHCPOFFER",
                        dhcp.DHCPREQUEST : "DHCPREQUEST",
                        dhcp.DHCPDECLINE : "DHCPDECLINE",
                        dhcp.DHCPACK : "DHCPACK",
                        dhcp.DHCPNAK : "DHCPNAK",
                        dhcp.DHCPRELEASE : "DHCPRELEASE",
                        dhcp.DHCPINFORM : "DHCPINFORM"  }


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

def mac_addr(address: bytes) -> str:
    return ':'.join('%02x' % compat_ord(b) for b in address)

def is_served_intf(ifname: str) -> bool:
    return bool(list(filter(ifname.startswith, intf_prefix)))

def add_sock_binding(poller_obj: poll, ifname: str, intf_sock: socket.socket) -> bool:
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            intf_sock.bind(('', 67))
        except OSError:
            logger.error("Failed to bind to the socket for ", ifname)
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
