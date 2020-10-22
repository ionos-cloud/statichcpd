#!/usr/bin/env python3

import socket
from select import poll 
from dpkt.compat import compat_ord
import ipaddress
from dpkt import dhcp
from typing import Dict, List

sock_type = socket.socket

ifname_to_sock: Dict = {}
fd_to_ifname: Dict = {}
intf_prefix: List[str] = ['veth0dummy']

dhcp_type_to_str: Dict = {dhcp.DHCPDISCOVER : "DHCPDISCOVER", \
                        dhcp.DHCPOFFER : "DHCPOFFER",    \
                        dhcp.DHCPREQUEST : "DHCPREQUEST",  \
                        dhcp.DHCPDECLINE : "DHCPDECLINE",  \
                        dhcp.DHCPACK : "DHCPACK",      \
                        dhcp.DHCPNAK : "DHCPNAK",      \
                        dhcp.DHCPRELEASE : "DHCPRELEASE",  \
                        dhcp.DHCPINFORM : "DHCPINFORM"  }

single_valued_dhcp_attr: List[int] = [dhcp.DHCP_OPT_NETMASK, dhcp.DHCP_OPT_TIMEOFFSET, 
                                   dhcp.DHCP_OPT_DOMAIN, dhcp.DHCP_OPT_HOSTNAME, 
                                   dhcp.DHCP_OPT_NBTCPSCOPE, dhcp.DHCP_OPT_MTUSIZE]


# Socket Helper Functions

def socket_to_fd(sock: sock_type) -> int:
    return sock.fileno()

def fetch_intf_sock(ifname: str) -> sock_type:
        return ifname_to_sock.get(ifname, None)

def fd_to_socket(fd: int) -> sock_type:
    ifname = fd_to_ifname.get(fd, None)
    if ifname:
        return fetch_intf_sock(ifname)

def mac_addr(address: bytes) -> str:
    return ':'.join('%02x' % compat_ord(b) for b in address)

def is_served_intf(ifname: str) -> bool:
    return bool(list(filter(ifname.startswith, intf_prefix)))

def sock_binding_exists(ifname: str) -> bool:
    return bool(ifname_to_sock.get(ifname, False))

def add_sock_binding(poller_obj: poll, ifname: str, intf_sock: sock_type) -> None:
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            intf_sock.bind(('', 67))
        except OSError:
            print("Failed to bind the socket for ", ifname)
            intf_sock.close()   # No entry is added to internal datastructs at this point and not registered with poll
            return

        ifname_to_sock[ifname] = intf_sock
        fd_to_ifname[socket_to_fd(intf_sock)] = ifname

def del_sock_binding(ifname: str, intf_sock: sock_type) -> None:
        del fd_to_ifname[socket_to_fd(intf_sock)]
        del ifname_to_sock[ifname]
        intf_sock.close()

# Poll helper functions

def register_with_poll(poller_obj: poll, ifname: str) -> None:
    if sock_binding_exists(ifname):
	    print("Ignoring already exisitng intf: ", ifname)
	    return
    try:
        intf_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return
    
    add_sock_binding(poller_obj, ifname, intf_sock)
    print("Polling on interface ", ifname)
    poller_obj.register(socket_to_fd(intf_sock))

def deregister_with_poll(poller_obj: poll, ifname: str) -> None:
    if not sock_binding_exists(ifname):
	    print("Ignoring non-exisitng intf: ", ifname)
	    return
    intf_sock = fetch_intf_sock(ifname)
    poller_obj.unregister(socket_to_fd(intf_sock))
    del_sock_binding(ifname, intf_sock)

# Packet helper functions

def is_valid_ip(ip: str) -> bool:
    return bool(not ipaddress.ip_address(ip).is_unspecified)

def is_equal_ip(ip1: str, ip2: str) -> bool:
    return bool(ipaddress.ip_address(ip1) == ipaddress.ip_address(ip2))


def validate_requested_ip(offer_ip: str, requested_ip: str) -> bool:
    return bool(is_valid_ip(requested_ip) and is_equal_ip(offer_ip, requested_ip))


