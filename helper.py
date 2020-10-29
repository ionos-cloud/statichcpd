#!/usr/bin/env python3

import socket
from select import poll 
from dpkt.compat import compat_ord
import ipaddress
from dpkt import dhcp
from typing import Dict, List, Any, Tuple
from ipaddress import ip_address, IPv4Address
import struct

ifname_to_sock: Dict = {}
fd_to_ifname: Dict = {}
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
    return sock.fileno()

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

def add_sock_binding(poller_obj: poll, ifname: str, intf_sock: socket.socket) -> None:
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

def del_sock_binding(ifname: str, intf_sock: socket.socket) -> None:
        del fd_to_ifname[socket_to_fd(intf_sock)]
        del ifname_to_sock[ifname]
        intf_sock.close()

# Poll helper functions

def register_with_poll(poller_obj: poll, ifname: str) -> None:
    if ifname_to_socket(ifname) != None:
	    print("Ignoring already exisitng intf: ", ifname)
	    return
    try:
        intf_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        print("Failed to open socket for ", ifname)
        return
    
    add_sock_binding(poller_obj, ifname, intf_sock)
    print("Polling on interface ", ifname)
    poller_obj.register(socket_to_fd(intf_sock))

def deregister_with_poll(poller_obj: poll, ifname: str) -> None:
    intf_sock = ifname_to_socket(ifname)
    if not intf_sock:
	    print("Ignoring non-exisitng intf: ", ifname)
	    return
    poller_obj.unregister(socket_to_fd(intf_sock))
    del_sock_binding(ifname, intf_sock)

# Packet helper functions

def is_valid_ip(ip: str) -> bool:
    return bool(not ipaddress.ip_address(ip).is_unspecified)

def is_equal_ip(ip1: str, ip2: str) -> bool:
    return ipaddress.ip_address(ip1) == ipaddress.ip_address(ip2)


def validate_requested_ip(offer_ip: str, requested_ip: str) -> bool:
    if offer_ip:
        return is_valid_ip(requested_ip) and is_equal_ip(offer_ip, requested_ip)
    elif not is_valid_ip(requested_ip):
        return True
    else:
        return False

def is_ipaddr(s: str) -> bool:
    try: 
        if type(ip_address(s)) is IPv4Address:
             return True
    except ValueError: 
        return False

def ip_to_int(ip: str) -> int:
    return struct.unpack("!L", socket.inet_aton(ip))[0]

def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)

def str_to_bytes(s: str) -> bytes:
    return bytes(s, 'utf-8')

def int_to_32bits(num: int) -> bytes:
    return num.to_bytes(4, 'big')

def iplist_to_bytes(val_list: List) -> bytes:
    new_str = b''
    for ele in val_list:
        new_str += ip_to_bytes(ele) 
    return new_str

def encode_option(val: Any) -> bytes:
    if isinstance(val, str):
        if is_ipaddr(val):
            return ip_to_bytes(val)
        else:
            return str_to_bytes(val)
    elif type(val) == list:
        return iplist_to_bytes(val)
    else:
        return int_to_32bits(val)

