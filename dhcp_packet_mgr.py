#!/usr/bin/env python3

from database_manager import *
import dpkt
from dpkt import dhcp
import struct
import ipaddress
import socket
import netifaces as ni
from helper import *
from typing import Any, List, Tuple, Optional


dhcppacket_type = dhcp.DHCP

def fetch_dhcp_opt(dhcp_obj: dhcp, opt: int) -> Any:
    for t, data in dhcp_obj.opts:
        if t == opt:
            return data
    return -1

def fetch_dhcp_type(dhcp_obj: dhcp) -> int:
    data = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_MSGTYPE)
    return struct.unpack("b", data)[0]

def fetch_dhcp_req_ip(dhcp_obj: dhcp) -> str:
    data = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_REQ_IP)
    return str( ipaddress.ip_address(data))
   
# If giaddr != 0, send to giaddr
# If ciaddr != 0, send to ciaddr
# If ciaddr = 0 and giaddr = 0 and broadcast = 1, send broadcast
# If ciaddr = 0 and giaddr = 0 and broadcast = 0, send to yiaddr

def send_packet(dhcp_packet: dhcppacket_type, ifname: str, dhcp_obj: dhcp) -> None:
    sock = ifname_to_socket(ifname)
    data = bytes(dhcp_packet)
    if is_valid_ip(str(ipaddress.ip_address(dhcp_obj.giaddr))):
        addr = str(ipaddress.ip_address(dhcp_obj.giaddr))
    elif is_valid_ip(str(ipaddress.ip_address(dhcp_obj.ciaddr))):
        addr = str(ipaddress.ip_address(dhcp_obj.ciaddr))
    else:
        yiaddr = str(ipaddress.ip_address(dhcp_obj.yiaddr))
        is_broadcast = dhcp_obj.flags & (1 << 0) 
        if is_broadcast or not(is_valid_ip(yiaddr)):
            print("Broadcasting packet...")
            addr = '255.255.255.255'
        else:
            addr = yiaddr
            print("Unicasting the packet to .. ", addr)
    print('Sending to addr ', addr)
    sock.sendto(data, (addr, 68))

def append_msg_type_and_server_id(opt_tuple: Tuple, option: str, server_id: str) -> Tuple:
    opt_list = list(opt_tuple)
    print('Server ID: ' , server_id)
    
    opt_list.extend([(dhcp.DHCP_OPT_MSGTYPE, bytes([option])),
                     (dhcp.DHCP_OPT_SERVER_ID, server_id),
                     (255, b'')])
   
    return tuple(opt_list)

# Purpose : Constructs the dhcp options list with corresponding values as requested by client 
# Input:  List(opt1, opt2,..), mac value and ifname value
# Return: dhcp options list with corresponding values from the database

def construct_dhcp_opt_list(request_list_opt: List[int], mac: str, 
                            ifname: str, host_conf_data: Dict[str, str]) -> Tuple:
    opt_list = []
    if request_list_opt ==  -1:
        print("No parameter request list")
        return tuple(opt_list)
    for opcode in host_conf_data:
        if opcode and opcode in request_list_opt:
            opt_list.append((opcode, host_conf_data[opcode]))
    return tuple(opt_list)
          
def construct_dhcp_packet(dhcp_obj: dhcp, client_ip: str, opt_list: Tuple) -> dhcppacket_type:
     
    dhcp_packet = dhcp.DHCP(
            op=dhcp.DHCP_OP_REPLY, #htype='ETHERNET', 
            hlen=bytes([6]), hops=0, xid=dhcp_obj.xid, 
            secs=0, flags=dhcp_obj.flags, 
            ciaddr=dhcp_obj.ciaddr, 
            yiaddr=ip_to_int(client_ip), 
            siaddr=dhcp_obj.siaddr,  # What should be filled?
            giaddr=dhcp_obj.giaddr,  # What should be filled? 
            chaddr=dhcp_obj.chaddr, sname=b'', 
            file=b'', opts=opt_list)
    dhcp_packet.pack_opts()
    return dhcp_packet
    
def construct_dhcp_offer(dhcp_obj: dhcp, ifname: str, offer_ip: str, 
                         request_list_opt: List[int], host_conf_data: Dict[str, str]) -> dhcppacket_type:
    server_id = socket.inet_aton(ni.ifaddresses(ifname)[ni.AF_INET][0]['addr'])
    print("Server IP: ", server_id)
    opt_list = construct_dhcp_opt_list(request_list_opt, mac_addr(dhcp_obj.chaddr), ifname, host_conf_data)
    if offer_ip == None and opt_list == []: # If no other parameters were requested by client, should offer be sent?
        return None
    opt_list = append_msg_type_and_server_id(opt_list, dhcp.DHCPOFFER, server_id)
    return construct_dhcp_packet(dhcp_obj, offer_ip, opt_list)

def construct_dhcp_nak(dhcp_obj: dhcp, ifname: str, requested_ip: str, 
                       request_list_opt: List[int], host_conf_data: Dict[str, str]) -> dhcppacket_type:
    server_id = socket.inet_aton(ni.ifaddresses(ifname)[ni.AF_INET][0]['addr'])
    print("Server IP for NAK: ", server_id)
    opt_list = construct_dhcp_opt_list(request_list_opt, mac_addr(dhcp_obj.chaddr), ifname, host_conf_data)
    opt_list = append_msg_type_and_server_id(opt_list, dhcp.DHCPNAK, server_id)
    return construct_dhcp_packet(dhcp_obj, requested_ip, opt_list)

def construct_dhcp_ack(dhcp_obj: dhcp, ifname: str, requested_ip: str, 
                       request_list_opt: List[int], host_conf_data: Dict[str, str]) -> dhcppacket_type:
    server_id = socket.inet_aton(ni.ifaddresses(ifname)[ni.AF_INET][0]['addr'])
    print("Server IP for ACK: ", server_id)
    opt_list = construct_dhcp_opt_list(request_list_opt, mac_addr(dhcp_obj.chaddr), ifname, host_conf_data)
    opt_list = append_msg_type_and_server_id(opt_list, dhcp.DHCPACK, server_id)
    return construct_dhcp_packet(dhcp_obj, requested_ip, opt_list)

# In case of DHCP Discover
# Lookup in the SQL DB for an appropriate data
# Compose DHCP Offer message and send back
def process_dhcp_discover(dhcp_obj: dhcp, ifname: str) -> None:
    request_list_opt = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_PARAM_REQ)
    client_mac =  mac_addr(dhcp_obj.chaddr)
    host_conf_data = dhcp_db.fetch_host_conf_data(ifname, client_mac)

    if host_conf_data == {}:
        print("No configuration data found for the host. Skipping ..")
        return
       
    offer_ip = dhcp_db.fetch_ip(ifname, client_mac) 
    if offer_ip:
        print("Constructing DHCP OFFER with IP: ", offer_ip)        

    dhcp_offer = construct_dhcp_offer(dhcp_obj, ifname, offer_ip, request_list_opt, host_conf_data)
    if dhcp_offer:
        send_packet(dhcp_offer, ifname, dhcp_obj)

# In case of DHCP Request
# Lookup in the SQL DB for the appropriate data and check if that matches the requested IP
# Compose DHCP Accept message and send back

def process_dhcp_request(dhcp_obj: dhcp, ifname: str) -> None:
    #Match XID with pending requests??
    client_mac =  mac_addr(dhcp_obj.chaddr)
    requested_ip = fetch_dhcp_req_ip(dhcp_obj)
    host_conf_data = dhcp_db.fetch_host_conf_data(ifname, client_mac)
    
    if host_conf_data == {}:
        print("No configuration data found for the host. Skipping ..")
        return
        
    offer_ip = dhcp_db.fetch_ip(ifname, client_mac) 
    if offer_ip:
        print("Constructing DHCP OFFER with IP: ", offer_ip)        

    is_valid_request = validate_requested_ip(offer_ip, requested_ip)

    if is_valid_request:
        print("Constructing DHCP Accept with IP: ", requested_ip)
        request_list_opt = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_PARAM_REQ)
        dhcp_ack = construct_dhcp_ack(dhcp_obj, ifname, requested_ip, request_list_opt, host_conf_data)
        send_packet(dhcp_ack, ifname, dhcp_obj)
    else:
        request_list_opt = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_PARAM_REQ)
        print("Requested IP (", requested_ip, ") doesn't match available IP(", offer_ip,")")
        dhcp_nak = construct_dhcp_nak(dhcp_obj, ifname, requested_ip, request_list_opt, host_conf_data)
        send_packet(dhcp_nak, ifname, dhcp_obj)

# If there is a new msg in any of the dhcp intfs, process the data  (Incomplete)

def process_dhcp_packet(fd: int, msg: bytes) -> None:

    ifname = fd_to_ifname[fd]
    dhcp_obj = dpkt.dhcp.DHCP(msg)
    dhcp_type = fetch_dhcp_type(dhcp_obj)
    print("Received DHCP packet on ", ifname, "of type ", dhcp_type_to_str[dhcp_type])

    if (dhcp_type == dhcp.DHCPDISCOVER):
        process_dhcp_discover(dhcp_obj, ifname)
    elif (dhcp_type == dhcp.DHCPREQUEST):
        process_dhcp_request(dhcp_obj, ifname)
    else:
        # Handle other packet types!!
        print("Unexpected DHCP packet type to server: ", dhcp_type_to_str[dhcp_type])

    return

