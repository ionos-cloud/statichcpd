#!/usr/bin/env python3

from database_manager import database
import dpkt
from dpkt import dhcp
import struct
import ipaddress
import socket
import dhcppython
import netifaces as ni
from helper import fetch_intf_sock, is_valid_ip
from helper import mac_addr, validate_requested_ip, dhcp_type_to_str
from helper import fd_to_ifname, single_valued_dhcp_attr
from typing import Any, List, Tuple


dhcp_db = database()
dhcp_option_type = dhcppython.options.OptionDirectory
dhcppacket_type = dhcppython.packet.DHCPPacket
dhcp_options_list_type = dhcppython.options.OptionList

def fetch_dhcp_opt(dhcp_obj: dhcp, opt: int) -> Any:
    for t, data in dhcp_obj.opts:
        if t == opt:
            return data
    return -1

# Purpose : Fetches the requested list of attributes by join of multiple tables 
#           under the constraint of mac and ifname value
# Input:  List[(table_name, attribute_name),..] , mac value and ifname value
# Return: List of rows of values obtained through join

def fetch_joined_sql_attr(tab_attr_pairs: List[Tuple[str, ...]], mac: str, ifname: str) -> List[Tuple[str, ...]]:
    sqlite_select_query = dhcp_db.construct_generic_joined_sql_lookup_query(tab_attr_pairs, 
                                             [(dhcp_db.ifname_col_name, ifname), (dhcp_db.mac_col_name, mac)])
    dhcp_db.db_handler.execute(sqlite_select_query)
    result = dhcp_db.db_handler.fetchall()
    return result

# Purpose : Fetches the requested attribute from table specified 
#           that matches the value of mac and ifname
# Input:  (table_name, attribute_name), mac value and ifname value
# Return: List of value(s) from rows that match the condition


def fetch_sql_attr(table_name: str, attr: str, ifname: str, mac: str) -> Any:
    sqlite_select_query = dhcp_db.construct_generic_sql_lookup_query(table_name, attr, 
                    [(dhcp_db.ifname_col_name, ifname), (dhcp_db.mac_col_name, mac)])
    dhcp_db.db_handler.execute(sqlite_select_query)
    result = dhcp_db.db_handler.fetchall()
    return result


def fetch_dhcp_type(dhcp_obj: dhcp) -> int:
    data = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_MSGTYPE)
    return struct.unpack("b", data)[0]

def fetch_dhcp_req_ip(dhcp_obj: dhcp) -> str:
    data = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_REQ_IP)
    return str( ipaddress.ip_address(data))
    

def fetch_offer_ip(ifname: str, mac: str, table_name: str) -> str:
    table_name, attribute = dhcp_db.host_ip_config_tab_name, dhcp_db.addr4_col_name
    results = fetch_sql_attr(table_name, attribute, ifname, mac)
    if results:
        return results[0][0]
    else:
        return None

# If giaddr != 0, send to giaddr
# If ciaddr != 0, send to ciaddr
# If ciaddr = 0 and giaddr = 0 and broadcast = 1, send broadcast
# If ciaddr = 0 and giaddr = 0 and broadcast = 0, send to yiaddr

def send_packet(dhcp_packet: dhcppacket_type, ifname: str, dhcp_obj: dhcp) -> None:
    sock = fetch_intf_sock(ifname)
    data = dhcp_packet.asbytes
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

# Purpose : Constructs the dhcp options list with corresponding values as requested by client 
# Input:  List(opt1, opt2,..), mac value and ifname value
# Return: dhcp options list with corresponding values from the database


def construct_dhcp_opt_list(request_list_opt: List[int], mac: str, ifname: str) -> dhcp_option_type:
    opt_list = dhcppython.options.OptionList([])
    if request_list_opt ==  -1:
        print("No parameter request list")
        return opt_list
    
    tab_attr_pairs = []
    valid_op_list = []
    for op in request_list_opt:
        table_name, attr = dhcp_db.fetch_table_and_column(op)
        if table_name and attr:
            valid_op_list.append(op)
            tab_attr_pairs.append((table_name, attr))

    result = fetch_joined_sql_attr(tab_attr_pairs, mac, ifname)

    if result:
        op_index = 0
        for op in valid_op_list:
            val_list = list(set(entry[op_index] for entry in result))
            if op in single_valued_dhcp_attr:
                opt_list.append(dhcppython.options.options.short_value_to_object(op, val_list[0]))
            else:
                if dhcp_db.fetch_table_and_column(op)[0] != None:
                    opt_list.append(dhcppython.options.options.short_value_to_object(op, val_list))
            op_index += 1
    return opt_list

def construct_dhcp_packet(dhcp_obj: dhcp, client_ip: str, opt_list: dhcp_options_list_type) -> dhcppacket_type:
    dhcp_packet = dhcppython.packet.DHCPPacket(
            op='BOOTREPLY', htype='ETHERNET', 
            hlen=6, hops=0, xid=dhcp_obj.xid, 
            secs=0, flags=dhcp_obj.flags, 
            ciaddr=ipaddress.IPv4Address(dhcp_obj.ciaddr), 
            yiaddr=ipaddress.IPv4Address(client_ip), 
            siaddr=ipaddress.IPv4Address(dhcp_obj.siaddr),  # What should be filled?
            giaddr=ipaddress.IPv4Address(dhcp_obj.giaddr),  # What should be filled? 
            chaddr=mac_addr(dhcp_obj.chaddr), sname=b'', 
            file=b'', options=opt_list)
    return dhcp_packet
    

def construct_dhcp_offer(dhcp_obj: dhcp, ifname: str, offer_ip: str, request_list_opt: List[int]) -> dhcppacket_type:
    server_ip = socket.inet_aton(ni.ifaddresses(ifname)[ni.AF_INET][0]['addr'])
    print("Server IP: ", server_ip)
    opt_list = construct_dhcp_opt_list(request_list_opt, mac_addr(dhcp_obj.chaddr), ifname)
    if offer_ip == None and opt_list == []: # If no other parameters were requested by client, should offer be sent?
        return None
    opt_list.append(dhcppython.options.options.short_value_to_object(dhcp.DHCP_OPT_MSGTYPE, "DHCPOFFER"))
    opt_list.append(dhcppython.options.options.short_value_to_object(dhcp.DHCP_OPT_SERVER_ID, server_ip))
    opt_list.append(dhcppython.options.options.short_value_to_object(255, ''))
    return construct_dhcp_packet(dhcp_obj, offer_ip, opt_list)

def construct_dhcp_nak(dhcp_obj: dhcp, ifname: str, requested_ip: str, request_list_opt: List[int]) -> dhcppacket_type:
    server_ip = socket.inet_aton(ni.ifaddresses(ifname)[ni.AF_INET][0]['addr'])
    print("Server IP for NAK: ", server_ip)
    opt_list = construct_dhcp_opt_list(request_list_opt, mac_addr(dhcp_obj.chaddr), ifname)
    opt_list.append(dhcppython.options.options.short_value_to_object(dhcp.DHCP_OPT_MSGTYPE, "DHCPNAK"))
    opt_list.append(dhcppython.options.options.short_value_to_object(dhcp.DHCP_OPT_SERVER_ID, server_ip))
    opt_list.append(dhcppython.options.options.short_value_to_object(255, ''))
    return construct_dhcp_packet(dhcp_obj, requested_ip, opt_list)

def construct_dhcp_ack(dhcp_obj: dhcp, ifname: str, requested_ip: str, request_list_opt: List[int]) -> dhcppacket_type:
    server_ip = socket.inet_aton(ni.ifaddresses(ifname)[ni.AF_INET][0]['addr'])
    print("Server IP for ACK: ", server_ip)
    opt_list = construct_dhcp_opt_list(request_list_opt, mac_addr(dhcp_obj.chaddr), ifname)
    opt_list.append(dhcppython.options.options.short_value_to_object(dhcp.DHCP_OPT_MSGTYPE, "DHCPACK"))
    opt_list.append(dhcppython.options.options.short_value_to_object(dhcp.DHCP_OPT_SERVER_ID, server_ip))
    opt_list.append(dhcppython.options.options.short_value_to_object(255, ''))
    return construct_dhcp_packet(dhcp_obj, requested_ip, opt_list)

# In case of DHCP Discover
# Lookup in the SQL DB for an appropriate data
# Compose DHCP Offer message and send back
def process_dhcp_discover(dhcp_obj: dhcp, ifname: str, table_name: str) -> None:
    request_list_opt = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_PARAM_REQ)
    client_mac =  mac_addr(dhcp_obj.chaddr)
    offer_ip = fetch_offer_ip(ifname, client_mac, table_name)
    if offer_ip == None:
        print("No IP address entry found")
    print("Constructing DHCP OFFER with IP: ", offer_ip)        
    dhcp_offer = construct_dhcp_offer(dhcp_obj, ifname, offer_ip, request_list_opt)
    if dhcp_offer:
        send_packet(dhcp_offer, ifname, dhcp_obj)

# In case of DHCP Request
# Lookup in the SQL DB for the appropriate data and check if that matches the requested IP
# Compose DHCP Accept message and send back

def process_dhcp_request(dhcp_obj: dhcp, ifname: str, table_name: str) -> None:
    #Match XID with pending requests??
    client_mac =  mac_addr(dhcp_obj.chaddr)
    requested_ip = fetch_dhcp_req_ip(dhcp_obj)
    offer_ip = fetch_offer_ip(ifname, client_mac, table_name)
    is_valid_request = validate_requested_ip(offer_ip, requested_ip)
    if is_valid_request:
        print("Constructing DHCP Accept with IP: ", requested_ip)
        request_list_opt = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_PARAM_REQ)
        dhcp_ack = construct_dhcp_ack(dhcp_obj, ifname, requested_ip, request_list_opt)
        send_packet(dhcp_ack, ifname, dhcp_obj)
    else:
        request_list_opt = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_PARAM_REQ)
        print("Requested IP (", requested_ip, ") doesn't match available IP(", offer_ip,")")
        dhcp_nak = construct_dhcp_nak(dhcp_obj, ifname, requested_ip, request_list_opt)
        send_packet(dhcp_nak, ifname, dhcp_obj)

# If there is a new msg in any of the dhcp intfs, process the data  (Incomplete)

def process_dhcp_packet(fd: int, msg: bytes, table_name: str) -> None:

    # Fetch ifname from fd and use ifname-MAC combination to lookup SQL DB
    ifname = fd_to_ifname[fd]
    dhcp_obj = dpkt.dhcp.DHCP(msg)
    dhcp_type = fetch_dhcp_type(dhcp_obj)
    print("Received DHCP packet on ", ifname, "of type ", dhcp_type_to_str[dhcp_type])

    if (dhcp_type == dhcp.DHCPDISCOVER):
        process_dhcp_discover(dhcp_obj, ifname, table_name)
    elif (dhcp_type == dhcp.DHCPREQUEST):
        process_dhcp_request(dhcp_obj, ifname, table_name)
    else:
        # Handle other packet types!!
        print("Unexpected DHCP packet type to server: ", dhcp_type_to_str[dhcp_type])

    return

