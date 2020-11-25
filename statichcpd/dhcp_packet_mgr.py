#!/usr/bin/env python3

import dpkt
from dpkt import dhcp
from dpkt.compat import compat_ord
import struct
from ipaddress import IPv4Address
import socket
from configparser import SectionProxy
from typing import Any, List, Tuple, Optional

from .datatypes import *
from .database_manager import *
from .logmgr import logger

dhcp_type_to_str: Dict = {dhcp.DHCPDISCOVER : "DHCPDISCOVER",
                        dhcp.DHCPOFFER : "DHCPOFFER",
                        dhcp.DHCPREQUEST : "DHCPREQUEST",
                        dhcp.DHCPDECLINE : "DHCPDECLINE",
                        dhcp.DHCPACK : "DHCPACK",
                        dhcp.DHCPNAK : "DHCPNAK",
                        dhcp.DHCPRELEASE : "DHCPRELEASE",
                        dhcp.DHCPINFORM : "DHCPINFORM"  }

dhcppacket_type = dhcp.DHCP
default_lease_time = 0
max_lease_time = 0

def init(config: SectionProxy):
    global default_lease_time, max_lease_time
    default_lease_time = config.getint('default_lease_time')
    max_lease_time = config.getint('max_lease_time')

def mac_addr(address: bytes) -> str:
    return ':'.join('%02x' % compat_ord(b) for b in address)

def fetch_dhcp_opt(dhcp_obj: dhcp, opt: int) -> Any:
    for t, data in dhcp_obj.opts:
        if t == opt:
            return data
    opcode = fetch_dhcp_type(dhcp_obj)
    logger.debug("Optcode %d not set in %s from %s", 
                 opt, dhcp_type_to_str.get(opcode, opcode),
                 str(Mac(dhcp_obj.chaddr)))
    return None

def fetch_dhcp_type(dhcp_obj: dhcp) -> int:
    data = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_MSGTYPE)
    return struct.unpack("b", data)[0]

def fetch_dhcp_req_ip(dhcp_obj: dhcp) -> Optional[str]:
    data = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_REQ_IP)
    try:
        return None if data is None else IPv4Address(data)
    except Exception as err:
        opcode = fetch_dhcp_type(dhcp_obj)
        logger.debug("%s: Failed to parse requested IP (%s) for %s packet from %s",
                        err, data, dhcp_type_to_str.get(opcode, opcode),
                        str(Mac(dhcp_obj.chaddr)))
        return None
   
# If giaddr != 0, send to giaddr
# If ciaddr != 0, send to ciaddr
# If ciaddr = 0 and giaddr = 0 and broadcast = 1, send broadcast
# If ciaddr = 0 and giaddr = 0 and broadcast = 0, send to yiaddr

def fetch_destination_address(dhcp_obj: dhcp) -> Optional[IPv4Address]:
    try:
        if not IPv4Address(dhcp_obj.giaddr).is_unspecified:
            # Packet was gatewayed; Unicast to gateway
            addr = str(IPv4Address(dhcp_obj.giaddr))
        elif not IPv4Address(dhcp_obj.ciaddr).is_unspecified:
            # Client with valid IP in Renewal state, unicast
            addr = str(IPv4Address(dhcp_obj.ciaddr))
        else:
            yiaddr = IPv4Address(dhcp_obj.yiaddr)
            is_broadcast = dhcp_obj.flags & (1 << 0) 
            # If broadcast bit is set, send to limited broadcast address
            if is_broadcast or yiaddr.is_unspecified:
                addr = '255.255.255.255'
            else:
            # If broadcast bit is not set, unicast to the client
                addr = str(yiaddr)
    except AddressValueError as err:
        logger.error("%s: Failed to fetch destination address for DHCP packet on %s", err, ifname)
        return None
    logger.debug("Destination IP for DHCP response: %s ", addr)
    return addr

def fetch_addr_lease_time(dhcp_obj: dhcp, opt_tuple: Tuple):
    opt_list = list(opt_tuple)
    lease_time = default_lease_time

    # If a lease time is requested by client, validate and assign accordingly
    if dhcp.DHCP_OPT_LEASE_SEC in opt_list:
        req_lease_time = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_LEASE_SEC)
        if req_lease_time <= max_lease_time:
            lease_time = req_lease_time
    return lease_time

def append_mandatory_options(dhcp_obj: dhcp, opt_tuple: Tuple, option: str, server_id: IPv4Address) -> Tuple:
    opt_list = list(opt_tuple)
    dhcp_type = fetch_dhcp_type(dhcp_obj)
    opt_list.extend([(dhcp.DHCP_OPT_MSGTYPE, bytes([option]))])
    if dhcp_type != dhcp.DHCPINFORM:
        lease_time = fetch_addr_lease_time(dhcp_obj, opt_tuple) 
        opt_list.extend([(dhcp.DHCP_OPT_LEASE_SEC, (lease_time).to_bytes(4, 'big'))])
    opt_list.extend([(dhcp.DHCP_OPT_SERVER_ID, server_id.packed),
                     (255, b'')])
    return tuple(opt_list)

# Purpose : Constructs the dhcp options list with corresponding values as requested by client 
# Input:  List(opt1, opt2,..), mac value and ifname value
# Return: dhcp options list with corresponding values from the database

def construct_dhcp_opt_list(request_list_opt: List[int], ifname: str, 
                            host_conf_data: Dict[str, str]) -> Tuple:
    opt_list = []
    if request_list_opt ==  None:
        logger.debug("No parameter request list")
        return tuple(opt_list)
    for opcode in request_list_opt:
        if opcode in host_conf_data:       # For every option value, do the appropriate encoding
            data = host_conf_data[opcode]
            encoded_data = None
            if isinstance(data, IPv4Address):
                encoded_data = data.packed
            elif isinstance(data, str):
                encoded_data = data.encode('utf-8')
            elif isinstance(data, Int16):
                encoded_data = (data.value).to_bytes(2, 'big')
            elif isinstance(data, Int32):
                encoded_data = (data.value).to_bytes(4, 'big')
            elif isinstance(data, list) and len(data) > 0:
                if all(isinstance(ele, IPv4Address) for ele in data):
                    encoded_data = b''.join([elem.packed for elem in data]) 
                elif all(isinstance(ele, Staticrt) for ele in data):
                    encoded_data = b''.join([bytes(elem) for elem in data]) 
                else:
                    logger.error("Elements of unexpected type in the list: %s".format(data))
            else:
                logger.error("Value(%s) of unexpected type received for opcode %d".format(data, opcode))
            opt_list.append((opcode, encoded_data))
    return tuple(opt_list)
          
def construct_dhcp_packet(dhcp_obj: dhcp, client_ip: str, opt_list: Tuple) -> dhcppacket_type:
    client_addr = int(client_ip) if client_ip is not None else 0 
    dhcp_packet = dhcp.DHCP(
            op=dhcp.DHCP_OP_REPLY, #htype='ETHERNET', 
            hlen=bytes([6]), hops=0, xid=dhcp_obj.xid, 
            secs=0, flags=dhcp_obj.flags, 
            ciaddr=dhcp_obj.ciaddr, 
            yiaddr=client_addr, 
            siaddr=dhcp_obj.siaddr,  # What should be filled?
            giaddr=dhcp_obj.giaddr,  # What should be filled? 
            chaddr=dhcp_obj.chaddr, sname=b'', 
            file=b'', opts=opt_list)
    return dhcp_packet
    
def construct_dhcp_offer(dhcp_obj: dhcp, ifname: str, server_id: IPv4Address,
                         offer_ip: str, request_list_opt: List[int], 
                         host_conf_data: Dict[str, str]) -> Optional[dhcppacket_type]:
    opt_list = construct_dhcp_opt_list(request_list_opt, ifname, host_conf_data)
    if offer_ip is None and not opt_list: # If no other parameters were requested by client, should offer be sent?
        return (None, None)
    opt_list = append_mandatory_options(dhcp_obj, opt_list, dhcp.DHCPOFFER, server_id)
    return construct_dhcp_packet(dhcp_obj, offer_ip, opt_list)

def construct_dhcp_nak(dhcp_obj: dhcp, ifname: str, server_id: IPv4Address, 
                       requested_ip: str, request_list_opt: List[int], 
                       host_conf_data: Dict[str, str]) -> Optional[dhcppacket_type]:
    logger.debug("Server IP for NAK: %s", server_id)
    opt_list = construct_dhcp_opt_list(request_list_opt, ifname, host_conf_data)
    opt_list = append_mandatory_options(dhcp_obj, opt_list, dhcp.DHCPNAK, server_id)
    return construct_dhcp_packet(dhcp_obj, requested_ip, opt_list)

def construct_dhcp_ack(dhcp_obj: dhcp, ifname: str, server_id: IPv4Address,
                       client_ip: str, request_list_opt: List[int], 
                       host_conf_data: Dict[str, str]) -> Optional[dhcppacket_type]:
    logger.debug("Server IP for ACK: %s", server_id)
    opt_list = construct_dhcp_opt_list(request_list_opt, ifname, host_conf_data)
    opt_list = append_mandatory_options(dhcp_obj, opt_list, dhcp.DHCPACK, server_id)
    return construct_dhcp_packet(dhcp_obj, client_ip, opt_list)

# In case of DHCP Discover
# Lookup in the SQL DB for an appropriate data
# Compose DHCP Offer message and send back
def process_dhcp_discover(dhcp_obj: dhcp, server_id: IPv4Address, ifname: str) -> Optional[Tuple[bytes, IPv4Address, IPv4Address]]:
    request_list_opt = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_PARAM_REQ)
    client_mac =  Mac(dhcp_obj.chaddr)
    host_conf_data = fetch_host_conf_data(ifname, client_mac)

    if not host_conf_data:
        logger.debug("No configuration data found for the host %s on intf %s. Skipping ..", str(client_mac), ifname)
        return (None, None, None)
    
    offer_ip = None
    if DHCP_IP_OPCODE in host_conf_data:
        offer_ip = host_conf_data[DHCP_IP_OPCODE]
        if offer_ip:
            logger.debug("Constructing DHCP OFFER with IP: %s ", offer_ip)

    if DHCP_NON_DEFAULT_SERVERID_OPCODE in host_conf_data:
        logger.debug("For client %s on intf %s using non-default server id: %s (default server id: %s))",
                      str(client_mac), ifname, host_conf_data[DHCP_NON_DEFAULT_SERVERID_OPCODE], server_id)
        server_id = host_conf_data[DHCP_NON_DEFAULT_SERVERID_OPCODE]

    dhcp_offer = construct_dhcp_offer(dhcp_obj, ifname, server_id, offer_ip, request_list_opt, host_conf_data)
    if not dhcp_offer:
        logger.error("Failed to construct DHCP offer packet on interface %s", ifname)
        return (None, None, None)
        
    data = bytes(dhcp_offer)
    addr = fetch_destination_address(dhcp_obj)
    return (data, addr, server_id)

# In case of DHCP Request
# Lookup in the SQL DB for the appropriate data and check if that matches the requested IP
# Compose DHCP Accept message and send back

class state(Enum):
    SELECTING_INIT_REBOOT = 1
    RENEWING_REBINDING = 2
    INVALID = 3

# Valid client states:
# SELECTING : ciaddr = 0 , valid requested_ip, valid server_id 
# INIT-REBOOT : ciaddr = 0, valid requested_ip, no server_id
# RENEWING : valid ciaddr, no requested ip, no server_id
# REBINDING : valid ciaddr, no requested ip, no server_id

def fetch_client_state(server_id: IPv4Address, ciaddr: str, requested_ip: str) -> state:
    try:
         ciaddr = IPv4Address(ciaddr)
    except AddressValueError:
         return state.INVALID
         
    if not ciaddr.is_unspecified:
        if not requested_ip and (not server_id or server_id.is_unspecified):
            return state.RENEWING_REBINDING
        else:
            return state.INVALID
    try:
        if IPv4Address(requested_ip):
            return state.SELECTING_INIT_REBOOT
    except:
        return state.INVALID
        
def process_dhcp_request(dhcp_obj: dhcp, server_id: IPv4Address, ifname: str) -> Optional[Tuple[bytes, IPv4Address, IPv4Address]]:
    client_mac =  Mac(dhcp_obj.chaddr)
    server_id_in_request = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_SERVER_ID)
    ciaddr_in_request = dhcp_obj.ciaddr
    requested_ip = fetch_dhcp_req_ip(dhcp_obj)
    client_state = fetch_client_state(server_id_in_request, ciaddr_in_request, requested_ip)
    logger.debug("Based on DHCP Request opts, client %s is in %s state", 
                              str(client_mac), client_state.name) 
    host_conf_data = fetch_host_conf_data(ifname, client_mac)
    
    if not host_conf_data:
        logger.debug("No configuration data found for the host %s on intf %s. Skipping ..", str(client_mac), ifname)
        return (None, None, None)
        
    offer_ip = None
    if DHCP_IP_OPCODE in host_conf_data:
        offer_ip = host_conf_data[DHCP_IP_OPCODE]

    if DHCP_NON_DEFAULT_SERVERID_OPCODE in host_conf_data:
        logger.debug("For client %s on intf %s using non-default server id: %s (default server id: %s))",
                      str(client_mac), ifname, host_conf_data[DHCP_NON_DEFAULT_SERVERID_OPCODE], server_id)
        server_id = host_conf_data[DHCP_NON_DEFAULT_SERVERID_OPCODE]

    # Validate the requested IP
    if client_state is state.INVALID:
        logger.debug("DHCP-Request: Invalid packet received from %s with server_id: %s ciaddr: %s requested_ip: %s",
                       str(client_mac), server_id_in_request, ciaddr_in_request, requested_ip)
        is_valid_request = False
    
    else:
        if client_state is state.SELECTING_INIT_REBOOT:
            if not offer_ip:
                logger.debug("DHCP-Request: No offer IP found for client %s on intf %s with request IP %s",
                              str(client_mac), ifname, requested_ip)
                is_valid_request = False
            else:
                is_valid_request = (requested_ip and
                            not requested_ip.is_unspecified and 
                            not offer_ip.is_unspecified and 
                            offer_ip == requested_ip)
        else:
            # If the client is in RENEWING or REBINDING state, request IP is not filled
            # So, respond back with available data
            is_valid_request = True
            if not offer_ip:
                logger.debug("DHCP-Request: No offer IP found for client %s in %s state on intf %s",
                             str(client_mac), client_state.name, ifname)
                is_valid_request = False
    
    dhcp_packet = None

    if is_valid_request:
        logger.debug("Constructing DHCP Accept with IP: %s", offer_ip)
        request_list_opt = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_PARAM_REQ)
        # In case of valid request, it is safer to construct reply packet with offer IP, than request IP
        dhcp_packet = construct_dhcp_ack(dhcp_obj, ifname, server_id, offer_ip, request_list_opt, host_conf_data)
    else:
        request_list_opt = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_PARAM_REQ)
        logger.debug("Requested IP (%s) doesn't match available IP (%s)", requested_ip, offer_ip)
        dhcp_packet = construct_dhcp_nak(dhcp_obj, ifname, server_id, requested_ip, request_list_opt, host_conf_data)

    if dhcp_packet is None:
        logger.error("Failed to construct DHCP response packet on interface %s", ifname)
        return (None, None, None)
        
    data = bytes(dhcp_packet)
    addr = fetch_destination_address(dhcp_obj)
    return (data, addr, server_id)

def process_dhcp_inform(dhcp_obj: dhcp, server_id: IPv4Address, ifname: str) -> Optional[Tuple[bytes, IPv4Address, IPv4Address]]:
    client_mac =  Mac(dhcp_obj.chaddr)
    host_conf_data = fetch_host_conf_data(ifname, client_mac)
    if not host_conf_data:
        logger.debug("No configuration data found for the host %s on intf %s. Skipping ..", str(client_mac), ifname)
        return (None, None, None)

    if DHCP_NON_DEFAULT_SERVERID_OPCODE in host_conf_data:
        logger.debug("For client %s on intf %s using non-default server id: %s (default server id: %s))",
                      str(client_mac), ifname, host_conf_data[DHCP_NON_DEFAULT_SERVERID_OPCODE], server_id)
        server_id = host_conf_data[DHCP_NON_DEFAULT_SERVERID_OPCODE]

    logger.debug("Constructing DHCP ACK for client: %s", client_mac)
    request_list_opt = fetch_dhcp_opt(dhcp_obj, dhcp.DHCP_OPT_PARAM_REQ)
    dhcp_packet = construct_dhcp_ack(dhcp_obj, ifname, server_id, None, request_list_opt, host_conf_data)
    if dhcp_packet is None:
        logger.error("Failed to construct DHCP response packet on interface %s", ifname)
        return (None, None, None)
    data = bytes(dhcp_packet)
    addr = fetch_destination_address(dhcp_obj)
    return (data, addr, server_id)

def build_frame(dhcp_data: bytes, dest_mac: Mac, dest_ip: str, 
                src_ip: IPv4Address, ifname: str, server_mac: Mac) -> bytes:
    dh = dpkt.dhcp.DHCP(dhcp_data)
    udp = dpkt.udp.UDP(sport=67, dport=68, data=bytes(dh))
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(dst=IPv4Address(dest_ip).packed,
                    src=IPv4Address(src_ip).packed,
                    ttl=64,
                    p=dpkt.ip.IP_PROTO_UDP,
                    data=udp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=bytes(server_mac),
                                 dst=bytes(dest_mac),
                                 type=0x0800,
                                 data = bytes(ip))
    return bytes(eth)

# If there is a new msg in any of the dhcp intfs, process the data  (Incomplete)

def process_dhcp_packet(ifname: str, server_addr: str, pkt_src_mac: Mac, 
                        dhcp_obj: bytes, server_mac: Mac) -> Optional[bytes]:

    dhcp_type = fetch_dhcp_type(dhcp_obj)
    logger.debug("Received DHCP packet on %s of type %s", ifname, dhcp_type_to_str.get(dhcp_type, dhcp_type))

    try:
        server_id = IPv4Address(server_addr)
    except ValueError as err:
        server_id = IPv4Address('0.0.0.0')

    if (dhcp_type == dhcp.DHCPDISCOVER):
        dhcp_pkt, address, server_id = process_dhcp_discover(dhcp_obj, server_id, ifname)
    elif (dhcp_type == dhcp.DHCPREQUEST):
        dhcp_pkt, address, server_id = process_dhcp_request(dhcp_obj, server_id, ifname)
    elif (dhcp_type == dhcp.DHCPINFORM):
        dhcp_pkt, address, server_id = process_dhcp_inform(dhcp_obj, server_id, ifname)
    elif dhcp_type in dhcp_type_to_str:
        logger.debug("Received DHCP packet of type %s. Ignoring.", dhcp_type_to_str.get(dhcp_type, dhcp_type))
        dhcp_pkt, dest_addr, server_id = (None, None, None)
    else:
        logger.error("Unexpected packet type for DHCP payload %d", dhcp_type)
        dhcp_pkt, dest_addr, server_id = (None, None, None)

    if dhcp_pkt is None or address is None:
        return (None, None, None)

    # If dhcp packet is gatewayed, let the stack do the routing to gateway IP ; Return the dhcp payload
    # Else, use chaddr as the destination mac ; Return the complete dhcp frame
    # How to handle L2 relay agents??
    try:
        if not IPv4Address(dhcp_obj.giaddr).is_unspecified:
            return (dhcp_pkt, IPv4Address(dhcp_obj.giaddr), server_id)
        else:
            dest_mac = Mac(dhcp_obj.chaddr)
            return (build_frame(dhcp_pkt, dest_mac, address, server_id, ifname, server_mac) , None, None)
    except (AddressValueError, ValueError) as err:
        logger.error("%s: Failed to derive destination mac for %s packet from smac %s",
                      err, dhcp_type_to_str.get(dhcp_type, dhcp_type), str(pkt_src_mac))
        return (None, None, None)
