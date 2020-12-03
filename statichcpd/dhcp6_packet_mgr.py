#!/usr/bin/env python3


import socket
from typing import Any, List, Tuple, Optional

from .datatypes import *
from .database_manager import *
from .dhcp6_database_manager import *
from .logmgr import logger
from .dhcp6 import *

# Message Validation: RFC 3315 Section 15

def validate_msg(msg: (Message.ClientServerDHCP6, Message.RelayServerDHCP6)) -> bool:
    if msg.mtype in [SOLICIT, CONFIRM, REBIND] :
        return fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID) and \
               not fetch_dhcp6_opt(msg, DHCP6_OPT_SERVERID)
    elif msg.mtype in [REQUEST, RENEW, DECLINE, RELEASE]:
        return fetch_dhcp6_opt(msg, DHCP6_OPT_SERVERID) and \
               fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID) #and serverid == my DUID
    elif msg.mtype == INFORMATIONREQUEST:
        return not fetch_dhcp6_opt(msg, DHCP6_OPT_IA_NA) and \
               not fetch_dhcp6_opt(msg, DHCP6_OPT_IA_TA) #and
               #(not fetch_dhcp6_opt(msg, DHCP6_OPT_SERVERID) or serverid == my DUID)
    return True

def convert_bytestr_to_intlist(reqstr: bytes) -> List:
    temp = reqstr
    reqlist = []
    while temp:
        try:
            # Request list options are 2 bytes each
            reqlist.append(int.from_bytes(temp[:2], byteorder='big'))
        except:
            logger.error("Error converting request list bytestring to list of integers")
            return reqlist
        temp = temp[2:]

    return reqlist

def ll_addr(address: bytes) -> str:
    return ''.join('%02x' % compat_ord(b) for b in address)

class DUID(Enum):
    lladdr_time = 1
    enterprise_num = 2
    lladdr = 3

def process_solicit_msg(ifname: str, msg: Message.ClientServerDHCP6) -> Optional[bytes]:
    rapid_commit = fetch_dhcp6_opt(msg, DHCP6_OPT_RAPID_COMMIT)
    request_list_bytestr = fetch_dhcp6_opt(msg, DHCP6_OPT_ORO)
    request_list_opts = convert_bytestr_to_intlist(request_list_bytestr)
    client_duid = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    
    # First two bytes of the DUID represent the DUID type
    duid_type = convert_bytestr_to_intlist(client_duid[:2])[0]

    # Client ID in database is expected to be of the form : DUID_Type + Hardware_Type + LL_Addr
    #                                                     or DUID_Type + Enterprise_Num + ID
    # eg: DUID_Type=1, Hardware_Type=1 and LL_Addr = 5a:20:9d:28:56:e5 => DUID = 115a209d2856e5

    # Why not have just the LL address as client_id ?? What about DUID type 2??

    if duid_type == DUID.lladdr_time.value: # Static HCPD server cannot server client DUID with dynamic value (time)
        client_id = ''.join(str(elem) for elem in convert_bytestr_to_intlist(client_duid[:4])) + \
                    ll_addr(client_duid[8:])
        logger.debug("Unable to serve dynamic client DUID %s."
                     " Removing time from the value for DB lookup: %s", client_duid, client_id)
    elif duid_type == DUID.lladdr.value:
        client_id = ''.join(str(elem) for elem in convert_bytestr_to_intlist(client_duid[:4])) + \
                    ll_addr(client_duid[4:])
    else:
        client_id = ''.join(str(elem) for elem in convert_bytestr_to_intlist(client_duid[:2])) + \
                    ''.join(str(elem) for elem in convert_bytestr_to_intlist(client_duid[2:6])) + \
                    client_duid[6:]  # Should the value be stored as int or hex in DB?

    logger.debug("Client ID received: %s", client_id)

    
    host_conf_data = fetch_v6host_conf_data(ifname, client_id)
    if not host_conf_data:
        logger.debug("No configuration data found for the host %s on intf %s. Skipping ..", client_id, ifname)
        return None

    print(host_conf_data)

    '''
    if DHCP_IPV6_OPCODE in host_conf_data:
        advertise_ip6 = host_conf_data[DHCP_IPV6_OPCODE]
        if advertise_ip6:
            logger.debug("Constructing DHCP OFFER with IP: %s ", advertise_ip6)

    if not rapid_commit:
        dhcp_advertise = construct_dhcp_adv(ifname, payload, advertise_ip6, request_list_opt, host_conf_data)

    if not dhcp_advertise:
        logger.error("Error constructing DHCP6 advertise packet "
                      "on interface %s for client %s", ifname, client_mac)
        return (None, None, None)


    data = bytes(dhcp_advertise)
    addr = fetch_destination_address(payload)
    return...
    '''
    return None

def process_client_server_msg(ifname: str, msg: Message.ClientServerDHCP6) -> Optional[bytes]:
    client_id = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    valid_msg = validate_msg(msg)
    if not valid_msg:
        logger.error("%s message validation failed.", dhcp6_type_to_str(msg.mtype))
        return None

    logger.debug("Received a client server message of type %s from client with id %s", 
                dhcp6_type_to_str(msg.mtype),
                client_id)

    if msg.mtype is SOLICIT:
        return process_solicit_msg(ifname, msg)
    '''
    if msg.mtype is REQUEST:
        return process_request_msg(ifname, payload)
    if msg.mtype is CONFIRM:
        return process_confirm_msg(ifname, payload)
    if msg.mtype is RENEW:
        return process_renew_msg(ifname, payload)
    if msg.mtype is REBIND:
        return process_rebind_msg(ifname, payload)
    if msg.mtype is DECLINE:
        return process_decline_msg(ifname, payload)
    if msg.mtype is RELEASE:
        return process_release_msg(ifname, payload)
    if msg.mtype is INFORMATIONREQUEST:
        return process_inforequest_msg(ifname, payload)
    '''
    return None

def process_relay_server_msg(ifname: str, payload: Message.RelayServerDHCP6) -> Optional[bytes]:
    logger.debug("Received a relay server message of type %s", dhcp6_type_to_str(payload.mtype))
    if msg.mtype is RELAYFORW:
        return process_relayforw_msg(ifname, payload)
    return None

def process_dhcp6_packet(ifname: str, dhcp6_msg: Message, server_mac: Mac) -> Optional[bytes]:
    payload = dhcp6_msg.data
    if isinstance(payload, Message.ClientServerDHCP6):
        pkt = process_client_server_msg(ifname, payload)
    elif isinstance(payload, Message.RelayServerDHCP6):
        pkt = process_relay_server_msg(ifname, payload)
    else:
        logger.error("Malformed packet with unknown DHCP msg type %d received", type(payload))
        pkt = None

    return pkt
