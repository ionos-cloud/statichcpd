#!/usr/bin/env python3


import socket
from typing import Any, List, Tuple, Optional

from .datatypes import *
#from .database_manager import *
from .dhcp6_database_manager import *
from .logmgr import logger
from .dhcp6 import *
import binascii

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

def ll_addr(address: bytes) -> str:
    return ''.join('%02x' % compat_ord(b) for b in address)

class DUID(Enum):
    lladdr_time = 1
    enterprise_num = 2
    lladdr = 3

def construct_dhcp6_packet(msg: (Message.ClientServerDHCP6, Message.RelayServerDHCP6), msg_type: int,
                           ip6: IPv6Address, opt_list: Tuple) -> (Message.ClientServerDHCP6, Message.RelayServerDHCP6):
    if isinstance(msg, Message.ClientServerDHCP6):
        return Message.ClientServerDHCP6(
                                         mtype=msg_type,
                                         xid=msg.xid,
                                         opts=opt_list
                                        )

DEFAULT_T1 = 60
DEFAULT_T2 = 60
DEFAULT_PREF_LIFETIME = 60
DEFAULT_VALID_LIFETIME = 60

def construct_ia_na_response_data(msg: Message.ClientServerDHCP6, data: List[Tuple]) -> bytes:
    ia_na_opts = fetch_all_dhcp6_opt(msg, DHCP6_OPT_IA_NA) # There could be multiple IA_NA options
    encoded_value = b'' 
    # If the IA address mentioned in client request is different from what we have 
    # configured, send back the old one with lifeftime 0 and new one with a valid lifetime
    for requested_na in ia_na_opts:
        requested_id = hex(struct.unpack(">I", requested_na[:4])[0])
        addr6_list = [val[1] for val in data if val[0] ==  requested_id] # Returns a list of addresses confgd for this ID
            
        encoded_value += requested_na[:4]

        (t1,t2) = struct.unpack(">ii", requested_na[4:12])
        if (t1 == t2 and t1 == 0) or t1 > t2 :
            t1 = DEFAULT_T1
            t2 = DEFAULT_T2

        # For testing purpose, set t1 and t2 to low value
        t1 = DEFAULT_T1
        t2 = DEFAULT_T2
        encoded_value += t1.to_bytes(4, 'big') + t2.to_bytes(4, 'big') 

        if len(addr6_list) == 0:
            status_code_val =  2 # No Address Available
            encoded_value += struct.pack(">HHH", DHCP6_OPT_STATUS_CODE, 
                                                 len(bytes(status_code_val)), status_code_val)
            continue


        if len(requested_na) > 12: # Len > 12 => TODO: options are present.. Anything to handle?
            do_something = 1

        pref_lifetime = DEFAULT_PREF_LIFETIME
        valid_lifetime = DEFAULT_VALID_LIFETIME
        iaddr_length = 24

        logger.debug("Constructing IA_ADDR options with the following data: %s", addr6_list)
        for addr in addr6_list:
            encoded_value += struct.pack(">HH", DHCP6_OPT_IAADDR, iaddr_length) + addr.packed + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big')
            # TODO: Any possible IAADDR options to be added??

    return encoded_value

def append_mandatory_options(msg: Message.ClientServerDHCP6, opt_tuple: Tuple, 
                             server_duid: str, advertise_ip6: (IPv6Address, List[IPv6Address])) -> Tuple:
    opt_list = list(opt_tuple)
    client_duid = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    rapid_commit = fetch_dhcp6_opt(msg, DHCP6_OPT_RAPID_COMMIT)
    if rapid_commit:
        opt_list.extend([(DHCP6_OPT_RAPID_COMMIT, rapid_commit)])
    # TODO:
    # Add support for server preference and reconfigure
    # The server preference value MUST default to zero unless otherwise
    # configured by the server administrator.
    # If the Relay-forward messages included an Interface-id option, the server copies that
    # option to the Relay-reply message.
    opt_list.extend([(DHCP6_OPT_SERVERID, struct.pack(">HH%is"%(len(server_duid[2:])/2), 
                                                                int(server_duid[0]), 
                                                                int(server_duid[1]), 
                                                                binascii.unhexlify(server_duid[2:]))), # Find a proper encoding of duid
                     (DHCP6_OPT_CLIENTID, client_duid)])
    return tuple(opt_list)

def construct_dhcp6_opt_list(msg: Message.ClientServerDHCP6,
                             request_list_opt: List[int], ifname: str, 
                             host_conf_data: Dict[str, str]) -> Tuple:
    opt_list = []
    if request_list_opt ==  None:
        logger.debug("No parameter request list")
        return tuple(opt_list)
    other_msg_opts = [ele[0] for ele in msg.opts] 
    for opcode in host_conf_data:
        if opcode in request_list_opt or opcode in other_msg_opts:  # For every option value, do the appropriate encoding
            data = host_conf_data[opcode]
            encoded_data = None
            if isinstance(data, IPv6Address):
                encoded_data = data.packed
            elif isinstance(data, str):
                encoded_data = data.encode('utf-8')
            elif isinstance(data, Int16):
                encoded_data = (data.value).to_bytes(2, 'big')
            elif isinstance(data, Int32):
                encoded_data = (data.value).to_bytes(4, 'big')
            elif isinstance(data, list) and len(data) > 0:
                if all(isinstance(ele, IPv6Address) for ele in data):
                    encoded_data = b''.join([elem.packed for elem in data])
                elif all(isinstance(ele, str) for ele in data):
                    encoded_data = b''.join([elem.encode('utf-8') for elem in data])
                elif all(isinstance(ele, tuple) for ele in data): # Case of IA_NA or IA_TA values
                    if opcode == DHCP6_OPT_IA_NA: 
                        encoded_data = construct_ia_na_response_data(msg, data)
                    elif opcode == DHCP6_OPT_IA_TA:
                        encoded_data = construct_ia_ta_response_data(msg, data)
                    else:
                        logger.error("Configuration data for opcode %d "
                                     " has unexpected values %s of type List of Tuples", 
                                     data, opcode)
                else:
                    logger.error("Elements of unexpected datatype "
                                 "in the client parameter list: %s", data)
            else:
                logger.error("Value(%s) of unexpected type received for opcode %d".format(data, opcode))
            opt_list.append((opcode, encoded_data))
    return tuple(opt_list)

def construct_dhcp_adv(ifname: str, msg: Message.ClientServerDHCP6, 
                       advertise_ip6: (IPv6Address, List[IPv6Address]), request_list_opt: List[int], 
                       host_conf_data: Dict[str, str]) -> Message.ClientServerDHCP6:
    opt_list = construct_dhcp6_opt_list(msg, request_list_opt, ifname, host_conf_data)
    if advertise_ip6 is None and not opt_list: # If no other parameters were requested by client, should offer be sent?
        return None
    # What should be the format of server duid from configuration??? Just take ll address?
    opt_list = append_mandatory_options(msg, opt_list, "315a2a9a2a5aea", advertise_ip6)#, server_duid)
    return construct_dhcp6_packet(msg, ADVERTISE, advertise_ip6, opt_list)


def process_solicit_msg(ifname: str, msg: Message.ClientServerDHCP6) -> Optional[bytes]:
    rapid_commit = fetch_dhcp6_opt(msg, DHCP6_OPT_RAPID_COMMIT)
    request_list_bytestr = fetch_dhcp6_opt(msg, DHCP6_OPT_ORO)
    request_list_opts = struct.unpack('>%iH'%(len(request_list_bytestr)/2), request_list_bytestr)
    client_duid = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    
    # First two bytes of the DUID represent the DUID type
    duid_type = struct.unpack('>H', client_duid[:2])[0]

    # Client ID in database is expected to be of the form : DUID_Type + Hardware_Type + LL_Addr
    #                                                     or DUID_Type + Enterprise_Num + ID
    # eg: DUID_Type=1, Hardware_Type=1 and LL_Addr = 5a:20:9d:28:56:e5 => DUID = 115a209d2856e5

    # Why not have just the LL address as client_id ?? What about DUID type 2??

    if duid_type == DUID.lladdr_time.value: # Static HCPD server cannot server client DUID with dynamic value (time)
        client_id = ''.join(str(elem) for elem in struct.unpack('>HH', client_duid[:4])) + \
                    ll_addr(client_duid[8:])
        logger.debug("Unable to serve dynamic client DUID %s."
                     " Removing time from the value for DB lookup: %s", client_duid, client_id)
    elif duid_type == DUID.lladdr.value:
        client_id = ''.join(str(elem) for elem in struct.unpack('>HH',client_duid[:4])) + \
                    ll_addr(client_duid[4:])
    else:
        client_id = ''.join(str(elem) for elem in struct.unpack('>H', client_duid[:2])) + \
                    ''.join(str(elem) for elem in struct.unpack('>%iH'%(len(client_duid[2:6])/ 2), client_duid[2:6])) + \
                    client_duid[6:]  # Should the value be stored as int or hex in DB?

    logger.debug("Client ID received: %s", client_id)

    
    host_conf_data = fetch_v6host_conf_data(ifname, client_id)
    if not host_conf_data:
        logger.debug("No configuration data found for the host %s on intf %s. Skipping ..", client_id, ifname)
        return None


    advertise_ip6 = None
    if DHCP_IPV6_OPCODE in host_conf_data:
        logger.debug("Found an IPv6 configuration")
        advertise_ip6 = host_conf_data[DHCP_IPV6_OPCODE]
        logger.debug("Constructing DHCP Advertise message with IPv6: %s ", advertise_ip6)

    if rapid_commit:
        do_nothing = 1
        #dhcp_response = construct_dhcp_reply(ifname, msg, advertise_ip6, request_list_opts, host_conf_data)
    else:
        dhcp_response = construct_dhcp_adv(ifname, msg, advertise_ip6, request_list_opts, host_conf_data)

    if not dhcp_response:
        logger.error("Error constructing DHCP6 %s packet "
                      "on interface %s for client %s",
                      dhcp6_type_to_str(dhcp_response.mtype),
                      ifname, client_mac)
        return None
    data = bytes(dhcp_response)
    '''
    addr = fetch_destination_address(payload)
    return...
    '''
    return data

def process_client_server_msg(ifname: str, msg: Message.ClientServerDHCP6) -> Optional[bytes]:
    client_id = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    valid_msg = validate_msg(msg)
    if not valid_msg:
        logger.error("%s message validation failed.", dhcp6_type_to_str(msg.mtype))
        # TODO:
        # Server MAY send a Reply (or Advertise as appropriate) with a Server
        # Identifier option, a Client Identifier option if one was included in
        # the message and a Status Code option with status UnSpecFail.

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
