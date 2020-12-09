#!/usr/bin/env python3


import socket
import binascii
from typing import Any, List, Tuple, Optional
from ipaddress import IPv6Address, AddressValueError

from .datatypes import *
from .dhcp6_database_manager import *
from .logmgr import logger
from .dhcp6 import *

use_mac_as_duid = False
disable_ia_id = False

def init(config: SectionProxy) -> None:
    global use_mac_as_duid, disable_ia_id
    use_mac_as_duid = config.get('use_mac_as_client_duid', 'False')
    disable_ia_id = config.get('disable_ia_id', 'False')
 
# Message Validation: RFC 3315 Section 15

def validate_msg(msg: Union[Message.ClientServerDHCP6, Message.RelayServerDHCP6]) -> bool:
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

def construct_dhcp6_packet(msg: Union[Message.ClientServerDHCP6, Message.RelayServerDHCP6], msg_type: int,
                           opt_list: Tuple) -> Union[Message.ClientServerDHCP6, Message.RelayServerDHCP6]:
    if isinstance(msg, Message.ClientServerDHCP6):
        return Message.ClientServerDHCP6(
                                         mtype=msg_type,
                                         xid=msg.xid,
                                         opts=opt_list
                                        )

DEFAULT_T1 = 60
DEFAULT_T2 = 120
DEFAULT_PREF_LIFETIME = 60
DEFAULT_VALID_LIFETIME = 60
DEFAULT_IAADDR_LEN = 24

def construct_ia_na_response_data(msg: Message.ClientServerDHCP6, 
                                  conf_data: List[Union[IPv6Address, Tuple]]) -> Optional[bytes]:
    ia_na_opts = fetch_all_dhcp6_opt(msg, DHCP6_OPT_IA_NA) # There could be multiple IA_NA options
    if conf_data is None:
        return None
    encoded_value = b'' 

    # For each requested IA_NA option, find a corresponding configuration with that IA_ID
    for requested_na in ia_na_opts:
        requested_id = hex(struct.unpack(">I", requested_na[:4])[0])
        logger.debug("IA_NA requested for ID: %s",requested_id)
        logger.debug("Available IA_NA configurations for the client: %s",conf_data)
        if disable_ia_id:
            # Ignore IAID values and return all addresses associated with this client
            # When disable_ia_id is set, conf_data is expected to be List[IPv6Address]
            configured_addr6_list = conf_data
        else:
            # Consider only the set of addresses that have the same ID
            configured_addr6_list = [val[1] for val in \
                                conf_data if val[0] ==  requested_id]
            
        encoded_value += requested_na[:4] # The IA_NA value starts with IA_ID

        (t1,t2) = struct.unpack(">ii", requested_na[4:12])
        if (t1 == t2 and t1 == 0) or t1 > t2 :
            t1 = DEFAULT_T1
            t2 = DEFAULT_T2

        # For testing purpose, set t1 and t2 to low value
        t1 = DEFAULT_T1
        t2 = DEFAULT_T2
        encoded_value += t1.to_bytes(4, 'big') + t2.to_bytes(4, 'big') # Append t1,t2 to the IA_NA value 

        if len(configured_addr6_list) == 0:
            status_code_val =  DHCP6_NoAddrsAvail
            encoded_value += struct.pack(">HHH", DHCP6_OPT_STATUS_CODE, 
                                                 len(bytes(status_code_val)), status_code_val)
            continue


        if len(requested_na) > 12: # Len > 12 => IA_NA options are present
            offset = 12
            requested_addr_list = []
            while offset < len(requested_na):
                op = struct.unpack(">H", requested_na[offset:offset+2])[0]
                if op == DHCP6_OPT_IAADDR:
                    try:
                        requested_addr_list.extend([IPv6Address(requested_na[offset+4:offset+20])])
                    except AddressValueError:
                        logger.error("Invalid IPv6 address in IAADDR option: %s", 
                                                 requested_na[offset+4:offset+20])
                    # TODO: Should other IAADDR options be considered?
                # Next offset is at offset + sizeof(opcode) + sizeof(option-len) + option-len
                offset += (2 + 2 + struct.unpack(">H", requested_na[offset+2:offset+4])[0])
            logger.debug("Requested list of IAADDRs is %s", requested_addr_list)
            # For request msgs, if the IA address mentioned in client request is different from what we have 
            # configured, send back the old one with lifeftime 0 and new one with a valid lifetime
            expired_addresses = [addr for addr in requested_addr_list if addr not in configured_addr6_list]
            logger.debug("Expired address list: %s", expired_addresses)
            if expired_addresses != [] and msg.mtype == CONFIRM:
                # If atleast one message is not valid, send back reply with status NotOnLink
                return None
            for addr in expired_addresses:
                pref_lifetime = 0
                valid_lifetime = 0
                iaddr_length = DEFAULT_IAADDR_LEN
                encoded_value += struct.pack(">HH", DHCP6_OPT_IAADDR, iaddr_length) + addr.packed + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big')


        pref_lifetime = DEFAULT_PREF_LIFETIME
        valid_lifetime = DEFAULT_VALID_LIFETIME
        iaddr_length = DEFAULT_IAADDR_LEN

        logger.debug("Constructing IA_ADDR options for IA_NA with the following data: %s", configured_addr6_list)
        for addr in configured_addr6_list:
            encoded_value += struct.pack(">HH", DHCP6_OPT_IAADDR, iaddr_length) + addr.packed + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big')
            # TODO: Any possible IAADDR options to be added??

    return encoded_value

def construct_ia_ta_response_data(msg: Message.ClientServerDHCP6, 
                                  conf_data: List[Union[IPv6Address, Tuple]]) -> Optional[bytes]:
    ia_ta_opts = fetch_all_dhcp6_opt(msg, DHCP6_OPT_IA_TA) # There could be multiple IA_NA options
    encoded_value = b'' 
    if conf_data is None:
        return None
    # For each requested IA_TA option, find a corresponding configuration with that IA_ID
    for requested_ta in ia_ta_opts:
        requested_id = hex(struct.unpack(">I", requested_ta[:4])[0])
        if disable_ia_id:
            # Ignore IAID values and return all addresses associated with this client
            # When disable_ia_id is set, conf_data is expected to be List[IPv6Address]
            configured_addr6_list = conf_data
        else:
            # Consider only the set of addresses that have the same ID
            configured_addr6_list = [val[1] for val in conf_data if val[0] ==  requested_id]            
        encoded_value += requested_ta[:4] # The IA_NA value starts with IA_ID

        if len(configured_addr6_list) == 0:
            status_code_val =  DHCP6_NoAddrsAvail
            encoded_value += struct.pack(">HHH", DHCP6_OPT_STATUS_CODE, 
                                                 len(bytes(status_code_val)), status_code_val)
            continue


        if len(requested_ta) > 4: # Len > 4 => Options are present
            offset = 4
            requested_addr_list = []
            while offset < len(requested_na):
                op = struct.unpack(">H", requested_na[offset:offset+2])[0]
                if op == DHCP6_OPT_IAADDR:
                    try:
                        requested_addr_list.extend([IPv6Address(requested_na[offset+4:offset+20])])
                    except AddressValueError:
                        logger.error("Invalid IPv6 address in IAADDR option: %s", 
                                                 requested_na[offset+4:offset+20])
                    # TODO: Should other IAADDR options be considered?
                # Next offset is at offset + sizeof(opcode) + sizeof(option-len) + option-len
                offset += (2 + 2 + struct.unpack(">H", requested_na[offset+2:offset+4])[0])
            logger.debug("Requested list of temporary IAADDRs is %s", requested_addr_list)
            # For request msgs, if the IA address mentioned in client request is different from what we have 
            # configured, send back the old one with lifeftime 0 and new one with a valid lifetime
            expired_addresses = [addr for addr in requested_addr_list if addr not in configured_addr6_list]
            logger.debug("Expired temporary address list: %s", expired_addresses)
            if expired_addresses != [] and msg.mtype == CONFIRM:
                # If atleast one message is not valid, send back reply with status NotOnLink
                return None
            for addr in expired_addresses:
                pref_lifetime = 0
                valid_lifetime = 0
                iaddr_length = DEFAULT_IAADDR_LEN
                encoded_value += struct.pack(">HH", DHCP6_OPT_IAADDR, iaddr_length) + addr.packed + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big')


        pref_lifetime = DEFAULT_PREF_LIFETIME
        valid_lifetime = DEFAULT_VALID_LIFETIME
        iaddr_length = DEFAULT_IAADDR_LEN

        logger.debug("Constructing IA_ADDR options for IA_TA with the following data: %s", configured_addr6_list)
        for addr in configured_addr6_list:
            encoded_value += struct.pack(">HH", DHCP6_OPT_IAADDR, iaddr_length) + addr.packed + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big')
            # TODO: Any possible IAADDR options to be added??

    return encoded_value


def append_mandatory_options(msg: Message.ClientServerDHCP6, opt_tuple: Tuple, 
                             server_duid: str) -> Tuple:
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
    # opt_list.extend([(DHCP6_OPT_SERVERID, struct.pack(">HH%is"%(len(server_duid[2:])/2), 
    #                                                            int(server_duid[0]), 
    #                                                            int(server_duid[1]), 
    #                                                            binascii.unhexlify(server_duid[2:]))), # Find a proper encoding of duid
    opt_list.extend([(DHCP6_OPT_SERVERID, server_duid),
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
                    if opcode == DHCP6_OPT_IA_NA: 
                        encoded_data = construct_ia_na_response_data(msg, data)
                    elif opcode == DHCP6_OPT_IA_TA:
                        encoded_data = construct_ia_ta_response_data(msg, data)
                        #TODO: Add code to handle IA_PREFIX option as well
                    else:
                        encoded_data = b''.join([elem.packed for elem in data])
                elif all(isinstance(ele, str) for ele in data):
                    encoded_data = b''.join([elem.encode('utf-8') for elem in data])
                elif all(isinstance(ele, tuple) for ele in data): # Case of IA_NA or IA_TA values
                    if opcode == DHCP6_OPT_IA_NA: 
                        encoded_data = construct_ia_na_response_data(msg, data)
                    elif opcode == DHCP6_OPT_IA_TA:
                        encoded_data = construct_ia_ta_response_data(msg, data)
                        #TODO:Add code to handle IA_PREFIX option as well
                    else:
                        logger.error("Configuration data for opcode %d "
                                     " has unexpected values %s of type List of Tuples", 
                                     data, opcode)
                        continue
                else:
                    logger.error("Elements of unexpected datatype "
                                 "in the client parameter list: %s", data)
                    continue
            else:
                logger.error("Value(%s) of unexpected type received for opcode %d".format(data, opcode))
            opt_list.append((opcode, encoded_data))
    return tuple(opt_list)

def construct_dhcp_reply(ifname: str, msg: Message.ClientServerDHCP6, 
                       request_list_opt: List[int], 
                       host_conf_data: Dict[str, str],
                       server_duid: str) -> Message.ClientServerDHCP6:
    opt_list = construct_dhcp6_opt_list(msg, request_list_opt, ifname, host_conf_data)
    if not opt_list: # If no other parameters were requested by client, should offer be sent?
        return None
    # What should be the format of server duid from configuration??? Just take ll address?
    opt_list = append_mandatory_options(msg, opt_list, server_duid)
    return construct_dhcp6_packet(msg, REPLY, opt_list)

def construct_dhcp_adv(ifname: str, msg: Message.ClientServerDHCP6, 
                       request_list_opt: List[int], 
                       host_conf_data: Dict[str, str],
                       server_duid: str) -> Message.ClientServerDHCP6:
    opt_list = construct_dhcp6_opt_list(msg, request_list_opt, ifname, host_conf_data)
    if not opt_list: # If no other parameters were requested by client, should offer be sent?
        return None
    # What should be the format of server duid from configuration??? Just take ll address?
    opt_list = append_mandatory_options(msg, opt_list, server_duid)
    return construct_dhcp6_packet(msg, ADVERTISE, opt_list)

def fetch_client_duid(client_duid: str) -> str:
    # First two bytes of the DUID represent the DUID type
    # Validation has confirmed that DHCP6_OPT_CLIENTID is set
    duid_type = struct.unpack('>H', client_duid[:2])[0]

    # Client ID in database is expected to be of the form : DUID_Type + Hardware_Type + LL_Addr
    #                                                     or DUID_Type + Enterprise_Num + ID
    # eg: DUID_Type=1, Hardware_Type=1 and LL_Addr = 5a:20:9d:28:56:e5 => DUID = 115a209d2856e5

    # Why not have just the LL address as client_id ?? What about DUID type 2??

    if duid_type == DUID.lladdr_time.value: # Static HCPD server cannot server client DUID with dynamic value (time)
        client_id = ''.join(str(elem) for elem in struct.unpack('>HH', client_duid[:4])) + \
                    ll_addr(client_duid[8:])
        logger.debug("Unable to serve dynamic client DUID %s."
                     " Removing time from the duid value for DB lookup: %s", client_duid, client_id)
    elif duid_type == DUID.lladdr.value:
        client_id = ''.join(str(elem) for elem in struct.unpack('>HH',client_duid[:4])) + \
                    ll_addr(client_duid[4:])
    else:
        client_id = ''.join(str(elem) for elem in struct.unpack('>H', client_duid[:2])) + \
                    ''.join(str(elem) for elem in struct.unpack('>%iH'%(len(client_duid[2:6])/ 2), client_duid[2:6])) + \
                    client_duid[6:]  # Should the value be stored as int or hex in DB?
    return client_id

def process_solicit_msg(ifname: str, msg: Message.ClientServerDHCP6, server_duid: str, src_mac: Mac) -> Optional[bytes]:
    rapid_commit = fetch_dhcp6_opt(msg, DHCP6_OPT_RAPID_COMMIT)
    request_list_bytestr = fetch_dhcp6_opt(msg, DHCP6_OPT_ORO)
    request_list_opts = struct.unpack('>%iH'%(len(request_list_bytestr)/2), request_list_bytestr) \
                        if request_list_bytestr is not None else []
    client_duid = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    
    if use_mac_as_duid:
        client_id = src_mac
    else:
        client_id = fetch_client_duid(client_duid)
    logger.debug("Client ID received: %s", client_id)

    
    host_conf_data = fetch_v6host_conf_data(ifname, client_id)
    if not host_conf_data:
        logger.debug("No configuration data found for the host %s on intf %s. Skipping ..", client_id, ifname)
        return None

    if rapid_commit:
        dhcp_response = construct_dhcp_reply(ifname, msg, request_list_opts, host_conf_data, server_duid)
    else:
        dhcp_response = construct_dhcp_adv(ifname, msg, request_list_opts, host_conf_data, server_duid)

    if not dhcp_response:
        logger.error("Error constructing DHCP6 Advertise packet for %s"
                      "on interface %s for client %s",
                      msg.mtype,
                      ifname, client_mac)
        return None
    data = bytes(dhcp_response)
    return data

def process_request_renew_rebind_msg(ifname: str, msg: Message.ClientServerDHCP6, 
                                     server_duid: str, src_mac: Mac) -> Optional[bytes]:
    client_duid = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    # TODO: If it's unicast and unicast is not supported for this client,
    #       send back Status code UseMulticast
    request_list_bytestr = fetch_dhcp6_opt(msg, DHCP6_OPT_ORO)
    request_list_opts = struct.unpack('>%iH'%(len(request_list_bytestr)/2), request_list_bytestr) \
                        if request_list_bytestr is not None else []
   
    if use_mac_as_duid:
        client_id = src_mac
    else:
        client_id = fetch_client_duid(client_duid)
    logger.debug("Client ID received: %s", client_id)
    
    host_conf_data = fetch_v6host_conf_data(ifname, client_id)
    if not host_conf_data:
        logger.debug("No configuration data found for the host %s on intf %s. Skipping ..", client_id, ifname)
        return None

    dhcp_response = construct_dhcp_reply(ifname, msg, request_list_opts, host_conf_data, server_duid)

    if not dhcp_response:
        logger.error("Error constructing DHCP6 Reply packet for %s "
                      "on interface %s for client %s",
                      msg.mtype,
                      ifname, client_mac)
        return None
    data = bytes(dhcp_response)
    return data

def process_confirm_msg(ifname: str, msg: Message.ClientServerDHCP6, server_duid: str, src_mac: Mac) -> Optional[bytes]:
    client_duid = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    # TODO: If it's unicast and unicast is not supported for this client,
    #       send back Status code UseMulticast
   
    if use_mac_as_duid:
        client_id = src_mac
    else:
        client_id = fetch_client_duid(client_duid)
    logger.debug("Client ID received: %s", client_id)
    
    host_conf_data = fetch_v6host_conf_data(ifname, client_id)
    if not host_conf_data:
        logger.debug("No configuration data found for the host %s on intf %s. Skipping ..", client_id, ifname)
        return None

    encoded_ia_na = ''
    encoded_ia_ta = ''
    if DHCP6_OPT_IA_NA in msg.opts: 
        encoded_ia_na  = construct_ia_na_response_data(msg, host_conf_data.get(DHCP6_OPT_IA_NA, None))
    if DHCP6_OPT_IA_TA in msg.opts:
        encoded_ia_ta = construct_ia_ta_response_data(msg, host_conf_data.get(DHCP6_OPT_IA_TA, None))

    opt_list = [(DHCP6_OPT_STATUS_CODE, DHCP6_Success)]
    if encoded_ia_na is None or encoded_ia_ta is None:
        opt_list = [(DHCP6_OPT_STATUS_CODE, DHCP6_NotOnLink)]
        
    opt_list = append_mandatory_options(msg, opt_list, server_duid)
    dhcp_response = construct_dhcp6_packet(msg, REPLY, opt_list)

    if not dhcp_response:
        logger.error("Error constructing DHCP6 Reply packet for %s"
                      "on interface %s for client %s",
                      msg.mtype,
                      ifname, client_mac)
        return None
    data = bytes(dhcp_response)
    return data

def process_client_server_msg(ifname: str, msg: Message.ClientServerDHCP6, server_duid: str, src_mac: Mac) -> Optional[bytes]:
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
        return process_solicit_msg(ifname, msg, server_duid, src_mac)
    if msg.mtype is REQUEST or msg.mtype is RENEW or msg.mtype is REBIND:
        return process_request_renew_rebind_msg(ifname, msg, server_duid, src_mac)
    if msg.mtype is CONFIRM:
        return process_confirm_msg(ifname, msg, server_duid, src_mac)
    '''
    if msg.mtype is DECLINE:
        return process_decline_msg(ifname, payload)
    if msg.mtype is RELEASE:
        return process_release_msg(ifname, payload)
    if msg.mtype is INFORMATIONREQUEST:
        return process_inforequest_msg(ifname, payload)
    '''
    return None

def process_relay_server_msg(ifname: str, payload: Message.RelayServerDHCP6, server_duid: str, src_mac: Mac) -> Optional[bytes]:
    logger.debug("Received a relay server message of type %s", dhcp6_type_to_str(payload.mtype))
    if msg.mtype is RELAYFORW:
        return process_relayforw_msg(ifname, payload)
    return None

def process_dhcp6_packet(ifname: str, dhcp6_msg: Message, server_mac: Mac, src_mac: Mac) -> Optional[bytes]:
    payload = dhcp6_msg.data
    server_duid = struct.pack(">HH", 3, 1) + (str(server_mac).replace(":","")).encode('utf-8')
    if isinstance(payload, Message.ClientServerDHCP6):
        pkt = process_client_server_msg(ifname, payload, server_duid, src_mac)
    elif isinstance(payload, Message.RelayServerDHCP6):
        pkt = process_relay_server_msg(ifname, payload, server_duid, src_mac)
    else:
        logger.error("Malformed packet with unknown DHCP msg type %d received", type(payload))
        pkt = None

    return pkt
