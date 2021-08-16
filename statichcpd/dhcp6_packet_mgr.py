#!/usr/bin/env python3


import socket
import struct
import binascii
from typing import Any, List, Tuple, Union, Optional, Dict, cast, Iterable
from ipaddress import IPv6Address, IPv6Network, AddressValueError
from configparser import SectionProxy
from enum import Enum
from dpkt.compat import compat_ord

from .datatypes import *
from .database_manager import *
from .logmgr import logger
from .dhcp6 import *

use_mac_as_duid = False
disable_ia_id = False

DEFAULT_IAADDR_LEN = 24
DEFAULT_IAPD_LEN = 25

default_t1 = 0
default_t2 = 0
default_pref_lifetime = 0
default_valid_lifetime = 0

def init(config: Dict[str, Any]) -> None:
    global use_mac_as_duid, disable_ia_id
    global default_t1, default_t2, default_pref_lifetime, default_valid_lifetime
    use_mac_as_duid = bool(config.get('use_mac_as_client_duid', False))
    disable_ia_id = bool(config.get('disable_ia_id', False))
    default_t1 = int(config.get('default_renew_time', 1000))
    default_t2 = int(config.get('default_rebind_time', 2000))
    default_pref_lifetime = int(config.get('default_pref_lifetime', 3000))
    default_valid_lifetime = int(config.get('default_valid_lifetime', 4000))
 
# Message Validation: RFC 3315 Section 15

def validate_msg(msg: Message.ClientServerDHCP6,
                 server_duid: bytes) -> bool:
    if msg.mtype in [SOLICIT, CONFIRM, REBIND] :
        return fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID) is not None and \
               fetch_dhcp6_opt(msg, DHCP6_OPT_SERVERID) is None
    elif msg.mtype in [REQUEST, RENEW, DECLINE, RELEASE]:
        return fetch_dhcp6_opt(msg, DHCP6_OPT_SERVERID) is not None and \
               fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID) is not None and \
               fetch_dhcp6_opt(msg, DHCP6_OPT_SERVERID) == server_duid
    elif msg.mtype == INFORMATIONREQUEST:
        return fetch_dhcp6_opt(msg, DHCP6_OPT_IA_NA) is None and \
               fetch_dhcp6_opt(msg, DHCP6_OPT_IA_TA) is None and \
               (fetch_dhcp6_opt(msg, DHCP6_OPT_SERVERID) is None or \
               fetch_dhcp6_opt(msg, DHCP6_OPT_SERVERID) == server_duid)
    return True

def ll_addr(address: bytes) -> str:
    return ''.join('%02x' % compat_ord(b) for b in address)

class DUID(Enum):
    lladdr_time = 1
    enterprise_num = 2
    lladdr = 3

def construct_dhcp6_packet(msg: Message.ClientServerDHCP6, msg_type: int,
                           opt_list: Tuple[Tuple[int, Any], ...]) -> Message.ClientServerDHCP6:
    if isinstance(msg, Message.ClientServerDHCP6):
        return Message.ClientServerDHCP6(
                                         mtype=msg_type,
                                         xid=msg.xid,
                                         opts=opt_list
                                        )

def construct_ia_na_response_data(msg: Message.ClientServerDHCP6, 
                                  conf_data: List[Union[IPv6Address, Tuple[str, IPv6Address]]],
                                  host_data: Dict[int,Any], ifname: str,
                                  client_id: Union[Mac, str]) -> Optional[bytes]:
    ia_na_opts = fetch_all_dhcp6_opt(msg, DHCP6_OPT_IA_NA) # There could be multiple IA_NA options
    if conf_data is None:
        return None
    encoded_value = b''

    # For each requested IA_NA option, find a corresponding configuration with that IA_ID
    for requested_na in ia_na_opts:
        requested_id = hex(struct.unpack(">I", requested_na[:4])[0])
        logger.debug("Client: %s Ifname: %s IA_NA requested for IAID: %s",
                      client_id, ifname, requested_id)
        logger.debug("Client: %s Ifname: %s Available IA_NA configurations for the client: %s",
                      client_id, ifname, conf_data)
        configured_addr6_list: List[IPv6Address]
        if disable_ia_id:
            # Ignore IAID values and return all addresses associated with this client
            # When disable_ia_id is set, conf_data is expected to be List[IPv6Address]
            if not all(isinstance(ele, IPv6Address) for ele in conf_data):
                logger.error("Client %s: Input Error: Invalid data for client's IA_NA"
                             " when disable_ia_id is set: %s", client_id, conf_data)
                return encoded_value
            configured_addr6_list = cast(List[IPv6Address], conf_data) # To satisfy mypy
        else:
            # Consider only the set of addresses that have the same ID
            if (not all(isinstance(ele, tuple) for ele in conf_data) or 
                   not all(isinstance(val, str) for val in [ele[0] for ele in conf_data]) or  #type: ignore
                   not all(isinstance(val, IPv6Address) for val in [ele[1] for ele in conf_data])) : #type: ignore
                logger.error("Client: %s : Input Error: Invalid data for client's IA_NA"
                             " when disable_ia_id is not set: %s", client_id, conf_data)
                return encoded_value
            configured_addr6_list = [val[1] for val in \
                                cast(Iterable[Tuple[str, IPv6Address]], conf_data) \
                                if val[0] ==  requested_id]
            
        encoded_value += requested_na[:4] # The IA_NA value starts with IA_ID

        (t1,t2) = struct.unpack(">ii", requested_na[4:12])
        if (t1 == t2 and t1 == 0) or t1 > t2 :
            t1 = default_t1
            t2 = default_t2

        if DHCP6_NON_DEFAULT_T1 in host_data:
            t1 = host_data[DHCP6_NON_DEFAULT_T1].value
        if DHCP6_NON_DEFAULT_T2 in host_data:
            t2 = host_data[DHCP6_NON_DEFAULT_T2].value

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
                        logger.error("Client:%s Ifname:%s Invalid IPv6 address in IAADDR option: %s",
                                      client_id, ifname,
                                      requested_na[offset+4:offset+20])
                    # TODO: Should other IAADDR options be considered?
                # Next offset is at offset + sizeof(opcode) + sizeof(option-len) + option-len
                offset += (2 + 2 + struct.unpack(">H", requested_na[offset+2:offset+4])[0])
            logger.debug("Client: %s Ifname: %s Requested list of IAADDRs is %s", 
                          client_id, ifname, requested_addr_list)
            # For request msgs, if the IA address mentioned in client request is different from what we have 
            # configured, send back the old one with lifeftime 0 and new one with a valid lifetime
            expired_addresses = [addr for addr in requested_addr_list if addr not in configured_addr6_list]
            logger.debug("Client: %s Ifname: %s Expired address list: %s", 
                          client_id, ifname, expired_addresses)
            if expired_addresses != [] and msg.mtype == CONFIRM:
                # If atleast one message is not valid, send back reply with status NotOnLink
                return None
            for addr in expired_addresses:
                pref_lifetime = 0
                valid_lifetime = 0
                iaddr_length = DEFAULT_IAADDR_LEN
                encoded_value += struct.pack(">HH", DHCP6_OPT_IAADDR, iaddr_length) + addr.packed + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big')


        iaddr_length = DEFAULT_IAADDR_LEN
        pref_lifetime = default_pref_lifetime
        valid_lifetime = default_valid_lifetime
        if DHCP6_NON_DEFAULT_PREF_LIFETIME in host_data:
            pref_lifetime = host_data[DHCP6_NON_DEFAULT_PREF_LIFETIME].value
        if DHCP6_NON_DEFAULT_VALID_LIFETIME in host_data:
            valid_lifetime = host_data[DHCP6_NON_DEFAULT_VALID_LIFETIME].value

        for addr in configured_addr6_list:
            encoded_value += struct.pack(">HH", DHCP6_OPT_IAADDR, iaddr_length) + addr.packed + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big')
            # TODO: Any possible IAADDR options to be added??

    return encoded_value

def construct_ia_ta_response_data(msg: Message.ClientServerDHCP6, 
                                  conf_data: List[Union[IPv6Address, Tuple[str, IPv6Address]]],
                                  host_data: Dict[int, Any], ifname: str,
                                  client_id: Union[Mac, str]) -> Optional[bytes]:
    ia_ta_opts = fetch_all_dhcp6_opt(msg, DHCP6_OPT_IA_TA) # There could be multiple IA_NA options
    encoded_value = b''
    if conf_data is None:
        return None
    # For each requested IA_TA option, find a corresponding configuration with that IA_ID
    for requested_ta in ia_ta_opts:
        requested_id = hex(struct.unpack(">I", requested_ta[:4])[0])
        configured_addr6_list: List[IPv6Address]
        if disable_ia_id:
            # Ignore IAID values and return all addresses associated with this client
            # When disable_ia_id is set, conf_data is expected to be List[IPv6Address]
            if not all(isinstance(ele, IPv6Address) for ele in conf_data):
                logger.error("Client: %s Input Error: Invalid data for client's IA_TA"
                             " when disable_ia_id is set: %s", client_id, conf_data)
                return encoded_value
            configured_addr6_list = cast(List[IPv6Address], conf_data) # To satisfy mypy
        else:
            # Consider only the set of addresses that have the same ID
            if (not all(isinstance(ele, tuple) for ele in conf_data) or 
                   not all(isinstance(val, str) for val in [ele[0] for ele in conf_data]) or  #type: ignore
                   not all(isinstance(val, IPv6Address) for val in [ele[1] for ele in conf_data])) : #type: ignore
                logger.error("Client: %s Input Error: Invalid data for client's IA_TA"
                             " when disable_ia_id is not set: %s", client_id, conf_data)
                return encoded_value
            configured_addr6_list = [val[1] for val in \
                                     cast(Iterable[Tuple[str, IPv6Address]], conf_data) \
                                     if val[0] ==  requested_id]            
        encoded_value += requested_ta[:4] # The IA_NA value starts with IA_ID

        if len(configured_addr6_list) == 0:
            status_code_val =  DHCP6_NoAddrsAvail
            encoded_value += struct.pack(">HHH", DHCP6_OPT_STATUS_CODE, 
                                                 len(bytes(status_code_val)), status_code_val)
            continue


        if len(requested_ta) > 4: # Len > 4 => Options are present
            offset = 4
            requested_addr_list = []
            while offset < len(requested_ta):
                op = struct.unpack(">H", requested_ta[offset:offset+2])[0]
                if op == DHCP6_OPT_IAADDR:
                    try:
                        requested_addr_list.extend([IPv6Address(requested_ta[offset+4:offset+20])])
                    except AddressValueError:
                        logger.error("Client: %s Ifname:%s Invalid IPv6 address in IAADDR option: %s",
                                     client_id, ifname,
                                     requested_ta[offset+4:offset+20])
                    # TODO: Should other IAADDR options be considered?
                # Next offset is at offset + sizeof(opcode) + sizeof(option-len) + option-len
                offset += (2 + 2 + struct.unpack(">H", requested_ta[offset+2:offset+4])[0])
            logger.debug("Client: %s Ifname: %s Requested list of temporary IAADDRs is %s", 
                          client_id, ifname, requested_addr_list)
            # For request msgs, if the IA address mentioned in client request is different from what we have 
            # configured, send back the old one with lifeftime 0 and new one with a valid lifetime
            expired_addresses = [addr for addr in requested_addr_list if addr not in configured_addr6_list]
            logger.debug("Client: %s Ifname: %s Expired temporary address list: %s", 
                          client_id, ifname, expired_addresses)
            if expired_addresses != [] and msg.mtype == CONFIRM:
                # If atleast one message is not valid, send back reply with status NotOnLink
                return None
            for addr in expired_addresses:
                pref_lifetime = 0
                valid_lifetime = 0
                iaddr_length = DEFAULT_IAADDR_LEN
                encoded_value += struct.pack(">HH", DHCP6_OPT_IAADDR, iaddr_length) + addr.packed + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big')


        pref_lifetime = default_pref_lifetime
        valid_lifetime = default_valid_lifetime
        iaddr_length = DEFAULT_IAADDR_LEN

        if DHCP6_NON_DEFAULT_PREF_LIFETIME in host_data:
            pref_lifetime = host_data[DHCP6_NON_DEFAULT_PREF_LIFETIME].value
        if DHCP6_NON_DEFAULT_VALID_LIFETIME in host_data:
            valid_lifetime = host_data[DHCP6_NON_DEFAULT_VALID_LIFETIME].value


        for addr in configured_addr6_list:
            encoded_value += struct.pack(">HH", DHCP6_OPT_IAADDR, iaddr_length) + addr.packed + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big')
            # TODO: Any possible IAADDR options to be added??

    return encoded_value

def construct_ia_pd_response_data(msg: Message.ClientServerDHCP6, 
                                  conf_data: List[Union[IPv6Network, Tuple[str, IPv6Network]]],
                                  host_data: Dict[int, Any], ifname: str,
                                  client_id: Union[Mac, str]) -> Optional[bytes]:
    ia_pd_opts = fetch_all_dhcp6_opt(msg, DHCP6_OPT_IA_PD) # There could be multiple IA_PD options
    if conf_data is None:
        return None
    encoded_value = b'' 

    # For each requested IA_PD option, find a corresponding configuration with that IA_ID
    for requested_pd in ia_pd_opts:
        requested_id = hex(struct.unpack(">I", requested_pd[:4])[0])
        logger.debug("Client: %s Ifname: %s IA_PD requested for ID: %s",
                      client_id, ifname, requested_id)
        logger.debug("Client:%s Ifname:%s Available IA_PD configurations for the client: %s",
                      client_id, ifname, conf_data)
        configured_pd_list: List[IPv6Network]
        if disable_ia_id:
            # Ignore IAID values and return all addresses associated with this client
            # When disable_ia_id is set, conf_data is expected to be List[IPv6Network]
            if not all(isinstance(ele, IPv6Network) for ele in conf_data):
                logger.error("Client: %s Input Error: Invalid data for client's prefix"
                             " delegation when disable_ia_id is set: %s", client_id, conf_data)
                return encoded_value
            configured_pd_list = cast(List[IPv6Network], conf_data) # To satisfy mypy
        else:
            if not all(isinstance(ele, tuple) for ele in conf_data) or \
               not all(isinstance(val, str) for val in [ele[0] for ele in conf_data]) or \
               not all(isinstance(val, IPv6Network) for val in [ele[1] for ele in conf_data]) :
                logger.error("Client: %s Input Error: Invalid data for client's prefix"
                             " delegation when disable_ia_id is not set: %s", client_id,conf_data)
                return encoded_value
            # Consider only the set of addresses that have the same ID
            configured_pd_list = [val[1] for val in \
                                cast(Iterable[Tuple[str, IPv6Network]], conf_data) \
                                if val[0] ==  requested_id]
            
        encoded_value += requested_pd[:4] # The IA_PD value starts with IA_ID

        (t1,t2) = struct.unpack(">ii", requested_pd[4:12])
        if (t1 == t2 and t1 == 0) or t1 > t2 :
            t1 = default_t1
            t2 = default_t2

        if DHCP6_NON_DEFAULT_T1 in host_data:
            t1 = host_data[DHCP6_NON_DEFAULT_T1].value
        if DHCP6_NON_DEFAULT_T2 in host_data:
            t2 = host_data[DHCP6_NON_DEFAULT_T2].value

        encoded_value += t1.to_bytes(4, 'big') + t2.to_bytes(4, 'big') # Append t1,t2 to the IA_PD value 

        if len(configured_pd_list) == 0:
            status_code_val =  DHCP6_NoBinding
            encoded_value += struct.pack(">HHH", DHCP6_OPT_STATUS_CODE, 
                                                 len(bytes(status_code_val)), status_code_val)
            continue


        if len(requested_pd) > 12: # Len > 12 => IA_PD options are present
            offset = 12
            requested_pd_list = []
            while offset < len(requested_pd):
                op = struct.unpack(">H", requested_pd[offset:offset+2])[0]
                if op == DHCP6_OPT_IAPREFIX:
                    try:
                        # IAPREFIX structure: Opcode(2) + Length(2) + PreferredLife(4) + ValidLife(4) + PrefixLen(1) + Addr(16)
                        prefix_len = str(struct.unpack(">B", requested_pd[offset+12:offset+13])[0])
                        network_addr = str(IPv6Address(requested_pd[offset+13:offset+29]))
                        requested_pd_list.extend([IPv6Network(network_addr + '/' + prefix_len)])
                    except AddressValueError:
                        logger.error("Client: %s Ifname: %s Invalid IPv6 values in IAPREFIX option: %s",
                                     client_id, ifname,
                                     requested_pd[offset+13:offset+29])
                    # TODO: Should other IAADDR options be considered?
                # Next offset is at offset + sizeof(opcode) + sizeof(option-len) + option-len
                offset += (2 + 2 + struct.unpack(">H", requested_pd[offset+2:offset+4])[0])
            logger.debug("Client: %s Ifname:%s Requested list of IAADDRs is %s", 
                          client_id, ifname, requested_pd_list)
            # For request msgs, if the IA address mentioned in client request is different from what we have 
            # configured, send back the old one with lifeftime 0 and new one with a valid lifetime
            expired_prefixes = [prefix for prefix in requested_pd_list if prefix not in configured_pd_list]
            logger.debug("Client:%s Ifname:%s Expired address list: %s", 
                          client_id, ifname, expired_prefixes)
            if expired_prefixes != [] and msg.mtype == CONFIRM:
                # If atleast one message is not valid, send back reply with status NotOnLink
                return None
            for prefix in expired_prefixes:
                pref_lifetime = 0
                valid_lifetime = 0
                iapd_length = DEFAULT_IAPD_LEN
                encoded_value += struct.pack(">HH", DHCP6_OPT_IAPREFIX, iapd_length) + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big') + \
                                   struct.pack(">B", prefix.prefixlen) + prefix.network_address.packed 


        pref_lifetime = default_pref_lifetime
        valid_lifetime = default_valid_lifetime
        iapd_length = DEFAULT_IAPD_LEN

        if DHCP6_NON_DEFAULT_PREF_LIFETIME in host_data:
            pref_lifetime = host_data[DHCP6_NON_DEFAULT_PREF_LIFETIME].value
        if DHCP6_NON_DEFAULT_VALID_LIFETIME in host_data:
            valid_lifetime = host_data[DHCP6_NON_DEFAULT_VALID_LIFETIME].value

        for prefix in configured_pd_list:
            encoded_value += struct.pack(">HH", DHCP6_OPT_IAPREFIX, iapd_length) + \
                                   pref_lifetime.to_bytes(4, 'big') + valid_lifetime.to_bytes(4, 'big') + \
                                   struct.pack(">B", prefix.prefixlen) + prefix.network_address.packed
            # TODO: Any possible IAADDR options to be added??

    return encoded_value


def append_mandatory_options(msg: Message.ClientServerDHCP6, opt_tuple: Tuple[Tuple[int, bytes], ...], 
                             server_duid: bytes) -> Tuple[Tuple[int, bytes], ...]:
    opt_list: List[Tuple[int, bytes]] = list(opt_tuple)
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
    if client_duid is not None: # To satisfy mypy
        opt_list.extend([(DHCP6_OPT_SERVERID, server_duid),
                         (DHCP6_OPT_CLIENTID, client_duid)])
    return tuple(opt_list)

def construct_dhcp6_opt_list(msg: Message.ClientServerDHCP6,
                             request_list_opt: List[int], ifname: str, 
                             host_conf_data: Dict[int, Any],
                             client_id: Union[Mac, str]) -> Tuple[Tuple[int, bytes], ...]:
    opt_list: List[Tuple[int, Any]] = []
    if request_list_opt ==  None:
        logger.debug("Client:%s Ifname:%s No parameter request list", client_id, ifname)
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
                        encoded_data = construct_ia_na_response_data(msg, data, host_conf_data, ifname, client_id)
                    elif opcode == DHCP6_OPT_IA_TA:
                        encoded_data = construct_ia_ta_response_data(msg, data, host_conf_data, ifname, client_id)
                    else:
                        encoded_data = b''.join([elem.packed for elem in data])
                elif all(isinstance(ele, str) for ele in data):
                    encoded_data = b''.join([elem.encode('utf-8') for elem in data])
                elif all(isinstance(ele, IPv6Network) for ele in data):
                    encoded_data = construct_ia_pd_response_data(msg, data, host_conf_data, ifname, client_id)    
                elif all(isinstance(ele, tuple) for ele in data): # Case of IA_NA, IA_PD or IA_TA values
                    if opcode == DHCP6_OPT_IA_NA: 
                        encoded_data = construct_ia_na_response_data(msg, data, host_conf_data, ifname, client_id)
                    elif opcode == DHCP6_OPT_IA_TA:
                        encoded_data = construct_ia_ta_response_data(msg, data, host_conf_data, ifname, client_id)
                    elif opcode == DHCP6_OPT_IA_PD:
                        encoded_data = construct_ia_pd_response_data(msg, data, host_conf_data, ifname, client_id)
                    else:
                        logger.error("Client:%s Ifname:%s Configuration data for opcode %d "
                                     " has unexpected values %s of type List of Tuples",
                                     client_id, ifname,
                                     data, opcode)
                        continue
                else:
                    logger.error("Client:%s Ifname:%s Elements of unexpected datatype "
                                 "in the client parameter list: %s", 
                                 client_id, ifname, data)
                    continue
            else:
                logger.error("Client:%s Ifname:%s Value(%s) of unexpected type "
                             "received for opcode %d", client_id, ifname, data, opcode)
            if encoded_data:
                opt_list.append((opcode, encoded_data))
    return tuple(opt_list)

def construct_dhcp_reply(ifname: str, msg: Message.ClientServerDHCP6, 
                       request_list_opt: List[int], 
                       host_conf_data: Dict[int, Any],
                       server_duid: bytes,
                       client_id: Union[Mac, str]) -> Optional[Message.ClientServerDHCP6]:
    opt_list = construct_dhcp6_opt_list(msg, request_list_opt, ifname, host_conf_data, client_id)
    if not opt_list: # If no other parameters were requested by client, should offer be sent?
        logger.debug("Client:%s Ifname:%s No configuration data found", client_id, ifname)
        return None
    # What should be the format of server duid from configuration??? Just take ll address?
    opt_list = append_mandatory_options(msg, opt_list, server_duid)
    return construct_dhcp6_packet(msg, REPLY, opt_list)

def construct_dhcp_adv(ifname: str, msg: Message.ClientServerDHCP6, 
                       request_list_opt: List[int], 
                       host_conf_data: Dict[int, Any],
                       server_duid: bytes, 
                       client_id: Union[Mac, str]) -> Optional[Message.ClientServerDHCP6]:
    opt_list = construct_dhcp6_opt_list(msg, request_list_opt, ifname, host_conf_data, client_id)
    if not opt_list: # If no other parameters were requested by client, should offer be sent?
        logger.debug("Client:%s Ifname:%s No configuration data found", client_id, ifname)
        return None
    # What should be the format of server duid from configuration??? Just take ll address?
    opt_list = append_mandatory_options(msg, opt_list, server_duid)
    return construct_dhcp6_packet(msg, ADVERTISE, opt_list)

def fetch_client_duid(client_duid: Optional[bytes]) -> str:
    if client_duid is None:
        # Ideally, since packet has been validated, this condition should not be True
        return ''
    # First two bytes of the DUID represent the DUID type
    # Validation has confirmed that DHCP6_OPT_CLIENTID is set
    duid_type = struct.unpack('>H', client_duid[:2])[0]

    # Client ID in database is expected to be of the form : DUID_Type + Hardware_Type + LL_Addr
    #                                                     or DUID_Type + Enterprise_Num + ID
    # eg: DUID_Type=1, Hardware_Type=1 and LL_Addr = 5a:20:9d:28:56:e5 => DUID = 115a209d2856e5

    if duid_type == DUID.lladdr_time.value: # Static HCPD server cannot server client DUID with dynamic value (time)
        client_id = ''.join(str(elem) for elem in struct.unpack('>HH', client_duid[:4])) + \
                    ll_addr(client_duid[8:])
        logger.debug("Unable to serve dynamic client DUID %s."
                     " Removing time from the duid value for DB lookup: %s", client_duid, client_id)
    elif duid_type == DUID.lladdr.value:
        client_id = ''.join(str(elem) for elem in struct.unpack('>HH',client_duid[:4])) + \
                    ll_addr(client_duid[4:])
    else:
        # Should the value be stored as int or hex in DB?
        client_id = ''.join(str(elem) for elem in struct.unpack('>H', client_duid[:2])) + \
                    ''.join(str(elem) for elem in struct.unpack('>%iH'%(len(client_duid[2:6])/ 2), client_duid[2:6])) + \
                    ''.join(str(elem) for elem in struct.unpack('>%iH'%(len(client_duid[6:])/2), client_duid[6:]))
    return client_id

def process_solicit_msg(ifname: str, msg: Message.ClientServerDHCP6, 
                        server_duid: bytes, src_mac: Mac) -> Tuple[Optional[bytes], Optional[str]]:
    err_return_val: Tuple[None, None] = (None, None)
    rapid_commit = fetch_dhcp6_opt(msg, DHCP6_OPT_RAPID_COMMIT)
    request_list_bytestr = fetch_dhcp6_opt(msg, DHCP6_OPT_ORO)
    request_list_opts = list(struct.unpack('>%iH'%(len(request_list_bytestr)/2), request_list_bytestr)) \
                        if request_list_bytestr is not None else []
    client_duid = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    
    client_id: Union[Mac, str]
    if use_mac_as_duid:
        client_id = src_mac
    else:
        client_id = fetch_client_duid(client_duid)
    logger.debug("%s used as client ID for database lookup for packet on %s", client_id, ifname)

    
    host_conf_data, server_iface = fetch_host_conf_data(DHCPv6DB(), ifname, client_id)
    if not host_conf_data:
        logger.debug("Client: %s Ifname: %s No configuration data found for the host. Skipping ..", client_id, ifname)
        return err_return_val

    if rapid_commit:
        dhcp_response = construct_dhcp_reply(ifname, msg, request_list_opts, host_conf_data, server_duid, client_id)
    else:
        dhcp_response = construct_dhcp_adv(ifname, msg, request_list_opts, host_conf_data, server_duid, client_id)

    if not dhcp_response:
        logger.debug("Client:%s Ifname:%s No response DHCP6 Advertise packet for %s ",
                      dhcp6_type_to_str(msg.mtype),
                      client_id, ifname)
        return err_return_val
    data = bytes(dhcp_response)
    return (data, server_iface)

def process_request_renew_rebind_info_msg(ifname: str, msg: Message.ClientServerDHCP6, 
                                     server_duid: bytes, src_mac: Mac) -> Tuple[Optional[bytes], Optional[str]]:
    err_return_val: Tuple[None, None] = (None, None)
    client_duid = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    # TODO: If it's unicast and unicast is not supported for this client,
    #       send back Status code UseMulticast
    request_list_bytestr = fetch_dhcp6_opt(msg, DHCP6_OPT_ORO)
    request_list_opts = list(struct.unpack('>%iH'%(len(request_list_bytestr)/2), request_list_bytestr)) \
                        if request_list_bytestr is not None else []
   
    client_id: Union[Mac, str]
    if use_mac_as_duid:
        client_id = src_mac
    else:
        client_id = fetch_client_duid(client_duid)
    
    host_conf_data, server_iface = fetch_host_conf_data(DHCPv6DB(), ifname, client_id)
    if not host_conf_data:
        logger.debug("Client:%s Ifname:%s No configuration data found for the host. Skipping ..", client_id, ifname)
        return err_return_val

    dhcp_response = construct_dhcp_reply(ifname, msg, request_list_opts, host_conf_data, server_duid, client_id)

    if not dhcp_response:
        logger.debug("Client:%s Ifname:%s No DHCP6 Reply packet for %s ",
                      client_id, ifname, msg.mtype,)
        return err_return_val
    data = bytes(dhcp_response)
    return data, server_iface

def process_confirm_msg(ifname: str, msg: Message.ClientServerDHCP6,
                        server_duid: bytes, src_mac: Mac) -> Tuple[Optional[bytes], Optional[str]]:
    err_return_val: Tuple[None, None] = (None, None)
    client_duid = fetch_dhcp6_opt(msg, DHCP6_OPT_CLIENTID)
    # TODO: If it's unicast and unicast is not supported for this client,
    #       send back Status code UseMulticast
   
    client_id: Union[Mac, str]
    if use_mac_as_duid:
        client_id = src_mac
    else:
        client_id = fetch_client_duid(client_duid)
    
    host_conf_data, server_iface = fetch_host_conf_data(DHCPv6DB(), ifname, client_id)
    if not host_conf_data:
        logger.debug("Client:%s Ifname:%s No configuration data found for the host. Skipping ..", client_id, ifname)
        return err_return_val

    encoded_ia_na: Optional[bytes] = b''
    encoded_ia_ta: Optional[bytes] = b''
    opts = [ele[0] for ele in msg.opts] #type: List[int]
    if DHCP6_OPT_IA_NA in opts:
        encoded_ia_na  = construct_ia_na_response_data(msg, host_conf_data.get(DHCP6_OPT_IA_NA, None),
                                                            host_conf_data, ifname, client_id)
    if DHCP6_OPT_IA_TA in opts:
        encoded_ia_ta = construct_ia_ta_response_data(msg, host_conf_data.get(DHCP6_OPT_IA_TA, None), 
                                                           host_conf_data, ifname, client_id)

    opt_list: Tuple[Tuple[int, bytes],...] = ((DHCP6_OPT_STATUS_CODE, struct.pack(">H", DHCP6_Success)),)
    
    # construct_ia_na_response_data and construct_ia_ta_response_data returns None
    # only in two cases: 1. There is no IA config for this client 
    # 2. One or more of requested IA has expired
    if encoded_ia_na is None or encoded_ia_ta is None:
        opt_list = ((DHCP6_OPT_STATUS_CODE, struct.pack(">H", DHCP6_NotOnLink)),)
    opt_list = append_mandatory_options(msg, opt_list, server_duid)
    dhcp_response = construct_dhcp6_packet(msg, REPLY, opt_list)

    if not dhcp_response:
        logger.debug("Client:%s Ifname:%s No response DHCP6 Reply packet for %s",
                      client_id, ifname, msg.mtype)
        return err_return_val
    data = bytes(dhcp_response)
    return data, server_iface

def process_client_server_msg(ifname: str, msg: Message.ClientServerDHCP6, 
                              server_duid: bytes, src_mac: Mac) -> Tuple[Optional[bytes], Optional[str]]:
    err_return_val: Tuple[None, None] = (None, None)
    valid_msg = validate_msg(msg, server_duid)
    if not valid_msg:
        logger.error("%s message validation failed on interface %s from source mac %s.", 
                      dhcp6_type_to_str(msg.mtype), ifname, src_mac)
        # TODO:
        # Server MAY send a Reply (or Advertise as appropriate) with a Server
        # Identifier option, a Client Identifier option if one was included in
        # the message and a Status Code option with status UnSpecFail.

        return err_return_val

    logger.debug("Ifname:%s SrcMac: %s Received a client server message of type %s",
                ifname, src_mac,
                dhcp6_type_to_str(msg.mtype))

    if msg.mtype is SOLICIT:
        return process_solicit_msg(ifname, msg, server_duid, src_mac)
    if msg.mtype is REQUEST or msg.mtype is RENEW or \
       msg.mtype is REBIND or msg.mtype is INFORMATIONREQUEST:
        return process_request_renew_rebind_info_msg(ifname, msg, server_duid, src_mac)
    if msg.mtype is CONFIRM:
        return process_confirm_msg(ifname, msg, server_duid, src_mac)
    return err_return_val

def process_relayforw_msg(ifname: str, payload: Message.RelayServerDHCP6, 
                          server_duid: bytes, src_mac: Mac) -> Tuple[Optional[bytes], Optional[str]]:
    err_return_val: Tuple[None, None] = (None, None)
    dhcp_msg = fetch_dhcp6_opt(payload, DHCP6_OPT_RELAY_MSG)
    if dhcp_msg is None:
        logger.debug("Empty DHCP Message in DHCP Relay Forward msg from %s on intf %s",
                                                       src_mac, ifname)
        return err_return_val
    reply_msg, server_iface = process_client_server_msg(ifname, Message.ClientServerDHCP6(dhcp_msg),
                                                                  server_duid, src_mac)
    if reply_msg is None:
        logger.debug("Empty DHCP Message in DHCP Relay Reply to %s on intf %s",
                                                       src_mac, ifname)
        return err_return_val
    relay_reply = Message.RelayServerDHCP6(
                                         mtype=RELAYREPL,
                                         hops=payload.hops,
                                         la=payload.la,
                                         pa=payload.pa,
                                         opts=[(DHCP6_OPT_RELAY_MSG, reply_msg)]
                                        )
    return bytes(relay_reply), server_iface



def process_relay_server_msg(ifname: str, payload: Message.RelayServerDHCP6, 
                             server_duid: bytes, src_mac: Mac) -> Tuple[Optional[bytes], Optional[str]]:
    err_return_val: Tuple[None, None] = (None, None)
    logger.debug("Received a relay server message of type %s from %s", 
                  dhcp6_type_to_str(payload.mtype), src_mac)
    if payload.mtype is not RELAYFORW:
        return err_return_val
    if use_mac_as_duid:
        logger.error("Server configured to use source mac as client DUID. Unable to handle %s from relay agent(%s).",
                      dhcp6_type_to_str(payload.mtype), src_mac)
        return err_return_val
    return process_relayforw_msg(ifname, payload, server_duid, src_mac)

def process_dhcp6_packet(ifname: str, dhcp6_msg: Message,
                         server_mac: Mac, src_mac: Mac) -> Tuple[Optional[bytes], bool, Optional[str]]:
    payload = dhcp6_msg.data
    server_duid = struct.pack(">HH", 3, 1) + binascii.unhexlify((str(server_mac)).replace(":",""))
    direct_unicast_from_client = False
    pkt : Optional[bytes]
    if isinstance(payload, Message.ClientServerDHCP6):
        pkt, server_iface = process_client_server_msg(ifname, payload, server_duid, src_mac)
        direct_unicast_from_client = True
    elif isinstance(payload, Message.RelayServerDHCP6):
        pkt, server_iface = process_relay_server_msg(ifname, payload, server_duid, src_mac)
    else:
        logger.error("Malformed packet with unknown DHCP msg type %s received", type(payload))
        pkt = None

    return (pkt, direct_unicast_from_client, server_iface)
