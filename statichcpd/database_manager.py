#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List, Any, Dict, Optional
import os
from ipaddress import IPv4Address
from enum import Enum

from .datatypes import *
from .logmgr import logger

schema = [
        """create table if not exists clients (
           ifname text not null,
           mac text not null,
           constraint compkey_mac_if unique(ifname, mac));""",
        """create table if not exists valid_attributes(
           name text,
           opcode int not null,
           max_count int not null,
           datatype int not null,
           constraint unique_opcode unique(opcode));""",
        """create table if not exists host_configuration_data (
           ifname text not null,
           mac text not null,
           attr_code int not null,
           attr_val not null,
           constraint compkey_mac_if_attr unique(ifname, mac, attr_code, attr_val)
           foreign key (ifname, mac) references clients(ifname, mac) on delete cascade,
           foreign key (attr_code) references valid_attributes(opcode) on delete restrict);"""
        ]

DHCP_IP_OPCODE = 200  
DHCP_IPV6_OPCODE = 201

class dtype(Enum):
    IPV4 = 1
    IPV6 = 2
    INT16 = 3
    INT32 = 4
    STRING = 5
    STATICRT = 6

def fetch_host_conf_data(ifname: str, mac: str) -> Dict[str,Any]:
    logger.debug("Fetching Host conf for intf:{} mac:{}".format(ifname, mac))
    result = {}

    cursor = dhcp_db_conn.cursor()
    for (opcode, max_count, datatype, value) in cursor.execute( 
                     """ select valid_attributes.opcode, valid_attributes.max_count, 
                         valid_attributes.datatype, host_configuration_data.attr_val 
                         from host_configuration_data
                         join valid_attributes on 
                         host_configuration_data.attr_code = valid_attributes.opcode    
                         where ifname=? and mac=?""", (ifname, mac)
                     ):
        try:
            datatype = dtype(datatype)
        except ValueError as err:
            logger.error("Invalid datatype entry {} for opcode {} ".format(datatype, opcode))
            cursor.close()
            continue   # Shouldn't remaining entries be processed for this client?
        if max_count == 1:                           ## Assumed that application handles insertion of attr values
            if datatype is dtype.IPV4:               ## appropriately
                result[opcode] = IPv4Address(value)
            elif datatype is dtype.INT16:
                result[opcode] = Int16(value)
            elif datatype is dtype.INT32:
                result[opcode] = Int32(value)
            elif datatype is dtype.STRING:
                result[opcode] = value
            else:
                logger.error("Invalid entry (datatype, maxcount):({}, {}) ".format(datatype, max_count))
        else:
            if opcode not in result:
                result[opcode] = []
            if datatype is dtype.IPV4:               # Should this also be IPV4?
                result[opcode].append(IPv4Address(value))
            elif datatype is dtype.STATICRT:
                result[opcode].append(Staticrt(value))
            else:
                logger.error("Invalid entry (datatype, maxcount):({}, {}) ".format(datatype, max_count))
    cursor.close()
    return result

dhcp_db_name = "Static_DHCP_DB.db"
dhcp_db_conn = None

def init_dhcp_db():
    global dhcp_db_conn
    if dhcp_db_conn is None:
        dhcp_db_conn = sqlite3.connect(dhcp_db_name)
        if dhcp_db_conn is None:
            raise Exception("Connecting to DHCP db {} failed".format(dhcp_db_name))

init_dhcp_db()

