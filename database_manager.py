#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List, Any, Dict, Optional
import os
from datatypes import *
from ipaddress import IPv4Address
from enum import Enum

schema = [
        """create table if not exists clients (
           ifname text not null,
           mac text not null,
           constraint compkey_mac_if unique(ifname, mac));""",
        """create table if not exists valid_attributes(
           name text not null,
           opcode int not null,
           max_count int not null,
           datatype int not null,
           constraint unique_name unique(name),
           constraint unique_opcode unique(opcode));""",
        """create table if not exists host_configuration_data (
           ifname text not null,
           mac text not null,
           attr_name not null,
           attr_val not null,
           constraint compkey_mac_if_attr unique(ifname, mac, attr_name, attr_val)
           foreign key (ifname, mac) references clients(ifname, mac) on delete cascade,
           foreign key (attr_name) references valid_attributes(name) on delete restrict);"""
        ]

DHCP_IP_OPCODE = 90  ## Either differentiate the address values with opcodes or store them in separate tables
DHCP_IPV6_OPCODE = 91

class dtype(Enum):
    IPV4 = 1
    IPV6 = 2
    INT16 = 3
    INT32 = 4
    STRING = 5
    STATICRT = 6

def fetch_ip_from_database(ifname: str, mac: str) -> Optional[str]:
    cursor = dhcp_db_conn.cursor()
    cursor.execute( """select attr_val from host_configuration_data
                               join valid_attributes on
                               host_configuration_data.attr_name = valid_attributes.name
                               where ifname=? and mac=? and valid_attributes.opcode=?""", 
                               (ifname, mac, DHCP_IP_OPCODE) )
    result = cursor.fetchone()
    cursor.close()
    if result == []:
        return None
    return IPv4Address(result[0])

def fetch_host_conf_data(ifname: str, mac: str) -> Dict[str,Any]:
    print("Fetching Host conf for ", ifname, " ", mac)
    result = {}
    # Should the presence of table be confirmed? If table is not created, this will return error
    cursor = dhcp_db_conn.cursor()
    for (opcode, max_count, datatype, value) in cursor.execute( ## Use attr code instead of attr_name
                     """ select valid_attributes.opcode, valid_attributes.max_count, 
                         valid_attributes.datatype, host_configuration_data.attr_val 
                         from host_configuration_data
                         join valid_attributes on 
                         host_configuration_data.attr_name = valid_attributes.name    
                         where ifname=? and mac=?""", (ifname, mac)
                     ):
        if max_count == 1:                           ## Assumed that application handles insertion of attr values
            if datatype == dtype.IPV4.value:         ## appropriately
                result[opcode] = IPv4Address(value)
            elif datatype == dtype.INT16.value:
                result[opcode] = Int16(value)
            elif datatype == dtype.INT32.value:
                result[opcode] = Int32(value)
            elif datatype == dtype.STRING.value:
                result[opcode] = value
            else:
                print("Unknown datatype: ", datatype)
        else:
            if opcode not in result:
                result[opcode] = []
            if datatype == dtype.IPV4.value:    # Should this also be IPV4?
                result[opcode].append(IPv4Address(value))
            elif datatype == dtype.STATICRT.value:
                result[opcode].append(Staticrt(value))
            else:
                print("Unknown datatype: ", datatype)
    cursor.close()
    return result

dhcp_db_name = "Static_DHCP_DB.db"
dhcp_db_conn = None

def init_dhcp_db():
    global dhcp_db_conn
    if dhcp_db_conn is None:
        try:
            dhcp_db_conn = sqlite3.connect(dhcp_db_name)
        except sqlite3.Error as error:
            print("Error while connecting to sqlite", error)

init_dhcp_db()

