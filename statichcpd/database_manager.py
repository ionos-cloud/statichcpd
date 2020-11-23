#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List, Any, Dict, Optional
import os
from ipaddress import IPv4Address
from enum import Enum
from configparser import SectionProxy
import csv

from .datatypes import *
from .logmgr import logger

dhcp_db_conn = None

schema = [
        """create table if not exists valid_attributes(
           opcode int not null,
           max_count int not null,
           datatype int not null,
           constraint unique_opcode unique(opcode));""",
        """create table if not exists clients (
           ifname text not null,
           mac text not null,
           constraint compkey_mac_if unique(ifname, mac));""",
        """create table if not exists client_configuration (
           ifname text not null,
           mac text not null,
           attr_code int not null,
           attr_val not null,
           constraint compkey_mac_if_attr unique(ifname, mac, attr_code, attr_val)
           foreign key (ifname, mac) references clients(ifname, mac) on delete cascade,
           foreign key (attr_code) references valid_attributes(opcode) on delete restrict);"""
        ]

# Using IP(v4/v6) opcode value outside permitted
# DHCP opcode range to avoid conflict

DHCP_IP_OPCODE = 256
DHCP_IPV6_OPCODE = 257
DHCP_NON_DEFAULT_SERVERID_OPCODE = 258

class dtype(Enum):
    IPV4 = 1
    IPV6 = 2
    INT16 = 3
    INT32 = 4
    STRING = 5
    STATICRT = 6

def insert_data_from(csv_filename: str) -> None:
    cursor = dhcp_db_conn.cursor()
    with open (csv_filename, 'r') as f:
        reader = csv.reader(f)
        columns = next(reader)
        query = 'insert into valid_attributes({0}) values ({1})'.format(','.join(columns), ','.join('?' * len(columns)))
        for row in reader:
            # Opcode can be an integer or dpkt.dhcp module optcode alias
            try:
                data = (str(getattr(dhcp, row[0])), row[1], str(eval("dtype." + row[2] + ".value")))
            except:
                data = (str(row[0]), row[1], str(eval("dtype." + row[2] + ".value")))

            cursor.execute(query, data)
    dhcp_db_conn.commit()

def init(config: SectionProxy) -> None:
    dhcp_db_name = config['dhcp_db_filename']
    global dhcp_db_conn
    dhcp_db_name = str(dhcp_db_name) if type(dhcp_db_name) is not str else dhcp_db_name
    logger.debug("Connecting to %s", dhcp_db_name)
    dhcp_db_conn = sqlite3.connect(dhcp_db_name)
    if dhcp_db_conn is None:
        raise Exception("Connecting to DHCP db {} failed".format(dhcp_db_name))

    cursor = dhcp_db_conn.cursor()
    for command in schema:
        cursor.execute(command)
    cursor.execute('delete from valid_attributes')
    dhcp_db_conn.commit()
    cursor.close()
    logger.debug("Created config tables")

    #Populate the valid_attributes table

    # Insert default attributes
    insert_data_from('/usr/share/statichcpd/default_attr.csv')

    # Insert user defined attributes, if any
    if 'additional_attributes_file' in config:
        insert_data_from(config.get('additional_attributes_file'))

def exit():
    global dhcp_db_conn
    dhcp_db_conn.close()
    logger.debug("Closed the connection to DHCP database")

def fetch_host_conf_data(ifname: str, mac: Mac) -> Dict[str,Any]:
    logger.debug("Fetching Host conf for intf:%s mac:%s",ifname, str(mac))
    result = {}

    cursor = dhcp_db_conn.cursor()
    for (opcode, max_count, datatype, value) in cursor.execute( 
                     """ select valid_attributes.opcode, valid_attributes.max_count, 
                         valid_attributes.datatype, client_configuration.attr_val 
                         from client_configuration
                         join valid_attributes on 
                         client_configuration.attr_code = valid_attributes.opcode    
                         where ifname=? and mac=?""", (ifname, str(mac))
                     ):
        try:
            datatype = dtype(datatype)
        except ValueError as err:
            logger.error("Invalid datatype entry %d for opcode %d ", datatype, opcode)
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
                logger.error("Invalid entry (datatype, maxcount):(%d, %d) ", datatype, max_count)
        else:
            if opcode not in result:
                result[opcode] = []
            if datatype is dtype.IPV4:
                result[opcode].append(IPv4Address(value))
            elif datatype is dtype.STATICRT:
                result[opcode].append(Staticrt(value))
            else:
                logger.error("Invalid entry (datatype, maxcount):(%d, %d) ", datatype, max_count)
    cursor.close()
    return result

