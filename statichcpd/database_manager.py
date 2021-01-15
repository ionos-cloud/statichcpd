#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List, Any, Dict, Optional, Union
import os
from ipaddress import IPv4Address
from enum import Enum
from configparser import SectionProxy
import csv
from ipaddress import IPv6Address, IPv6Network

from .datatypes import *
from .logmgr import logger
from .dhcp6 import *

__all__ = ["schema", "DHCP_IP_OPCODE", "DHCP_NON_DEFAULT_SERVERID_OPCODE", 
           "DHCP6_NON_DEFAULT_T1", "DHCP6_NON_DEFAULT_T2", 
           "DHCP6_NON_DEFAULT_PREF_LIFETIME", "DHCP6_NON_DEFAULT_VALID_LIFETIME", 
           "dtype", "DHCPv4DB", "DHCPv6DB", "exit", "fetch_host_conf_data"]

dhcp_db_conn = None

schema = [
        """create table if not exists valid_attributes(
           opcode int not null,
           max_count int not null,
           datatype int not null,
           constraint unique_opcode unique(opcode));""",
        """create table if not exists valid_v6attributes(
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
           foreign key (attr_code) references valid_attributes(opcode) on delete restrict);""",
        """create table if not exists client_v6configuration (
           ifname text not null,
           duid text not null,
           attr_code int not null,
           attr_val not null,
           constraint compkey_clientid_if_attr unique(ifname, duid, attr_code, attr_val)
           foreign key (ifname, duid) references clients(ifname, mac) on delete cascade,
           foreign key (attr_code) references valid_v6attributes(opcode) on delete restrict);"""
        ]

# Using IP(v4/v6) opcode value outside permitted
# DHCP opcode range to avoid conflict

DHCP_IP_OPCODE = 256
DHCP_NON_DEFAULT_SERVERID_OPCODE = 258
DHCP6_NON_DEFAULT_T1 = 259
DHCP6_NON_DEFAULT_T2 = 260
DHCP6_NON_DEFAULT_PREF_LIFETIME = 261
DHCP6_NON_DEFAULT_VALID_LIFETIME = 262

class dtype(Enum):
    IPV4 = 1
    IPV6 = 2
    INT16 = 3
    INT32 = 4
    STRING = 5
    STATICRT = 6
    IA = 7
    PD = 8

class DHCPv4DB(object):
    select_command = """ select valid_attributes.opcode, valid_attributes.max_count,
                         valid_attributes.datatype, client_configuration.attr_val
                         from client_configuration
                         join valid_attributes on
                         client_configuration.attr_code = valid_attributes.opcode
                         where ifname=? and mac=?"""

 
class DHCPv6DB(object):
    select_command = """ select valid_v6attributes.opcode, valid_v6attributes.max_count,
                         valid_v6attributes.datatype, client_v6configuration.attr_val
                         from client_v6configuration
                         join valid_v6attributes on
                         client_v6configuration.attr_code = valid_v6attributes.opcode
                         where ifname=? and duid=?"""


def populate_table_from(table_name: str, csv_filename: str) -> None:
    if dhcp_db_conn is None:
        return
    cursor = dhcp_db_conn.cursor()
    with open (csv_filename, 'r') as f:
        reader = csv.reader(f)
        columns = next(reader)
        query = 'insert into {0}({1}) values ({2})'.format(table_name, ','.join(columns), ','.join('?' * len(columns)))
        for row in reader:
            # Opcode can be an integer or dpkt.dhcp module optcode alias
            try:
                if hasattr(dhcp, row[0]):
                    data = (str(getattr(dhcp, row[0])), row[1], str(eval("dtype." + row[2] + ".value")))
                else:
                    data = (str(globals()[row[0]]), row[1], str(eval("dtype." + row[2] + ".value")))
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
    cursor.execute('delete from valid_v6attributes')
    dhcp_db_conn.commit()
    cursor.close()
    logger.debug("Created DHCP config tables")

    #Populate the valid_attributes (v4) table

    # Insert default attributes
    populate_table_from('valid_attributes', '/usr/share/statichcpd/default_attr.csv')

    # Insert user defined attributes, if any
    if 'additional_attributes_file' in config:
        populate_table_from('valid_attributes', config.get('additional_attributes_file'))

    #Populate the valid_v6attributes table

    # Insert default attributes
    populate_table_from('valid_v6attributes', '/usr/share/statichcpd/default_v6attr.csv')

    # Insert user defined attributes, if any
    if 'additional_v6attributes_file' in config:
        populate_table_from('valid_v6attributes', config.get('additional_v6attributes_file'))

def exit() -> None:
    global dhcp_db_conn
    if dhcp_db_conn is not None:
        dhcp_db_conn.close()
    logger.debug("Closed the connection to DHCP database")

def fetch_host_conf_data(db_obj: Union[DHCPv4DB, DHCPv6DB], ifname: str, client_id: Union[Mac, str]) -> Dict[int,Any]:
    logger.debug("Fetching Host conf for intf:%s client ID:%s",ifname, str(client_id))
    result:Dict[int, Any] = {}

    if dhcp_db_conn is None:
        return result
    cursor = dhcp_db_conn.cursor()
    for (opcode, max_count, datatype, value) in cursor.execute(db_obj.select_command, (ifname, str(client_id))):
        try:
            datatype = dtype(datatype)
        except ValueError as err:
            logger.error("Invalid datatype entry %d for opcode %d "
                         "for client (%s, %s)",
                         datatype.value, opcode, ifname, client_id)
            cursor.close()
            continue   # Shouldn't remaining entries be processed for this client?
        if max_count == 1:                           ## Assumed that application handles insertion of attr values
            if datatype is dtype.IPV4:               ## appropriately
                result[opcode] = IPv4Address(value)
            elif datatype is dtype.IPV6:
                result[opcode] = IPv6Address(value)
            elif datatype is dtype.INT16:
                result[opcode] = Int16(value)
            elif datatype is dtype.INT32:
                result[opcode] = Int32(value)
            elif datatype is dtype.STRING:
                result[opcode] = value
            else:
                logger.error("Invalid entry (datatype, maxcount):(%d, %d) "
                             "for client (%s, %s)",
                             datatype, max_count, ifname, client_id)
        else:
            if opcode not in result:
                result[opcode] = []
            if datatype is dtype.IPV4:
                result[opcode].append(IPv4Address(value))
            elif datatype is dtype.STATICRT:
                result[opcode].append(Staticrt(value))
            elif datatype is dtype.IPV6:
                result[opcode].append(IPv6Address(value))
            elif datatype is dtype.IA:
                try:
                    ia_id, ia_addr = value.split(',')
                    result[opcode].extend([(ia_id.strip(), IPv6Address(ia_addr.strip()))])
                except ValueError:
                    result[opcode].append(IPv6Address(value))
            elif datatype is dtype.PD:
                try:
                    ia_id, ia_pd = value.split(',')
                    result[opcode].extend([(ia_id.strip(), IPv6Network(ia_addr.strip()))])
                except ValueError:
                    result[opcode].append(IPv6Network(value))
            elif datatype is dtype.STRING:
                result[opcode].append(value)
            else:
                logger.error("Invalid entry (datatype, maxcount):(%d, %d) "
                             "for client (%s, %s)",
                             datatype, max_count, ifname, client_id)
    cursor.close()
    return result

