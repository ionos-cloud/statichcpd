#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List, Any, Dict, Optional
import os
from helper import encode_option

schema = [
        """create table if not exists clients (
           ifname text not null,
           mac text not null,
           constraint compkey_mac_if unique(ifname, mac));""",
        """create table if not exists valid_attributes(
           name text not null,
           opcode int not null,
           max_count int not null,
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

class database:
    def fetch_ip(self, ifname: str, mac: str) -> Optional[str]:
        self.db_handler.execute( """select attr_val from host_configuration_data
                                 join valid_attributes on
                                 host_configuration_data.attr_name = valid_attributes.name
                                 where ifname=? and mac=? and valid_attributes.opcode=?""", 
                                 (ifname, mac, DHCP_IP_OPCODE) )
        result = dhcp_db.db_handler.fetchone()
        if result == []:
            return None
        return result[0]


    def fetch_host_conf_data(self, ifname: str, mac: str) -> Dict[str,Any]:
        print("Fetching Host conf for ", ifname, " ", mac)
        result = {}
        # Should the presence of table be confirmed? If table is not created, this will return error
        for (opcode, max_count, value) in self.db_handler.execute(
                         """ select valid_attributes.opcode, valid_attributes.max_count, host_configuration_data.attr_val 
                             from host_configuration_data
                             join valid_attributes on 
                             host_configuration_data.attr_name = valid_attributes.name
                             where ifname=? and mac=?""", (ifname, mac)
                         ):
            if max_count == 1:                             ## Assumed that application handles insertion of attr values
                result[opcode] = encode_option(value)     ## appropriately
            else:
                if opcode not in result:
                    result[opcode] = b''
                result[opcode] += encode_option(value)

        return result

    def __init__(self):
        self.db_name = "Static_DHCP_DB.db"
        self.db_handler = None
        self.connection = None
        try:
            self.connection = sqlite3.connect(self.db_name)
            self.db_handler =  self.connection.cursor()
        except sqlite3.Error as error:
            print("Error while connecting to sqlite", error)
            return

dhcp_db = database()
db_handler = dhcp_db.db_handler
