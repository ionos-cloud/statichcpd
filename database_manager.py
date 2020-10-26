#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List, Any, Dict
import os

schema = [
        """create table if not exists clients (
           ifname text not null,
           mac text not null,
           constraint compkey_mac_if unique(ifname, mac));""",
        """create table if not exists valid_attributes(
           name text not null,
           constraint unique_name unique(name));""",
        """create table if not exists host_configuration_data (
           ifname text not null,
           mac text not null,
           attr_name not null,
           attr_val not null,
           attr_type not null,
           constraint compkey_mac_if_attr unique(ifname, mac, attr_name, attr_val)
           foreign key (ifname, mac) references clients(ifname, mac) on delete cascade,
           foreign key (attr_name) references valid_attributes(name) on delete restrict);"""
        ]

# Do we need a separate table for single valued attr to ensure no repetition?

valid_single_valued_attr: Dict[str, int] = {"Subnet Mask": dhcp.DHCP_OPT_NETMASK, 
                                            "Time Offset": dhcp.DHCP_OPT_TIMEOFFSET, 
                                            "Domain Name": dhcp.DHCP_OPT_DOMAIN, 
                                            "IPv4": 90, # Using unused option type 
                                            "Hostname": dhcp.DHCP_OPT_HOSTNAME, 
                                            "NETBIOS Scope": dhcp.DHCP_OPT_NBTCPSCOPE, 
                                            "MTU Interface": dhcp.DHCP_OPT_MTUSIZE,
                                            "Broadcast Address": dhcp.DHCP_OPT_BROADCASTADDR}

valid_multi_valued_attr: Dict[str, int] = {"Router": dhcp.DHCP_OPT_ROUTER, 
                                           "Time Server": dhcp.DHCP_OPT_TIMESERVER, 
                                           "Name Server": dhcp. DHCP_OPT_NAMESERVER, 
                                           "Log Server": dhcp.DHCP_OPT_LOGSERV,
                                           "Domain Server": dhcp.DHCP_OPT_DNS_SVRS, 
                                           "Static Route": dhcp.DHCP_OPT_STATICROUTE, 
                                           "SMTP-Server": dhcp.DHCP_OPT_SMTPSERVER, 
                                           "POP3-Server": dhcp.DHCP_OPT_POP3SERVER, 
                                           "IPv6": 91}  # Using unused option type

class database:
    def fetch_host_conf_data(self, ifname: str, mac: str) -> Dict[str,Any]:
        print("Fetching Host conf for ", ifname, " ", mac)
        sql_query = """ select attr_name, attr_val from host_configuration_data
                        where ifname='""" + ifname + "' and mac='" + mac + "';"
        print(sql_query)
        self.db_handler.execute(sql_query)
        sqldata = self.db_handler.fetchall()
        result = {}
        for data in sqldata:
            if data[0] in valid_single_valued_attr:   ## Assumed that application handles insertion of attr values
                result[data[0]] = data[1]             ## appropriately
            elif data[0] in valid_multi_valued_attr:
                existing_data = result.get(data[0])
                if existing_data != None:
                    result[data[0]].append(data[1])
                else:
                    result[data[0]] = [data[1]]
            else:
                print("Unknown option type ", data[0])
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
