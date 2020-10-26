#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List, Any
from database_manager import *
import socket
import fcntl
import struct

def getHwAddr(ifname: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sock.fileno(), 0x8927,  struct.pack('256s', bytes(ifname[:15], 'utf-8')))
    mac = ''.join(['%02x:' % char for char in info[18:24]])[:-1]
    print(mac)
    return mac


def init_client_table(mac_list: List[str], ifname_list: List[str]) -> None:
    for i in range(len(mac_list)):
        mac  = mac_list[i]
        ifname = ifname_list[i]
        sql_insert_query = " insert into clients (ifname, mac) " + "values ('" + ifname + "', '" + mac + "');"
        dhcp_db.db_handler.execute(sql_insert_query)
        dhcp_db.connection.commit()


def init_valid_attributes_table():
    for attr in valid_single_valued_attr:
        sql_insert_query = " insert into valid_attributes (name) values ('" + attr + "');" 
    for attr in valid_multi_valued_attr:
        sql_insert_query = " insert into valid_attributes (name) values ('" + attr + "');" 

def init_host_conf_table(mac_list: List[str], ifname_list: List[str], attr_lists: List[List[Tuple[str, str]]]) -> None:
    for i in range(len(mac_list)):
        mac = mac_list[i]
        ifname = ifname_list[i]
        attr_list = attr_lists[i]
        for attr in attr_list:
            if isinstance(attr[1], str):
                sql_insert_query = """ insert into host_configuration_data 
                           (ifname, mac, attr_name, attr_val) """ \
                           + "values ('" + ifname +  \
                           "', '" + mac + "', '" + attr[0] + \
                           "', '" + attr[1] + "');"
            else:
                sql_insert_query = """ insert into host_configuration_data 
                           (ifname, mac, attr_name, attr_val) """ \
                           + "values ('" + ifname +  \
                           "', '" + mac + "', '" + attr[0] + \
                           "', " + str(attr[1]) + ");"
            dhcp_db.db_handler.execute(sql_insert_query)
            dhcp_db.connection.commit()


def create_dhcp_database(mac: List[str], ifname: List[str], attr_lists: List[List[Tuple[str, str]]]) -> None:
    for command in schema:
        print("Executing.. ", command)
        dhcp_db.db_handler.execute(command)

    init_client_table(mac, ifname)
    init_valid_attributes_table()
    init_host_conf_table(mac, ifname, attr_lists)



server_if_list  = ["veth0dummy0", "veth0dummy0"]
ifname_list = ["veth0dummy1", "dummy0"]
mac_list = []
for name in ifname_list:
    mac_list.extend([getHwAddr(name)])
print(mac_list)
attr_lists = [[("IPv4", "20.0.0.1"),
              ("Subnet Mask", "255.255.255.0"), 
              ("Time Offset", 1245),
              ("Router", "30.1.1.1"),
              ("Router", "30.1.1.2"),
              ("Router", "30.1.1.3"),
              ("Domain Name", "20.0.0.5"),
              ("Hostname", "20.0.0.6"),
              ("Domain Server", '192.168.144.56'),
              ("Name Server",  '192.168.144.57'),
              ("NETBIOS Scope", '40.0.0.5')],
              [("IPv4", "60.0.0.1"),
              ("Subnet Mask", "255.255.255.0"), 
              ("Time Offset", 1234, "int"),
              ("Router", "70.1.1.1"),
              ("Router", "70.1.1.2"),
              ("Router", "70.1.1.3"),
              ("Domain Name", "80.0.0.5"),
              ("Hostname", "60.0.0.6"),
              ("Domain Server", '192.168.144.60'),
              ("Name Server",  '192.168.144.66'),
              ("NETBIOS Scope", '60.0.0.5')],]

create_dhcp_database(mac_list, server_if_list, attr_lists)


