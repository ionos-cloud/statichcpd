#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List, Any
import socket
import fcntl
import struct

from statichcpd.database_manager import *
conn = None

valid_single_valued_attr: Dict[str, int] = {"Subnet Mask": (dhcp.DHCP_OPT_NETMASK, dtype.IPV4.value), 
                                            "Time Offset": (dhcp.DHCP_OPT_TIMEOFFSET, dtype.INT32.value), 
                                            "Domain Name": (dhcp.DHCP_OPT_DOMAIN, dtype.STRING.value), 
                                            "IPv4": (DHCP_IP_OPCODE, dtype.IPV4.value), # Using unused option type 
                                            "Non Default Server ID": (DHCP_NON_DEFAULT_SERVERID_OPCODE, dtype.IPV4.value), 
                                            "Hostname": (dhcp.DHCP_OPT_HOSTNAME, dtype.STRING.value), 
                                            "NETBIOS Scope": (dhcp.DHCP_OPT_NBTCPSCOPE, dtype.STRING.value), 
                                            "MTU Interface": (dhcp.DHCP_OPT_MTUSIZE, dtype.INT16.value),
                                            "Broadcast Address": (dhcp.DHCP_OPT_BROADCASTADDR, dtype.IPV4.value)}

valid_multi_valued_attr: Dict[str, int] = {"Router": (dhcp.DHCP_OPT_ROUTER, dtype.IPV4.value),
                                           "Time Server": (dhcp.DHCP_OPT_TIMESERVER, dtype.IPV4.value),
                                           "Name Server": (dhcp.DHCP_OPT_NAMESERVER, dtype.IPV4.value),
                                           "Log Server": (dhcp.DHCP_OPT_LOGSERV, dtype.IPV4.value),
                                           "Domain Server": (dhcp.DHCP_OPT_DNS_SVRS, dtype.IPV4.value),
                                           "Static Route": (dhcp.DHCP_OPT_STATICROUTE, dtype.STATICRT.value),
                                           "SMTP-Server": (dhcp.DHCP_OPT_SMTPSERVER, dtype.IPV4.value),
                                           "POP3-Server": (dhcp.DHCP_OPT_POP3SERVER, dtype.IPV4.value),
                                           "Classless Static Route": (121, dtype.STATICRT.value),
                                           "IPv6": (DHCP_IPV6_OPCODE, dtype.IPV6.value)}  # Using unused option type


def getHwAddr(ifname: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sock.fileno(), 0x8927,  struct.pack('256s', bytes(ifname[:15], 'utf-8')))
    mac = ''.join(['%02x:' % char for char in info[18:24]])[:-1]
    print(mac)
    return mac


def init_client_table(mac_list: List[str], ifname_list: List[str]) -> None:
    cursor = conn.cursor()
    cursor.execute('''delete from clients;''')
    conn.commit()
    for i in range(len(mac_list)):
        mac  = mac_list[i]
        ifname = ifname_list[i]
        cursor.execute(" replace into clients (ifname, mac) values (?,?)", (ifname, mac))
    conn.commit()
    cursor.close()

def init_host_conf_table(mac_list: List[str], ifname_list: List[str], attr_lists: List[List[Tuple[str, str]]]) -> None:
    cursor = conn.cursor()
    cursor.execute('''delete from client_configuration;''')
    conn.commit()
    for i in range(len(mac_list)):
        mac = mac_list[i]
        ifname = ifname_list[i]
        attr_list = attr_lists[i]
        for attr in attr_list:
            cursor.execute(""" replace into client_configuration
                                       (ifname, mac, attr_code, attr_val) values
                                       (?, ?, ?, ?)""", (ifname, mac, attr[0], attr[1]))
        conn.commit()
    cursor.close()


def create_dhcp_database(mac: List[str], ifname: List[str], attr_lists: List[List[Tuple[str, str]]]) -> None:
    global conn
    if conn is None:
        conn = sqlite3.connect('/var/lib/statichcpd/Static_DHCP_DB.db')
    cursor = conn.cursor()
    for command in schema:
        print("Executing.. ", command)
        cursor.execute(command)
    conn.commit()
    cursor.close()
    init_client_table(mac, ifname)
    init_host_conf_table(mac, ifname, attr_lists)

server_if_list  = ["veth0dummy0", "veth0dummy0"]
ifname_list = ["veth0dummy1", "dummy0"]
mac_list = []
for name in ifname_list:
    mac_list.extend([getHwAddr(name)])
attr_lists = [[(valid_single_valued_attr["IPv4"][0], "20.0.0.1"),
              (valid_single_valued_attr["Subnet Mask"][0], "255.255.255.0"), 
              (valid_single_valued_attr["Time Offset"][0], 0xFFFFD5D0),      # Use hex to denote negative time offset
              (valid_multi_valued_attr["Router"][0], "30.1.1.1"),
              (valid_multi_valued_attr["Router"][0], "30.1.1.2"),
              (valid_multi_valued_attr["Router"][0], "30.1.1.3"),
              (valid_single_valued_attr["Domain Name"][0], "mydomain"),
              (valid_single_valued_attr["Hostname"][0], "myhost"),
              (valid_single_valued_attr["Non Default Server ID"][0], '20.0.0.2'),
              (valid_multi_valued_attr["Domain Server"][0], '192.168.144.56'),
              (valid_multi_valued_attr["Name Server"][0],  '192.168.144.57'),
              (dhcp.DHCP_OPT_NNTPSERVER,  '192.168.144.100'),
              (dhcp.DHCP_OPT_NNTPSERVER,  '192.168.144.101'),
              (dhcp.DHCP_OPT_NBNS, '192.168.33.33'),
              (dhcp.DHCP_OPT_NBNS, '192.168.33.34'),
              (dhcp.DHCP_OPT_NBNS, '192.168.33.35'),
              (valid_single_valued_attr["NETBIOS Scope"][0], 'nbscope'),
              (valid_multi_valued_attr["Classless Static Route"][0], '30.1.0.0/16,30.1.0.1'),
              (valid_multi_valued_attr["Classless Static Route"][0], '20.10.10.0/24,20.10.10.1')],
              [(valid_single_valued_attr["IPv4"][0], "60.0.0.1"),
              (valid_single_valued_attr["Subnet Mask"][0], "255.255.255.0"), 
              (valid_single_valued_attr["Time Offset"][0], 1234, "int"),
              (valid_multi_valued_attr["Router"][0], "70.1.1.1"),
              (valid_multi_valued_attr["Router"][0], "70.1.1.2"),
              (valid_multi_valued_attr["Router"][0], "70.1.1.3"),
              (valid_single_valued_attr["Domain Name"][0], "80.0.0.5"),
              (valid_single_valued_attr["Hostname"][0], "60.0.0.6"),
              (valid_multi_valued_attr["Domain Server"][0], '192.168.144.60'),
              (valid_multi_valued_attr["Name Server"][0],  '192.168.144.66'),
              (valid_single_valued_attr["NETBIOS Scope"][0], '60.0.0.5')],]

create_dhcp_database(mac_list, server_if_list, attr_lists)
