#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List, Any
import socket
import fcntl
import struct
import re
from pyroute2 import NSPopen, netns, NetNS, IPRoute
import subprocess
import os

from statichcpd.database_manager import *
from pyroute2.netlink.exceptions import NetlinkError

conn = None

class server_process():
    def __init__(self, cfg=None):
        self.process = None
        self.conf_file = cfg.conf_file if cfg else '/tmp/statichcpd.conf'
        self.nsname = cfg.server_nsname if cfg else 'dummy_dhcp_ns'
        
        
        # Setup a new conf file in /tmp location
        if os.path.exists(self.conf_file):
            os.remove(self.conf_file)
        with open('/etc/statichcpd/statichcpd.conf') as f:
            with open(self.conf_file, "a") as f1:
                for line in f:
                    f1.write(line)

        # Add non-default dhcp database file path and regex
        with open(self.conf_file, "a") as f1:
            f1.write('dhcp_db_filename = /tmp/Static_DHCP_DB.db\n')
            if all(re.match('^vethserver.*', intf.name) for intf in cfg.servers): 
                f1.write('served_interface_regex = ^vethserver.*\n')
            else:
                # If the interface names are different from default
                # user needs to mandatorily supply the regex
                f1.write('served_interface_regex = ' + cfg.get('regex') + "\n")

    def __enter__(self):
        bashcommand = "python3 -m statichcpd -c /tmp/statichcpd.conf"
        self.process = NSPopen(self.nsname, bashcommand.split(), stdout=subprocess.PIPE)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.process.kill()
        self.process.wait()
        self.process.stdout.close()

    def stop(self):
        self.process.kill()
        self.process.wait()
        self.process.stdout.close()

class packet_sender():
    def __init__(self, args):
        self.process = None
        self.argstr = args

    def __enter__(self):
        bashcommand = "dhclient -d " + self.argstr
        self.process = subprocess.Popen(bashcommand.split(), stdout=subprocess.PIPE)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.process:
            self.process.terminate()
        self.process.wait()
        self.process.stdout.close()

class Interface():
    def __init__(self, name=None, addr=None):
        self.name = name
        self.addr = addr

class Config():
    def __init__(self, arg_dict={}):
        self.server_nsname = arg_dict.get('server_nsname', 'dummy_dhcp_ns')
        self.conf_file = arg_dict.get('conf_file', '/tmp/statichcpd.conf')
        self.server_ns = NetNS(self.server_nsname)
        self.ip = None
        self.count = arg_dict.get('count', 1)
        self.clients = [Interface(name=name) for name in ['vethclient' + str(idx) for idx in range(self.count)]]
        self.servers = [Interface(name=name) for name in ['vethserver' + str(idx) for idx in range(self.count)]]
        if 'server_ips' in arg_dict and len(arg_dict['server_ips']) >= self.count:
            for idx in range(self.count):
                self.servers[idx].addr = arg_dict['server_ips'][idx]
        else:
            for idx in range(self.count):
                self.servers[idx].addr = str((idx + 2) * 10) + '.0.0.1'
        self.client_conf = arg_dict.get('client_conf', None)

    def __enter__(self):
        self.ip = IPRoute()
        try:
            for i in range(self.count):
                # Create client-server veth pairs
                self.ip.link('add', ifname=self.clients[i].name, kind='veth', peer=self.servers[i].name)

                # Set the client interface to UP
                idx = self.ip.link_lookup(ifname=self.clients[i].name)[0]
                self.ip.link('set', index=idx, state='up')

                # Set the server interface to UP
                idx = self.ip.link_lookup(ifname=self.servers[i].name)[0]
                self.ip.link('set', index=idx, state='up')

                # Add IP address to the server interface

                idx = self.ip.link_lookup(ifname=self.servers[i].name)[0]
                self.ip.addr('add', idx, address=self.servers[i].addr, mask=24)
              
                # Move the server interface to server namespace
                self.ip.link('set', index=idx, net_ns_fd=self.server_nsname)

                # Set the interface to UP and add address again since
                # all configs are lost on vrf move
                self.server_ns.link('set', index=idx, state='up')
                self.server_ns.addr('add', idx, address=self.servers[i].addr, mask=24)

             
            loidx = self.server_ns.link_lookup(ifname='lo')[0]
            self.server_ns.link('set', index=loidx, state='up')
            if self.client_conf is None:
                self.client_conf = build_default_conf(self.clients)
            return self
        except NetlinkError:
            if self.ip is not None:
                self.ip.close()
                self.ip = None
            if self.server_ns is not None:
                self.server_ns.close()
                self.server_ns = None
                netns.remove(self.server_nsname)
 
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.ip is not None:
            self.ip.close()
        if self.server_ns is not None:
            self.server_ns.close()
            netns.remove(self.server_nsname)
        del self.client_conf

def getHwAddr(ifname: str) -> str:
    sock =  socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sock.fileno(), 0x8927,  struct.pack('256s', bytes(ifname[:15], 'utf-8')))
    mac = ''.join(['%02x:' % char for char in info[18:24]])[:-1]
    sock.close()
    return mac


def init_client_table(mac_list: List[str], ifname_list: List[str]) -> None:
    cursor = conn.cursor()
    cursor.execute('''delete from clients;''')
    conn.commit()
    for i in range(len(mac_list)):
        mac  = mac_list[i]
        ifname = ifname_list[i]
        cursor.execute(" insert into clients (ifname, mac) values (?,?)", (ifname, mac))
    conn.commit()
    cursor.close()

def init_host_conf_table(mac_list: List[str], ifname_list: List[str], 
                         clients: List[Interface], attr_lists: List[List[Tuple[str, str]]]) -> None:
    cursor = conn.cursor()
    cursor.execute('''delete from client_configuration;''')
    conn.commit()
    for i in range(len(mac_list)):
        mac = mac_list[i]
        ifname = ifname_list[i]
        attr_list = attr_lists[clients[i].name]
        for attr in attr_list:
            cursor.execute(""" insert into client_configuration
                                       (ifname, mac, attr_code, attr_val) values
                                       (?, ?, ?, ?)""", (ifname, mac, attr[0], attr[1]))
        conn.commit()
    cursor.close()

def init_v6_tables(mac_list: List[str], ifname_list: List[str], 
                   clients: List[Interface], v6_attr_lists: List[List[Tuple[str, str]]]) -> None:
    cursor = conn.cursor()
    cursor.execute('''delete from client_v6configuration;''')
    conn.commit()
    for i in range(len(mac_list)):
        mac = mac_list[i]
        ifname = ifname_list[i]
        attr_list = v6_attr_lists[i]
        for attr in attr_list:
            cursor.execute(""" insert into client_v6configuration
                                       (ifname, duid, attr_code, attr_val) values
                                       (?, ?, ?, ?)""", (ifname, mac, attr[0], attr[1]))
            conn.commit()

        cursor.execute(""" insert into client_v6configuration
                           (ifname, duid, attr_code, attr_val) values
                           (?, ?, ?, ?)""", (ifname, mac, 259, 60)) 
        cursor.execute(""" insert into client_v6configuration
                           (ifname, duid, attr_code, attr_val) values
                           (?, ?, ?, ?)""", (ifname, mac, 260, 120))
        cursor.execute(""" insert into client_v6configuration
                           (ifname, duid, attr_code, attr_val) values
                           (?, ?, ?, ?)""", (ifname, mac, 261, 60))
        cursor.execute(""" insert into client_v6configuration
                           (ifname, duid, attr_code, attr_val) values
                           (?, ?, ?, ?)""", (ifname, mac, 262, 120))
    cursor.close()

def create_dhcp_database(mac: List[str], ifname: List[str],
                         clients: List[Interface],
                         attr_lists: List[List[Tuple[str, str]]], 
                         v6_attr_lists: List[List[Tuple[str, str]]]) -> None:
    global conn
    if conn is None:
        conn = sqlite3.connect('/tmp/Static_DHCP_DB.db')
    cursor = conn.cursor()
    for command in schema:
        cursor.execute(command)
    conn.commit()
    cursor.close()
    init_client_table(mac, ifname)
    init_host_conf_table(mac, ifname, clients, attr_lists)
    init_v6_tables(mac, ifname, clients, v6_attr_lists)

def build_default_conf(clients: List[Interface]):
    default_conf = {}
    for idx in range(len(clients)):
        client_ip = str((idx + 2) * 10) + '.0.0.2'
        subnet_mask = '255.255.255.0'
        time_offset = 0xFFFFD5D0
        hostname = 'host' + str(idx)

        default_conf[clients[idx].name] = [(256, client_ip),
                                     (dhcp.DHCP_OPT_NETMASK, subnet_mask),
                                     (dhcp.DHCP_OPT_TIMEOFFSET, time_offset),
                                     (dhcp.DHCP_OPT_HOSTNAME, hostname)]


        # Add multiple routers
        for i in range(10, 13):
            default_conf[clients[idx].name].extend([(dhcp.DHCP_OPT_ROUTER, str((idx + 1) * 10) + '.0.0.' + str(i))])

        # Add classless routes
        classless_rt = [str((idx + 2)* 20) + '.1.0.0/16,' + str((idx + 2)* 20) + '.1.0.1', str((idx + 2)* 30) + '.10.10.0/24,' + str((idx + 2)* 30) + '.10.10.1']
        for rt in classless_rt:
            default_conf[clients[idx].name].extend([(121, rt)])
    
    return default_conf
        
def fill_db(cfg: Config):
    server_if_list  = cfg.servers
    client_list = cfg.clients
    mac_list = [getHwAddr(client.name) for client in cfg.clients]
    v6_attr_lists = [[(3, '20::1'),
                  (3, '20::2'),
                  (4, '40::1'),
                  (25, '20::/64')],
                 [(3, '30::1'),
                  (3, '30::2'),
                  (4, '50::1'),
                  (25, '30::/64')]]
    create_dhcp_database(mac_list, [server.name for server in cfg.servers], cfg.clients, cfg.client_conf, v6_attr_lists)
    conn.close()
