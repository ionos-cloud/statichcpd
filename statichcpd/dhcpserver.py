#!/usr/bin/env python3

from select import poll, POLLIN, POLLOUT, POLLERR 
from pyroute2 import IPRoute
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg
from pyroute2.netlink.rtnl.ifaddrmsg import ifaddrmsg
import socket
from logging import Logger
from typing import Dict, List, Any, Tuple, TypeVar, Optional
from ipaddress import AddressValueError
from dpkt import dhcp
import re
from configparser import SectionProxy
from socket import htons
import dpkt
from ctypes import create_string_buffer, addressof
from struct import pack
import psutil

from .dhcp_packet_mgr import process_dhcp_packet
from .database_manager import exit
from .datatypes import * 
from .logmgr import logger

#  If there is a new NL msg, add the new interface to poll if it's create 
#  and remove the intf from poll if it's delete

any_nlmsg = TypeVar('any_nlmsg', ifinfmsg, ifaddrmsg)
server_regexobj = None
routing_disabled = False

def init(config: SectionProxy) -> None:
    global server_regexobj, routing_disabled
    server_regexobj = re.compile(config['served_interface_regex'])
    routing_disabled = config.getboolean('routing_disabled', False)

def get_mac_address(ifname: str) -> Optional[Mac]:
    nics = psutil.net_if_addrs()
    if ifname in nics:
        nic = nics[ifname]
        for i in nic:
            if i.family == psutil.AF_LINK:
                return Mac(i.address)
    return None

# An interface cache entry exists only for an interface whose state is UP 
# OR has a valid IP address configured. At any point, if the interface state
# becomes down and IP is also deleted, the entry will get erased

class InterfaceCacheEntry():
    def __init__(self, ifname, idx):
        self.fd = None
        self.sock = None
        self.ifname = ifname
        self.ip = None
        self.mac = None
        self.up = False
        self.idx = idx

class InterfaceCache(object):
    def __init__(self):
        self._by_fd = {}   # Access using fd will be available only after the entry is active!
        self._by_ifname = {}

    def add(self, ifname, idx):
        entry = InterfaceCacheEntry(ifname, idx)
        self._by_ifname[ifname] = entry
        logger.debug("Created a new cache entry for %s ", ifname)
        return entry

    def delete(self, entry):
        logger.debug("Deleting cache entry for %s", entry.ifname)
        if entry.fd is not None: # Access using fd will be availabe only after activation
            del self._by_fd[entry.fd]
        del self._by_ifname[entry.ifname]

    def fetch_ifcache_by_fd(self, fd):
        return self._by_fd.get(fd)

    def fetch_ifcache_by_ifname(self, ifname):
        return self._by_ifname.get(ifname)

    def activate(self, entry, sock):
        entry.sock = sock
        entry.fd =  sock.fileno()
        self._by_fd[entry.fd] = entry
        self._by_ifname[entry.ifname] =  entry

    def deactivate(self, entry):
        if entry.sock:
            entry.sock.close()
        entry.sock = None
        entry.fd =  None
        self._by_fd[entry.fd] = entry
        self._by_ifname[entry.ifname] =  entry


ifcache = InterfaceCache()

def is_served_intf(ifname: str) -> bool:
    return bool(server_regexobj.search(ifname))

 
#Filter on port 67 generated using the following command:
#sudo tcpdump -p -i lo -dd -s 1024 '(port 67)' | sed -e 's/{ /(/' -e 's/ }/)/


dhcp_filter_list = [
(0x28, 0, 0, 0x0000000c),
(0x15, 0, 8, 0x000086dd),
(0x30, 0, 0, 0x00000014),
(0x15, 2, 0, 0x00000084),
(0x15, 1, 0, 0x00000006),
(0x15, 0, 17, 0x00000011),
(0x28, 0, 0, 0x00000036),
(0x15, 14, 0, 0x00000043),
(0x28, 0, 0, 0x00000038),
(0x15, 12, 13, 0x00000043),
(0x15, 0, 12, 0x00000800),
(0x30, 0, 0, 0x00000017),
(0x15, 2, 0, 0x00000084),
(0x15, 1, 0, 0x00000006),
(0x15, 0, 8, 0x00000011),
(0x28, 0, 0, 0x00000014),
(0x45, 6, 0, 0x00001fff),
(0xb1, 0, 0, 0x0000000e),
(0x48, 0, 0, 0x0000000e),
(0x15, 2, 0, 0x00000043),
(0x48, 0, 0, 0x00000010),
(0x15, 0, 1, 0x00000043),
(0x6, 0, 0, 0x00000400),
(0x6, 0, 0, 0x00000000),
]

def add_sock_binding(ifname: str) -> Optional[socket.socket]:
    # Create a socket
    try:
        ETH_P_ALL = 3 # defined in linux/if_ether.h
        intf_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, htons(ETH_P_ALL))
    except OSError as err:
        logger.error("%s Failed to open socket for %s. Skipping poll registration", err, ifname)
        return None

    # Set socket options and bind the socket
    try:
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        SO_ATTACH_FILTER = 26 # defined in linux/filter.h
        filter_bytestring = b''.join([pack('HBBI', code, jt, jf, k) for 
                                      code, jt, jf, k in dhcp_filter_list])
        sock_filter_buf = create_string_buffer(filter_bytestring)
        sock_fprog = pack('HL', len(dhcp_filter_list), addressof(sock_filter_buf))
        intf_sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, sock_fprog)
    except OSError as err:
        logger.error("%s Failed to set socket options for %s", err, ifname)
        intf_sock.close()
        return None

    try:
        intf_sock.bind((ifname, ETH_P_ALL))
    except OSError as err:
        logger.error("%s Failed to bind to the socket for %s", err, ifname)
        intf_sock.close()   # No entry is added to internal datastructs at this point and not registered with poll
        return None

    return intf_sock

# Registration with poll is only done for an interface whose state is UP 
# AND has a valid IP address configured. At any point, if the interface state
# becomes down or IP is deleted, the interface will be de-registered

def activate_and_start_polling(poller_obj: poll, ifcache_entry: InterfaceCacheEntry) -> None:
    ifname = ifcache_entry.ifname

    # Skip for already activated interface
    if ifcache_entry.fd is not None:
        logger.debug("Interface %s is already active. Skipping..", ifname)
        return

    # Create and bind a socket
    intf_sock = add_sock_binding(ifname)
    if intf_sock is None:
        logger.error("Failed to add socket binding for %s. Not registering intf with poll", ifname)
        return

    # Activate the cache entry
    ifcache.activate(ifcache_entry, intf_sock)
 
    # Register with poller object
    logger.debug("Registering fd: %d with poll", intf_sock.fileno())
    try:
        poller_obj.register(intf_sock.fileno(), POLLIN)
        logger.info("Polling on interface %s", ifname)
    except AttributeError as err:
        logger.error("%s: Registering with poll failed for %s", err, ifname)
        # Cleanup the socket binding and deativate the cache entry: 
        # To re-register the intf, restart of process/reconfiguration of intf will be required!
        ifcache_entry = ifcache.fetch_ifcache_by_ifname(ifname)
        if ifcache_entry:
            ifcache.deactivate(ifcache_entry)

def deactivate_and_stop_polling(poller_obj: poll, ifcache_entry: InterfaceCacheEntry) -> None:
    ifname = ifcache_entry.ifname

    # Skip already deactivated entries
    if ifcache_entry is None or ifcache_entry.fd is None:
	       logger.debug("Ignoring non-registered intf: %s", ifname)
	       return

    try:
        poller_obj.unregister(ifcache_entry.fd)
        logger.info("Deregistered interface %s with fd: %d", ifname, ifcache_entry.fd)
    except KeyError as err:
        logger.error("%s: Deregistering with poll failed for %s", err, ifname)
        return
    
    ifcache.deactivate(ifcache_entry)

def process_nlmsg(poller_obj: poll, nlmsg: any_nlmsg) -> None:
    nl_event = nlmsg['event']
    if_index = nlmsg['index']
    if nl_event not in ['RTM_NEWLINK', 'RTM_DELLINK', 'RTM_NEWADDR', 'RTM_DELADDR']:
        return
    if nl_event == 'RTM_NEWLINK':
        ifname = nlmsg.IFLA_IFNAME.value
        state = nlmsg.IFLA_OPERSTATE.value
        if_mac = Mac(nlmsg.IFLA_ADDRESS.value)
        if not is_served_intf(ifname):
            return
        ifcache_entry = ifcache.fetch_ifcache_by_ifname(ifname)
        if ifcache_entry is None:
            ifcache_entry = ifcache.add(ifname, if_index)
        ifcache_entry.mac = if_mac
       
        if state == 'LOWERLAYERDOWN' or state == 'DOWN':
            logger.debug("State change to DOWN for %s ", ifname)
            # When the state is down, deactivate and stop polling
            deactivate_and_stop_polling(poller_obj, ifcache_entry)
            ifcache_entry.up = False
            return

        # If the state is up, start polling
        logger.debug("State change to UP for %s ", ifname)
        # Set up to True and start polling
        ifcache_entry.up = True
        activate_and_start_polling(poller_obj, ifcache_entry)
    elif nl_event == 'RTM_DELLINK':
        ifname = nlmsg.IFLA_IFNAME.value
        if not is_served_intf(ifname):
            return
        logger.debug("%s notif for %s ", nl_event, ifname)
        ifcache_entry = ifcache.fetch_ifcache_by_ifname(ifname)
        if not ifcache_entry:
            return
        # On link delete, deactivate, stop polling and delete the cache entry
        deactivate_and_stop_polling(poller_obj, ifcache_entry)
        ifcache.delete(ifcache_entry)
    elif nl_event == 'RTM_NEWADDR':
        ifname = nlmsg.IFA_LABEL.value
        if not is_served_intf(ifname):
            return
        logger.debug("%s notif for %s ", nl_event, ifname)
        ifaddr = nlmsg.IFA_ADDRESS.value
        ifcache_entry = ifcache.fetch_ifcache_by_ifname(ifname)
        if ifcache_entry is None:
            logger.debug("Ignoring %s for interface %s which is not in cache", nl_event, ifname)
            return
        logger.debug("%s notif for %s IP %s", nl_event, ifname, ifaddr)
        # Set the up state to True
        ifcache_entry.ip = ifaddr
    else: # Case of RTM_DELADDR
        ifname = nlmsg.IFA_LABEL.value
        if not is_served_intf(ifname):
            return
        logger.debug("%s notif for %s ", nl_event, ifname)
        ifcache_entry = ifcache.fetch_ifcache_by_ifname(ifname)
        # When the IP is removed, remove ip value from cache
        if not ifcache_entry:
            return
            
        ifcache_entry.ip = None

def start_server():
    try:
    # 1. Create an NL socket and bind
        nlsock = IPRoute()
        try:
            nlsock.bind(groups=(rtnl.RTMGRP_LINK | rtnl.RTMGRP_IPV4_IFADDR))
        except OSError as err:
            logger.exception("%s: Exception binding netlink socket", err)
            raise KeyboardInterrupt

    # 2. Poll on the NL socket

        poller_obj = poll()
        poller_obj.register(nlsock, POLLIN)
        logger.debug("Registered Netlink socket for polling...")

        try:
            tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tx_sock.bind(('', 67))
        except OSError as err:
            logger.error("%s: Failed to open TX socket", err)
            if tx_sock is not None:
                tx_sock.close()
            raise KeyboardInterrupt


    # 3. Add any existing served interfaces to the ifcache if state is UP or if it has IP address.
    #    Interfaces with IP address and UP state should be added to the poll list(to handle cases of process restart)

        for intf in nlsock.get_links():
            state = intf.IFLA_OPERSTATE.value
            ifname = intf.IFLA_IFNAME.value
            if is_served_intf(ifname):
                try:
                    idx = nlsock.link_lookup(ifname=ifname)[0]
                except IndexError:
                    logger.error("Failed to fetch interface idx "
                                 "for %s. Skipping", 
                                 ifname)
                    continue

                # Add a new intf cache entry for every served interface
                ifcache_entry = ifcache.add(ifname, idx)

                # Check if there is an IP configured
                try:
                    interface_ip = str(IPv4Address(nlsock.get_addr(index=idx)[0].get_attr('IFA_ADDRESS')))
                except (AddressValueError, IndexError):
                    interface_ip = None 
                
                # Update IP, MAC and Interface State in the cache
                ifcache_entry.up = (state == 'UP')
                ifcache_entry.ip = interface_ip
                ifcache_entry.mac = get_mac_address(ifname)

                # If state is UP, start polling irrespective of IP address configuration
                if ifcache_entry.up:
                    activate_and_start_polling(poller_obj, ifcache_entry)

    # 4. Keep checking for any events on the polled FDs and process them
        while True:
            fdEvent = poller_obj.poll(1024)
            for fd, event in fdEvent:
                if event & POLLIN:                    #TODO: Add code to handle other events
                    if fd == nlsock.fileno():
                        for nlmsg in nlsock.get():
                            process_nlmsg(poller_obj, nlmsg)
                    else:
                        ifcache_entry = ifcache.fetch_ifcache_by_fd(fd)
                        if not ifcache_entry:
                            logger.error("Received packet on untracked fd %d!", fd)
                            raise KeyboardInterrupt
                        intf_sock = ifcache_entry.sock
                        if intf_sock:
                            ifname = ifcache_entry.ifname
                            try:
                                msg, (ifname, ethproto, pkttype, arphrd, rawmac) = intf_sock.recvfrom(1024)
                                eth = dpkt.ethernet.Ethernet(msg)
                                if not isinstance(eth.data, dpkt.ip.IP):
                                    continue

                                ip = eth.data
                                if not isinstance(ip.data, dpkt.udp.UDP):
                                    continue

                                udp = ip.data
                                dh = dpkt.dhcp.DHCP(udp.data)
                            except OSError as err:
                                logger.error("%s: Failed to receive packet on %s. "
                                             " Removing interface from cache", err, ifname)
                                deactivate_and_stop_polling(poller_obj, ifcache_entry)
                                ifcache.delete(ifcache_entry)
                                continue
                            src_mac = Mac(eth.src)
                            server_ip = ifcache_entry.ip
                            if server_ip is None:
                                logger.warning("Received DHCP packet on %s with no IP address", ifname)
                            if ifcache_entry.mac is None:
                                logger.error("No hardware address found on the interface %s.", ifname)
                                logger.error("Skipping DHCP packet from %s", src_mac)
                                continue
 
                            logger.debug("Received DHCP packet on %s from %s", ifname, src_mac)

                            dhcp_frame, gw_address, server_id = process_dhcp_packet(ifname, server_ip, src_mac, dh, 
                                                                ifcache_entry.mac)
                            if dhcp_frame is None:
                                logger.debug("No DHCP response sent for packet on %s", ifname)
                                continue
                            try:
                                # If gw_address is None, 'dhcp_frame' is a complete ethernet frame
                                # Else, 'dhcp_frame' is just dhcp hdr payload
                                if gw_address is None:
                                    intf_sock.send(dhcp_frame)
                                else:
                                    destination_ip, port = gw_address
                                    SOL_IP_PKTINFO = 8
                                    logger.debug("Unicasting DHCP reply: Dst IP:%s Src IP:%s Request Src Mac: %s", 
                                                  destination_ip, server_id, src_mac)
                                    # As per RFC 1542 Section 5.4:
                                    # In case the packet holds a non-zero ciaddr or giaddr, 
                                    #   Reply should follow normal IP routing => Use udp socket to unicast
                                    # But if routing is disabled, specify the source interface for the reply
                                    if routing_disabled:
                                        # Non-zero intf idx and Non-default source IP used unlike 
                                        # how the ip(7) linux documentation for IP_PKTINFO suggests
                                        logger.debug("Routing disabled: Unicast reply to %s through interface %s", 
                                                      gw_address, ifname)
                                        pktinfo = pack('=I4s4s', ifcache_entry.idx, socket.inet_aton(str(server_id)),
                                                                 socket.inet_aton(str(destination_ip)))
                                    else:
                                        logger.debug("Routing enabled: Unicast reply to %s", gw_address)
                                        pktinfo = pack('=I4s4s', 0, socket.inet_aton(str(server_id)), 
                                                                    socket.inet_aton(str(destination_ip)))
                                    tx_sock.sendmsg([dhcp_frame], 
                                                    [(socket.IPPROTO_IP, SOL_IP_PKTINFO, pktinfo)], 
                                                    0, (str(destination_ip), port))
                            except OSError as err:
                                logger.error("%s: Failed to send packet on %s. "
                                             " Removing interface from cache", err, ifname)
                                deactivate_and_stop_polling(poller_obj, ifcache_entry)
                                ifcache.delete(ifcache_entry)
                                continue
    except KeyboardInterrupt:
        exit()
        logger.info("Server exiting..")
