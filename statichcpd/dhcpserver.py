#!/usr/bin/env python3

from select import poll, POLLIN, POLLOUT, POLLERR 
from pyroute2 import IPRoute
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg
from pyroute2.netlink.rtnl.ifaddrmsg import ifaddrmsg
import socket
from logging import Logger
from typing import Dict, List, Any, Tuple, TypeVar
from ipaddress import AddressValueError
from dpkt import dhcp
import re
from configparser import SectionProxy

from .dhcp_packet_mgr import process_dhcp_packet
from .database_manager import *
from .logmgr import logger

#  If there is a new NL msg, add the new interface to poll if it's create 
#  and remove the intf from poll if it's delete

any_nlmsg = TypeVar('any_nlmsg', ifinfmsg, ifaddrmsg)
server_regexobj = None

def init(config: SectionProxy) -> None:
    global server_regexobj
    server_regexobj = re.compile(config['served_interface_regex'])

# An interface cache entry exists only for an interface whose state is UP 
# OR has a valid IP address configured. At any point, if the interface state
# becomes down and IP is also deleted, the entry will get erased

class InterfaceCacheEntry():
    def __init__(self, ifname):
        self.fd = None
        self.sock = None
        self.ifname = ifname
        self.ip = None
        self.up = False

class InterfaceCache(object):
    def __init__(self):
        self._by_fd = {}   # Access using fd will be available only after the entry is active!
        self._by_ifname = {}

    def add(self, ifname):
        entry = InterfaceCacheEntry(ifname)
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

def add_sock_binding(ifname: str) -> Optional[socket.socket]:
    # Create a socket
    try:
        intf_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        logger.error("Failed to open socket for %s. Skipping poll registration", ifname)
        return None

    # Set socket options and bind the socket
    try:
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError:
        logger.error("Failed to set socket options for %s", ifname)
        intf_sock.close()
        return None

    try:
        intf_sock.bind(('', 67))
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
        poller_obj.register(intf_sock.fileno())
        logger.debug("Polling on interface %s", ifname)
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

    logger.debug("Deregistering fd: %d", ifcache_entry.fd)
    try:
        poller_obj.unregister(ifcache_entry.fd)
    except KeyError as err:
        logger.error("%s: Deregistering with poll failed for %s", err, ifname)
        return
    
    ifcache.deactivate(ifcache_entry)

def process_nlmsg(poller_obj: poll, nlmsg: any_nlmsg) -> None:
    nl_event = nlmsg['event']
    if nl_event not in ['RTM_NEWLINK', 'RTM_DELLINK', 'RTM_NEWADDR', 'RTM_DELADDR']:
        return
    
    if nl_event == 'RTM_NEWLINK':
        ifname = nlmsg.IFLA_IFNAME.value
        state = nlmsg.IFLA_OPERSTATE.value
        if not is_served_intf(ifname):
            return
        
        if state == 'LOWERLAYERDOWN' or state == 'DOWN':
            logger.debug("State change to DOWN for %s ", ifname)
            ifcache_entry = ifcache.fetch_ifcache_by_ifname(ifname)
            if ifcache_entry is None:
                return

            # When the state is down, deactivate and stop polling
            deactivate_and_stop_polling(poller_obj, ifcache_entry)
            ifcache_entry.up = False

            # If the IP address is also None, remove the cache entry
            if ifcache_entry.ip is None:
                ifcache.delete(ifcache_entry)
            return

        # If the state is up and IP is present, start polling
        # If the state is up and no IP is present, just update the up state
        logger.debug("State change to UP for %s ", ifname)
        ifcache_entry = ifcache.fetch_ifcache_by_ifname(ifname)
        if ifcache_entry is not None:
            ifcache_entry.up = True
            if ifcache_entry.ip is not None:   # This will also handle case where previous activation failed
                activate_and_start_polling(poller_obj, ifcache_entry)
        else:
            # Add a new intf cache entry and set the up state to True
            ifcache_entry = ifcache.add(ifname)
            ifcache_entry.up = True
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
        if ifcache_entry is not None:
            logger.debug("%s notif for %s IP %s", nl_event, ifname, ifaddr)
            ifcache_entry.ip = ifaddr 
            if ifcache_entry.up:
                activate_and_start_polling(poller_obj, ifcache_entry)  # In case of multiple addresses,activation will be no-op
        else:
            # Add a new intf cache entry and set the up state to True
            ifcache_entry = ifcache.add(ifname)
            ifcache_entry.ip = ifaddr
    else: # Case of RTM_DELADDR
        ifname = nlmsg.IFA_LABEL.value
        if not is_served_intf(ifname):
            return
        logger.debug("%s notif for %s ", nl_event, ifname)
        ifcache_entry = ifcache.fetch_ifcache_by_ifname(ifname)
        # When the IP is removed, deactivate and stop polling
        if not ifcache_entry:
            return
            
        deactivate_and_stop_polling(poller_obj, ifcache_entry)
        ifcache_entry.ip = None
        # If state is also DOWN, remove the cache entry
        if not ifcache_entry.up:
            ifcache.delete(ifcache_entry)

def start_server():

# 1. Create an NL socket and bind
    nlsock = IPRoute()
    try:
        nlsock.bind(groups=(rtnl.RTMGRP_LINK | rtnl.RTMGRP_IPV4_IFADDR))
    except OSError as err:
        logger.exception("Exception binding netlink socket")

# 2. Poll on the NL socket

    poller_obj = poll()
    poller_obj.register(nlsock)
    logger.debug("Registered Netlink socket for polling...")


# 3. Add any existing served interfaces to the ifcache if state is UP or if it has IP address.
#    Interfaces with IP address and UP state should be added to the poll list(to handle cases of process restart)

    for intf in nlsock.get_links():
        state = intf.IFLA_OPERSTATE.value
        ifname = intf.IFLA_IFNAME.value
        ipr = IPRoute()
        if is_served_intf(ifname):
            # Check if there is an IP configured
            try:
                idx = ipr.link_lookup(ifname=ifname)[0]
                interface_ip = str(IPv4Address(ipr.get_addr(index=idx)[0].get_attr('IFA_ADDRESS')))
            except (AddressValueError, IndexError):
                logger.error("No IP address configuration found on %s. Skipping poll registration", ifname)
                interface_ip = None 

            # If the state is DOWN and has no IP, skip this interface  
            if state != 'UP' and interface_ip is None:
                continue
                
            # Add a new intf cache entry
            ifcache_entry = ifcache.add(ifname)

            ifcache_entry.up = (state == 'UP')
            ifcache_entry.ip = interface_ip

            # If IP is configured and state is also UP, start polling
            if ifcache_entry.up and ifcache_entry.ip is not None:
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
                        raise
                    intf_sock = ifcache_entry.sock
                    if intf_sock:
                        ifname = ifcache_entry.ifname
                        try:
                            msg, saddr = intf_sock.recvfrom(1024)
                        except OSError as err:
                            logger.error('''%s: Failed to receive packet on %s. 
                                          Removing interface from cache''', err, ifname)
                            deactivate_and_stop_polling(poller_obj, ifcache_entry)
                            ifcache.delete(ifcache_entry)
                            continue
                        server_ip = ifcache_entry.ip
                        if server_ip is None:
                            logger.error("Received DHCP packet on %s with no IP address", ifname)
                            continue
                            
                        logger.debug("Received DHCP packet on %s from %s", ifname, saddr)
                        (data, address) = process_dhcp_packet(ifname, server_ip, msg)
                        if data is None or address is None:
                            logger.debug("No DHCP response sent for packet on %s", ifname)
                            continue
                        try:
                            intf_sock.sendto(data, (address, 68))
                        except OSError as err:
                            logger.error('''%s: Failed to send packet on %s. 
                                          Removing interface from cache''', err, ifname)
                            deactivate_and_stop_polling(poller_obj, ifcache_entry)
                            ifcache.delete(ifcache_entry)
                            continue


