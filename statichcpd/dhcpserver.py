#!/usr/bin/env python3

from select import poll, POLLIN, POLLOUT, POLLERR
from pyroute2 import IPRoute
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg
from pyroute2.netlink.rtnl.ifaddrmsg import ifaddrmsg
import socket
from logging import Logger
from typing import Dict, List, Any, Tuple, TypeVar, Optional
from ipaddress import AddressValueError, IPv6Address, IPv4Address
from dpkt import dhcp
import re
from configparser import SectionProxy
from socket import htons
import dpkt
from ctypes import create_string_buffer, addressof
from struct import pack
import psutil
import time

from .dhcp_packet_mgr import process_dhcp_packet
from .dhcp6_packet_mgr import process_dhcp6_packet
from .database_manager import exit
from .datatypes import *
from .logmgr import logger
from .dhcp6 import *

#  If there is a new NL msg, add the new interface to poll if it's create
#  and remove the intf from poll if it's delete

any_nlmsg = TypeVar('any_nlmsg', ifinfmsg, ifaddrmsg)
server_regexobj = None
routing_disabled = False
dhcp_ratelimit = 1000

def init(config: SectionProxy) -> None:
    global server_regexobj, routing_disabled, dhcp_ratelimit
    server_regexobj = re.compile(config['served_interface_regex'])
    routing_disabled = config.getboolean('routing_disabled', fallback=False)
    dhcp_ratelimit = config.getint('dhcp_ratelimit', fallback=1000)

def get_mac_address(ifname: str) -> Optional[Mac]:
    nics = psutil.net_if_addrs()
    if ifname in nics:
        nic = nics[ifname]
        for i in nic:
            if i.family == psutil.AF_LINK:
                return Mac(i.address)
    return None

class RateLimiter():
    def __init__(self, ts: float, tokens: float) -> None:
        self.last_pkt_ts = ts
        self.pkt_tokens = tokens

suspended : List[Tuple[int, float]] = [] # A list of tuples of the form [(fd, timestamp),]
ratelimiter : Dict[int, RateLimiter] = {} # A dictionary of RateLimiter objects indexed by socket fd

# An interface cache entry exists only for an interface whose state is UP
# OR has a valid IP address configured. At any point, if the interface state
# becomes down and IP is also deleted, the entry will get erased

# The server uses common raw socket for receiving both DHCPv4 and DHCPv6 packets
# A global UDP socket is used for DHCPv4 unicasts and an interface specific UDP socket
# is used for DHCPv6 replies

class InterfaceCacheEntry():
    def __init__(self, ifname: str, idx: int) -> None:
        self.raw_fd : Optional[int] = None
        self.rawsock : Optional[socket.socket] = None
        self.ifname = ifname
        self.ip : Optional[str] = None
        self.ip6 = None
        self.mac : Optional[Mac] = None
        self.up = False
        self.idx = idx

class InterfaceCache(object):
    def __init__(self) -> None:
        self._by_fd : Dict[int, Optional[InterfaceCacheEntry]]= {}   # Access using fd will be available only after the entry is active!
        self._by_ifname : Dict[str, Optional[InterfaceCacheEntry]] = {}

    def __del__(self) -> None:
        for entry in self._by_ifname.values():
            if entry is not None:
                self.deactivate(entry)
        del self._by_fd
        del self._by_ifname

    def add(self, ifname: str, idx: int) -> InterfaceCacheEntry:
        entry = InterfaceCacheEntry(ifname, idx)
        self._by_ifname[ifname] = entry
        logger.debug("Created a new cache entry for %s ", ifname)
        return entry

    def delete(self, entry: InterfaceCacheEntry) -> None:
        logger.debug("Deleting cache entry for %s", entry.ifname)
        if entry.raw_fd is not None: # Access using fd will be availabe only after activation
            del self._by_fd[entry.raw_fd]
        del self._by_ifname[entry.ifname]

    def fetch_ifcache_by_fd(self, fd: int) -> Optional[InterfaceCacheEntry]:
        return self._by_fd.get(fd)

    def fetch_ifcache_by_ifname(self, ifname: str) -> Optional[InterfaceCacheEntry]:
        return self._by_ifname.get(ifname)

    def activate(self, entry: InterfaceCacheEntry, rawsock: socket.socket) -> None:
        if rawsock:
            entry.rawsock = rawsock
            entry.raw_fd =  rawsock.fileno()
            self._by_fd[entry.raw_fd] = entry
        self._by_ifname[entry.ifname] =  entry

    def deactivate(self, entry: InterfaceCacheEntry) -> None:
        if entry.rawsock:
            entry.rawsock.close()
        entry.rawsock = None
        # Invalidate access using fd since the cache entry is deactivated
        if entry.raw_fd is not None:
            self._by_fd[entry.raw_fd] = None
        entry.raw_fd =  None
        self._by_ifname[entry.ifname] =  entry


ifcache = InterfaceCache()

def is_served_intf(ifname: str) -> bool:
    if server_regexobj is not None:
        return bool(server_regexobj.search(ifname))
    return False


#Filter on port 67 generated using the following command:
#sudo tcpdump -p -i lo -dd -s 1024 'inbound and (dst port 67 or dst port 547)' | sed -e 's/{ /(/' -e 's/ }/)/'

dhcp_filter_list = [
(0x28, 0, 0, 0xfffff004),
(0x15, 20, 0, 0x00000004),
(0x28, 0, 0, 0x0000000c),
(0x15, 0, 6, 0x000086dd),
(0x30, 0, 0, 0x00000014),
(0x15, 2, 0, 0x00000084),
(0x15, 1, 0, 0x00000006),
(0x15, 0, 14, 0x00000011),
(0x28, 0, 0, 0x00000038),
(0x15, 11, 10, 0x00000043),
(0x15, 0, 11, 0x00000800),
(0x30, 0, 0, 0x00000017),
(0x15, 2, 0, 0x00000084),
(0x15, 1, 0, 0x00000006),
(0x15, 0, 7, 0x00000011),
(0x28, 0, 0, 0x00000014),
(0x45, 5, 0, 0x00001fff),
(0xb1, 0, 0, 0x0000000e),
(0x48, 0, 0, 0x00000010),
(0x15, 1, 0, 0x00000043),
(0x15, 0, 1, 0x00000223),
(0x6, 0, 0, 0x00000400),
(0x6, 0, 0, 0x00000000),
]

def add_rawsock_binding(ifname: str) -> Optional[socket.socket]:
    # Create a socket
    try:
        ETH_P_ALL = 3 # defined in linux/if_ether.h
        intf_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, htons(ETH_P_ALL))
    except OSError as err:
        logger.error("Error %s opening IPv4 RAW socket for %s. "
                     "Skipping service registration for the interface", err, ifname)
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
        logger.error("Error %s setting IPv4 RAW socket options for %s", err, ifname)
        intf_sock.close()
        return None

    try:
        intf_sock.bind((ifname, ETH_P_ALL))
    except OSError as err:
        logger.error("Error %s binding the IPv4 RAW socket for %s", err, ifname)
        intf_sock.close()   # No entry is added to internal datastructs at this point and not registered with poll
        return None

    return intf_sock

# Registration with poll is only done for an interface whose state is UP
# AND has a valid IP address configured. At any point, if the interface state
# becomes down or IP is deleted, the interface will be de-registered

def activate_and_start_polling(poller_obj: poll, ifcache_entry: InterfaceCacheEntry) -> None:
    ifname = ifcache_entry.ifname

    # Skip for already activated interface
    if ifcache_entry.raw_fd is not None :
        logger.debug("Interface %s is already active. Skipping..", ifname)
        return

    # Create and bind a socket
    intf_rawsock = ifcache_entry.rawsock if ifcache_entry.rawsock is not None else add_rawsock_binding(ifname)

    if intf_rawsock is None:
        logger.error("Failed to open sockets for interface %s."
                     " Not servicing the interface.",
                       ifname)
        return

    # Activate the cache entry
    ifcache.activate(ifcache_entry, intf_rawsock)

    # Register with poller object
    try:
        if intf_rawsock is not None and intf_rawsock.fileno() not in [fd for (fd,ts) in suspended]:
            logger.debug("Registering raw socket fd: %d with poll", intf_rawsock.fileno())
            poller_obj.register(intf_rawsock.fileno(), POLLIN)
            logger.info("Start servicing the interface %s", ifname)
    except AttributeError as err:
        logger.error("Error %s registering %s for service", err, ifname)
        # Cleanup the socket binding and deativate the cache entry:
        # To re-register the intf, restart of process/reconfiguration of intf will be required!
        #ifcache_entry = ifcache.fetch_ifcache_by_ifname(ifname)
        #if ifcache_entry:
        ifcache.deactivate(ifcache_entry)

def deactivate_and_stop_polling(poller_obj: poll, ifcache_entry: InterfaceCacheEntry) -> None:
    ifname = ifcache_entry.ifname

    # Skip already deactivated entries
    if ifcache_entry is None or \
       ifcache_entry.raw_fd is None :
	       logger.debug("Ignoring non-registered intf: %s", ifname)
	       return

    try:
        if ifcache_entry.raw_fd is not None and ifcache_entry.raw_fd not in [fd for (fd,ts) in suspended]:
            poller_obj.unregister(ifcache_entry.raw_fd)
            logger.info("Stop servicing interface %s (raw socket fd: %d)", ifname, ifcache_entry.raw_fd)
    except KeyError as err:
        logger.error("Error %s deregistering %s from service", err, ifname)
        return

    if ifcache_entry.raw_fd in ratelimiter:
        del ratelimiter[ifcache_entry.raw_fd]
    ifcache.deactivate(ifcache_entry)

def process_nlmsg(poller_obj: poll, nlmsg: any_nlmsg) -> None:
    nl_event = nlmsg['event']
    if_index = int(nlmsg['index'])
    if nl_event not in ['RTM_NEWLINK', 'RTM_DELLINK', 'RTM_NEWADDR', 'RTM_DELADDR']:
        return
    if nl_event == 'RTM_NEWLINK':
        ifname = nlmsg.IFLA_IFNAME.value
        state = nlmsg.IFLA_OPERSTATE.value
        if not is_served_intf(ifname):
            return
        if_mac = None
        if nlmsg.IFLA_ADDRESS.value:
            if_mac = Mac(nlmsg.IFLA_ADDRESS.value)
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

# Packet tokens will be credited to each file descriptor at the rate of
# configured dhcp_ratelimit. Insufficient number of tokens is a sign of
# packet burst and the interface will be suspended for one second

def ratelimit_monitor(now_t: float, ifcache_entry: InterfaceCacheEntry,
                      poller_obj: poll) -> None:
    if ifcache_entry.raw_fd is None:
        return
    if ifcache_entry.raw_fd not in ratelimiter:
        ratelimiter[ifcache_entry.raw_fd] = RateLimiter(now_t, 0)
        return

    rl_entry = ratelimiter[ifcache_entry.raw_fd]
    rl_entry.pkt_tokens += (now_t - rl_entry.last_pkt_ts) * dhcp_ratelimit

    if rl_entry.pkt_tokens < 1:
        logger.info("Ratelimit Warning: Burst of packets on %s. "
                    "Shutting down for a second", 
                    ifcache_entry.ifname)
        suspended.append((ifcache_entry.raw_fd, now_t))
        poller_obj.unregister(ifcache_entry.raw_fd)
    else:
        rl_entry.pkt_tokens -= 1
    rl_entry.last_pkt_ts = now_t

def start_server() -> None:
    global ifcache, suspended
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
            v4_tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            v4_tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            v4_tx_sock.bind(('', 67))
        except OSError as err:
            logger.error("Error %s opening IPv4 UDP socket for unicast replies", err)
            if v4_tx_sock is not None:
                v4_tx_sock.close()
            raise KeyboardInterrupt

        try:
            v6_tx_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            v6_tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            v6_tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            v6_tx_sock.bind(('', 547))
        except OSError as err:
            logger.error("Error %s opening IPv6 UDP socket for DHCPv6 replies", err)
            if v6_tx_sock is not None:
                v6_tx_sock.close()
            raise KeyboardInterrupt


    # 3. Add any existing served interfaces to the ifcache if state is UP or if it has IP address.
    #    Interfaces with IP address and UP state should be added to the poll list(to handle cases of process restart)

        for intf in nlsock.get_links():
            state = intf.IFLA_OPERSTATE.value
            ifname = intf.IFLA_IFNAME.value
            if is_served_intf(ifname):
                try:
                    idx = nlsock.link_lookup(ifname=ifname)[0]
                except IndexError as err:
                    logger.error("Error %s fetching interface index "
                                 "for %s. Unable to serve the interface",
                                 err, ifname)
                    continue
                # Add a new intf cache entry for every served interface
                if_entry = ifcache.add(ifname, idx)

                # Check if there is an IP configured
                interface_ip: Optional[str]
                try:
                    interface_ip = str(IPv4Address(nlsock.get_addr(index=idx)[0].get_attr('IFA_ADDRESS')))
                except (AddressValueError, IndexError):
                    interface_ip = None

                # Update IP, MAC and Interface State in the cache
                if_entry.up = (state == 'UP')
                if_entry.ip = interface_ip
                if_entry.mac = get_mac_address(ifname)

                # If state is UP, start polling irrespective of IP address configuration
                if if_entry.up:
                    activate_and_start_polling(poller_obj, if_entry)
        ifcache_entry : Optional[InterfaceCacheEntry]
    # 4. Keep checking for any events on the polled FDs and process them
        start_t = time.time()
        while True:
            fdEvent = poller_obj.poll(1024)
            
            # Recover all eligible FDs that were suspended earlier
            recovered = 0
            now_t = time.time()
            for fd, ts in suspended:
                if now_t - ts > 1:
                    # Ensure that we still have a valid cache entry for this fd
                    # This will handle situations where the interface was deleted after being suspended
                    ifcache_entry = ifcache.fetch_ifcache_by_fd(fd)
                    if ifcache_entry and ifcache_entry.raw_fd is not None:
                        poller_obj.register(ifcache_entry.raw_fd, POLLIN)
                        logger.info("Ratelimit Info: Restarted servicing "
                                    "interface %s", ifcache_entry.ifname)
                    recovered += 1
                else:
                    break
            suspended = suspended[recovered:]

            for fd, event in fdEvent:
                if event & POLLIN:                    #TODO: Add code to handle other events
                    if fd == nlsock.fileno():
                        for nlmsg in nlsock.get():
                            process_nlmsg(poller_obj, nlmsg)
                    else:
                        ifcache_entry = ifcache.fetch_ifcache_by_fd(fd)
                        if not ifcache_entry:
                            logger.error("Received packet on untracked interface file descriptor %d!", fd)
                            raise KeyboardInterrupt
                        intf_sock = ifcache_entry.rawsock
                        ifname = ifcache_entry.ifname
                        if intf_sock is None:
                            logger.error("Error finding a valid socket "
                                         "for interface %s and file descriptor %d",
                                         ifname, fd)
                            raise KeyboardInterrupt
                        try:
                            msg, (ifname, ethproto, pkttype, arphrd, rawmac) = intf_sock.recvfrom(1024)
                            now_t = time.time()
                            ratelimit_monitor(now_t, ifcache_entry, poller_obj)
                        except OSError as err:
                            logger.error("Error %s receiving packet on %s. "
                                         " Stop servicing interface.", err, ifname)
                            deactivate_and_stop_polling(poller_obj, ifcache_entry)
                            ifcache.delete(ifcache_entry)
                            continue
                        try:
                            eth = dpkt.ethernet.Ethernet(msg)
                            isv4 = True
                            if not isinstance(eth.data, dpkt.ip.IP):
                                if not isinstance(eth.data, dpkt.ip6.IP6):
                                    continue
                                isv4 = False


                            ip = eth.data
                            if not isinstance(ip.data, dpkt.udp.UDP):
                                continue

                            udp = ip.data
                        except OSError as err:
                            logger.error("Error %s receiving packet on %s. ", err, ifname)
                            continue
                        if isv4:
                            try:
                                dh = dpkt.dhcp.DHCP(udp.data)
                            except (OSError, dpkt.NeedData) as err:
                                logger.error("Error %s receiving packet on %s. ", err, ifname)
                                continue
                            src_mac = Mac(eth.src)
                            server_ip = ifcache_entry.ip
                            if server_ip is None:
                                logger.warning("Received DHCP packet on interface %s with no IP address", ifname)
                            if ifcache_entry.mac is None:
                                logger.error("No hardware address found on the interface %s.", ifname)
                                logger.error("Unable to process DHCP packet from %s", src_mac)
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
                                    continue
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
                                    v4_tx_sock.sendmsg([dhcp_frame],
                                                    [(socket.IPPROTO_IP, SOL_IP_PKTINFO, pktinfo)],
                                                    0, (str(destination_ip), port))
                                    continue
                            except OSError as err:
                                logger.error("Error %s sending packet on %s. "
                                             " Stop servicing the interface.", err, ifname)
                                deactivate_and_stop_polling(poller_obj, ifcache_entry)
                                ifcache.delete(ifcache_entry)
                                continue

                        # Case of IPv6 packet
                        try:
                            if len(udp.data) > 0:
                                src_mac = Mac(eth.src)
                                if ifcache_entry.mac is None:
                                    logger.error("No hardware address found on the interface %s.", ifname)
                                    logger.error("Unable to process DHCPv6 packet from %s", src_mac)
                                    continue

                                dhcp6_msg = Message(udp.data)
                                logger.debug("Received DHCPv6 packet on %s from %s", ifname, src_mac)

                                (pkt, direct_unicast_from_client)= process_dhcp6_packet(ifname, dhcp6_msg, 
                                                                           ifcache_entry.mac, Mac(rawmac))
                                if pkt is None:
                                    logger.debug("No DHCP6 response sent for packet on %s from %s", 
                                                  ifname, Mac(rawmac))
                                    continue
                                destination_ip6 = str(IPv6Address(ip.src))
                                if direct_unicast_from_client:
                                    logger.debug("Direct unicast from client: Unicast reply to %s through interface %s",
                                                  destination_ip6, ifname)
                                    pktinfo = pack('=16sI', bytes(0), ifcache_entry.idx)
                                    SOL_IP6_PKTINFO = 50
                                    v6_tx_sock.sendmsg([pkt],
                                                   [(socket.IPPROTO_IPV6, SOL_IP6_PKTINFO, pktinfo)],
                                                   0, (destination_ip6, udp.sport))
                                else:
                                    v6_tx_sock.sendto(pkt, (destination_ip6, udp.sport))
                        except OSError as err:
                            logger.error("Error %s sending packet on %s. "
                                         "Stop servicing the interface.", err, ifname)
                            deactivate_and_stop_polling(poller_obj, ifcache_entry)
                            ifcache.delete(ifcache_entry)
                            continue


    except KeyboardInterrupt:
        exit()
        del ifcache
        if v4_tx_sock:
            v4_tx_sock.close()
        if v6_tx_sock:
            v6_tx_sock.close()
        logger.info("Server exiting..")
