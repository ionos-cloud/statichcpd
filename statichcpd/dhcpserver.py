#!/usr/bin/env python3

"""
This module listens to packet events on certain netdevices
and processes any DHCP packet to send reponses to registered
clients
"""

from os import abort
from struct import pack
from time import time
from select import poll, POLLIN
import socket
from typing import (
    Dict,
    List,
    Any,
    Tuple,
    TypeVar,
    Optional,
    Set,
    Callable,
    Generic,
    Union,
    Pattern,
)
from ipaddress import AddressValueError, IPv6Address, IPv4Address
from dataclasses import dataclass
import re
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.ip6 import IP6
from dpkt.udp import UDP
from dpkt.dhcp import DHCP
from dpkt import NeedData

from pyroute2 import IPRoute  # pylint: disable=no-name-in-module
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg
from pyroute2.netlink.rtnl.ifaddrmsg import ifaddrmsg

try:
    from pyroute2.netlink.exceptions import NetlinkDumpInterrupted
except ImportError:

    class NetlinkDumpInterrupted(Exception):  # type: ignore
        """Dummy exception definition for older versions of pyroute."""


from .dhcp_packet_mgr import process_dhcp_packet
from .dhcp6_packet_mgr import process_dhcp6_packet
from .database_manager import db_exit
from .datatypes import Mac, DHCPError
from .logmgr import logger
from .dhcp6 import Message
from .utils import strtobool, get_mac_address, add_rawsock_binding

any_nlmsg = TypeVar("any_nlmsg", ifinfmsg, ifaddrmsg)


class ServerConfig:
    server_regexobj = re.compile(r".*")
    routing_disabled_with_udpsock = False
    routing_disabled_with_rawsock = False
    dhcp_ratelimit = 1000
    intf_suspension_period = 1

    @classmethod
    def init(
        cls,
        server_regex: Pattern[Any],
        use_udp: bool,
        use_raw: bool,
        dhcp_ratelimit: int,
        intf_suspension: int,
    ) -> None:
        cls.server_regexobj = server_regex
        cls.routing_disabled_with_udpsock = use_udp
        cls.routing_disabled_with_rawsock = use_raw
        cls.dhcp_ratelimit = dhcp_ratelimit
        cls.intf_suspension_period = intf_suspension


def init(config: Dict[str, Any]) -> None:
    server_regexobj = re.compile(config["served_interface_regex"])
    disable_with_udpsock = strtobool(
        config.get("disable_routing_with_udpsock", "False")
    )
    disable_with_rawsock = strtobool(
        config.get("disable_routing_with_rawsock", "False")
    )
    if disable_with_udpsock and disable_with_rawsock:
        raise RuntimeError(
            "Invalid configuration: "
            f"routing disabled_with udpsock={disable_with_udpsock}"
            f"rawsock={disable_with_rawsock}"
        )
    dhcp_ratelimit = int(config.get("dhcp_ratelimit", 1000))
    intf_suspension = 1
    ServerConfig.init(
        server_regexobj,
        disable_with_udpsock,
        disable_with_rawsock,
        dhcp_ratelimit,
        intf_suspension,
    )


def name_matches(ifname: str) -> bool:
    if ServerConfig.server_regexobj is not None:
        return bool(ServerConfig.server_regexobj.search(ifname))
    return False


def retry_interrupted(
    func: Callable[..., List[Any]], *args: Any, **kwargs: Any
) -> List[Any]:
    """
    Retry `func` with `args`, `kwargs` until NetlinkDumpInterrupted
    does not happen.  Assume that the generator returns a list!
    """
    tries = 0
    while True:
        tries += 1
        try:
            result = list(func(*args, **kwargs))
            break
        except NetlinkDumpInterrupted:
            continue
    if tries > 1:
        logger.warning(
            "%s %s %s got NetlinkDumpInterrupted, succeeded after %d tries",
            func,
            args,
            kwargs,
            tries,
        )
    return result


# An interface cache entry exists only for an interface whose state is UP
# OR has a valid IP address configured. At any point, if the interface state
# becomes down and IP is also deleted, the entry will get erased

# The server uses common raw socket for receiving both DHCPv4 and DHCPv6 packets
# A global UDP socket is used for DHCPv4 unicasts and an interface specific UDP socket
# is used for DHCPv6 replies


class InterfaceCacheEntry:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, ifname: str, idx: int) -> None:
        self.raw_fd: Optional[int] = None
        self.rawsock: Optional[socket.socket] = None
        self.ifname = ifname
        self.ip: Optional[str] = None
        self.ip6 = None
        self.mac: Optional[Mac] = None
        self.idx = idx
        self.to_be_deleted: bool = False


class InterfaceCache:
    def __init__(self) -> None:
        # Access using fd will be available only after the entry is active!
        self._by_fd: Dict[int, Optional[InterfaceCacheEntry]] = {}
        self._by_ifname: Dict[str, Optional[InterfaceCacheEntry]] = {}

    def __del__(self) -> None:
        for entry in self._by_ifname.values():
            if entry is not None:
                self.deactivate(entry)
        del self._by_fd
        del self._by_ifname

    def add(
        self, ifname: str, idx: int, mac: Optional[Mac]
    ) -> InterfaceCacheEntry:
        entry = self._by_ifname.get(ifname)
        if not entry:
            entry = InterfaceCacheEntry(ifname, idx)
        entry.mac = mac
        self._by_ifname[ifname] = entry
        logger.debug("Created/Updated cache entry for %s ", ifname)
        return entry

    def delete(self, entry: InterfaceCacheEntry) -> None:
        logger.debug("Deleting cache entry for %s", entry.ifname)
        if (
            entry.raw_fd is not None
        ):  # Access using fd will be availabe only after activation
            del self._by_fd[entry.raw_fd]
        del self._by_ifname[entry.ifname]

    def fetch_ifcache_by_fd(self, fd: int) -> Optional[InterfaceCacheEntry]:
        return self._by_fd.get(fd)

    def fetch_ifcache_by_ifname(
        self, ifname: str
    ) -> Optional[InterfaceCacheEntry]:
        return self._by_ifname.get(ifname)

    def activate(
        self, entry: InterfaceCacheEntry
    ) -> Union[socket.socket, int]:
        # Returns 0: No-op, -1: Failure, socket.socket: Success
        if entry.rawsock is not None:
            logger.debug(
                "Interface %s is already active. Skipping..", entry.ifname
            )
            return 0

        # Create and bind a socket
        rawsock = add_rawsock_binding(entry.ifname)

        if rawsock is None:
            logger.error(
                "Failed to open sockets for interface %s."
                " Interface cache entry will be removed.",
                entry.ifname,
            )
            return -1

        entry.rawsock = rawsock
        entry.raw_fd = rawsock.fileno()
        self._by_fd[entry.raw_fd] = entry
        self._by_ifname[entry.ifname] = entry
        return entry.rawsock

    def deactivate(self, entry: InterfaceCacheEntry) -> None:
        if entry.rawsock:
            entry.rawsock.close()
        entry.rawsock = None
        # Invalidate access using fd since the cache entry is deactivated
        if entry.raw_fd is not None:
            self._by_fd[entry.raw_fd] = None
        entry.raw_fd = None
        self._by_ifname[entry.ifname] = entry

    def set_interface_ip(self, ifname: str, ip: Optional[str]) -> None:
        entry = self._by_ifname.get(ifname)
        if entry:
            entry.ip = ip


class Controller(
    Generic[any_nlmsg]
):  # mypy suggests Generic to make any_nlmsg available
    def __init__(self) -> None:
        self.ifcache = InterfaceCache()
        self.poller_obj = Poll()
        self.ifs_to_deactivate: Set[str] = set()
        self.nlmsgs_to_process: List[any_nlmsg] = []

    # Registration with poll is only done for an interface whose state is UP
    # AND has a valid IP address configured. At any point, if the interface state
    # becomes down or IP is deleted, the interface will be de-registered

    def activate_and_start_polling(
        self, ifcache_entry: InterfaceCacheEntry
    ) -> int:
        # Return 0 on success, -1 on failure
        ifname = ifcache_entry.ifname

        # Activate the cache entry
        ret = self.ifcache.activate(ifcache_entry)
        if isinstance(ret, int):
            return ret

        # Register with poller object
        try:
            logger.debug(
                "Registering raw socket fd: %d with poll", ret.fileno()
            )
            self.poller_obj.register(ret.fileno(), POLLIN)
            logger.info(
                "Start servicing the interface %s (file descriptor %d)",
                ifname,
                ret.fileno(),
            )
        except AttributeError as err:
            logger.error("Error %s registering %s for service", err, ifname)
            # Cleanup the socket binding and deativate the cache entry:
            # To re-register the intf, restart of process/reconfiguration of intf will be required!
            self.ifcache.deactivate(ifcache_entry)
            return -1
        return 0

    def deactivate_and_stop_polling(
        self, ifcache_entry: Optional[InterfaceCacheEntry]
    ) -> None:
        # Skip already deactivated entries
        if ifcache_entry is None or ifcache_entry.raw_fd is None:
            logger.debug(
                "Ignoring non-registered intf: %s",
                ifcache_entry.ifname if ifcache_entry else None,
            )
            return

        try:
            self.poller_obj.unregister(ifcache_entry.raw_fd)
            logger.info(
                "Stop servicing interface %s (raw socket fd: %d)",
                ifcache_entry.ifname,
                ifcache_entry.raw_fd,
            )
        except KeyError as err:
            logger.error(
                "Error %s deregistering %s from service",
                err,
                ifcache_entry.ifname,
            )
            return

        self.ifcache.deactivate(ifcache_entry)

    def sanitise_pollset_and_ifcache(self) -> None:
        for ifname in self.ifs_to_deactivate:
            ifcache_entry = self.fetch_ifcache_by_ifname(ifname)
            if ifcache_entry:
                self.deactivate_and_stop_polling(ifcache_entry)
                if ifcache_entry.to_be_deleted:
                    self.ifcache.delete(ifcache_entry)
        for nlmsg in self.nlmsgs_to_process:
            ifname = (
                nlmsg.get_attr("IFLA_IFNAME")
                if nlmsg["event"] == "RTM_NEWLINK"
                else nlmsg.get_attr("IFA_LABEL")
            )
            if_index = int(nlmsg["index"])
            mac_attr: Optional[str] = nlmsg.get_attr("IFLA_ADDRESS")
            ifmac = None if mac_attr is None else Mac(mac_attr)

            ifcache_entry = self.fetch_ifcache_by_ifname(ifname)
            if nlmsg["event"] == "RTM_DELADDR":
                self.ifcache.set_interface_ip(ifname, None)
            elif nlmsg["event"] == "RTM_NEWADDR":
                self.ifcache.set_interface_ip(
                    ifname, nlmsg.get_attr("IFA_ADDRESS")
                )
            elif nlmsg["event"] == "RTM_NEWLINK":
                ifcache_entry = self.ifcache.add(ifname, if_index, ifmac)
                if self.activate_and_start_polling(ifcache_entry) < 0:
                    # Possible that the interface no longer exists
                    # Delete the entry at the cost of losing all
                    # previous mac/IP updates
                    self.ifcache.delete(ifcache_entry)
        self.ifs_to_deactivate = set()
        self.nlmsgs_to_process = []

    def add_if_to_deactivate_list(
        self, ifname: str, delete_ifcache_entry: bool = False
    ) -> None:
        entry = self.fetch_ifcache_by_ifname(ifname)
        if not entry:
            return
        self.ifs_to_deactivate.add(ifname)
        entry.to_be_deleted |= delete_ifcache_entry

    def fetch_ifcache_by_fd(self, fd: int) -> Optional[InterfaceCacheEntry]:
        return self.ifcache.fetch_ifcache_by_fd(fd)

    def fetch_ifcache_by_ifname(
        self, ifname: str
    ) -> Optional[InterfaceCacheEntry]:
        return self.ifcache.fetch_ifcache_by_ifname(ifname)

    def get_ifidx(self, ifname: str) -> Optional[int]:
        entry = self.fetch_ifcache_by_ifname(ifname)
        if not entry:
            logger.error(
                "Configured server interface %s is not in the tracked interface list!",
                ifname,
            )
            return None
        return entry.idx

    def empty_socket(self, fd: int) -> None:
        entry = self.fetch_ifcache_by_fd(fd)
        if not entry or not entry.rawsock:
            return
        logger.debug("Emptying socket for interface %s", entry.ifname)
        while True:
            try:
                data, _ = entry.rawsock.recvfrom(1024)
                if not data:
                    break
            except BlockingIOError:
                break


@dataclass
class RateLimiter:
    first_pkt_ts: float
    pkts: int


class Poll:
    def __init__(self) -> None:
        self.suspended: List[
            Tuple[int, float]
        ] = []  # A list of tuples of the form [(fd, timestamp),]
        self.pollset = poll()
        self.ratelimiter: Dict[
            int, RateLimiter
        ] = {}  # A dictionary of RateLimiter objects indexed by socket fd

    def poll(self, *args: int) -> List[Tuple[int, int]]:
        return self.pollset.poll(*args)

    def register(self, *args: Any) -> None:
        self.pollset.register(*args)

    def unregister(self, fd: int) -> None:
        if fd in self.ratelimiter:
            del self.ratelimiter[fd]
        suspended = [(sfd, ts) for (sfd, ts) in self.suspended if fd == sfd]
        if suspended:
            self.suspended.remove(suspended[0])
        else:
            self.pollset.unregister(fd)

    def suspend(self, fd: int) -> None:
        self.pollset.unregister(fd)
        self.suspended.append((fd, time()))

    def resume_suspended_fds(
        self, now_t: float, emptyfunc: Callable[[int], None]
    ) -> None:
        recovered = 0
        for fd, ts in self.suspended:
            if now_t - ts < ServerConfig.intf_suspension_period:
                break
            # Deleted/deactivated FDs are not expected to be present in
            # the list of suspended FDs
            emptyfunc(fd)
            self.pollset.register(fd, POLLIN)
            logger.info("Ratelimit Info: Restarted servicing FD %d", fd)
            recovered += 1
        self.suspended = self.suspended[recovered:]

    def ratelimit_monitor(self, fd: Optional[int], limit: int) -> None:
        if not fd:
            return
        now_t = time()
        if fd not in self.ratelimiter:
            self.ratelimiter[fd] = RateLimiter(first_pkt_ts=now_t, pkts=0)
            return

        rl_entry = self.ratelimiter[fd]
        if rl_entry.pkts == limit:
            if (
                now_t - rl_entry.first_pkt_ts
                <= ServerConfig.intf_suspension_period
            ):
                logger.info(
                    "Ratelimit Warning: %s hit maximum allowable packets in <=1 sec. "
                    "Shutting down for a second",
                    fd,
                )
                self.suspend(fd)
            else:
                rl_entry.pkts = 1
                rl_entry.first_pkt_ts = now_t
        else:
            rl_entry.pkts += 1


def process_nlmsg(nlmsg: any_nlmsg, ctrl: Controller[any_nlmsg]) -> None:
    nl_event = nlmsg["event"]
    if nl_event not in [
        "RTM_NEWLINK",
        "RTM_DELLINK",
        "RTM_NEWADDR",
        "RTM_DELADDR",
    ]:
        return
    ifname = (
        nlmsg.get_attr("IFLA_IFNAME")
        if nlmsg["event"] in ("RTM_NEWLINK", "RTM_DELLINK")
        else nlmsg.get_attr("IFA_LABEL")
    )
    if not name_matches(ifname):
        return

    if nl_event == "RTM_NEWLINK":
        state = nlmsg.get_attr("IFLA_OPERSTATE")
        ifcache_entry = ctrl.fetch_ifcache_by_ifname(ifname)
        if state in ("LOWERLAYERDOWN", "DOWN"):
            logger.debug("State change to DOWN for %s ", ifname)
            # When the state is down for an existing entry, add it
            # to the list of intfs to be deactivated such that the
            # entry is not deleted, but just deactivated
            if ifcache_entry:
                ctrl.add_if_to_deactivate_list(ifname, False)
            return

        # Events that require creation/updation of cache entry
        # should be queued irrespective of the presence of
        # an already existing ifcache_entry, considering
        # the possibility that it could be just an entry
        # with pending deletion
        ctrl.nlmsgs_to_process.append(nlmsg)

    elif nl_event == "RTM_DELLINK":
        logger.debug("%s notif for %s ", nl_event, ifname)
        ifcache_entry = ctrl.fetch_ifcache_by_ifname(ifname)
        if not ifcache_entry:
            return
        # On link delete, deactivate, stop polling and delete the cache entry
        ctrl.add_if_to_deactivate_list(ifname, True)
    elif nl_event == "RTM_NEWADDR":
        logger.debug(
            "%s notif for %s IP %s",
            nl_event,
            ifname,
            nlmsg.get_attr("IFA_ADDRESS"),
        )
        ctrl.nlmsgs_to_process.append(nlmsg)
    else:  # Case of RTM_DELADDR
        logger.debug("%s notif for %s ", nl_event, ifname)
        ctrl.nlmsgs_to_process.append(nlmsg)


# pylint: disable=too-many-locals,too-many-branches,too-many-statements
def start_server() -> None:
    ctrl = Controller()
    nlsock = IPRoute()
    try:
        # 1. Create an NL socket and bind
        try:
            nlsock.bind(rtnl.RTMGRP_LINK | rtnl.RTMGRP_IPV4_IFADDR)
        except OSError as err:
            logger.exception(
                "%s: Exception binding netlink socket. Server exiting.", err
            )
            abort()

        # 2. Poll on the NL socket

        ctrl.poller_obj.register(nlsock, POLLIN)
        logger.debug("Registered Netlink socket for polling...")

        try:
            v4_tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            v4_tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            v4_tx_sock.bind(("", 67))
        except OSError as err:
            logger.error(
                "Error %s opening IPv4 UDP socket for unicast replies.", err
            )
            if not ServerConfig.routing_disabled_with_rawsock:
                abort()

        try:
            v6_tx_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            v6_tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            v6_tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            v6_tx_sock.bind(("", 547))
        except OSError as err:
            logger.error(
                "Error %s opening IPv6 UDP socket for DHCPv6 replies. Server exiting.",
                err,
            )
            abort()

        # 3. Add any existing served interfaces to the ifcache
        #    if state is UP or if it has IP address.
        #    Interfaces in UP state should be added to the poll
        #    list(to handle cases of process restart)

        for intf in retry_interrupted(nlsock.get_links):
            state = intf.get_attr("IFLA_OPERSTATE")
            ifname = intf.get_attr("IFLA_IFNAME")
            if name_matches(ifname):
                try:
                    idx = retry_interrupted(nlsock.link_lookup, ifname=ifname)[
                        0
                    ]
                except IndexError as err:
                    logger.error(
                        "Error %s fetching interface index "
                        "for %s. Unable to serve the interface",
                        err,
                        ifname,
                    )
                    continue

                # Check if there is an IP configured
                interface_ip: Optional[str]
                try:
                    interface_ip = str(
                        IPv4Address(
                            retry_interrupted(nlsock.get_addr, index=idx)[
                                0
                            ].get_attr("IFA_ADDRESS")
                        )
                    )
                except (AddressValueError, IndexError):
                    interface_ip = None

                # Add a new intf cache entry for every served interface
                if_entry = ctrl.ifcache.add(
                    ifname, idx, get_mac_address(ifname)
                )
                ctrl.ifcache.set_interface_ip(ifname, interface_ip)
                if state != "UP":
                    continue
                # If state is UP, start polling irrespective of IP address configuration
                if ctrl.activate_and_start_polling(if_entry) < 0:
                    ctrl.ifcache.delete(if_entry)

        ifcache_entry: Optional[InterfaceCacheEntry]
        # 4. Keep checking for any events on the polled FDs and process them
        # TODO: Clean up and simplify this piece of code
        while True:  # pylint: disable=too-many-nested-blocks
            fdEvent = ctrl.poller_obj.poll(1024)
            # Recover all eligible FDs that were suspended earlier
            ctrl.poller_obj.resume_suspended_fds(time(), ctrl.empty_socket)
            for fd, event in fdEvent:
                if not event & POLLIN:
                    continue
                if fd == nlsock.fileno():
                    for nlmsg in nlsock.get():
                        process_nlmsg(nlmsg, ctrl)
                else:
                    ifcache_entry = ctrl.fetch_ifcache_by_fd(fd)
                    if not ifcache_entry:
                        # A given FD is expected to be valid for atleast a single iteration
                        # of poll events, hence ifcache_entrty shouldn't be NULL
                        logger.error(
                            "Received packet on untracked interface file descriptor %d!",
                            fd,
                        )
                        continue
                    intf_sock = ifcache_entry.rawsock
                    ifname = ifcache_entry.ifname
                    if intf_sock is None:
                        logger.error(
                            "Error finding a valid socket "
                            "for interface %s and file descriptor %d.",
                            ifname,
                            fd,
                        )
                        continue
                    try:
                        msg, (
                            ifname,
                            _,
                            _,
                            _,
                            rawmac,
                        ) = intf_sock.recvfrom(1024)
                        ctrl.poller_obj.ratelimit_monitor(
                            ifcache_entry.raw_fd, ServerConfig.dhcp_ratelimit
                        )
                    except OSError as err:
                        logger.error(
                            "Error %s receiving packet on %s. "
                            " Stop servicing interface.",
                            err,
                            ifname,
                        )
                        ctrl.add_if_to_deactivate_list(ifname, True)
                        continue

                    # From the time when raw packet socket is opened until when
                    # it is bound to the interface, packets to other interfaces
                    # are possibly queued in this socket queue. Ignore such
                    # packets.
                    if ifname != ifcache_entry.ifname:
                        logger.error(
                            "Ignoring irrelevant packet: Socket on %s received data"
                            " with interface name as %s",
                            ifcache_entry.ifname,
                            ifname,
                        )
                        continue

                    try:
                        eth = Ethernet(msg)
                        isv4 = True
                        if not isinstance(eth.data, IP):
                            if not isinstance(eth.data, IP6):
                                continue
                            isv4 = False

                        ip = eth.data
                        if not isinstance(ip.data, UDP):
                            continue

                        udp = ip.data
                    except (OSError, NeedData) as err:
                        logger.error(
                            "Error %s receiving packet on %s. ",
                            err,
                            ifname,
                        )
                        continue
                    if isv4:
                        try:
                            dh = DHCP(bytes(udp.data))
                        except (OSError, NeedData) as err:
                            logger.error(
                                "Error %s receiving packet on %s. ",
                                err,
                                ifname,
                            )
                            continue
                        src_mac = Mac(eth.src)  # pylint: disable=no-member
                        server_ip = ifcache_entry.ip
                        if server_ip is None:
                            logger.warning(
                                "Received DHCP packet on interface %s with no IP address",
                                ifname,
                            )
                        if ifcache_entry.mac is None:
                            logger.error(
                                "No hardware address found on the interface %s.",
                                ifname,
                            )
                            logger.error(
                                "Unable to process DHCP packet from %s",
                                src_mac,
                            )
                            continue

                        logger.debug(
                            "Received DHCP packet on %s from %s",
                            ifname,
                            src_mac,
                        )

                        dhcp_response, gw_address = process_dhcp_packet(
                            ifname,
                            server_ip,
                            src_mac,
                            dh,
                            ifcache_entry.mac,
                            ServerConfig.routing_disabled_with_rawsock,
                        )
                        if isinstance(dhcp_response, DHCPError):
                            logger.info(
                                "No DHCP response sent on %s: Client: %s Error %s",
                                dhcp_response.ifname,
                                dhcp_response.client,
                                dhcp_response.error,
                            )
                            continue
                        try:
                            # As per RFC 1542 Section 5.4:
                            # In case the packet holds a non-zero ciaddr or giaddr,
                            #   Reply should follow normal IP routing
                            #   => Use udp socket to unicast
                            # But 'ServerConfig.routing_disabled_with_rawsock' or
                            # 'ServerConfig.routing_disabled_with_udpsock' overrides this behaviour
                            # So, raw socket is used if routing_disabled_with_rawsock = True
                            # or if both ciaddr and giaddr are zero

                            # If gw_address is None, 'dhcp_response.data' is a
                            # complete ethernet frame
                            # Else, 'dhcp_response.data' is just dhcp hdr payload
                            if gw_address is None:
                                # The outgoing server intf could be different from
                                # incoming server intf if client grouping is enabled
                                if ifname != dhcp_response.server_iface:
                                    ifcache_entry = (
                                        ctrl.fetch_ifcache_by_ifname(
                                            dhcp_response.server_iface
                                        )
                                        if dhcp_response.server_iface
                                        else None
                                    )
                                    if not ifcache_entry:
                                        logger.error(
                                            "No server info found for server interface %s",
                                            dhcp_response.server_iface,
                                        )
                                        continue
                                if not ifcache_entry.rawsock:
                                    logger.error(
                                        "No socket info found for server interface %s",
                                        dhcp_response.server_iface,
                                    )
                                    continue
                                logger.debug(
                                    "Unicasting DHCP reply over RAW socket: "
                                    "Request Src Mac:%s Server Intf: %s",
                                    src_mac,
                                    dhcp_response.server_iface,
                                )
                                ifcache_entry.rawsock.send(dhcp_response.data)
                                continue
                            # dhcp_response.data' is just dhcp hdr payload
                            destination_ip, port = gw_address
                            SOL_IP_PKTINFO = 8
                            # If routing is disabled with udp socket,
                            # specify the source interface for the reply
                            if ServerConfig.routing_disabled_with_udpsock:
                                # Non-zero intf idx and Non-default source IP used unlike
                                # how the ip(7) linux documentation for IP_PKTINFO suggests
                                if dhcp_response.server_iface is None:
                                    logger.error(
                                        "Routing disabled: No valid server interface configured "
                                        "for client %s received on interface %s. No response sent",
                                        src_mac,
                                        ifname,
                                    )
                                    continue
                                server_if_idx = (
                                    ifcache_entry.idx
                                    if ifname == dhcp_response.server_iface
                                    else ctrl.get_ifidx(
                                        dhcp_response.server_iface
                                    )
                                )
                                if server_if_idx is None:
                                    logger.error(
                                        "Routing disabled: Failed to fetch if index for %s "
                                        "No response sent for client %s for pkt on interface %s.",
                                        dhcp_response.server_iface,
                                        src_mac,
                                        ifname,
                                    )
                                    continue

                                logger.debug(
                                    "Routing disabled: Unicast reply to %s through interface %s",
                                    gw_address,
                                    dhcp_response.server_iface,
                                )
                                pktinfo = pack(
                                    "=I4s4s",
                                    server_if_idx,
                                    socket.inet_aton(
                                        str(dhcp_response.server_id)
                                    ),
                                    socket.inet_aton(str(destination_ip)),
                                )
                            else:
                                logger.debug(
                                    "Routing enabled: Unicast reply to %s",
                                    gw_address,
                                )
                                pktinfo = pack(
                                    "=I4s4s",
                                    0,
                                    socket.inet_aton(
                                        str(dhcp_response.server_id)
                                    ),
                                    socket.inet_aton(str(destination_ip)),
                                )
                            logger.debug(
                                "Unicasting DHCP reply over UDP socket: "
                                "Dst IP:%s Src IP:%s Request Src Mac: %s",
                                destination_ip,
                                dhcp_response.server_id,
                                src_mac,
                            )
                            v4_tx_sock.sendmsg(
                                [dhcp_response.data],
                                [
                                    (
                                        socket.IPPROTO_IP,
                                        SOL_IP_PKTINFO,
                                        pktinfo,
                                    )
                                ],
                                0,
                                (str(destination_ip), port),
                            )
                            continue
                        except OSError as err:
                            logger.error(
                                "Error %s sending packet on %s. "
                                " Stop servicing the interface.",
                                err,
                                ifname,
                            )
                            ctrl.add_if_to_deactivate_list(ifname, True)
                            continue

                    # Case of IPv6 packet
                    try:
                        if len(udp.data) > 0:
                            src_mac = Mac(eth.src)  # pylint: disable=no-member
                            if ifcache_entry.mac is None:
                                logger.error(
                                    "No hardware address found on the interface %s.",
                                    ifname,
                                )
                                logger.error(
                                    "Unable to process DHCPv6 packet from %s",
                                    src_mac,
                                )
                                continue

                            dhcp6_msg = Message(bytes(udp.data))
                            logger.debug(
                                "Received DHCPv6 packet on %s from %s",
                                ifname,
                                src_mac,
                            )

                            (
                                dhcp6_response,
                                direct_unicast_from_client,
                            ) = process_dhcp6_packet(
                                ifname,
                                dhcp6_msg,
                                ifcache_entry.mac,
                                Mac(rawmac),
                            )
                            if isinstance(dhcp6_response, DHCPError):
                                logger.info(
                                    "No DHCP6 response sent on %s. Client: %s Error: %s",
                                    dhcp6_response.ifname,
                                    dhcp6_response.client,
                                    dhcp6_response.error,
                                )
                                continue
                            if dhcp6_response.data is None:
                                logger.info(
                                    "No DHCP6 response sent for packet on %s from %s",
                                    ifname,
                                    Mac(rawmac),
                                )
                                continue
                            destination_ip6 = str(IPv6Address(ip.src))
                            if direct_unicast_from_client:
                                logger.debug(
                                    "Direct unicast from client: "
                                    "Unicast reply to %s through interface %s",
                                    destination_ip6,
                                    ifname,
                                )
                                pktinfo = pack(
                                    "=16sI", bytes(0), ifcache_entry.idx
                                )
                                SOL_IP6_PKTINFO = 50
                                v6_tx_sock.sendmsg(
                                    [dhcp6_response.data],
                                    [
                                        (
                                            socket.IPPROTO_IPV6,
                                            SOL_IP6_PKTINFO,
                                            pktinfo,
                                        )
                                    ],
                                    0,
                                    (destination_ip6, udp.sport),
                                )
                            else:
                                v6_tx_sock.sendto(
                                    dhcp6_response.data,
                                    (destination_ip6, udp.sport),
                                )
                    except OSError as err:
                        logger.error(
                            "Error %s sending packet on %s. "
                            "Stop servicing the interface.",
                            err,
                            ifname,
                        )
                        ctrl.add_if_to_deactivate_list(ifname, True)
                        continue
            ctrl.sanitise_pollset_and_ifcache()

    except KeyboardInterrupt:
        db_exit()
        del ctrl.ifcache
        if "v4_tx_sock" in locals() and v4_tx_sock:
            v4_tx_sock.close()
        if "v6_tx_sock" in locals() and v6_tx_sock:
            v6_tx_sock.close()
        logger.info("Server exiting..")
