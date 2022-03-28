import socket
import struct
import fcntl
from ctypes import create_string_buffer, addressof
from typing import Optional
from .datatypes import *
from .logmgr import logger

# Filter on port 67 generated using the following command:
# sudo tcpdump -p -i lo -dd -s 1024 'inbound and (dst port 67 or dst port 547)' | sed -e 's/{ /(/' -e 's/ }/)/'

dhcp_filter_list = [
    (0x28, 0, 0, 0xFFFFF004),
    (0x15, 20, 0, 0x00000004),
    (0x28, 0, 0, 0x0000000C),
    (0x15, 0, 6, 0x000086DD),
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
    (0x45, 5, 0, 0x00001FFF),
    (0xB1, 0, 0, 0x0000000E),
    (0x48, 0, 0, 0x00000010),
    (0x15, 1, 0, 0x00000043),
    (0x15, 0, 1, 0x00000223),
    (0x6, 0, 0, 0x00000400),
    (0x6, 0, 0, 0x00000000),
]


def strtobool(val: str) -> bool:
    return val.lower() in ["true", "1"]


def get_mac_address(ifname: str) -> Optional[Mac]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(
            s.fileno(),
            0x8927,
            struct.pack("256s", bytes(ifname, "utf-8")[:15]),
        )
        if info:
            s.close()
            return Mac(":".join("%02x" % b for b in info[18:24]))
    except OSError as err:
        logger.error("Error %s fetching hardware address of  %s.", err, ifname)
    if s is not None:
        s.close()
    return None


def add_rawsock_binding(ifname: str) -> Optional[socket.socket]:
    # Create a socket
    try:
        ETH_P_ALL = 3  # defined in linux/if_ether.h
        intf_sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
        )
    except OSError as err:
        logger.error(
            "Error %s opening IPv4 RAW socket for %s. "
            "Skipping service registration for the interface",
            err,
            ifname,
        )
        return None

    # Set socket options and bind the socket
    try:
        intf_sock.bind((ifname, ETH_P_ALL))
        intf_sock.setblocking(False)
        intf_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        SO_ATTACH_FILTER = 26  # defined in linux/filter.h
        filter_bytestring = b"".join(
            [
                struct.pack("HBBI", code, jt, jf, k)
                for code, jt, jf, k in dhcp_filter_list
            ]
        )
        sock_filter_buf = create_string_buffer(filter_bytestring)
        sock_fprog = struct.pack(
            "HL", len(dhcp_filter_list), addressof(sock_filter_buf)
        )
        intf_sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, sock_fprog)
    except OSError as err:
        logger.error(
            "Error %s binding to / setting IPv4 RAW socket options for %s",
            err,
            ifname,
        )
        intf_sock.close()
        return None

    return intf_sock
