#!/usr/bin/env python3
import dpkt
from dpkt.compat import compat_ord
from enum import Enum
import struct
from .logmgr import logger
from typing import (
    Dict,
    Any,
    Tuple,
    Optional,
    Union,
    Iterable,
    cast,
    TYPE_CHECKING,
)


# DHCP6 Options: RFC 3315 Section 22

DHCP6_OPT_CLIENTID = 1
DHCP6_OPT_SERVERID = 2
DHCP6_OPT_IA_NA = 3
DHCP6_OPT_IA_TA = 4
DHCP6_OPT_IAADDR = 5
DHCP6_OPT_ORO = 6
DHCP6_OPT_PREFERENCE = 7
DHCP6_OPT_ELAPSED_TIME = 8
DHCP6_OPT_RELAY_MSG = 9
DHCP6_OPT_AUTH = 11
DHCP6_OPT_UNICAST = 12
DHCP6_OPT_STATUS_CODE = 13
DHCP6_OPT_RAPID_COMMIT = 14
DHCP6_OPT_USER_CLASS = 15
DHCP6_OPT_VENDOR_CLASS = 16
DHCP6_OPT_VENDOR_OPTS = 17
DHCP6_OPT_INTERFACE_ID = 18
DHCP6_OPT_RECONF_MSG = 19
DHCP6_OPT_RECONF_ACCEPT = 20

# DHCP6 Request Options

DHCP6_OPT_SIP_SERVER_D = 21
DHCP6_OPT_SIP_SERVER_A = 22
DHCP6_OPT_DNS_SERVERS = 23
DHCP6_OPT_DOMAIN_LIST = 24
DHCP6_OPT_IA_PD = 25
DHCP6_OPT_IAPREFIX = 26
DHCP6_OPT_NIS_SERVERS = 27
DHCP6_OPT_NISP_SERVERS = 28
DHCP6_OPT_NIS_DOMAIN_NAME = 29
DHCP6_OPT_NISP_DOMAIN_NAME = 30
DHCP6_OPT_SNTP_SERVERS = 31
DHCP6_OPT_INFORMATION_REFRESH_TIME = 32
DHCP6_OPT_BCMCS_SERVER_D = 33
DHCP6_OPT_BCMCS_SERVER_A = 34
DHCP6_OPT_GEOCONF_CIVIC = 36
DHCP6_OPT_REMOTE_ID = 37
DHCP6_OPT_SUBSCRIBER_ID = 38
DHCP6_OPT_CLIENT_FQDN = 39
DHCP6_OPT_PANA_AGENT = 40
DHCP6_OPT_NEW_POSIX_TIMEZONE = 41
DHCP6_OPT_NEW_TZDB_TIMEZONE = 42
DHCP6_OPT_ERO = 43
DHCP6_OPT_LQ_QUERY = 44
DHCP6_OPT_CLIENT_DATA = 45
DHCP6_OPT_CLT_TIME = 46
DHCP6_OPT_LQ_RELAY_DATA = 47
DHCP6_OPT_LQ_CLIENT_LINK = 48
DHCP6_OPT_MIP6_HNIDF = 49
DHCP6_OPT_MIP6_VDINF = 50
DHCP6_OPT_V6_LOST = 51
DHCP6_OPT_CAPWAP_AC_V6 = 52
DHCP6_OPT_RELAY_ID = 53
DHCP6_OPT_Address_MoS = 54
DHCP6_OPT_FQDN_MoS = 55
DHCP6_OPT_NTP_SERVER = 56
DHCP6_OPT_V6_ACCESS_DOMAIN = 57
DHCP6_OPT_SIP_UA_CS_LIST = 58
DHCP6_OPT_BOOTFILE_URL = 59
DHCP6_OPT_BOOTFILE_PARAM = 60
DHCP6_OPT_CLIENT_ARCH_TYPE = 61
DHCP6_OPT_NII = 62
DHCP6_OPT_GEOLOCATION = 63
DHCP6_OPT_AFTR_NAME = 64
DHCP6_OPT_ERP_LOCAL_DOMAIN_NAME = 65
DHCP6_OPT_RSOO = 66
DHCP6_OPT_PD_EXCLUDE = 67
DHCP6_OPT_VSS = 68
DHCP6_OPT_MIP6_IDINF = 69
DHCP6_OPT_MIP6_UDINF = 70
DHCP6_OPT_MIP6_HNP = 71
DHCP6_OPT_MIP6_HAA = 72
DHCP6_OPT_MIP6_HAF = 73
DHCP6_OPT_RDNSS_SELECTION = 74
DHCP6_OPT_KRB_PRINCIPAL_NAME = 75
DHCP6_OPT_KRB_REALM_NAME = 76
DHCP6_OPT_KRB_DEFAULT_REALM_NAME = 77
DHCP6_OPT_KRB_KDC = 78
DHCP6_OPT_CLIENT_LINKLAYER_ADDR = 79
DHCP6_OPT_LINK_ADDRESS = 80
DHCP6_OPT_RADIUS = 81
DHCP6_OPT_SOL_MAX_RT = 82
DHCP6_OPT_INF_MAX_RT = 83
DHCP6_OPT_ADDRSEL = 84
DHCP6_OPT_ADDRSEL_TABLE = 85
DHCP6_OPT_V6_PCP_SERVER = 86
DHCP6_OPT_DHCPV4_MSG = 87
DHCP6_OPT_DHCP4_O_DHCP6_SERVER = 88
DHCP6_OPT_S46_RULE = 89
DHCP6_OPT_S46_BR = 90
DHCP6_OPT_S46_DMR = 91
DHCP6_OPT_S46_V4V6BIND = 92
DHCP6_OPT_S46_PORTPARAMS = 93
DHCP6_OPT_S46_CONT_MAPE = 94
DHCP6_OPT_S46_CONT_MAPT = 95
DHCP6_OPT_S46_CONT_LW = 96
DHCP6_OPT_4RD = 97
DHCP6_OPT_4RD_MAP_RULE = 98
DHCP6_OPT_4RD_NON_MAP_RULE = 99
DHCP6_OPT_LQ_BASE_TIME = 100
DHCP6_OPT_LQ_START_TIME = 101
DHCP6_OPT_LQ_END_TIME = 102
DHCP6_OPT_MPL_PARAMETERS = 104
DHCP6_OPT_ANI_ATT = 105
DHCP6_OPT_ANI_NETWORK_NAME = 106
DHCP6_OPT_ANI_AP_NAME = 107
DHCP6_OPT_ANI_AP_BSSID = 108
DHCP6_OPT_ANI_OPERATOR_ID = 109
DHCP6_OPT_ANI_OPERATOR_REALM = 110
DHCP6_OPT_S46_PRIORITY = 111
DHCP6_OPT_MUD_URL_V6 = 112
DHCP6_OPT_V6_PREFIX64 = 113
DHCP6_OPT_F_BINDING_STATUS = 114
DHCP6_OPT_F_CONNECT_FLAGS = 115
DHCP6_OPT_F_DNS_REMOVAL_INFO = 116
DHCP6_OPT_F_DNS_HOST_NAME = 117
DHCP6_OPT_F_DNS_ZONE_NAME = 118
DHCP6_OPT_F_DNS_FLAGS = 119
DHCP6_OPT_F_EXPIRATION_TIME = 120
DHCP6_OPT_F_MAX_UNACKED_BNDUPD = 121
DHCP6_OPT_F_MCLT = 122
DHCP6_OPT_F_PARTNER_LIFETIME = 123
DHCP6_OPT_F_PARTNER_LIFETIME_SENT = 124
DHCP6_OPT_F_PARTNER_DOWN_TIME = 125
DHCP6_OPT_F_PARTNER_RAW_CLT_TIME = 126
DHCP6_OPT_F_PROTOCOL_VERSION = 127
DHCP6_OPT_F_KEEPALIVE_TIME = 128
DHCP6_OPT_F_RECONFIGURE_DATA = 129
DHCP6_OPT_F_RELATIONSHIP_NAME = 130
DHCP6_OPT_F_SERVER_FLAGS = 131
DHCP6_OPT_F_SERVER_STATE = 132
DHCP6_OPT_F_START_TIME_OF_STATE = 133
DHCP6_OPT_F_STATE_EXPIRATION_TIME = 134
DHCP6_OPT_RELAY_PORT = 135
DHCP6_OPT_V6_SZTP_REDIRECT = 136
DHCP6_OPT_S46_BIND_IPV6_PREFIX = 137
DHCP6_OPT_IA_LL = 138
DHCP6_OPT_LLADDR = 139
DHCP6_OPT_SLAP_QUAD = 140
DHCP6_OPT_V6_DOTS_RI = 141
DHCP6_OPT_V6_DOTS_ADDRESS = 142

# DHCP Message Types: RFC 3315 Section 5.3

SOLICIT = 1
ADVERTISE = 2
REQUEST = 3
CONFIRM = 4
RENEW = 5
REBIND = 6
REPLY = 7
RELEASE = 8
DECLINE = 9
RECONFIGURE = 10
INFORMATIONREQUEST = 11
RELAYFORW = 12
RELAYREPL = 13

# Status Codes: RFC 3315 Section 24.4

DHCP6_Success = 0
DHCP6_UnspecFail = 1
DHCP6_NoAddrsAvail = 2
DHCP6_NoBinding = 3
DHCP6_NotOnLink = 4
DHCP6_UseMulticast = 5

# Message type dictionaries used for classifying packets and for prints

client_server_msgs = {
    SOLICIT: "SOLICIT",
    ADVERTISE: "ADVERTISE",
    REQUEST: "REQUEST",
    CONFIRM: "CONFIRM",
    RENEW: "RENEW",
    REBIND: "REBIND",
    REPLY: "REPLY",
    RELEASE: "RELEASE",
    DECLINE: "DECLINE",
    RECONFIGURE: "RECONFIGURE",
    INFORMATIONREQUEST: "INFORMATIONREQUEST",
}

relay_server_msgs = {RELAYFORW: "RELAYFORW", RELAYREPL: "RELAYREPL"}


class Message(dpkt.Packet):
    __hdr__ = ()
    opts = ()
    __hdr_len__: int

    def __len__(self) -> int:
        return (
            self.__hdr_len__
            + sum(
                [
                    2 + len(o[1])
                    for o in cast(
                        Iterable[Tuple[Tuple[int, bytes], ...]], self.opts
                    )
                ]
            )
            + 1
            + len(self.data)
        )

    class ClientServerDHCP6(dpkt.Packet):
        mtype: int
        xid: bytes

        """

        0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |    msg-type   |               transaction-id                  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        .                            options                            .
        .                           (variable)                          .
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """

        __hdr__ = (("mtype", "B", SOLICIT), ("xid", "3s", b"\x00" * 3))

        opts: Tuple[
            Tuple[int, bytes], ...
        ] = ()  # tuple of (type, data) tuples

        def __bytes__(self) -> bytes:
            return self.pack_hdr() + self.pack_opts() + bytes(self.data)

        def pack_opts(self) -> bytes:
            """Return packed options string."""
            if not self.opts:
                return b""
            l = []
            for t, data in self.opts:
                l.append(struct.pack(">HH%is" % len(data), t, len(data), data))
            l.append(b"\xff")
            return b"".join(l)

        def unpack(self, buf: bytes) -> None:
            dpkt.Packet.unpack(self, buf)
            if TYPE_CHECKING:
                assert isinstance(self.data, bytes)
            buf = self.data

            l = []
            while buf:
                t = int.from_bytes(buf[0:2], byteorder="big")
                if t == 0xFF:
                    buf = buf[2:]
                    break
                elif t == 0:
                    buf = buf[2:]
                else:
                    n = int.from_bytes(buf[2:4], byteorder="big")
                    l.append((t, buf[4 : 4 + n]))
                    buf = buf[4 + n :]
            self.opts = tuple(l)
            self.data = buf

    class RelayServerDHCP6(dpkt.Packet):
        mtype: int
        hops: int
        la: str
        pa: str

        """

          0                   1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          |    msg-type   |   hop-count   |                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
          |                                                               |
          |                         link-address                          |
          |                                                               |
          |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
          |                               |                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
          |                                                               |
          |                         peer-address                          |
          |                                                               |
          |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
          |                               |                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
          .                                                               .
          .            options (variable number and length)   ....        .
          |                                                               |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        __hdr__ = (
            ("mtype", "B", RELAYFORW),
            ("hops", "B", 1),
            ("la", "16s", ""),
            ("pa", "16s", ""),
        )

        opts: Tuple[
            Tuple[int, bytes], ...
        ] = ()  # tuple of (type, data) tuples

        def __bytes__(self) -> bytes:
            return self.pack_hdr() + self.pack_opts() + bytes(self.data)

        def pack_opts(self) -> bytes:
            """Return packed options string."""
            if not self.opts:
                return b""
            l = []
            for t, data in self.opts:
                l.append(struct.pack(">HH%is" % len(data), t, len(data), data))
            l.append(b"\xff")
            return b"".join(l)

        def unpack(self, buf: bytes) -> None:
            dpkt.Packet.unpack(self, buf)
            if TYPE_CHECKING:
                assert isinstance(self.data, bytes)
            buf = self.data

            l = []
            while buf:
                t = int.from_bytes(buf[0:2], byteorder="big")
                if t == 0xFF:
                    buf = buf[2:]
                    break
                elif t == 0:
                    buf = buf[2:]
                else:
                    n = int.from_bytes(buf[2:4], byteorder="big")
                    l.append((t, buf[4 : 4 + n]))
                    buf = buf[4 + n :]
            self.opts = tuple(l)
            # self.data = buf

    # data: Union[bytes, ClientServerDHCP6, RelayServerDHCP6]
    def unpack(self, buf: bytes) -> None:
        dpkt.Packet.unpack(self, buf)
        if TYPE_CHECKING:
            assert isinstance(self.data, bytes)
        try:
            if buf[0] in client_server_msgs:
                self.data = self.ClientServerDHCP6(buf)
            elif buf[0] in relay_server_msgs:
                self.data = self.RelayServerDHCP6(buf)
            else:
                self.data = buf
            # setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            pass


def dhcp6_type_to_str(mtype: int) -> str:
    return client_server_msgs.get(
        mtype, relay_server_msgs.get(mtype, str(mtype))
    )


def fetch_dhcp6_opt(
    dhcp6_msg: Union[Message.ClientServerDHCP6, Message.RelayServerDHCP6],
    opt: int,
) -> Optional[bytes]:
    for t, data in dhcp6_msg.opts:
        if t == opt:
            return data
    mtype = dhcp6_msg.mtype
    logger.debug(
        "Optcode %d not set in %s message", opt, dhcp6_type_to_str(mtype)
    )
    return None


def fetch_all_dhcp6_opt(
    dhcp6_msg: Union[Message.ClientServerDHCP6, Message.RelayServerDHCP6],
    opt: int,
) -> Any:
    vals = []
    for t, data in dhcp6_msg.opts:
        if t == opt:
            vals.extend([data])
    if vals is []:
        mtype = dhcp6_msg.mtype
        logger.debug(
            "Optcode %d not set in %s message", opt, dhcp6_type_to_str(mtype)
        )
    return vals
