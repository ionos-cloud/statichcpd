import dpkt
from typing import Tuple, Any

DHCPDISCOVER: int
DHCPREQUEST: int
DHCPOFFER: int
DHCPINFORM: int
DHCPNAK: int
DHCPACK: int
DHCPDECLINE: int
DHCPRELEASE: int
DHCP_OPT_PARAM_REQ: int
DHCP_OPT_SERVER_ID: int
DHCP_OPT_LEASE_SEC: int
DHCP_OPT_MSGTYPE: int
DHCP_OPT_REQ_IP: int
DHCP_OP_REPLY: int

class DHCP(dpkt.Packet):
    def __init__(self, *args: bytes, **kwargs: Any) -> None:
        self.ciaddr: int
        self.yiaddr: int
        self.giaddr: int
        self.siaddr: int
        self.chaddr: str
        self.xid: int
        self.flags: int
        self.opts: Tuple[Tuple[int, bytes], ...]
