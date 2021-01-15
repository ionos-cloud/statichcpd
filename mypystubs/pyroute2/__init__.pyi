from typing import Dict, List, Optional, Union, Any
import socket
from pyroute2.netlink.rtnl.ifinfmsg import ifinfmsg
from pyroute2.netlink.rtnl.ifaddrmsg import ifaddrmsg

class _attr(object):
    def __init__(self) -> None:
        self.value: str

class IPRoute(object):
    def fileno(self) -> int:
        ...

    def bind(self, *argv: Any, **kwarg: Any) -> None:
        ...

    def get_links(self, *argv: Union[str, int], **kwarg: Any) -> List[ifinfmsg]:
        ...

    def link_lookup(self, **kwarg: Union[int, str]) -> List[int]:
        ...

    def get_addr(self, family:int = socket.AF_UNSPEC, match:Any = None, **kwarg: Union[int, str]) -> List[ifaddrmsg]:
        ...

    def get(self) -> List[Union[ifinfmsg, ifinfmsg]]: # Ideally, it can be any nlmsg
        ...
