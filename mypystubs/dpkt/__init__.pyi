from typing import Any, Union
from . import ethernet
from . import ip
from . import ip6
from . import dhcp
from . import udp

class Packet():
    def __init__(self, *args: bytes, **kwargs: Any) -> None:
        self.data: Packet
        self.__hdr_len__: int
        self.src: bytes # Ideally not part of Packet. Only to access ip.data where ip=eth.data

    def __len__(self) -> int:
        ...

    def pack_hdr(self) -> bytes:
        ...

    def __bytes__(self) -> bytes:
        ...

    def unpack(self, buf: bytes) -> None:
        ...

class Error(Exception):
    ...

class UnpackError(Error):
    ...

class NeedData(UnpackError):
    ...
