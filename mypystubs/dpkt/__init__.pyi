from typing import Any
from . import ethernet
from . import ip
from . import ip6
from . import dhcp
from . import udp

class Packet():
    def __init__(self, *args: bytes, **kwargs: Any) -> None:
        ...

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
