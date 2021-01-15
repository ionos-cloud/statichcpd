import dpkt
from typing import Any

class Ethernet(dpkt.Packet):
    def __init__(self, *args: bytes, **kwargs: Any) -> None:
        self.src: bytes
        self.dst: bytes
        self.type: int
        self.data: bytes
