from typing import Any

class Packet():
    self.data: bytes
    self.__hdr_len__: int
    def __init__(self, *args: bytes, **kwargs: Any):
        ...
