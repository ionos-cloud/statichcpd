import dpkt

class UDP(dpkt.Packet):
    def __init__(self, sport: int, dport: int, data: bytes) -> None:
        self.sport: int
        self.dport: int
        self.data: bytes
        self.ulen: int
