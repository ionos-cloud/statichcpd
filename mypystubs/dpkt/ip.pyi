import dpkt

IP_PROTO_UDP: int

class IP(dpkt.Packet):
    len: int
    def __len__(self) -> int:
        ...

