#!/usr/bin/env python3

from abc import ABC
from ipaddress import IPv4Network, IPv4Address
from typing import Union, Optional
from dataclasses import dataclass
import binascii
from dpkt.compat import compat_ord
from .logmgr import logger


class _IntXX(ABC):
    value: int  # Verify!

    def __repr__(self) -> str:
        return type(self).__name__ + "(" + str(self.value) + ")"


class Int16(_IntXX):
    def __init__(self, val: int):
        if val.bit_length() > 16:
            raise ValueError(f"Value {val} cannot be represented as Int16")
        self.value = val


class Int32(_IntXX):
    def __init__(self, val: int) -> None:
        if val.bit_length() > 32:
            raise ValueError(f"Value {val} cannot be represented as Int32")
        self.value = val


class Staticrt:
    def __init__(self, val: str) -> None:
        cidr, gw = val.split(",")
        try:
            self.value = (IPv4Network(cidr), IPv4Address(gw))
        except ValueError as err:
            logger.error("%s: Invalid route entry %s", err, val)

    def __bytes__(
        self,
    ) -> (
        bytes
    ):  # Returns a byte string in accordance with RFC 3442 DHCP Option 121
        network, gateway = self.value
        significant_netoctets = (network.prefixlen - 1) // 8 + 1
        subnet_width = bytes([network.prefixlen])
        destination_descriptor = (
            subnet_width
            + ((network.network_address).packed)[:significant_netoctets]
        )
        return destination_descriptor + gateway.packed


class Domain:
    def __init__(self, val: str) -> None:
        self.labels = val.split(".")

    def __repr__(self) -> str:
        return type(self).__name__ + "(" + str(self.labels) + ")"

    def __bytes__(
        self,
    ) -> (
        bytes
    ):  # Returns a byte string in accordance with RFC 3397 DHCP Option 119
        encoded_domain = b""
        null_terminator = 0
        for label in self.labels:
            encoded_domain += len(label).to_bytes(1, "big") + label.encode(
                "utf-8"
            )
        if len(encoded_domain) > 0:
            encoded_domain += null_terminator.to_bytes(1, "big")
        return encoded_domain


class Mac:
    def __init__(self, mac: Union[str, bytes]) -> None:
        if isinstance(mac, bytes):
            self.val = mac
        elif isinstance(mac, str):
            self.val = binascii.unhexlify((mac).replace(":", ""))
        elif isinstance(mac, Mac):
            self.val = mac.val
        else:
            raise ValueError(
                (
                    f"Value {mac} of type {type(mac)} "
                    "cannot be represented as Mac address"
                )
            )

    def __str__(self) -> str:
        return ":".join(f"{compat_ord(b):02x}" for b in self.val)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str(self)})"

    def __bytes__(self) -> bytes:
        return self.val


@dataclass
class DHCPResponse:
    data: bytes
    daddr: Optional[IPv4Address]
    server_id: IPv4Address
    server_iface: str


@dataclass
class DHCPError:
    error: str
    ifname: str
    client: Optional[Union[Mac, str]]


@dataclass
class DHCP6Response:
    data: bytes
    server_iface: Optional[str]
