#!/usr/bin/env python3

from abc import ABC
from ipaddress import IPv4Network, IPv4Address
from .logmgr import logger
from typing import Union
from dpkt.compat import compat_ord
import binascii


class _IntXX(ABC):
    value: int  # Verify!

    def __repr__(self) -> str:
        return type(self).__name__ + "(" + str(self.value) + ")"


class Int16(_IntXX):
    def __init__(self, val: int):
        if val.bit_length() > 16:
            raise ValueError(
                "Value {} cannot be represented as Int16".format(val)
            )
        self.value = val


class Int32(_IntXX):
    def __init__(self, val: int) -> None:
        if val.bit_length() > 32:
            raise ValueError(
                "Value {} cannot be represented as Int32".format(val)
            )
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
                """Value {} of type {} cannot be represented
                               as Mac address""".format(
                    mac, type(mac)
                )
            )

    def __str__(self) -> str:
        return ":".join("%02x" % compat_ord(b) for b in self.val)

    def __repr__(self) -> str:
        return type(self).__name__ + "(" + str(self) + ")"

    def __bytes__(self) -> bytes:
        return self.val
