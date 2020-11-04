#!/usr/bin/env python3

from abc import ABC
from ipaddress import IPv4Network, IPv4Address
from .logmgr import logger

class _IntXX(ABC):
    def __repr__(self):
        return type(self).__name__ + "(" + str(self.value) + ")"

class Int16(_IntXX):
    def __init__(self, val):
        if val.bit_length() > 16:
            raise ValueError('Value {} cannot be represented as Int16'.format(val))
        self.value = val

class Int32(_IntXX):
    def __init__(self, val):
        if val.bit_length() > 32:
            raise ValueError('Value {} cannot be represented as Int32'.format(val))
        self.value = val

class Staticrt():
    def __init__(self, val):
        cidr, gw = val.split(',')
        try:
            self.value = (IPv4Network(cidr), IPv4Address(gw))
        except ValueError as err:
            logger.error("{}: Invalid route entry {}".format(err, val))
    
    def __bytes__(self):        # Returns a byte string in accordance with RFC 3442 DHCP Option 121
        network, gateway = self.value
        significant_netoctets = (network.prefixlen - 1) // 8 + 1
        subnet_width =  bytes([network.prefixlen])
        destination_descriptor = subnet_width + ((network.network_address).packed)[:significant_netoctets]
        return destination_descriptor + gateway.packed

