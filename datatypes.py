#!/usr/bin/env python3

from abc import ABC

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
        self.value = tuple(IPv4Address(value[0]), IPv4Address(value[1]))


