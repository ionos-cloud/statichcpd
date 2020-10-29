#!/usr/bin/env python3

class Int16():
    def __init__(self, val):
        if val.bit_length() > 16:
            raise ValueError('Value cannot be represented as Int16')
        self.value = val

class Int32():
    def __init__(self, val):
        if val.bit_length() > 32:
            raise ValueError('Value cannot be represented as Int32')
        self.value = val

class Staticrt():
    def __init__(self, val):
        self.value = tuple(IPv4Address(value[0]), IPv4Address(value[1]))


