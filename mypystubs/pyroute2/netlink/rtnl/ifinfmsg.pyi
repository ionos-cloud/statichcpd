from typing import Dict

class _attr(object):
    def __init__(self) -> None:
        self.value: str

class ifinfmsg(Dict[str, str]):
    def __init__(self) -> None:
        self.IFLA_OPERSTATE: _attr
        self.IFLA_ADDRESS: _attr
        self.IFA_LABEL: _attr
        self.IFA_ADDRESS: _attr
        self.IFLA_IFNAME: _attr

