from typing import Dict, Optional

class _attr(object):
    def __init__(self) -> None:
        self.value: str

class ifaddrmsg(Dict[str, str]):
    def __init__(self) -> None:
        self.IFA_LABEL: _attr
        self.IFA_ADDRESS: _attr
        self.IFLA_IFNAME: _attr
        self.IFLA_ADDRESS: _attr
        self.IFLA_OPERSTATE: _attr

    def get_attr(self, attr: str) -> Optional[str]:
        ...
