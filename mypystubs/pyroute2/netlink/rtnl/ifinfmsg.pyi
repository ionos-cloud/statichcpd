from typing import Dict

class _attr(object):
    def __init__(self) -> None:
        self.value: str

class ifinfmsg(Dict[str, str]):
    def get_attr(self, attr: str) -> str: ...
