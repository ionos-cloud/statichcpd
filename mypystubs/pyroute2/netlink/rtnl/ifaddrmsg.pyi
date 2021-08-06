from typing import Dict, Optional

class _attr(object):
    def __init__(self) -> None:
        self.value: str

class ifaddrmsg(Dict[str, str]):
    def get_attr(self, attr: str) -> str:
        ...
