#!/usr/bin/env python3

from logging import Logger, getLogger, StreamHandler, Formatter, DEBUG, INFO
from logging.handlers import SysLogHandler
from argparse import Namespace
from typing import Type, Optional, Any
from types import TracebackType
import sys

logger = getLogger("statichcpd")
sfmt = "%(name)s[%(process)d]: %(levelname)s - %(message)s"
cfmt = "%(asctime)s - %(levelname)s - %(message)s"


def set_log_config(logconf: Namespace) -> None:
    global logger
    logger.setLevel(DEBUG if logconf.verbose else INFO)
    if logconf.foreground:
        chdl = StreamHandler()
        chdl.setFormatter(Formatter(cfmt))
        logger.addHandler(chdl)

    shdl = SysLogHandler(address="/dev/log")
    shdl.setFormatter(Formatter(sfmt))
    logger.addHandler(shdl)

    def handle_exception(
        type_: Type[BaseException],
        value: BaseException,
        traceback: Optional[TracebackType],
    ) -> Any:
        logger.error("Uncaught exception", exc_info=(type_, value, traceback))
        sys.exit(-1)

    sys.excepthook = handle_exception
