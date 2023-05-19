#!/usr/bin/env python3

from argparse import ArgumentParser
import configparser
import os
from pathlib import Path
from typing import Dict, Any

from .dhcpserver import start_server
from .logmgr import set_log_config
from . import database_manager
from . import dhcpserver
from . import dhcp_packet_mgr
from . import dhcp6_packet_mgr

if __name__ == "__main__":
    config_file = "/etc/statichcpd/statichcpd.conf"  # Default config file path
    addn_config_dir = None

    argparser = ArgumentParser()
    argparser.add_argument(
        "-v",
        "--verbose",
        help="Enable verbose debug logging",
        action="store_true",
    )
    argparser.add_argument(
        "-f",
        "--foreground",
        help="Do not daemonize and log to stdout",
        action="store_true",
    )

    argparser.add_argument(
        "-c",
        "--config_file",
        type=Path,
        help="Specify the default config file",
    )

    argparser.add_argument(
        "-a",
        "--config_dir",
        type=Path,
        help="Specify the directory for additionaly config file lookup",
    )

    namespace = argparser.parse_args()
    set_log_config(namespace)

    if namespace.config_file is not None:
        config_file = namespace.config_file
    if namespace.config_dir is not None:
        addn_config_dir = namespace.config_dir

    config = configparser.ConfigParser()

    # Load default configuration
    statichcpd_config: Dict[str, Any] = dict()
    config.read(config_file)
    statichcpd_config.update(config["statichcpd"])

    # Load any additional configuration
    if (
        addn_config_dir
        and os.path.isdir(addn_config_dir)
        and os.listdir(addn_config_dir)
    ):
        for conf_file in sorted(
            [el for el in os.listdir(addn_config_dir) if el.endswith(".conf")]
        ):
            config.read(os.path.join(addn_config_dir, conf_file))
            statichcpd_config.update(config["statichcpd"])

    database_manager.init(statichcpd_config)
    dhcpserver.init(statichcpd_config)
    dhcp_packet_mgr.init(statichcpd_config)
    dhcp6_packet_mgr.init(statichcpd_config)
    start_server()
