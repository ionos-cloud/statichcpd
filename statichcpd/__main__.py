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

    config_dir = '/etc/statichcpd' # Default config file directory

    argparser = ArgumentParser()
    argparser.add_argument('-v', '--verbose',
                        help="Enable verbose debug logging",
                        action="store_true")
    argparser.add_argument('-f', '--foreground',
                        help="Do not daemonize and log to stdout",
                        action="store_true")

    argparser.add_argument('-c', '--config_dir',
                        type=Path,
                        help="Specify the config file directory")

    namespace = argparser.parse_args()
    set_log_config(namespace)
    if namespace.config_dir is not None:
        config_dir = namespace.config_dir
    config = configparser.ConfigParser()
    statichcpd_config: Dict[str, Any] = dict()
    if not os.path.isdir(config_dir) or not os.listdir(config_dir):
        raise NotADirectoryError(config_dir)
    for conf_file in sorted([el for el in os.listdir(config_dir) if el.endswith('.conf')]):
        config.read(config_dir + '/' + conf_file)
        statichcpd_config.update(config['statichcpd'])

    database_manager.init(statichcpd_config)
    dhcpserver.init(statichcpd_config)
    dhcp_packet_mgr.init(statichcpd_config)
    dhcp6_packet_mgr.init(statichcpd_config)
    start_server()
