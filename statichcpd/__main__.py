#!/usr/bin/env python3

from argparse import ArgumentParser

from .dhcpserver import start_server 
from .logmgr import set_log_config
import configparser
from . import database_manager
from . import dhcpserver
from . import dhcp_packet_mgr
from pathlib import Path

if __name__ == "__main__":

    argparser = ArgumentParser()
    argparser.add_argument('-v', '--verbose',
                        help="Enable verbose debug logging",
                        action="store_true")
    argparser.add_argument('-f', '--foreground',
                        help="Do not daemonize and log to stdout",
                        action="store_true")

    argparser.add_argument('-c', '--config_file',
                        type=Path,
                        help="Specify the config file location")

    namespace = argparser.parse_args()
    set_log_config(namespace)

    config = configparser.ConfigParser()
    config.read(namespace.config_file)
    statichcpd_config = config['statichcpd'] 
    database_manager.init(statichcpd_config)
    dhcpserver.init(statichcpd_config)
    dhcp_packet_mgr.init(statichcpd_config)
    start_server()
