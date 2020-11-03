#!/usr/bin/env python3

from argparse import ArgumentParser

from .dhcpserver import start_server 
from .logmgr import set_log_config

if __name__ == "__main__":
    
    argparser = ArgumentParser()
    argparser.add_argument('-v', '--verbose',
                        help="Enable verbose debug logging",
                        action="store_true")
    argparser.add_argument('-f', '--foreground',
                        help="Do not daemonize and log to stdout",
                        action="store_true")

    logconf = argparser.parse_args()
    set_log_config(logconf)
    start_server()
