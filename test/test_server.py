import unittest
from time import sleep
import tracemalloc
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from unittest import skipUnless
from os import geteuid
from socket import AF_INET6

from test.common import fill_db, Config, server_process, dhcp_sender

tracemalloc.start()

class TestStatichcpdMethods(unittest.TestCase):
    @skipUnless(geteuid() == 0, "Unable to run test without root access")
    def test_dhcp(self):
        with Config() as cfg:
            fill_db(cfg)
            print("\nPopulated DHCP database with client configs...")
            with server_process(cfg) as srv:
                sleep(1) # Don't rush! Let the server get ready!

                for (client, server) in zip(cfg.clients, cfg.servers):

                    # DHCPv4 Selecting-Init state
                    with dhcp_sender('-v ' + client.name) as sender:
                        sleep(2) # Give some time for the address to get configured
                        client_idx = cfg.ip.link_lookup(ifname=client.name)[0]
                        client_ip = cfg.ip.get_addr(index=client_idx)[0].get_attr('IFA_ADDRESS')
                        try:
                            client_ip = IPv4Address(client_ip)
                            print("Client ", client.name, " succesfully configured with IP address", client_ip)
                        except AddressValueError:
                            self.fail("Client " + client.name + " failed to get succesful IP binding")

                    # DHCPv4 Renew state
                    with dhcp_sender('-v ' + client.name + ' -s ' + server.addr4) as sender:
                        sleep(1)
                        client_ip = cfg.ip.get_addr(index=client_idx)[0].get_attr('IFA_ADDRESS')
                        try:
                            client_ip = IPv4Address(client_ip)
                            print("Client ", client.name, " succesfully renewed IP address ", client_ip)
                        except AddressValueError:
                            self.fail("Client " + client.name + " failed to renew IP address " + client_ip)

                    # DHCPv6 IPv6 address request
                    with dhcp_sender('-v -6 ' + client.name) as sender:
                        sleep(2) # The solicit-advertisement-request-reply will take some time
                        client_ip = None
                        for addr in cfg.ip.get_addr(index=client_idx, family=AF_INET6):
                            if addr['scope'] == 0:
                                client_ip = cfg.ip.get_addr(index=client_idx, family=AF_INET6)[0].get_attr('IFA_ADDRESS')
                                break
                        try:
                            client_ip = IPv6Address(client_ip)
                            print("Client ", client.name, " succesfully configured with IPv6 address ", client_ip)
                        except AddressValueError:
                            self.fail("Client " + client.name + " failed to fetch IPv6 address ")

                    # DHCPv6 IPv6 Prefix request
                    with dhcp_sender('-v -6 -P ' + client.name) as sender:
                        sleep(2) # The solicit-advertisement-request-reply will take some time
                        client_ip = None
                        for addr in cfg.ip.get_addr(index=client_idx, family=AF_INET6):
                            if addr['scope'] == 0:
                                client_ip = cfg.ip.get_addr(index=client_idx, family=AF_INET6)[0].get_attr('IFA_ADDRESS')
                                break
                        try:
                            client_ip = IPv6Address(client_ip)
                            print("Client ", client.name, " succesfully configured with IPv6 address ", client_ip)
                        except AddressValueError:
                            self.fail("Client " + client.name + " failed to fetch IPv6 address ")



if __name__ == '__main__':
        unittest.main()
