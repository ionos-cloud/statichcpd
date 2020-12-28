import unittest
from time import sleep
import tracemalloc
from ipaddress import IPv4Address, AddressValueError

from test.common import fill_db, Config, server_process, packet_sender

tracemalloc.start()

class TestStatichcpdMethods(unittest.TestCase):
    @skipUnless(geteuid() == 0, "Unable to run test without root access")
    def test_dhcp_conf(self):
        with Config() as cfg:
            fill_db(cfg)
            print("\nPopulated DHCP database with client configs...")
            with server_process(cfg) as srv:
                sleep(1) # Don't rush! Let the server get ready!

                for (client, server) in zip(cfg.clients, cfg.servers):
                    with packet_sender('-v ' + client.name) as sender:
                        sleep(1) # Give some time for the address to get configured
                        client_idx = cfg.ip.link_lookup(ifname=client.name)[0]
                        client_ip = cfg.ip.get_addr(index=client_idx)[0].get_attr('IFA_ADDRESS')
                        try:
                            client_ip = IPv4Address(client_ip)
                            print("Client ", client.name, " succesfully configured with IP address", client_ip)
                        except AddressValueError:
                            self.fail("Client " + client.name + " failed to get succesful IP binding")

                    with packet_sender('-v ' + client.name + ' -s ' + server.addr) as sender:
                        sleep(1)
                        client_ip = cfg.ip.get_addr(index=client_idx)[0].get_attr('IFA_ADDRESS')
                        try:
                            client_ip = IPv4Address(client_ip)
                            print("Client ", client.name, " succesfully renewed IP address ", client_ip)
                        except AddressValueError:
                            self.fail("Client " + client.name + " failed to renew IP address " + client_ip)

if __name__ == '__main__':
        unittest.main()
