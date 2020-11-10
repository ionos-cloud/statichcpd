Static Host Configuration Protocol Daemon (statichcpd) listens on netlink socket for state change events of interfaces that qualify as "served interfaces". If the interface is in desired state (UP state with valid IP address), the process polls for any DHCP packet on that interface. A DHCP response packet is constructed using the database populated by the client dynamically. 

The application gives the client, the freedom to add more DHCP attributes in addition to the default attributes listed in (default_attr.csv). Any user specific configs may be added to statchcpd.conf file.
