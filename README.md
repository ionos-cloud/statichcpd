# Statichcpd - DHCP server for virtual hosting

Statichcpd is an implementation of DHCP and DHCP6 protocols targeted at
virtual hosting enviroments. It supports clients in multiple virtual
Layer 2 networks, and assumes that these networks are represented
by different interfaces, and only supports _static_ allocations
of IP addresses (and options) per MAC address of the client inside
a network. I.e. there is no support of address pools, and "unknown"
clients won't be offered an address. On the other side, clients in
different virtual networks may have the same MAC address, and will be
treated as different clients.

The daemon (statichcpd) listens on netlink socket for state change events
of interfaces that qualify as "served interfaces" (defined by matching
a configured regular expression). If the interface is "operational"
(in "UP" state), the daemon opens a packet socket on the interface and
waits for DHCP(6) packets. A DHCP response packet is constructed using
the database which needs to be populated by a third-party controller.
Updates to the database can be done dynamically, without the need
to restart the daemon.

Database schema defines two daemon-populated "validation" tables
named "valid_attributes" and "valid_v6attributes", and three
controller-populated tables: "clients", "client_attributes" and
"client_v6attributes". Attribute key is either RFC-defined
DHCP option, or one of the "special" keys for the IP addresses and
a few other "non-option" attributes. To configure client-specific
non-default values for server-identifier and DHCPv6 lease timeout
values (T1, T2, preferred lifetime and valid lifetime), additional
attribute keys are defined.

The table "clients" is used as the place with foreign keys for the
entries in the "client_*attributes" tables; because of sqlite
specifics, the controller program is advised to enable foreign keys
the first thing, when sqlite3 backend database is used (and it is the
only one supported as of this writing). Foreign keys are defined with
"on delete cascade" attribute to simplify cleanup of all data related
to one client. Insertion and deletion of client attributes may be
executed through regular sql insert/delete commands with <ifname, mac>
fields as client identifier and <attr_code, attr_val> as the attribute's
opcode and value, respectively. For example, insertion of classless static
route for a client may be executed as follows:
insert into client_configuration (ifname, mac, attr_code, attr_val) values
("dummy0", "de:ad:be:ef:aa:bb", 121, "30.1.0.0/16,30.1.0.1")

The application gives the controller ability to add more "valid" DHCP
attributes in addition to the default attributes listed in
(/usr/share/statichcpd/default_attr.csv and /usr/share/statichcpd/default_v6attr.csv).
User specific configuration can be put in /etc/statichcpd/statichcpd.conf file.

## Edge case behaviours

There are two known cases that may complicate things with DHCP
configuration in a hosting environment with statichcpd.

### Hosts with /32 addresses on NICs in different networks.

This may come up when guests are given public IP addresses. They
are often allocated as a single /32 address, and accompanied by
default route. It is possible to allocate different IP addresses to
the NICs of a guest that belong to different virtual networks, and
such use case is fully supported for initial allocation via broadcast.
However, for renewal of their lease, the client will typically send
DHCPREQEST via unicast, and if it is for a /32 address, it will
leave the client via the interface that has the default route,
which may be a different interface from the one that is requesting
the renewal.

So, from statichcpd server’s point of view, the server receives a
renewal request from client with a "correct" mac, but on the interface
of an "incorrect" virtual network. Database lookup for such combination
of <mac, network> fails since the server has an entry for this mac
in a different network (or even yield wrong result if the same mac is
configured on that network as a separate client). So, the server fails
to find a configuration for this client and hence, doesn’t respond.

On the other hand, if two such NICs were in the same network, the server
will be able to give expected response, since it receives packets from
both clients on the same interface irrespective of which of the client's
interfaces the default route is pinned to. Thus, this is the recommended
configuration.

### Changing DHCP configuration of a "live" client

It is possible to change a client's configured set of attributes, including its
IP address, and, importantly, the DHCP server's IP address, while the client
is active and using it's previously allocated IP address. However, if the
change of the advertised server's IP address is accompanied by removal of
this IP address from the host, this may cause trouble with unicast
renewal requests sent by the client.

Namely, the client will try to send unicast renewal DHCPREQUEST to the
previously advertised server IP address. If the client has the ARP entry
for this address, it will reach statichcpd server (because it is listening
on a packet socket, and receives dhcp packets regardless of their
destination IP address) and send DHCPNAK, resulting in prompt re-acqusition
of the (new) IP address by the client. But if the client does not have
the ARP entry, it will send ARP request for the _old_ server IP address
that has been removed from the host. In such case, the client will make
several retries before falling back to broadast workflow. This typically
takes much longer time, delaying the change of IP address in the client.

One way to mitigate the problem is to let the old dhcp server addresses
stay configured on the host for a time longer than DHCP lease renewal
period.
