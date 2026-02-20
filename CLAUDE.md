# statichcpd — Static DHCP Server

## Overview

statichcpd is a specialized DHCP/DHCPv6 server for virtual hosting environments. Unlike standard DHCP servers, it:

- Supports **static-only IP allocations** per MAC address per interface
- Allows the **same MAC to have different configurations** on different virtual networks
- Designed for hypervisor environments where clients are VMs with known MAC addresses

**Language:** Python 3
**Build:** setuptools (`setup.py`) + Debian packaging
**Config:** `/etc/statichcpd/statichcpd.conf`
**Database:** SQLite (path configured by pbsdnmgr via `DHCP_STATICHCP_DB`)

## Architecture

Event-driven architecture using `select` polling:

```
Netlink monitor detects interface state changes
  → Opens/closes raw packet sockets per interface
  → Listens for DHCP DISCOVER/REQUEST packets
  → Looks up MAC+interface in SQLite database
  → Constructs DHCP OFFER/ACK with configured attributes
  → Sends response via raw socket
```

### Components

| Module | Purpose |
|--------|---------|
| `dhcpserver.py` | Main server orchestration, netlink monitoring, socket management |
| `dhcp_packet_mgr.py` | DHCPv4 packet construction/parsing |
| `dhcp6_packet_mgr.py` | DHCPv6 packet construction/parsing |
| `database_manager.py` | SQLite schema definition and query execution |
| `datatypes.py` | Custom types (Int16, Int32, Staticrt, Domain) |
| `dhcp6.py` | DHCPv6 protocol message structures |
| `logmgr.py` | Logging configuration |
| `utils.py` | Helper utilities |

## Database Schema

### Daemon-populated tables
- `valid_attributes` — Supported DHCPv4 options
- `valid_v6attributes` — Supported DHCPv6 options

### Controller-populated tables (written by pbsdnmgr)
- `clients` — Client identifiers: `(ifname, MAC)` for v4; `(ifname, DUID)` for v6
- `client_configuration` — Per-client DHCPv4 attributes (option code → value)
- `client_v6configuration` — Per-client DHCPv6 attributes

### Special Option Codes (pseudo-options)

| Code | Meaning |
|------|---------|
| 256 | IPv4 address (non-standard) |
| 257 | IPv6 address (non-standard) |
| 258 | Server identifier (custom server IP) |
| 259 | DHCPv6 T1 (renewal time) |
| 260 | DHCPv6 T2 (rebinding time) |
| 261 | DHCPv6 preferred lifetime |
| 262 | DHCPv6 valid lifetime |
| 119 | Search domain list (RFC 3397) |
| 121 | Classless static routes (RFC 3442) |

## Integration with pbsdnmgr

pbsdnmgr integrates via `convergence/dhcp.py`:
1. Writes client records (MAC, interface, IP) to the SQLite database
2. Writes DHCP option attributes (gateway, DNS, routes, etc.)
3. statichcpd picks up changes without restart
4. Database path: `config.var.DHCP_STATICHCP_DB` (default: `/var/lib/statichcpd/Static_DHCP_DB.db`)

## Known Edge Cases

1. **/32 addresses across networks:** Renewal requests sent unicast may arrive on wrong interface. Workaround: use same network for multi-NIC configs.
2. **Same subnet across multiple NICs:** ARP flux can cause unicast replies to wrong interface. Clients fall back to DORA after failures.
3. **Live config changes:** Changing server IP while client is active may delay lease renewal.

## Server Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Interface pattern | `.*` (all) | Regex for served interfaces |
| Rate limit | 1000 packets/sec | DHCP packet rate limiting |
| Suspension period | 1 sec | Interface suspension after rate limit hit |

## Dependencies

**Python:** dpkt, pyroute2
