#!/usr/bin/env python3

import sqlite3
from typing import Tuple, Any, Dict, Optional, Union
from time import sleep
from enum import Enum
import csv
from ipaddress import IPv4Address, IPv6Address, IPv6Network
from dpkt import dhcp

from .datatypes import Int16, Int32, Mac, Staticrt, Domain
from .logmgr import logger

# Import all dhcp6 opcodes, which is used in populating valid attributes table
from .dhcp6 import *  # pylint: disable=wildcard-import,unused-wildcard-import


__all__ = [
    "schema",
    "DHCP_IP_OPCODE",
    "DHCP_NON_DEFAULT_SERVERID_OPCODE",
    "DHCP6_NON_DEFAULT_T1",
    "DHCP6_NON_DEFAULT_T2",
    "DHCP6_NON_DEFAULT_PREF_LIFETIME",
    "DHCP6_NON_DEFAULT_VALID_LIFETIME",
    "dtype",
    "DHCPv4DB",
    "DHCPv6DB",
    "db_exit",
    "fetch_host_conf_data",
]


class DatabaseManager:
    def __init__(self, name: str = ""):
        self.name = name
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        if logger:
            logger.debug("Connecting to %s", self.name)
        assert self.name
        self.conn = sqlite3.connect(self.name)

    def close(self) -> None:
        if self.conn:
            self.conn.close()


dhcp_db = DatabaseManager()

"""
In a scenario where the controller has not adapted to the new feature of
'port grouping' or if we have non-empty database left from previously running
version, the database will have NULL values in the groupID field. In such a
scenario, the triggers are defined such that it attempts to replace existing
entry with a valid groupID and not attempt to insert and fail with UNIQUE
constraint failure.

Also, additional triggers, 'client_insertion' and 'client_deletion', are defined
to make the new version of statichcp compatible with old controller code which
attempts to directly populate the 'clients' table before configuring the config tables.

When groupID is part of the foreign key, but allowed to be NULL at the same time, it
results in a tricky situation where, if the groupID value for an entry is NULL in all the
tables, the foreign key constraints are not really imposed nor does `delete cascade` take
effect. As a result, additional trigger `client_del_config_cleanup` is needed to
explicitly delete the configs upon delete on `clients` table, if the groupID is NULL.
"""

schema = [
    """create table if not exists valid_attributes(
           opcode int not null,
           max_count int not null,
           datatype int not null,
           constraint unique_opcode unique(opcode));""",
    """create table if not exists valid_v6attributes(
           opcode int not null,
           max_count int not null,
           datatype int not null,
           constraint unique_opcode unique(opcode));""",
    """create table if not exists client_groups (
           ifname text not null primary key,
           groupID text,
           constraint compkey_if_grp unique(ifname, groupID));""",
    """create table if not exists clients (
           ifname text not null,
           groupID text,
           mac text not null,
           foreign key (ifname, groupID) references
           client_groups(ifname, groupID) on delete cascade,
           constraint compkey_mac_grp_if unique(ifname, groupID, mac));""",
    """create table if not exists client_configuration (
           ifname text not null,
           groupID text,
           mac text not null,
           attr_code int not null,
           attr_val not null,
           constraint compkey_mac_if_attr
           unique(ifname, groupID, mac, attr_code, attr_val)
           foreign key (ifname, groupID, mac) references
           clients(ifname, groupID, mac) on delete cascade,
           foreign key (ifname, groupID) references
           client_groups(ifname, groupID) on delete cascade,
           foreign key (attr_code) references
           valid_attributes(opcode) on delete restrict);""",
    """create table if not exists client_v6configuration (
           ifname text not null,
           groupID text,
           duid text not null,
           attr_code int not null,
           attr_val not null,
           constraint compkey_clientid_if_attr
           unique(ifname, groupID, duid, attr_code, attr_val)
           foreign key (ifname, groupID, duid) references
           clients(ifname, groupID, mac) on delete cascade,
           foreign key (ifname, groupID) references
           client_groups(ifname, groupID) on delete cascade,
           foreign key (attr_code) references
           valid_v6attributes(opcode) on delete restrict);""",
    """create trigger if not exists client_insertion before insert on clients
           begin
           insert into client_groups (ifname, groupID)
           select new.ifname, new.groupID where not exists(
           select 1 from client_groups where ifname=new.ifname and
           (groupID=new.groupID or groupID is new.groupID));
           end;""",
    """create trigger if not exists client_deletion after delete on clients
           when (select count(*) from clients where ifname=old.ifname and
           (groupID=old.groupID or groupID is old.groupID)) == 0
           begin
           delete from client_groups where ifname=old.ifname and
           (groupID=old.groupID or groupID is old.groupID);
           end;""",
    """create trigger if not exists client_del_config_cleanup before delete on clients
           when exists(select 1 from clients where ifname=old.ifname and
           groupID is old.groupID and old.groupID is NULL)
           begin
           delete from client_configuration where
           ifname=old.ifname and mac=old.mac and groupID is NULL;
           delete from client_v6configuration where
           ifname=old.ifname and duid=old.mac and groupID is NULL;
           end;""",
    """create trigger if not exists client_v4_cfg_insertion before
           insert on client_configuration
           when (select count(*) from client_groups where
           ifname=new.ifname and groupID is NULL) == 0
           begin
           insert into client_groups (ifname, groupID) select
           new.ifname, new.groupID where not exists(
           select 1 from client_groups where
           ifname=new.ifname and groupID=new.groupID);
           insert into clients (ifname, groupID, mac) select
           new.ifname, new.groupID, new.mac where not exists(
           select 1 from clients where
           ifname=new.ifname and groupID=new.groupID and mac=new.mac);
           end;""",
    """create trigger if not exists client_v4_cfg_replace before
           insert on client_configuration
           when (select count(*) from client_groups where
           ifname=new.ifname and groupID is NULL) > 0 and
           new.groupID is not NULL
           begin
           replace into client_groups (ifname, groupID)
           values (new.ifname, new.groupID);
           replace into clients (ifname, groupID, mac)
           values (new.ifname, new.groupID, new.mac);
           end;""",
    """create trigger if not exists client_v6_cfg_insertion before
           insert on client_v6configuration
           when (select count(*) from client_groups where
           ifname=new.ifname and groupID is NULL) == 0
           begin
           insert into client_groups (ifname, groupID)
           select new.ifname, new.groupID where not exists(
           select 1 from client_groups where
           ifname=new.ifname and groupID=new.groupID);
           insert into clients (ifname, groupID, mac)
           select new.ifname, new.groupID, new.duid where not exists(
           select 1 from clients where
           ifname=new.ifname and groupID=new.groupID and mac=new.duid);
           end;""",
    """create trigger if not exists client_v6_cfg_replace before
           insert on client_v6configuration
           when (select count(*) from client_groups where
           ifname=new.ifname and groupID is NULL) > 0 and new.groupID is not NULL
           begin
           replace into client_groups (ifname, groupID)
           values (new.ifname, new.groupID);
           replace into clients (ifname, groupID, mac)
           values (new.ifname, new.groupID, new.duid);
           end;""",
    """create trigger if not exists client_v4_cfg_deletion after
           delete on client_configuration
           when (select count(*) from client_configuration where
           ifname=old.ifname and mac=old.mac) == 0
           and (select count(*) from client_v6configuration where
           ifname=old.ifname and duid=old.mac) == 0
           begin
           delete from clients where ifname=old.ifname and
           (groupID=old.groupID or groupID is old.groupID) and mac=old.mac;
           delete from client_groups where ifname=old.ifname and
           (groupID=old.groupID or groupID is old.groupID)
           and not exists(select 1 from clients where
           ifname=old.ifname and (groupID=old.groupID or groupID is old.groupID)
           and mac<>old.mac);
           end;""",
    """create trigger if not exists client_v6_cfg_deletion after
           delete on client_v6configuration
           when (select count(*) from client_v6configuration where
           ifname=old.ifname and duid=old.duid) == 0
           and (select count(*) from client_configuration where
           ifname=old.ifname and mac=old.duid) == 0
           begin
           delete from clients where ifname=old.ifname and
           (groupID=old.groupID or groupID is old.groupID) and mac=old.duid;
           delete from client_groups where ifname=old.ifname and
           (groupID=old.groupID or groupID is old.groupID)
           and not exists(select 1 from clients where
           ifname=old.ifname and (groupID=old.groupID or groupID is old.groupID)
           and mac<>old.duid);
           end;""",
]

# Using IP(v4/v6) opcode value outside permitted
# DHCP opcode range to avoid conflict

DHCP_IP_OPCODE = 256
DHCP_NON_DEFAULT_SERVERID_OPCODE = 258
DHCP6_NON_DEFAULT_T1 = 259
DHCP6_NON_DEFAULT_T2 = 260
DHCP6_NON_DEFAULT_PREF_LIFETIME = 261
DHCP6_NON_DEFAULT_VALID_LIFETIME = 262


class dtype(Enum):
    IPV4 = 1
    IPV6 = 2
    INT16 = 3
    INT32 = 4
    STRING = 5
    STATICRT = 6
    IA = 7
    PD = 8
    DOMAIN = 9


class DHCPv4DB:
    """
    In a scenario where the controller has not adapted to the new feature of
    'port grouping' or if we have non-empty database left from previously running
    version, the database will have NULL values in the groupID field. In such a
    case, fallback to the lookup that matches <ifname and mac>, without considering
    interface grouping.
    """

    select_command = """ select valid_attributes.opcode, valid_attributes.max_count,
                         valid_attributes.datatype, client_configuration.attr_val,
                         client_configuration.ifname
                         from client_configuration
                         join valid_attributes on
                         client_configuration.attr_code = valid_attributes.opcode
                         where mac=:client_id and
                         case when (select count(*) from client_groups where ifname=:ifname
                                    and groupID is NULL) == 0
                              then ifname in (select ifname from client_groups
                                   where groupID=(select groupID from client_groups
                                   where ifname=:ifname))
                              else ifname=:ifname
                         end;"""


class DHCPv6DB:
    select_command = """ select valid_v6attributes.opcode, valid_v6attributes.max_count,
                         valid_v6attributes.datatype, client_v6configuration.attr_val,
                         client_v6configuration.ifname
                         from client_v6configuration
                         join valid_v6attributes on
                         client_v6configuration.attr_code = valid_v6attributes.opcode
                         where duid=:client_id and
                         case when (select count(*) from client_groups where ifname=:ifname
                                    and groupID is NULL) == 0
                              then ifname in (select ifname from client_groups
                                   where groupID = (select groupID from client_groups
                                   where ifname=:ifname))
                              else ifname=:ifname
                         end;"""


alter_table_cmd = [
    """alter table clients add column groupID""",
    """alter table client_configuration add column groupID""",
    """alter table client_v6configuration add column groupID""",
]

migrate_cfgs_cmd = [
    """insert into clients (ifname, groupID, mac)
                       select distinct ifname, groupID, mac from
                       client_configuration where not exists(
                       select 1 from clients where ifname=ifname and mac=mac
                       and (groupID=groupID or groupID is groupID));""",
    """insert into client_groups (ifname, groupID)
                       select distinct ifname, groupID from
                       client_configuration where not exists(
                       select 1 from client_groups where ifname=ifname and
                       (groupID=groupID or groupID is groupID));""",
    """insert into clients (ifname, groupID, mac)
                       select distinct ifname, groupID, duid from
                       client_v6configuration where not exists(
                       select 1 from clients where ifname=ifname and mac=duid
                       and (groupID=groupID or groupID is groupID));""",
    """insert into client_groups (ifname, groupID)
                       select distinct ifname, groupID from
                       client_v6configuration where not exists(
                       select 1 from client_groups where ifname=ifname and
                       (groupID=groupID or groupID is groupID));""",
]


def populate_table_from(table_name: str, csv_filename: str) -> None:
    if dhcp_db.conn is None:
        return
    cursor = dhcp_db.conn.cursor()
    with open(csv_filename, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        columns = next(reader)
        query = (
            f"insert or replace into {table_name}("
            f"{','.join(columns)}) values ("
            f"{','.join('?' * len(columns))})"
        )

        for row in reader:
            # Opcode can be an integer or dpkt.dhcp module optcode alias
            optype = getattr(dtype, row[2].rstrip(), None)
            if optype is None:
                continue
            try:
                if hasattr(dhcp, row[0]):
                    data = (
                        str(getattr(dhcp, row[0])),
                        row[1],
                        str(optype.value),
                    )
                else:
                    data = (
                        str(globals()[row[0]]),
                        row[1],
                        str(optype.value),
                    )
            except (NameError, KeyError):
                data = (
                    str(row[0]),
                    row[1],
                    str(optype.value),
                )
            cursor.execute(query, data)


# pylint: disable=too-many-branches
def init(config: Dict[str, Any]) -> None:
    dhcp_db.name = str(config["dhcp_db_filename"])
    # Connect to the database
    dhcp_db.connect()
    if dhcp_db.conn is None:
        raise RuntimeError(f"Connecting to DHCP db {dhcp_db.name} failed")

    # Updating journal_mode is a persistent update and hence,
    # can result in 'database locked' error if a concurrent
    # writer is in middle of a transaction, unlike regular
    # sql writes that waits until connection timeout to quit.
    retry = 3
    while retry:
        try:
            dhcp_db.conn.execute("pragma journal_mode=WAL")
            logger.info("Connected to %s and set journal mode", dhcp_db.name)
            break
        except sqlite3.OperationalError as e:
            if e.args and "database is locked" in e.args[0]:
                logger.error(
                    "%s while connecting to %s. Retrying..",
                    e.args[0],
                    dhcp_db.name,
                )
                retry -= 1
                sleep(0.5)
            else:
                raise e
        retry -= 1
    else:
        dhcp_db.conn.execute("pragma journal_mode=WAL")
        logger.info("Connected to %s and set journal mode", dhcp_db.name)

    cursor = dhcp_db.conn.cursor()
    for command in schema:
        cursor.execute(command)

    # If migrating from older version of database which doesn't have groupID,
    # alter table to add that
    try:
        for command in alter_table_cmd:
            cursor.execute(command)
    except sqlite3.Error:
        pass
    dhcp_db.conn.commit()

    # "valid_attributes" and "valid_v6attributes" tables are shared among all
    # instances of statichcpd. Hence, cleanup of attributes table and their
    # complete re-population need to be done in a single transaction to avoid
    # conflicting writes from multiple users.

    cursor.execute("delete from valid_attributes")
    cursor.execute("delete from valid_v6attributes")

    # Populate the valid_attributes (v4) table

    # Insert default attributes
    populate_table_from(
        "valid_attributes", "/usr/share/statichcpd/default_attr.csv"
    )

    # Insert user defined attributes, if any
    if "additional_attributes_file" in config:
        populate_table_from(
            "valid_attributes", str(config["additional_attributes_file"])
        )

    # Populate the valid_v6attributes table

    # Insert default attributes
    populate_table_from(
        "valid_v6attributes", "/usr/share/statichcpd/default_v6attr.csv"
    )

    # Insert user defined attributes, if any
    if "additional_v6attributes_file" in config:
        populate_table_from(
            "valid_v6attributes", str(config["additional_v6attributes_file"])
        )
    dhcp_db.conn.commit()

    # Migrate configs from a non-empty database
    for command in migrate_cfgs_cmd:
        cursor.execute(command)
    cursor.close()
    dhcp_db.conn.commit()
    dhcp_db.conn.close()
    logger.debug("Created DHCP config tables")
    dhcp_db.conn = sqlite3.connect(dhcp_db.name)
    if dhcp_db.conn is None:
        raise RuntimeError(f"Re-connecting to DHCP {dhcp_db.name} failed")
    dhcp_db.conn.execute("pragma foreign_keys=on")
    dhcp_db.conn.commit()


def db_exit() -> None:
    if dhcp_db.conn is not None:
        dhcp_db.conn.commit()
        dhcp_db.conn.close()
    logger.debug("Closed the connection to DHCP database")


# pylint: disable=too-many-branches,too-many-statements
def fetch_host_conf_data(
    db_obj: Union[DHCPv4DB, DHCPv6DB], ifname: str, client_id: Union[Mac, str]
) -> Tuple[Dict[int, Any], Optional[str]]:
    logger.debug(
        "Fetching Host conf for intf:%s client ID:%s", ifname, str(client_id)
    )
    result: Dict[int, Any] = {}

    if dhcp_db.conn is None:
        return result, None
    cursor = dhcp_db.conn.cursor()
    client_if = None
    for opcode, max_count, datatype, value, iface in cursor.execute(
        db_obj.select_command, {"client_id": str(client_id), "ifname": ifname}
    ):
        if client_if and client_if != iface:
            logger.error(
                "Multiple server interfaces %s match the client ID %s",
                [client_if, iface],
                client_id,
            )
            return result, None
        client_if = iface
        try:
            datatype = dtype(datatype)
        except ValueError:
            logger.error(
                "Invalid datatype entry %d for opcode %d "
                "for client (%s, %s)",
                datatype.value,
                opcode,
                ifname,
                client_id,
            )
            cursor.close()
            continue  # Shouldn't remaining entries be processed for this client?
        if (
            max_count == 1
        ):  ## Assumed that application handles insertion of attr values
            if datatype is dtype.IPV4:  ## appropriately
                result[opcode] = IPv4Address(value)
            elif datatype is dtype.IPV6:
                result[opcode] = IPv6Address(value)
            elif datatype is dtype.INT16:
                result[opcode] = Int16(value)
            elif datatype is dtype.INT32:
                result[opcode] = Int32(value)
            elif datatype is dtype.STRING:
                result[opcode] = value
            else:
                logger.error(
                    "Invalid entry (datatype, maxcount):(%d, %d) "
                    "for client (%s, %s)",
                    datatype,
                    max_count,
                    ifname,
                    client_id,
                )
        else:
            if opcode not in result:
                result[opcode] = []
            if datatype is dtype.IPV4:
                result[opcode].append(IPv4Address(value))
            elif datatype is dtype.STATICRT:
                result[opcode].append(Staticrt(value))
            elif datatype is dtype.DOMAIN:
                result[opcode].append(Domain(value))
            elif datatype is dtype.IPV6:
                result[opcode].append(IPv6Address(value))
            elif datatype is dtype.IA:
                try:
                    ia_id, ia_addr = value.split(",")
                    result[opcode].extend(
                        [(ia_id.strip(), IPv6Address(ia_addr.strip()))]
                    )
                except ValueError:
                    result[opcode].append(IPv6Address(value))
            elif datatype is dtype.PD:
                try:
                    ia_id, ia_pd = value.split(",")
                    result[opcode].extend(
                        [(ia_id.strip(), IPv6Network(ia_pd.strip()))]
                    )
                except ValueError:
                    result[opcode].append(IPv6Network(value))
            elif datatype is dtype.STRING:
                result[opcode].append(value)
            else:
                logger.error(
                    "Invalid entry (datatype, maxcount):(%d, %d) "
                    "for client (%s, %s)",
                    datatype,
                    max_count,
                    ifname,
                    client_id,
                )
    cursor.close()
    return result, client_if
