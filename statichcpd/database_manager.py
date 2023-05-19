#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List, Any, Dict, Optional, Union
from time import sleep
import os
from ipaddress import IPv4Address
from enum import Enum
from configparser import SectionProxy
import csv
from ipaddress import IPv6Address, IPv6Network

from .datatypes import *
from .logmgr import logger
from .dhcp6 import *

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
    "exit",
    "fetch_host_conf_data",
]

dhcp_db_conn = None

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
           foreign key (ifname, groupID) references client_groups(ifname, groupID) on delete cascade,
           constraint compkey_mac_grp_if unique(ifname, groupID, mac));""",
    """create table if not exists client_configuration (
           ifname text not null,
           groupID text,
           mac text not null,
           attr_code int not null,
           attr_val not null,
           constraint compkey_mac_if_attr unique(ifname, groupID, mac, attr_code, attr_val)
           foreign key (ifname, groupID, mac) references clients(ifname, groupID, mac) on delete cascade,
           foreign key (ifname, groupID) references client_groups(ifname, groupID) on delete cascade,
           foreign key (attr_code) references valid_attributes(opcode) on delete restrict);""",
    """create table if not exists client_v6configuration (
           ifname text not null,
           groupID text,
           duid text not null,
           attr_code int not null,
           attr_val not null,
           constraint compkey_clientid_if_attr unique(ifname, groupID, duid, attr_code, attr_val)
           foreign key (ifname, groupID, duid) references clients(ifname, groupID, mac) on delete cascade,
           foreign key (ifname, groupID) references client_groups(ifname, groupID) on delete cascade,
           foreign key (attr_code) references valid_v6attributes(opcode) on delete restrict);""",
    """create trigger if not exists client_insertion before insert on clients
           begin
           insert into client_groups (ifname, groupID) select new.ifname, new.groupID where not exists(
           select 1 from client_groups where ifname=new.ifname and (groupID=new.groupID or groupID is new.groupID));
           end;""",
    """create trigger if not exists client_deletion after delete on clients
           when (select count(*) from clients where ifname=old.ifname and (groupID=old.groupID or groupID is old.groupID)) == 0
           begin
           delete from client_groups where ifname=old.ifname and (groupID=old.groupID or groupID is old.groupID);
           end;""",
    """create trigger if not exists client_del_config_cleanup before delete on clients
           when exists(select 1 from clients where ifname=old.ifname and groupID is old.groupID and old.groupID is NULL)
           begin
           delete from client_configuration where ifname=old.ifname and mac=old.mac and groupID is NULL;
           delete from client_v6configuration where ifname=old.ifname and duid=old.mac and groupID is NULL;
           end;""",
    """create trigger if not exists client_v4_cfg_insertion before insert on client_configuration
           when (select count(*) from client_groups where ifname=new.ifname and groupID is NULL) == 0
           begin
           insert into client_groups (ifname, groupID) select new.ifname, new.groupID where not exists(
           select 1 from client_groups where ifname=new.ifname and groupID=new.groupID);
           insert into clients (ifname, groupID, mac) select new.ifname, new.groupID, new.mac where not exists(
           select 1 from clients where ifname=new.ifname and groupID=new.groupID and mac=new.mac);
           end;""",
    """create trigger if not exists client_v4_cfg_replace before insert on client_configuration
           when (select count(*) from client_groups where ifname=new.ifname and groupID is NULL) > 0 and new.groupID is not NULL
           begin
           replace into client_groups (ifname, groupID) values (new.ifname, new.groupID);
           replace into clients (ifname, groupID, mac) values (new.ifname, new.groupID, new.mac);
           end;""",
    """create trigger if not exists client_v6_cfg_insertion before insert on client_v6configuration
           when (select count(*) from client_groups where ifname=new.ifname and groupID is NULL) == 0
           begin
           insert into client_groups (ifname, groupID) select new.ifname, new.groupID where not exists(
           select 1 from client_groups where ifname=new.ifname and groupID=new.groupID);
           insert into clients (ifname, groupID, mac) select new.ifname, new.groupID, new.duid where not exists(
           select 1 from clients where ifname=new.ifname and groupID=new.groupID and mac=new.duid);
           end;""",
    """create trigger if not exists client_v6_cfg_replace before insert on client_v6configuration
           when (select count(*) from client_groups where ifname=new.ifname and groupID is NULL) > 0 and new.groupID is not NULL
           begin
           replace into client_groups (ifname, groupID) values (new.ifname, new.groupID);
           replace into clients (ifname, groupID, mac) values (new.ifname, new.groupID, new.duid);
           end;""",
    """create trigger if not exists client_v4_cfg_deletion after delete on client_configuration
           when (select count(*) from client_configuration where ifname=old.ifname and mac=old.mac) == 0
           and (select count(*) from client_v6configuration where ifname=old.ifname and duid=old.mac) == 0
           begin
           delete from clients where ifname=old.ifname and (groupID=old.groupID or groupID is old.groupID) and mac=old.mac;
           delete from client_groups where ifname=old.ifname and (groupID=old.groupID or groupID is old.groupID)
           and not exists(select 1 from clients where ifname=old.ifname and (groupID=old.groupID or groupID is old.groupID)
           and mac<>old.mac);
           end;""",
    """create trigger if not exists client_v6_cfg_deletion after delete on client_v6configuration
           when (select count(*) from client_v6configuration where ifname=old.ifname and duid=old.duid) == 0
           and (select count(*) from client_configuration where ifname=old.ifname and mac=old.duid) == 0
           begin
           delete from clients where ifname=old.ifname and (groupID=old.groupID or groupID is old.groupID) and mac=old.duid;
           delete from client_groups where ifname=old.ifname and (groupID=old.groupID or groupID is old.groupID)
           and not exists(select 1 from clients where ifname=old.ifname and (groupID=old.groupID or groupID is old.groupID)
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


"""
In a scenario where the controller has not adapted to the new feature of
'port grouping' or if we have non-empty database left from previously running
version, the database will have NULL values in the groupID field. In such a
case, fallback to the lookup that matches <ifname and mac>, without considering
interface grouping.
"""


class DHCPv4DB(object):
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


class DHCPv6DB(object):
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
                       select distinct ifname, groupID, mac from client_configuration where not exists(
                       select 1 from clients where ifname=ifname and mac=mac
                       and (groupID=groupID or groupID is groupID));""",
    """insert into client_groups (ifname, groupID)
                       select distinct ifname, groupID from client_configuration where not exists(
                       select 1 from client_groups where ifname=ifname and
                       (groupID=groupID or groupID is groupID));""",
    """insert into clients (ifname, groupID, mac)
                       select distinct ifname, groupID, duid from client_v6configuration where not exists(
                       select 1 from clients where ifname=ifname and mac=duid
                       and (groupID=groupID or groupID is groupID));""",
    """insert into client_groups (ifname, groupID)
                       select distinct ifname, groupID from client_v6configuration where not exists(
                       select 1 from client_groups where ifname=ifname and
                       (groupID=groupID or groupID is groupID));""",
]


def populate_table_from(table_name: str, csv_filename: str) -> None:
    if dhcp_db_conn is None:
        return
    cursor = dhcp_db_conn.cursor()
    with open(csv_filename, "r") as f:
        reader = csv.reader(f)
        columns = next(reader)
        query = "insert or replace into {0}({1}) values ({2})".format(
            table_name, ",".join(columns), ",".join("?" * len(columns))
        )
        for row in reader:
            # Opcode can be an integer or dpkt.dhcp module optcode alias
            try:
                if hasattr(dhcp, row[0]):
                    data = (
                        str(getattr(dhcp, row[0])),
                        row[1],
                        str(eval("dtype." + row[2] + ".value")),
                    )
                else:
                    data = (
                        str(globals()[row[0]]),
                        row[1],
                        str(eval("dtype." + row[2] + ".value")),
                    )
            except:
                data = (
                    str(row[0]),
                    row[1],
                    str(eval("dtype." + row[2] + ".value")),
                )
            cursor.execute(query, data)


def init(config: Dict[str, Any]) -> None:
    global dhcp_db_conn
    dhcp_db_name = config["dhcp_db_filename"]
    dhcp_db_name = (
        str(dhcp_db_name) if type(dhcp_db_name) is not str else dhcp_db_name
    )
    logger.debug("Connecting to %s", dhcp_db_name)
    dhcp_db_conn = sqlite3.connect(dhcp_db_name)
    if dhcp_db_conn is None:
        raise Exception("Connecting to DHCP db {} failed".format(dhcp_db_name))

    """
    Updating journal_mode is a persistent update and hence,
    can result in 'database locked' error if a concurrent
    writer is in middle of a transaction, unlike regular
    sql writes that waits until connection timeout to quit.
    """
    retry = 3
    for i in range(retry):
        try:
            dhcp_db_conn.execute("pragma journal_mode=WAL")
            logger.info("Connected to %s and set journal mode", dhcp_db_name)
            break
        except sqlite3.OperationalError as e:
            if e.args and "database is locked" in e.args[0]:
                logger.error(
                    "%s while connecting to %s. Retrying..",
                    e.args[0],
                    dhcp_db_name,
                )
                retry -= 1
                sleep(0.5)
            else:
                raise e
    else:
        dhcp_db_conn.execute("pragma journal_mode=WAL")
        logger.info("Connected to %s and set journal mode", dhcp_db_name)

    cursor = dhcp_db_conn.cursor()
    for command in schema:
        cursor.execute(command)

    # If migrating from older version of database which doesn't have groupID,
    # alter table to add that
    try:
        for command in alter_table_cmd:
            cursor.execute(command)
    except:
        pass
    dhcp_db_conn.commit()

    """
    "valid_attributes" and "valid_v6attributes" tables are shared among all
    instances of statichcpd. Hence, cleanup of attributes table and their
    complete re-population need to be done in a single transaction to avoid
    conflicting writes from multiple users.
    """

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
    dhcp_db_conn.commit()

    # Migrate configs from a non-empty database
    for command in migrate_cfgs_cmd:
        cursor.execute(command)
    cursor.close()
    dhcp_db_conn.commit()
    dhcp_db_conn.close()
    logger.debug("Created DHCP config tables")
    dhcp_db_conn = sqlite3.connect(dhcp_db_name)
    if dhcp_db_conn is None:
        raise Exception(
            "Re-connecting to DHCP db {} failed".format(dhcp_db_name)
        )
    dhcp_db_conn.execute("pragma foreign_keys=on")
    dhcp_db_conn.commit()


def exit() -> None:
    global dhcp_db_conn
    if dhcp_db_conn is not None:
        dhcp_db_conn.commit()
        dhcp_db_conn.close()
    logger.debug("Closed the connection to DHCP database")


def fetch_host_conf_data(
    db_obj: Union[DHCPv4DB, DHCPv6DB], ifname: str, client_id: Union[Mac, str]
) -> Tuple[Dict[int, Any], Optional[str]]:
    logger.debug(
        "Fetching Host conf for intf:%s client ID:%s", ifname, str(client_id)
    )
    result: Dict[int, Any] = {}

    if dhcp_db_conn is None:
        return result, None
    cursor = dhcp_db_conn.cursor()
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
        except ValueError as err:
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
