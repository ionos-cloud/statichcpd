#!/usr/bin/env python3

import sqlite3
from dpkt import dhcp
from typing import Tuple, List

# Create table and insert commands are included for testing purpose alone. To be removed after use.

class database:
    def fetch_table_and_column(self, opt: int) -> Tuple[str,str] :
        return self.sql_tab_col.get(opt, [None, None])

    def create_ip_config_table(self, table_name: str) -> None:
        sqlite_create_table_query = 'CREATE TABLE if not exists ' + table_name + \
                        '(' + self.mac_col_name + ' text NOT NULL, ' \
                        + self.ifname_col_name + ' text NOT NULL, ' + \
                        self.addr4_col_name + ' text, ' + 'mask text, ' \
                        + 'timeoffset number, '+ 'domain_name text NOT NULL,' \
                        + 'host_name text NOT NULL, ' +  \
                        'CONSTRAINT CompKey_MAC_IF PRIMARY KEY (' \
                        + self.mac_col_name + ', ' + self.ifname_col_name + '));'
        self.db_handler.execute(sqlite_create_table_query)
        self.connection.commit()
        sqlite_insert_query = 'INSERT INTO ' + table_name + '(' + \
                        self.mac_col_name + ', ' + self.ifname_col_name + \
                        ', ' + self.addr4_col_name + \
                        ',mask, timeoffset, domain_name, host_name) VALUES (' \
                        + "'ba:8a:6d:ee:fe:d3', 'veth0dummy0','20.0.0.1', \
                        '255.255.255.0', 12, '30.0.0.3', '20.0.0.5')"
        count = self.db_handler.execute(sqlite_insert_query)
        self.connection.commit()

    def create_ip_router_table(self, table_name: str) -> None:
        sqlite_create_table_query = 'CREATE TABLE if not exists ' + table_name + \
                        '(' + self.mac_col_name + ' text NOT NULL, ' \
                        + self.ifname_col_name + ' text NOT NULL, ' + \
                        'gw text NOT NULL, CONSTRAINT CompKey_MAC_IF_GW PRIMARY KEY (' \
                        + self.mac_col_name + ', ' + self.ifname_col_name + \
                        ', gw), FOREIGN KEY (ifname, mac) references ' + \
                        self.host_ip_config_tab_name + '(ifname, mac) on delete cascade);'
        self.db_handler.execute(sqlite_create_table_query)
        self.connection.commit()
        sqlite_insert_query = 'INSERT INTO ' + table_name + '(' + self.mac_col_name + \
                        ', ' + self.ifname_col_name + ', gw) VALUES (' + \
                        "'ba:8a:6d:ee:fe:d3', 'veth0dummy0', '192.168.144.1')"
        count = self.db_handler.execute(sqlite_insert_query)
        self.connection.commit()
        sqlite_insert_query = 'INSERT INTO ' + table_name + '(' + self.mac_col_name + \
                        ', ' + self.ifname_col_name + ', gw) VALUES (' + \
                        "'ba:8a:6d:ee:fe:d3', 'veth0dummy0', '192.168.144.2')"
        count = self.db_handler.execute(sqlite_insert_query)
        self.connection.commit()
        sqlite_insert_query = 'INSERT INTO ' + table_name + '(' + self.mac_col_name + \
                        ', ' + self.ifname_col_name + ', gw) VALUES (' + \
                        "'ba:8a:6d:ee:fe:d3', 'veth0dummy0', '192.168.144.3')"
        count = self.db_handler.execute(sqlite_insert_query)
        self.connection.commit()


    def create_dns_name_srv_table(self, table_name: str) -> None :
        sqlite_create_table_query = 'CREATE TABLE if not exists ' + table_name + '(' \
                        + self.mac_col_name + ' text NOT NULL, ' + \
                        self.ifname_col_name + ' text NOT NULL, ' + \
                        'dns_server text NOT NULL, CONSTRAINT CompKey_MAC_IF_SRV PRIMARY KEY (' \
                        + self.mac_col_name + ', ' + self.ifname_col_name + \
                        ', dns_server), FOREIGN KEY (ifname, mac) references ' \
                        + self.host_ip_config_tab_name + '(ifname, mac) on delete cascade);'
        self.db_handler.execute(sqlite_create_table_query)
        self.connection.commit()
        sqlite_insert_query = 'INSERT INTO ' + table_name + '(' + self.mac_col_name + \
                        ', ' + self.ifname_col_name + ', dns_server) VALUES (' + \
                        "'ba:8a:6d:ee:fe:d3', 'veth0dummy0', '192.168.144.56')"
        count = self.db_handler.execute(sqlite_insert_query)
        self.connection.commit()


    def create_nb_name_srv_table(self, table_name: str) -> None :
        sqlite_create_table_query = 'CREATE TABLE if not exists ' + table_name + '(' + self.mac_col_name + \
                        ' text NOT NULL, ' + self.ifname_col_name + ' text NOT NULL, ' + \
                        'name_server text NOT NULL, CONSTRAINT CompKey_MAC_IF_SRV PRIMARY KEY (' \
                        + self.mac_col_name + ', ' + self.ifname_col_name + \
                        ', name_server), FOREIGN KEY (ifname, mac) references ' + \
                        self.host_ip_config_tab_name + '(ifname, mac) on delete cascade);'
        self.db_handler.execute(sqlite_create_table_query)
        self.connection.commit()
        sqlite_insert_query = 'INSERT INTO ' + table_name + '(' + self.mac_col_name + \
                        ', ' + self.ifname_col_name + ', name_server) VALUES (' \
                        + "'ba:8a:6d:ee:fe:d3', 'veth0dummy0', '192.168.144.57')"
        count = self.db_handler.execute(sqlite_insert_query)
        self.connection.commit()


    def create_service_config_table(self, table_name: str) -> None:
        sqlite_create_table_query = 'CREATE TABLE if not exists ' + table_name + '(' + \
                        self.mac_col_name + ' text NOT NULL, ' + self.ifname_col_name + \
                        ' text NOT NULL, ' + 'nb_scope text, CONSTRAINT CompKey_MAC_IF PRIMARY KEY (' \
                        + self.mac_col_name + ', ' + self.ifname_col_name + \
                        '), FOREIGN KEY (ifname, mac) references ' + self.host_ip_config_tab_name + \
                        '(ifname, mac) on delete cascade);'
        self.db_handler.execute(sqlite_create_table_query)
        self.connection.commit()
        sqlite_insert_query = 'INSERT INTO ' + table_name + '(' + self.mac_col_name + \
                        ', ' + self.ifname_col_name + ', nb_scope) VALUES (' \
                        + "'ba:8a:6d:ee:fe:d3', 'veth0dummy0', '40.0.0.5')"
        count = self.db_handler.execute(sqlite_insert_query)
        self.connection.commit()


    def create_intf_ip_table(self, table_name: str) -> None:
        sqlite_create_table_query = 'CREATE TABLE if not exists ' + table_name + \
                        '(' + self.mac_col_name + ' text NOT NULL, ' + \
                        self.ifname_col_name + ' text NOT NULL, ' + \
                        'intf_mtu number, CONSTRAINT CompKey_MAC_IF PRIMARY KEY (' + \
                        self.mac_col_name + ', ' + self.ifname_col_name + \
                        '), FOREIGN KEY (ifname, mac) references ' + \
                        self.host_ip_config_tab_name + '(ifname, mac) on delete cascade);'
        self.db_handler.execute(sqlite_create_table_query)
        self.connection.commit()
        sqlite_insert_query = 'INSERT INTO ' + table_name + '(' + self.mac_col_name + \
                        ', ' + self.ifname_col_name + ', intf_mtu) VALUES (' + \
                        "'ba:8a:6d:ee:fe:d3', 'veth0dummy0', 65535)"
        count = self.db_handler.execute(sqlite_insert_query)
        self.connection.commit()


    def create_intf_ip_static_rt_table(self, table_name: str) -> None:
        sqlite_create_table_query = 'CREATE TABLE if not exists ' + table_name + \
                        '(' + self.mac_col_name + ' text NOT NULL, ' + \
                        self.ifname_col_name + ' text NOT NULL, ' + \
                        'static_rt text NOT NULL, CONSTRAINT CompKey_MAC_IF_RT PRIMARY KEY (' + \
                        self.mac_col_name + ', ' + self.ifname_col_name + \
                        ', static_rt), FOREIGN KEY (ifname, mac) references ' + \
                        self.host_ip_config_tab_name + '(ifname, mac) on delete cascade);'
        self.db_handler.execute(sqlite_create_table_query)
        self.connection.commit()
        sqlite_insert_query = 'INSERT INTO ' + table_name + '(' + self.mac_col_name + \
                        ', ' + self.ifname_col_name + ', static_rt) VALUES (' \
                        + "'ba:8a:6d:ee:fe:d3', 'veth0dummy0', 'ip route bla')"
        count = self.db_handler.execute(sqlite_insert_query)
        self.connection.commit()


    def create_service_ntp_table(self, table_name: str) -> None:
        sqlite_create_table_query = 'CREATE TABLE if not exists ' + table_name + \
                        '(' + self.mac_col_name + ' text NOT NULL, ' + \
                        self.ifname_col_name + ' text NOT NULL, ' + \
                        'ntp_server text NOT NULL, CONSTRAINT CompKey_MAC_IF_SRV PRIMARY KEY (' + \
                        self.mac_col_name + ', ' + self.ifname_col_name + \
                        ', ntp_server), FOREIGN KEY (ifname, mac) references ' + \
                        self.host_ip_config_tab_name + '(ifname, mac) on delete cascade);'
        self.db_handler.execute(sqlite_create_table_query)
        self.connection.commit()
        sqlite_insert_query = 'INSERT INTO ' + table_name + '(' + self.mac_col_name + \
                        ', ' + self.ifname_col_name + ', ntp_server) VALUES (' + \
                        "'ba:8a:6d:ee:fe:d3', 'veth0dummy0', '192.168.144.59')"
        count = self.db_handler.execute(sqlite_insert_query)
        self.connection.commit()

    def construct_generic_sql_lookup_query(self, table_name: str, lookup_attr: str, condn_attr_val_pairs: List[Tuple[str, str]]) -> None:
        sql_query = "SELECT " + lookup_attr + " FROM " + table_name + " WHERE "
        n = len(condn_attr_val_pairs)
        for i in range(n):
            sql_query += condn_attr_val_pairs[i][0] + "='" + condn_attr_val_pairs[i][1] + "'"
            if i == n-1:
                sql_query += ";"
            else:
                sql_query += " AND "
        return sql_query

    def construct_generic_joined_sql_lookup_query(self, tab_attr_pairs: List[Tuple[str, ...]], 
                                                  condn_attr_val_pairs: List[Tuple[str, str]]) -> None:
       
        # SELECT a.x, b,y, c,z 
        sql_query = "SELECT "
        table_list = list(set(entry[0] for entry in tab_attr_pairs))
        n = len(tab_attr_pairs)
        for i in range(n):
            if i == n-1:
                sql_query += " " + str(tab_attr_pairs[i][0]) + "." + str(tab_attr_pairs[i][1]) 
            else:
                sql_query += " " + str(tab_attr_pairs[i][0]) + "." + str(tab_attr_pairs[i][1]) + ","
        sql_query = sql_query.rstrip(',')

        # FROM a
        sql_query += " FROM " + str(table_list[0]) + " "
       
        # JOIN b ON b.u = a.u JOIN c ON c.u = b.u 
        n = len(table_list)
        for j in range(1, n):
            sql_query += "JOIN " + str(table_list[j]) + " ON "
            m = len(condn_attr_val_pairs)
            for i in range(m):
                sql_query += str(table_list[j]) + "." + condn_attr_val_pairs[i][0] + "=" +  \
                             str(table_list[j-1]) + "." + condn_attr_val_pairs[i][0] + " "
                if i < m-1:
                    sql_query += "AND "
        
	# WHERE a.mac = <> AND a.ifname = <> ... 
        sql_query += " WHERE "
        m = len(condn_attr_val_pairs)
        for i in range(m):
            sql_query += str(table_list[0]) + "." + condn_attr_val_pairs[i][0] + "='" + condn_attr_val_pairs[i][1] + "' "
            if i == m-1:
                sql_query += ";"
            else:
                sql_query += "AND "
        return sql_query



    def init_tables(self):
        self.create_ip_config_table(self.host_ip_config_tab_name)
        self.create_ip_router_table(self.host_ip_routers_tab_name)
        self.create_dns_name_srv_table(self.host_ip_dns_name_servers_tab_name)
        self.create_nb_name_srv_table(self.host_service_nb_name_servers_tab_name)
        self.create_service_config_table(self.host_service_config_tab_name)
        self.create_intf_ip_table(self.intf_ip_config_tab_name)
        self.create_intf_ip_static_rt_table(self.intf_ip_static_rt_tab_name)
        self.create_service_ntp_table(self.host_service_ntp_tab_name)



    def __init__(self):
        self.db_name = "Static_DHCP_DB.db"
        self.db_handler = None
        self.connection = None
        try:
            self.connection = sqlite3.connect(self.db_name)
            self.db_handler =  self.connection.cursor()
        except sqlite3.Error as error:
            print("Error while connecting to sqlite", error)
            return

        self.mac_col_name = 'mac'
        self.ifname_col_name = 'ifname'
        self.addr4_col_name = 'addr4'
        self.addr6_col_name = 'addr6'

        self.host_ip_config_tab_name = 'ip_conf'
        self.host_ip_routers_tab_name = 'ip_rt'
        self.host_ip_time_servers_tab_name = 'ip_time_srv'
        self.host_ip_ien_name_servers_tab_name = None
        self.host_ip_dns_name_servers_tab_name = 'dns_srv'
        self.host_ip_log_servers_tab_name = None
        self.host_ip_cookie_servers_tab_name = None
        self.host_ip_lpr_servers_tab_name = None
        self.host_ip_impress_servers_tab_name = None
        self.host_ip_rls_servers_tab_name = None
        self.host_ip_policy_filter_tab_name = None
        self.host_ip_mtu_tab_name = 'ip_mtu'

        self.host_ip_v6_config_tab_name = None

        self.intf_ip_config_tab_name = 'intf_ip_conf'
        self.intf_ip_static_rt_tab_name = 'intf_ip_static_rt'
        self.intf_link_config_tab_name = None

        self.host_tcp_config_tab_name = None

        self.host_service_config_tab_name = 'service_conf'
        self.host_service_nis_tab_name = None
        self.host_service_ntp_tab_name = 'service_ntp'
        self.host_service_nb_name_servers_tab_name = 'service_nb_name_srv'
        self.host_service_nb_dist_servers_tab_name = None
        self.host_service_font_servers_tab_name = None
        self.host_service_display_mgrs_tab_name = None
        self.host_service_home_agents_tab_name = None
        self.host_service_smtp_tab_name = None
        self.host_service_pop3_tab_name = None
        self.host_service_nntp_tab_name = 'service_ntp'
        self.host_service_www_tab_name = None
        self.host_service_finger_tab_name = None
        self.host_service_irc_tab_name = None
        self.host_service_street_talk_tab_name = None
        self.host_service_stda_tab_name = None

        self.sql_tab_col = {
            dhcp.DHCP_OPT_NETMASK: (self.host_ip_config_tab_name, 'mask'),
            dhcp.DHCP_OPT_TIMEOFFSET: (self.host_ip_config_tab_name, 'timeoffset'),
            dhcp.DHCP_OPT_ROUTER: (self.host_ip_routers_tab_name, 'gw'),
            dhcp.DHCP_OPT_DOMAIN: (self.host_ip_config_tab_name, 'domain_name'),
            dhcp.DHCP_OPT_DNS_SVRS: (self.host_ip_dns_name_servers_tab_name, 'dns_server'),
            dhcp.DHCP_OPT_HOSTNAME: (self.host_ip_config_tab_name, 'host_name'),
            dhcp.DHCP_OPT_NBNS: (self.host_service_nb_name_servers_tab_name, 'name_server'),
            dhcp.DHCP_OPT_NBTCPSCOPE: (self.host_service_config_tab_name, 'nb_scope'),
            dhcp.DHCP_OPT_MTUSIZE: (self.intf_ip_config_tab_name, 'intf_mtu'),
            dhcp.DHCP_OPT_STATICROUTE: (self.intf_ip_static_rt_tab_name, 'static_rt'),
            dhcp.DHCP_OPT_NNTPSERVER: (self.host_service_ntp_tab_name, 'ntp_server')

            }

        self.init_tables()
