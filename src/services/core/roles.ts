export type Protocol = "tcp" | "udp" | "icmp" | "any";

export type RoleFlow = {
  fromRoles: string[];
  toRoles: string[];
  protocol: Protocol;
  ports?: string[];
  description: string;
};

export const DB_ROLES = [
  "db_server",
  "database",
  "mariadb_server",
  "mysql_server"
];

export const FIREWALL_ROLES = [
  "edge_firewall",
  "internal_firewall"
];

export const OPENCTI_ROLES = [
  "opencti_server"
];

export const PASSBOLT_ROLES = [
  "passbolt_server"
];

export const WAZUH_AGENT_ROLES = [
  "bastion",
  "reverse_proxy",
  "db_server",
  "database",
  "mariadb_server",
  "mysql_server",
  "ids_sensor",
  "soc_ai_agent",
  "zabbix_server",
  "opencti_server",
  "passbolt_server"
];

export const ZABBIX_AGENT_ROLES = [
  "bastion",
  "opencti_server",
  "reverse_proxy",
  "db_server",
  "database",
  "mariadb_server",
  "mysql_server",
  "ids_sensor",
  "soc_ai_agent",
  "wazuh_server",
  "zabbix_server",
  "passbolt_server"
];