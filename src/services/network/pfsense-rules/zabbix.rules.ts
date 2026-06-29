import { RoleFlow } from "../../core/roles.js";
import {
  DB_ROLES,
  FIREWALL_ROLES,
  ZABBIX_AGENT_ROLES
} from "../../core/roles.js";

export const ZABBIX_FLOWS: RoleFlow[] = [
  {
    fromRoles: ["zabbix_server"],
    toRoles: FIREWALL_ROLES,
    protocol: "udp",
    ports: ["161"],
    description: "Allow Zabbix SNMP polling to pfSense"
  },

  {
    fromRoles: ["zabbix_server"],
    toRoles: FIREWALL_ROLES,
    protocol: "icmp",
    description: "Allow Zabbix ICMP ping to pfSense"
  },

  {
    fromRoles: ["zabbix_server"],
    toRoles: DB_ROLES,
    protocol: "tcp",
    ports: ["3306"],
    description: "Allow Zabbix database access to MariaDB"
  },

  {
    fromRoles: ["zabbix_server"],
    toRoles: DB_ROLES,
    protocol: "icmp",
    description: "Allow Zabbix ICMP diagnostic to MariaDB"
  },

  {
    fromRoles: ["zabbix_server"],
    toRoles: ZABBIX_AGENT_ROLES,
    protocol: "tcp",
    ports: ["10050"],
    description: "Allow Zabbix server to poll agents"
  },

  {
    fromRoles: ZABBIX_AGENT_ROLES,
    toRoles: ["zabbix_server"],
    protocol: "tcp",
    ports: ["10051"],
    description: "Allow Zabbix agents active checks to server"
  },

  {
    fromRoles: ZABBIX_AGENT_ROLES,
    toRoles: ["zabbix_server"],
    protocol: "icmp",
    description: "Allow Zabbix ICMP diagnostic"
  }
];