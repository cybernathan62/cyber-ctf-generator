import {
  DB_ROLES,
  PASSBOLT_ROLES,
  RoleFlow
} from "../../core/roles.js";

export const DB_SERVER_FLOWS: RoleFlow[] = [
  {
    fromRoles: ["zabbix_server"],
    toRoles: DB_ROLES,
    protocol: "tcp",
    ports: ["3306"],
    description: "Allow Zabbix server to reach MariaDB database"
  },

  {
    fromRoles: PASSBOLT_ROLES,
    toRoles: DB_ROLES,
    protocol: "tcp",
    ports: ["3306"],
    description: "Allow Passbolt to reach MariaDB database"
  },

  {
    fromRoles: ["bastion"],
    toRoles: DB_ROLES,
    protocol: "tcp",
    ports: ["22"],
    description: "Allow Bastion SSH administration to DB server"
  },

  {
    fromRoles: DB_ROLES,
    toRoles: ["wazuh_server"],
    protocol: "tcp",
    ports: ["1514", "1515"],
    description: "Allow DB server Wazuh agent to reach Wazuh manager"
  },

  {
    fromRoles: DB_ROLES,
    toRoles: ["zabbix_server"],
    protocol: "tcp",
    ports: ["10051"],
    description: "Allow DB server Zabbix active agent to reach Zabbix server"
  },

  {
    fromRoles: ["zabbix_server"],
    toRoles: DB_ROLES,
    protocol: "tcp",
    ports: ["10050"],
    description: "Allow Zabbix server to poll DB server passive agent"
  },

  {
    fromRoles: DB_ROLES,
    toRoles: ["any"],
    protocol: "udp",
    ports: ["53", "123"],
    description: "Allow DB server DNS and NTP outbound"
  },

  {
    fromRoles: DB_ROLES,
    toRoles: ["any"],
    protocol: "tcp",
    ports: ["80", "443"],
    description: "Allow DB server HTTP/HTTPS outbound for updates"
  }
];