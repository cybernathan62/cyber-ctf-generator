import { RoleFlow } from "../../core/roles.js";

export const PASSBOLT_RULES: RoleFlow[] = [
  {
    fromRoles: ["bastion"],
    toRoles: ["passbolt_server"],
    protocol: "tcp",
    ports: ["443"],
    description: "Allow Bastion HTTPS access to Passbolt"
  },

  {
    fromRoles: ["zabbix_server"],
    toRoles: ["passbolt_server"],
    protocol: "tcp",
    ports: ["10050"],
    description: "Allow Zabbix agent monitoring on Passbolt"
  },

  {
    fromRoles: ["passbolt_server"],
    toRoles: ["wazuh_server"],
    protocol: "tcp",
    ports: ["1514", "1515"],
    description: "Allow Passbolt Wazuh agent enrollment and log forwarding"
  },

  {
    fromRoles: ["passbolt_server"],
    toRoles: ["any"],
    protocol: "udp",
    ports: ["53"],
    description: "Allow Passbolt DNS queries"
  },

  {
    fromRoles: ["passbolt_server"],
    toRoles: ["any"],
    protocol: "tcp",
    ports: ["53"],
    description: "Allow Passbolt DNS over TCP"
  },

  {
    fromRoles: ["passbolt_server"],
    toRoles: ["any"],
    protocol: "udp",
    ports: ["123"],
    description: "Allow Passbolt NTP synchronization"
  },

  {
    fromRoles: ["passbolt_server"],
    toRoles: ["any"],
    protocol: "tcp",
    ports: ["80", "443"],
    description: "Allow Passbolt OS updates and package downloads"
  }
];