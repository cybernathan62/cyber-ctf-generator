import { RoleFlow, ZABBIX_AGENT_ROLES } from "../../core/roles.js";
export const BASTION_FLOWS: RoleFlow[] = [
  {
    fromRoles: ["bastion"],
    toRoles: [
      ...ZABBIX_AGENT_ROLES,
      "zabbix_server",
      "wazuh_server"
    ],
    protocol: "tcp",
    ports: ["22"],
    description: "Allow Bastion SSH administration"
  },

  {
    fromRoles: ["bastion"],
    toRoles: [
      ...ZABBIX_AGENT_ROLES,
      "zabbix_server",
      "wazuh_server"
    ],
    protocol: "icmp",
    description: "Allow Bastion ICMP diagnostic"
  },

  {
    fromRoles: ["bastion"],
    toRoles: ["opencti_server"],
    protocol: "tcp",
    ports: ["8080", "443", "22"],
    description: "Allow Bastion administration of OpenCTI"
  }
];