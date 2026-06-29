import { RoleFlow } from "../../core/roles.js";
import { OPENCTI_ROLES } from "../../core/roles.js";

export const OPENCTI_FLOWS: RoleFlow[] = [
  {
    fromRoles: [
      "bastion",
      "wazuh_server",
      "zabbix_server",
      "ids_sensor",
      "soc_ai_agent"
    ],
    toRoles: OPENCTI_ROLES,
    protocol: "tcp",
    ports: ["8080"],
    description: "Allow SOC tools and Bastion to reach OpenCTI API"
  },

  {
    fromRoles: ["bastion"],
    toRoles: OPENCTI_ROLES,
    protocol: "tcp",
    ports: ["22"],
    description: "Allow Bastion SSH administration to OpenCTI"
  },

  {
    fromRoles: [
      "wazuh_server",
      "zabbix_server"
    ],
    toRoles: OPENCTI_ROLES,
    protocol: "tcp",
    ports: ["443"],
    description: "Allow SOC services HTTPS access to OpenCTI"
  },

  {
    fromRoles: OPENCTI_ROLES,
    toRoles: ["wazuh_server"],
    protocol: "icmp",
    description: "Allow OpenCTI ICMP diagnostics to Wazuh"
  },

  {
    fromRoles: OPENCTI_ROLES,
    toRoles: ["zabbix_server"],
    protocol: "icmp",
    description: "Allow OpenCTI ICMP diagnostics to Zabbix"
  }
];