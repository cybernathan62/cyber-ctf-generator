import { RoleFlow } from "../../core/roles.js";
import { WAZUH_AGENT_ROLES } from "../../core/roles.js";

export const WAZUH_FLOWS: RoleFlow[] = [
  {
    fromRoles: WAZUH_AGENT_ROLES,
    toRoles: ["wazuh_server"],
    protocol: "tcp",
    ports: ["1514"],
    description: "Allow Wazuh agents to send events to Wazuh manager"
  },
  {
    fromRoles: WAZUH_AGENT_ROLES,
    toRoles: ["wazuh_server"],
    protocol: "tcp",
    ports: ["1515"],
    description: "Allow Wazuh agents enrollment to Wazuh manager"
  },
  {
    fromRoles: WAZUH_AGENT_ROLES,
    toRoles: ["wazuh_server"],
    protocol: "tcp",
    ports: ["55000"],
    description: "Allow Wazuh agents/API communication to Wazuh manager"
  },
  {
    fromRoles: WAZUH_AGENT_ROLES,
    toRoles: ["wazuh_server"],
    protocol: "icmp",
    description: "Allow Wazuh agents ICMP diagnostic to Wazuh manager"
  }
];