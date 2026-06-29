import type { NetworkPlanHost } from "../../core/type.js";

import type { PfSenseAlias } from "../../core/pfsenseTypes.js";

import {
  DB_ROLES,
  OPENCTI_ROLES,
  PASSBOLT_ROLES,
  WAZUH_AGENT_ROLES,
  ZABBIX_AGENT_ROLES
} from "../../core/roles.js";

import {
  addAliasOnce,
  addHostAliasByRoles,
  aliasName,
  networkFromCidr,
  roleAliasName
} from "./helpers.js";

function addServiceAliases(
  aliases: PfSenseAlias[],
  seen: Set<string>,
  allHosts: NetworkPlanHost[]
): void {
  addHostAliasByRoles(
    aliases,
    seen,
    allHosts,
    "WAZUH_SERVER",
    ["wazuh_server"],
    "Wazuh manager"
  );

  addHostAliasByRoles(
    aliases,
    seen,
    allHosts,
    "ZABBIX_SERVER",
    ["zabbix_server"],
    "Zabbix server"
  );

  addHostAliasByRoles(
    aliases,
    seen,
    allHosts,
    "OPENCTI_SERVER",
    OPENCTI_ROLES,
    "OpenCTI server"
  );

  addHostAliasByRoles(
    aliases,
    seen,
    allHosts,
    "PASSBOLT_SERVER",
    PASSBOLT_ROLES,
    "Passbolt password vault"
  );

  addHostAliasByRoles(
    aliases,
    seen,
    allHosts,
    "MARIADB_SERVER",
    DB_ROLES,
    "MariaDB or DB server"
  );

  addHostAliasByRoles(
    aliases,
    seen,
    allHosts,
    "DB_SERVER",
    DB_ROLES,
    "Database server"
  );

  addHostAliasByRoles(
    aliases,
    seen,
    allHosts,
    "WAZUH_AGENTS",
    WAZUH_AGENT_ROLES,
    "Hosts monitored by Wazuh"
  );

  addHostAliasByRoles(
    aliases,
    seen,
    allHosts,
    "ZABBIX_AGENTS",
    ZABBIX_AGENT_ROLES,
    "Hosts monitored by Zabbix"
  );

  const roles = new Set(allHosts.map((host) => host.role).filter(Boolean));

  for (const role of roles) {
    addHostAliasByRoles(
      aliases,
      seen,
      allHosts,
      roleAliasName(role),
      [role],
      `Hosts with role ${role}`
    );
  }
}

export function generateAliases(
  firewallHost: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): PfSenseAlias[] {
  const aliases: PfSenseAlias[] = [];
  const seen = new Set<string>();

  for (const iface of firewallHost.interfaces ?? []) {
    if (!iface.name || !iface.ip || iface.name === "wan") continue;

    addAliasOnce(aliases, seen, {
      name: aliasName(iface.name),
      type: "network",
      values: [networkFromCidr(iface.ip)],
      description: `Network attached to ${firewallHost.id}/${iface.name}`
    });
  }

  addServiceAliases(aliases, seen, allHosts);

  return aliases;
}