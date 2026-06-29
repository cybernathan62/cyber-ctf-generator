import type { NetworkPlanHost } from "../../core/type.js";
import type { PfSenseFirewallRule } from "../../core/pfsenseTypes.js";

import { addRuleOnce, aliasName } from "./helpers.js";

function addDeploymentRules(
  rules: PfSenseFirewallRule[],
  seen: Set<string>,
  ifaceName: string,
  sourceAlias: string
): void {
  for (const protocol of ["udp", "tcp"] as const) {
    addRuleOnce(rules, seen, {
      interface: ifaceName,
      action: "pass",
      protocol,
      source: sourceAlias,
      destination: "any",
      destinationPort: "53",
      description: `Allow ${sourceAlias} DNS ${protocol.toUpperCase()}`
    });
  }

  for (const port of ["80", "443", "22"]) {
    addRuleOnce(rules, seen, {
      interface: ifaceName,
      action: "pass",
      protocol: "tcp",
      source: sourceAlias,
      destination: "any",
      destinationPort: port,
      description: `Allow ${sourceAlias} deployment TCP ${port}`
    });
  }

  addRuleOnce(rules, seen, {
    interface: ifaceName,
    action: "pass",
    protocol: "udp",
    source: sourceAlias,
    destination: "any",
    destinationPort: "123",
    description: `Allow ${sourceAlias} NTP`
  });
}

export function addCoreZoneRules(
  rules: PfSenseFirewallRule[],
  seen: Set<string>,
  firewallHost: NetworkPlanHost
): void {
  const interfaces = (firewallHost.interfaces ?? []).filter(
    (iface: any) => iface.name && iface.ip && iface.name !== "wan"
  );

  for (const iface of interfaces) {
    addDeploymentRules(rules, seen, iface.name, aliasName(iface.name));

    addRuleOnce(rules, seen, {
      interface: iface.name,
      action: "pass",
      protocol: "icmp",
      source: aliasName(iface.name),
      destination: "any",
      description: `Allow ICMP from ${aliasName(iface.name)}`
    });
  }

  for (const iface of interfaces) {
    if (!iface.name.startsWith("transit")) continue;

    addRuleOnce(rules, seen, {
      interface: iface.name,
      action: "pass",
      protocol: "any",
      source: "any",
      destination: "any",
      description: `Allow routed traffic on ${firewallHost.id}/${iface.name}`
    });
  }

  const hasDmz = interfaces.some((iface: any) => iface.name === "dmz");
  const hasData = interfaces.some((iface: any) => iface.name === "data");
  const hasSoc = interfaces.some((iface: any) => iface.name === "soc");
  const hasManagement = interfaces.some(
    (iface: any) => iface.name === "management"
  );

  if (hasSoc) {
    addRuleOnce(rules, seen, {
      interface: "soc",
      action: "pass",
      protocol: "tcp",
      source: "SOC_NET",
      destination: "OPENCTI_SERVER",
      destinationPort: "8080",
      description: "Allow SOC access to OpenCTI web UI"
    });

    addRuleOnce(rules, seen, {
      interface: "soc",
      action: "pass",
      protocol: "tcp",
      source: "SOC_NET",
      destination: "OPENCTI_SERVER",
      destinationPort: "443",
      description: "Allow SOC HTTPS access to OpenCTI"
    });
  }

  if (hasManagement) {
    addRuleOnce(rules, seen, {
      interface: "management",
      action: "pass",
      protocol: "any",
      source: "MANAGEMENT_NET",
      destination: "any",
      description: "Allow MANAGEMENT outbound and administration"
    });

    addRuleOnce(rules, seen, {
      interface: "management",
      action: "pass",
      protocol: "tcp",
      source: "MANAGEMENT_NET",
      destination: "OPENCTI_SERVER",
      destinationPort: "8080",
      description: "Allow MANAGEMENT access to OpenCTI web UI"
    });

    addRuleOnce(rules, seen, {
      interface: "management",
      action: "pass",
      protocol: "tcp",
      source: "MANAGEMENT_NET",
      destination: "OPENCTI_SERVER",
      destinationPort: "443",
      description: "Allow MANAGEMENT HTTPS access to OpenCTI"
    });

    addRuleOnce(rules, seen, {
      interface: "management",
      action: "pass",
      protocol: "tcp",
      source: "MANAGEMENT_NET",
      destination: "PASSBOLT_SERVER",
      destinationPort: "443",
      description: "Allow MANAGEMENT HTTPS access to Passbolt"
    });
  }

  if (hasDmz) {
    addRuleOnce(rules, seen, {
      interface: "dmz",
      action: "block",
      protocol: "any",
      source: "DMZ_NET",
      destination: "MARIADB_SERVER",
      description: "Block DMZ direct access to MariaDB"
    });

    addRuleOnce(rules, seen, {
      interface: "dmz",
      action: "block",
      protocol: "any",
      source: "DMZ_NET",
      destination: "DB_SERVER",
      description: "Block DMZ direct access to DB server"
    });

    addRuleOnce(rules, seen, {
      interface: "dmz",
      action: "block",
      protocol: "any",
      source: "DMZ_NET",
      destination: "PASSBOLT_SERVER",
      description: "Block DMZ direct access to Passbolt"
    });

    addRuleOnce(rules, seen, {
      interface: "dmz",
      action: "pass",
      protocol: "tcp",
      source: "DMZ_NET",
      destination: "any",
      description: "Allow DMZ TCP outbound"
    });

    addRuleOnce(rules, seen, {
      interface: "dmz",
      action: "pass",
      protocol: "udp",
      source: "DMZ_NET",
      destination: "any",
      destinationPort: "53",
      description: "Allow DMZ DNS outbound"
    });
  }

  if (hasData) {
    addRuleOnce(rules, seen, {
      interface: "data",
      action: "pass",
      protocol: "icmp",
      source: "DATA_NET",
      destination: "ZABBIX_SERVER",
      description: "Allow DATA ICMP to Zabbix for diagnostics"
    });

    addRuleOnce(rules, seen, {
      interface: "data",
      action: "pass",
      protocol: "tcp",
      source: "DATA_NET",
      destination: "ZABBIX_SERVER",
      destinationPort: "10051",
      description: "Allow DATA Zabbix agents active checks"
    });

    addRuleOnce(rules, seen, {
      interface: "data",
      action: "pass",
      protocol: "tcp",
      source: "DATA_NET",
      destination: "WAZUH_SERVER",
      destinationPort: "1514",
      description: "Allow DATA Wazuh agent events"
    });

    addRuleOnce(rules, seen, {
      interface: "data",
      action: "pass",
      protocol: "tcp",
      source: "DATA_NET",
      destination: "WAZUH_SERVER",
      destinationPort: "1515",
      description: "Allow DATA Wazuh agent enrollment"
    });
  }
}

export const generateCoreZoneRules = addCoreZoneRules;