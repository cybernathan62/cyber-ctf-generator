import * as fs from "node:fs";
import { NetworkPlan, NetworkPlanHost } from "./type.js";

import {
  PfSenseAlias,
  PfSenseFirewallRule,
  PfSenseNatRule,
  PfSensePlan
} from "./pfsenseTypes.js";

type Protocol = "tcp" | "udp" | "icmp" | "any";

type RoleFlow = {
  fromRoles: string[];
  toRoles: string[];
  protocol: Protocol;
  ports?: string[];
  description: string;
};

const DB_ROLES = ["db_server", "database", "mariadb_server", "mysql_server"];

const FIREWALL_ROLES = ["edge_firewall", "internal_firewall"];

const WAZUH_AGENT_ROLES = [
  "bastion",
  "reverse_proxy",
  "db_server",
  "database",
  "mariadb_server",
  "mysql_server",
  "ids_sensor",
  "soc_ai_agent",
  "zabbix_server"
];

const ZABBIX_AGENT_ROLES = [
  "bastion",
  "reverse_proxy",
  "db_server",
  "database",
  "mariadb_server",
  "mysql_server",
  "ids_sensor",
  "soc_ai_agent",
  "wazuh_server",
  "zabbix_server"
];

const ROLE_FLOWS: RoleFlow[] = [
  {
    fromRoles: WAZUH_AGENT_ROLES,
    toRoles: ["wazuh_server"],
    protocol: "tcp",
    ports: ["1514", "1515", "55000"],
    description: "Allow Wazuh agents to reach Wazuh manager"
  },
  {
    fromRoles: WAZUH_AGENT_ROLES,
    toRoles: ["wazuh_server"],
    protocol: "icmp",
    description: "Allow Wazuh agents ICMP diagnostic to Wazuh"
  },
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
  },
  {
    fromRoles: ["bastion"],
    toRoles: [...ZABBIX_AGENT_ROLES, "zabbix_server", "wazuh_server"],
    protocol: "tcp",
    ports: ["22"],
    description: "Allow Bastion SSH administration"
  },
  {
    fromRoles: ["bastion"],
    toRoles: [...ZABBIX_AGENT_ROLES, "zabbix_server", "wazuh_server"],
    protocol: "icmp",
    description: "Allow Bastion ICMP diagnostic"
  }
];

function ipOnly(ipCidr: string): string {
  return ipCidr.split("/")[0];
}

function networkFromCidr(ipCidr: string): string {
  const [ip, cidr] = ipCidr.split("/");
  if (!ip || !cidr) throw new Error(`CIDR invalide: ${ipCidr}`);

  const [a, b, c] = ip.split(".");
  if (!a || !b || !c) throw new Error(`IP invalide: ${ipCidr}`);

  return `${a}.${b}.${c}.0/${cidr}`;
}

function aliasName(rawName: string): string {
  return `${rawName.toUpperCase().replace(/[^A-Z0-9_]/g, "_")}_NET`;
}

function roleAliasName(role: string): string {
  return `${role.toUpperCase().replace(/[^A-Z0-9_]/g, "_")}_HOSTS`;
}

function firstIp(host: NetworkPlanHost): string | null {
  const iface = host.interfaces?.find((i: any) => i.ip && i.name !== "monitor");
  const fallback = host.interfaces?.find((i: any) => i.ip);
  return iface?.ip ? ipOnly(iface.ip) : fallback?.ip ? ipOnly(fallback.ip) : null;
}

function findHostsByRoles(
  allHosts: NetworkPlanHost[],
  roles: string[]
): NetworkPlanHost[] {
  return allHosts.filter((h) => roles.includes(h.role));
}

function addAliasOnce(
  aliases: PfSenseAlias[],
  seen: Set<string>,
  alias: PfSenseAlias
): void {
  if (seen.has(alias.name)) return;
  seen.add(alias.name);
  aliases.push(alias);
}

function addRuleOnce(
  rules: PfSenseFirewallRule[],
  seen: Set<string>,
  rule: PfSenseFirewallRule
): void {
  const key = JSON.stringify(rule);
  if (seen.has(key)) return;
  seen.add(key);
  rules.push(rule);
}

function addHostAliasByRoles(
  aliases: PfSenseAlias[],
  seen: Set<string>,
  allHosts: NetworkPlanHost[],
  alias: string,
  roles: string[],
  description: string
): void {
  const values = findHostsByRoles(allHosts, roles)
    .map(firstIp)
    .filter((ip): ip is string => Boolean(ip));

  if (values.length === 0) return;

  addAliasOnce(aliases, seen, {
    name: alias,
    type: "host",
    values,
    description
  });
}

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
    "MARIADB_SERVER",
    DB_ROLES,
    "MariaDB or DB server"
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

  const roles = new Set(allHosts.map((h) => h.role).filter(Boolean));
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

function generateAliases(
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

function addRuleOnEveryNonWanInterface(
  rules: PfSenseFirewallRule[],
  seen: Set<string>,
  firewallHost: NetworkPlanHost,
  source: string,
  destination: string,
  protocol: Protocol,
  description: string,
  ports?: string[]
): void {
  for (const iface of firewallHost.interfaces ?? []) {
    if (!iface.name || !iface.ip || iface.name === "wan") continue;

    if (protocol === "icmp" || protocol === "any") {
      addRuleOnce(rules, seen, {
        interface: iface.name,
        action: "pass",
        protocol,
        source,
        destination,
        description: `${description} via ${iface.name}`
      });
      continue;
    }

    for (const port of ports ?? []) {
      addRuleOnce(rules, seen, {
        interface: iface.name,
        action: "pass",
        protocol,
        source,
        destination,
        destinationPort: port,
        description: `${description} ${protocol.toUpperCase()}/${port} via ${iface.name}`
      });
    }
  }
}

function addRoleToRoleRules(
  rules: PfSenseFirewallRule[],
  seen: Set<string>,
  firewallHost: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): void {
  for (const flow of ROLE_FLOWS) {
    const sources = findHostsByRoles(allHosts, flow.fromRoles);
    const destinations = findHostsByRoles(allHosts, flow.toRoles);

    if (sources.length === 0 || destinations.length === 0) continue;

    for (const sourceHost of sources) {
      const sourceIp = firstIp(sourceHost);
      if (!sourceIp) continue;

      for (const destinationHost of destinations) {
        const destinationIp = firstIp(destinationHost);
        if (!destinationIp || sourceIp === destinationIp) continue;

        addRuleOnEveryNonWanInterface(
          rules,
          seen,
          firewallHost,
          sourceIp,
          destinationIp,
          flow.protocol,
          `${flow.description}: ${sourceHost.id} -> ${destinationHost.id}`,
          flow.ports
        );
      }
    }
  }
}

function addCoreZoneRules(
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

  /*
   * Transit interfaces are router-to-router links.
   * They must accept routed traffic carrying original source IPs
   * from remote zones, otherwise SOC->DATA and DATA->SOC flows die.
   */
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
  const hasManagement = interfaces.some((iface: any) => iface.name === "management");

  if (hasManagement) {
    addRuleOnce(rules, seen, {
      interface: "management",
      action: "pass",
      protocol: "any",
      source: "MANAGEMENT_NET",
      destination: "any",
      description: "Allow MANAGEMENT outbound and administration"
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

  /*
   * Do not add a broad DATA_NET -> any block here.
   * pfSense evaluates rules top-down, but keeping a hard block in the
   * generated plan made debugging painful and broke monitoring flows
   * whenever the XML builder reordered rules.
   */
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

function generateRules(
  firewallHost: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): PfSenseFirewallRule[] {
  const rules: PfSenseFirewallRule[] = [];
  const seen = new Set<string>();

  addCoreZoneRules(rules, seen, firewallHost);
  addRoleToRoleRules(rules, seen, firewallHost, allHosts);

  return rules;
}

function generateNat(
  firewallHost: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): PfSenseNatRule[] {
  const nat: PfSenseNatRule[] = [];

  if (firewallHost.role !== "edge_firewall") return nat;

  const reverseProxy = allHosts.find((h) => h.role === "reverse_proxy");
  if (!reverseProxy) return nat;

  const dmzInterface = reverseProxy.interfaces?.find((i: any) =>
    String(i.network_id).includes("dmz")
  );

  if (!dmzInterface?.ip) return nat;

  const reverseProxyIp = ipOnly(dmzInterface.ip);

  nat.push({
    interface: "wan",
    protocol: "tcp",
    externalPort: "443",
    internalIp: reverseProxyIp,
    internalPort: "443",
    description: "HTTPS to reverse proxy"
  });

  nat.push({
    interface: "wan",
    protocol: "tcp",
    externalPort: "80",
    internalIp: reverseProxyIp,
    internalPort: "80",
    description: "HTTP to reverse proxy"
  });

  return nat;
}

export function generatePfSenseMinimalPlan(
  networkPlanPath: string,
  outputPath: string
): void {
  const networkPlan = JSON.parse(
    fs.readFileSync(networkPlanPath, "utf-8")
  ) as NetworkPlan;

  const firewallHosts = networkPlan.hosts.filter(
    (h) => h.profile === "pfsense"
  );

  const plans: PfSensePlan[] = [];

  for (const firewallHost of firewallHosts) {
    plans.push({
      firewall: firewallHost.id,
      aliases: generateAliases(firewallHost, networkPlan.hosts),
      rules: generateRules(firewallHost, networkPlan.hosts),
      nat: generateNat(firewallHost, networkPlan.hosts)
    });
  }

  fs.writeFileSync(outputPath, JSON.stringify(plans, null, 2), "utf-8");

  console.log(`[pfSense] Plan minimal généré : ${outputPath}`);
}
