import * as fs from "node:fs";
import { NetworkPlan, NetworkPlanHost } from "./type.js";

import {
  PfSenseAlias,
  PfSenseFirewallRule,
  PfSenseNatRule,
  PfSensePlan
} from "./pfsenseTypes.js";

type RoleFlow = {
  fromRoles: string[];
  toRoles: string[];
  protocol: "tcp" | "udp" | "icmp" | "any";
  ports?: string[];
  description: string;
};

const AGENT_ROLES = [
  "bastion",
  "reverse_proxy",
  "db_server",
  "database",
  "mariadb_server",
  "mysql_server",
  "wazuh_server",
  "ids_sensor",
  "soc_ai_agent"
];

const DB_ROLES = ["db_server", "database", "mariadb_server", "mysql_server"];

const ROLE_FLOWS: RoleFlow[] = [
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
    toRoles: AGENT_ROLES,
    protocol: "tcp",
    ports: ["10050"],
    description: "Allow Zabbix server to poll agents"
  },
  {
    fromRoles: AGENT_ROLES,
    toRoles: ["zabbix_server"],
    protocol: "tcp",
    ports: ["10051"],
    description: "Allow Zabbix agents active checks to server"
  },
  {
    fromRoles: AGENT_ROLES,
    toRoles: ["zabbix_server"],
    protocol: "icmp",
    description: "Allow agents ICMP diagnostic to Zabbix"
  },
  {
    fromRoles: ["wazuh_server"],
    toRoles: DB_ROLES,
    protocol: "tcp",
    ports: ["22", "10050"],
    description: "Allow Wazuh supervision access to DB server"
  },
  {
    fromRoles: ["bastion"],
    toRoles: [...AGENT_ROLES, "zabbix_server"],
    protocol: "tcp",
    ports: ["22"],
    description: "Allow Bastion SSH administration"
  },
  {
    fromRoles: ["bastion"],
    toRoles: [...AGENT_ROLES, "zabbix_server"],
    protocol: "icmp",
    description: "Allow Bastion ICMP diagnostic"
  }
];

function networkFromCidr(ipCidr: string): string {
  const [ip, cidr] = ipCidr.split("/");
  if (!ip || !cidr) throw new Error(`CIDR invalide: ${ipCidr}`);

  const [a, b, c] = ip.split(".");
  if (!a || !b || !c) throw new Error(`IP invalide: ${ipCidr}`);

  return `${a}.${b}.${c}.0/${cidr}`;
}

function ipOnly(ipCidr: string): string {
  return ipCidr.split("/")[0];
}

function aliasName(interfaceName: string): string {
  return `${interfaceName.toUpperCase()}_NET`;
}

function firstIp(host: NetworkPlanHost): string | null {
  const iface = host.interfaces?.find((i: any) => i.ip);
  return iface?.ip ? ipOnly(iface.ip) : null;
}

function firstNetwork(host: NetworkPlanHost): string | null {
  const iface = host.interfaces?.find((i: any) => i.ip);
  return iface?.ip ? networkFromCidr(iface.ip) : null;
}

function findHostsByRoles(
  allHosts: NetworkPlanHost[],
  roles: string[]
): NetworkPlanHost[] {
  return allHosts.filter((h) => roles.includes(h.role));
}

function findHostIpByRoles(
  allHosts: NetworkPlanHost[],
  roles: string[]
): string | null {
  const host = allHosts.find((h) => roles.includes(h.role));
  return host ? firstIp(host) : null;
}

function findWazuhIp(allHosts: NetworkPlanHost[]): string | null {
  return findHostIpByRoles(allHosts, ["wazuh_server"]);
}

function findWazuhNetwork(allHosts: NetworkPlanHost[]): string | null {
  const wazuh = allHosts.find((h) => h.role === "wazuh_server");
  return wazuh ? firstNetwork(wazuh) : null;
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

function addServiceAliases(
  aliases: PfSenseAlias[],
  seen: Set<string>,
  allHosts: NetworkPlanHost[]
): void {
  const zabbixHosts = findHostsByRoles(allHosts, ["zabbix_server"]);
  const mariadbHosts = findHostsByRoles(allHosts, DB_ROLES);

  const zabbixIps = zabbixHosts.map(firstIp).filter((ip): ip is string => Boolean(ip));
  const mariadbIps = mariadbHosts.map(firstIp).filter((ip): ip is string => Boolean(ip));

  if (zabbixIps.length > 0) {
    addAliasOnce(aliases, seen, {
      name: "ZABBIX_SERVER",
      type: "host",
      values: [zabbixIps[0]],
      description: "Primary Zabbix server"
    });

    addAliasOnce(aliases, seen, {
      name: "ZABBIX_SERVERS",
      type: "host",
      values: zabbixIps,
      description: "All Zabbix servers"
    });
  }

  if (mariadbIps.length > 0) {
    addAliasOnce(aliases, seen, {
      name: "MARIADB_SERVER",
      type: "host",
      values: [mariadbIps[0]],
      description: "Primary MariaDB server"
    });

    addAliasOnce(aliases, seen, {
      name: "MARIADB_SERVERS",
      type: "host",
      values: mariadbIps,
      description: "All MariaDB or DB servers"
    });
  }
}

function generateAliases(
  host: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): PfSenseAlias[] {
  const aliases: PfSenseAlias[] = [];
  const seen = new Set<string>();

  for (const iface of host.interfaces ?? []) {
    if (!iface.name || !iface.ip || iface.name === "wan") continue;

    addAliasOnce(aliases, seen, {
      name: aliasName(iface.name),
      type: "network",
      values: [networkFromCidr(iface.ip)],
      description: `Network for ${iface.name}`
    });
  }

  const wazuhIp = findWazuhIp(allHosts);

  if (wazuhIp) {
    addAliasOnce(aliases, seen, {
      name: "WAZUH_SERVER",
      type: "host",
      values: [wazuhIp],
      description: "Wazuh manager, API, dashboard and indexer"
    });
  }

  addServiceAliases(aliases, seen, allHosts);

  return aliases;
}

function addDeploymentRules(
  rules: PfSenseFirewallRule[],
  ifaceName: string,
  sourceAlias: string
): void {
  for (const protocol of ["udp", "tcp"] as const) {
    rules.push({
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
    rules.push({
      interface: ifaceName,
      action: "pass",
      protocol: "tcp",
      source: sourceAlias,
      destination: "any",
      destinationPort: port,
      description: `Allow ${sourceAlias} deployment TCP ${port}`
    });
  }

  rules.push({
    interface: ifaceName,
    action: "pass",
    protocol: "udp",
    source: sourceAlias,
    destination: "any",
    destinationPort: "123",
    description: `Allow ${sourceAlias} NTP`
  });
}

function addWazuhRules(
  rules: PfSenseFirewallRule[],
  host: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): void {
  const wazuhIp = findWazuhIp(allHosts);
  const wazuhNetwork = findWazuhNetwork(allHosts);

  if (!wazuhIp || !wazuhNetwork) return;

  for (const iface of host.interfaces ?? []) {
    if (!iface.name || !iface.ip || iface.name === "wan") continue;

    const sourceNetwork = networkFromCidr(iface.ip);
    if (sourceNetwork === wazuhNetwork) continue;

    for (const protocol of ["tcp", "udp"] as const) {
      rules.push({
        interface: iface.name,
        action: "pass",
        protocol,
        source: "any",
        destination: "WAZUH_SERVER",
        destinationPort: "1514",
        description: `Allow traffic entering ${iface.name} to Wazuh ${protocol.toUpperCase()} 1514`
      });
    }

    for (const port of ["1515", "55000", "5601", "9200"]) {
      rules.push({
        interface: iface.name,
        action: "pass",
        protocol: "tcp",
        source: "any",
        destination: "WAZUH_SERVER",
        destinationPort: port,
        description: `Allow traffic entering ${iface.name} to Wazuh TCP ${port}`
      });
    }
  }
}

function addRoleToRoleRules(
  rules: PfSenseFirewallRule[],
  host: NetworkPlanHost,
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
        if (!destinationIp) continue;
        if (sourceIp === destinationIp) continue;

        for (const iface of host.interfaces ?? []) {
          if (!iface.name || !iface.ip || iface.name === "wan") continue;

          if (flow.protocol === "icmp" || flow.protocol === "any") {
            rules.push({
              interface: iface.name,
              action: "pass",
              protocol: flow.protocol,
              source: sourceIp,
              destination: destinationIp,
              description: `${flow.description}: ${sourceHost.id} -> ${destinationHost.id} via ${iface.name}`
            });
            continue;
          }

          for (const port of flow.ports ?? []) {
            rules.push({
              interface: iface.name,
              action: "pass",
              protocol: flow.protocol,
              source: sourceIp,
              destination: destinationIp,
              destinationPort: port,
              description: `${flow.description}: ${sourceHost.id} -> ${destinationHost.id} ${flow.protocol.toUpperCase()}/${port} via ${iface.name}`
            });
          }
        }
      }
    }
  }
}

function generateRules(
  host: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): PfSenseFirewallRule[] {
  const rules: PfSenseFirewallRule[] = [];

  const interfaces = (host.interfaces ?? []).filter(
    (iface: any) => iface.name && iface.ip && iface.name !== "wan"
  );

  const interfaceNames = interfaces.map((iface: any) => iface.name);

  const hasDmz = interfaceNames.includes("dmz");
  const hasTransitData = interfaceNames.includes("transit_data");
  const hasTransit = interfaceNames.includes("transit");
  const hasData = interfaceNames.includes("data");

  for (const iface of interfaces) {
    addDeploymentRules(rules, iface.name, aliasName(iface.name));
  }

  addWazuhRules(rules, host, allHosts);
  addRoleToRoleRules(rules, host, allHosts);

  if (hasDmz && hasTransitData) {
    rules.push({
      interface: "dmz",
      action: "block",
      protocol: "any",
      source: "DMZ_NET",
      destination: "DATA_NET",
      description: "Block DMZ to DATA"
    });
  }

  if (hasDmz) {
    rules.push({
      interface: "dmz",
      action: "pass",
      protocol: "tcp",
      source: "DMZ_NET",
      destination: "any",
      description: "Allow DMZ TCP outbound"
    });

    rules.push({
      interface: "dmz",
      action: "pass",
      protocol: "udp",
      source: "DMZ_NET",
      destination: "any",
      destinationPort: "53",
      description: "Allow DMZ DNS outbound"
    });
  }

  if (hasTransitData) {
    rules.push({
      interface: "transit_data",
      action: "pass",
      protocol: "any",
      source: "TRANSIT_DATA_NET",
      destination: "DATA_NET",
      description: "Allow EDGE transit to DATA firewall"
    });
  }

  if (hasTransit && hasData) {
    rules.push({
      interface: "transit",
      action: "pass",
      protocol: "any",
      source: "TRANSIT_NET",
      destination: "DATA_NET",
      description: "Allow transit to DATA"
    });
  }

  if (interfaceNames.includes("management")) {
    rules.push({
      interface: "management",
      action: "pass",
      protocol: "icmp",
      source: "MANAGEMENT_NET",
      destination: "any",
      description: "Allow MANAGEMENT ICMP"
    });

    rules.push({
      interface: "management",
      action: "pass",
      protocol: "any",
      source: "MANAGEMENT_NET",
      destination: "any",
      description: "Allow MANAGEMENT outbound"
    });
  }

  if (hasData) {
    rules.push({
      interface: "data",
      action: "block",
      protocol: "any",
      source: "DATA_NET",
      destination: "any",
      description: "Block DATA outbound by default"
    });
  }

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

  for (const host of firewallHosts) {
    plans.push({
      firewall: host.id,
      aliases: generateAliases(host, networkPlan.hosts),
      rules: generateRules(host, networkPlan.hosts),
      nat: generateNat(host, networkPlan.hosts)
    });
  }

  fs.writeFileSync(outputPath, JSON.stringify(plans, null, 2), "utf-8");

  console.log(`[pfSense] Plan minimal généré : ${outputPath}`);
}