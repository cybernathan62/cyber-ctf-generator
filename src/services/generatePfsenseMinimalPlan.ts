import * as fs from "node:fs";
import { NetworkPlan, NetworkPlanHost } from "./type.js";

import {
  PfSenseAlias,
  PfSenseFirewallRule,
  PfSenseNatRule,
  PfSensePlan
} from "./pfsenseTypes.js";

function networkFromCidr(ipCidr: string): string {
  const [ip, cidr] = ipCidr.split("/");

  if (!ip || !cidr) {
    throw new Error(`CIDR invalide: ${ipCidr}`);
  }

  const [a, b, c] = ip.split(".");

  if (!a || !b || !c) {
    throw new Error(`IP invalide: ${ipCidr}`);
  }

  return `${a}.${b}.${c}.0/${cidr}`;
}

function ipOnly(ipCidr: string): string {
  return ipCidr.split("/")[0];
}

function aliasName(interfaceName: string): string {
  return `${interfaceName.toUpperCase()}_NET`;
}

function findWazuhIp(allHosts: NetworkPlanHost[]): string | null {
  const wazuh = allHosts.find((h) => h.role === "wazuh_server");

  if (!wazuh) {
    return null;
  }

  const iface = wazuh.interfaces?.find((i: any) => i.ip);

  if (!iface?.ip) {
    return null;
  }

  return ipOnly(iface.ip);
}

function findWazuhNetwork(allHosts: NetworkPlanHost[]): string | null {
  const wazuh = allHosts.find((h) => h.role === "wazuh_server");

  if (!wazuh) {
    return null;
  }

  const iface = wazuh.interfaces?.find((i: any) => i.ip);

  if (!iface?.ip) {
    return null;
  }

  return networkFromCidr(iface.ip);
}

function generateAliases(
  host: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): PfSenseAlias[] {
  const aliases: PfSenseAlias[] = [];

  const seen = new Set<string>();

  for (const iface of host.interfaces ?? []) {
    if (!iface.name || !iface.ip || iface.name === "wan") continue;

    const name = aliasName(iface.name);

    if (seen.has(name)) continue;
    seen.add(name);

    aliases.push({
      name,
      type: "network",
      values: [networkFromCidr(iface.ip)],
      description: `Network for ${iface.name}`
    });
  }

  const wazuhIp = findWazuhIp(allHosts);

  if (wazuhIp) {
    aliases.push({
      name: "WAZUH_SERVER",
      type: "host",
      values: [wazuhIp],
      description: "Wazuh manager"
    });
  }

  return aliases;
}

function addWazuhAgentRules(
  rules: PfSenseFirewallRule[],
  host: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): void {
  const wazuhIp = findWazuhIp(allHosts);
  const wazuhNetwork = findWazuhNetwork(allHosts);

  if (!wazuhIp || !wazuhNetwork) {
    return;
  }

  for (const iface of host.interfaces ?? []) {
    if (!iface.name || !iface.ip || iface.name === "wan") continue;

    const sourceNetwork = networkFromCidr(iface.ip);

    /*
      Si l'interface pfSense est déjà dans le même réseau que Wazuh,
      inutile d'ajouter une règle "zone -> Wazuh" sur ce firewall.
    */
    if (sourceNetwork === wazuhNetwork) {
      continue;
    }

    const sourceAlias = aliasName(iface.name);

    rules.push({
      interface: iface.name,
      action: "pass",
      protocol: "tcp",
      source: sourceAlias,
      destination: "WAZUH_SERVER",
      destinationPorts: "1514-1515",
      description: `Allow ${sourceAlias} to Wazuh agent enrollment and events`
    });

    rules.push({
      interface: iface.name,
      action: "pass",
      protocol: "tcp",
      source: sourceAlias,
      destination: "WAZUH_SERVER",
      destinationPorts: "55000",
      description: `Allow ${sourceAlias} to Wazuh manager API`
    });
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

  /*
    Wazuh global :
    tous les réseaux internes qui passent par ce firewall peuvent joindre
    le manager Wazuh pour enrollment/logs/API.
  */
  addWazuhAgentRules(rules, host, allHosts);

  /*
    EDGE firewall :
    Bloquer DMZ vers DATA
  */
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

  /*
    DMZ outbound minimal
  */
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

  /*
    Transit EDGE -> DATA
  */
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

  /*
    Transit -> DATA
  */
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

  /*
    DATA deny default
  */
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

  /*
    MANAGEMENT outbound
  */
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

  return rules;
}

function generateNat(
  firewallHost: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): PfSenseNatRule[] {
  const nat: PfSenseNatRule[] = [];

  if (firewallHost.role !== "edge_firewall") {
    return nat;
  }

  const reverseProxy = allHosts.find((h) => h.role === "reverse_proxy");

  if (!reverseProxy) {
    return nat;
  }

  const dmzInterface = reverseProxy.interfaces?.find((i: any) =>
    String(i.network_id).includes("dmz")
  );

  if (!dmzInterface?.ip) {
    return nat;
  }

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