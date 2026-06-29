import type { NetworkPlanHost } from "../../core/type.js";

import type {
  PfSenseAlias,
  PfSenseFirewallRule
} from "../../core/pfsenseTypes.js";

export function ipOnly(ipCidr: string): string {
  return ipCidr.split("/")[0];
}

export function ipv4ToNumber(ip: string): number {
  const parts = ip.split(".").map((part) => Number(part));

  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    throw new Error(`IPv4 invalide: ${ip}`);
  }

  return (
    ((parts[0] << 24) >>> 0) +
    ((parts[1] << 16) >>> 0) +
    ((parts[2] << 8) >>> 0) +
    (parts[3] >>> 0)
  ) >>> 0;
}

export function numberToIpv4(value: number): string {
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255
  ].join(".");
}

export function networkFromCidr(ipCidr: string): string {
  const [ip, cidrRaw] = ipCidr.split("/");
  const cidr = Number(cidrRaw);

  if (!ip || !Number.isInteger(cidr) || cidr < 0 || cidr > 32) {
    throw new Error(`CIDR invalide: ${ipCidr}`);
  }

  const ipNumber = ipv4ToNumber(ip);
  const mask = cidr === 0 ? 0 : (0xffffffff << (32 - cidr)) >>> 0;
  const network = ipNumber & mask;

  return `${numberToIpv4(network)}/${cidr}`;
}

export function aliasName(rawName: string): string {
  return `${rawName.toUpperCase().replace(/[^A-Z0-9_]/g, "_")}_NET`;
}

export function roleAliasName(role: string): string {
  return `${role.toUpperCase().replace(/[^A-Z0-9_]/g, "_")}_HOSTS`;
}

export function firstIp(host: NetworkPlanHost): string | null {
  const iface = host.interfaces?.find((i: any) => i.ip && i.name !== "monitor");
  const fallback = host.interfaces?.find((i: any) => i.ip);

  return iface?.ip ? ipOnly(iface.ip) : fallback?.ip ? ipOnly(fallback.ip) : null;
}

export function findHostsByRoles(
  allHosts: NetworkPlanHost[],
  roles: string[]
): NetworkPlanHost[] {
  if (roles.includes("any")) {
    return allHosts.filter((host) => host.profile !== "pfsense");
  }

  return allHosts.filter((host) => roles.includes(host.role));
}

export function addAliasOnce(
  aliases: PfSenseAlias[],
  seen: Set<string>,
  alias: PfSenseAlias
): void {
  if (seen.has(alias.name)) return;

  seen.add(alias.name);
  aliases.push(alias);
}

export function addRuleOnce(
  rules: PfSenseFirewallRule[],
  seen: Set<string>,
  rule: PfSenseFirewallRule
): void {
  const key = JSON.stringify(rule);

  if (seen.has(key)) return;

  seen.add(key);
  rules.push(rule);
}

export function addHostAliasByRoles(
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