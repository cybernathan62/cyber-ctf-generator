import type { NetworkPlanHost } from "../../core/type.js";

import type { PfSenseFirewallRule } from "../../core/pfsenseTypes.js";

import type { Protocol, RoleFlow } from "../../core/roles.js";

import { ALL_ROLE_FLOWS } from "./index.js";

import {
  addRuleOnce,
  findHostsByRoles,
  firstIp
} from "./helpers.js";

const ROLE_FLOWS: RoleFlow[] = ALL_ROLE_FLOWS;

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

export function addRoleToRoleRules(
  rules: PfSenseFirewallRule[],
  seen: Set<string>,
  firewallHost: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): void {
  for (const flow of ROLE_FLOWS) {
    if (flow.toRoles.includes("any")) {
      const sources = findHostsByRoles(allHosts, flow.fromRoles);

      if (sources.length === 0) continue;

      for (const sourceHost of sources) {
        const sourceIp = firstIp(sourceHost);
        if (!sourceIp) continue;

        addRuleOnEveryNonWanInterface(
          rules,
          seen,
          firewallHost,
          sourceIp,
          "any",
          flow.protocol,
          `${flow.description}: ${sourceHost.id} -> any`,
          flow.ports
        );
      }

      continue;
    }

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

export function generateRoleFlowRules(
  firewallHost: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): PfSenseFirewallRule[] {
  const rules: PfSenseFirewallRule[] = [];
  const seen = new Set<string>();

  addRoleToRoleRules(rules, seen, firewallHost, allHosts);

  return rules;
}