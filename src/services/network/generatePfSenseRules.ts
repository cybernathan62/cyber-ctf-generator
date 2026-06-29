import * as fs from "node:fs";

import type { NetworkPlan, NetworkPlanHost } from "../core/type.js";

import type {
  PfSenseFirewallRule,
  PfSensePlan
} from "../core/pfsenseTypes.js";

import { generateAliases } from "./pfsense-rules/aliases.js";
import { generateNatRules } from "./pfsense-rules/nat.rules.js";
import { addPfSenseSnmpRules } from "./pfsense-rules/snmp.rules.js";
import { addCoreZoneRules } from "./pfsense-rules/core-zone.rules.js";
import { addRoleToRoleRules } from "./pfsense-rules/role-flow-engine.js";

function generateRules(
  firewallHost: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): PfSenseFirewallRule[] {
  const rules: PfSenseFirewallRule[] = [];
  const seen = new Set<string>();

  addCoreZoneRules(rules, seen, firewallHost);
  addPfSenseSnmpRules(rules, seen, firewallHost, allHosts);
  addRoleToRoleRules(rules, seen, firewallHost, allHosts);

  return rules;
}

export function generatePfSenseRules(
  networkPlanPath: string,
  outputPath: string
): void {
  const networkPlan = JSON.parse(
    fs.readFileSync(networkPlanPath, "utf-8")
  ) as NetworkPlan;

  const firewallHosts = networkPlan.hosts.filter(
    (host) => host.profile === "pfsense"
  );

  const plans: PfSensePlan[] = [];

  for (const firewallHost of firewallHosts) {
    plans.push({
      firewall: firewallHost.id,
      aliases: generateAliases(firewallHost, networkPlan.hosts),
      rules: generateRules(firewallHost, networkPlan.hosts),
      nat: generateNatRules(firewallHost, networkPlan.hosts)
    });
  }

  fs.writeFileSync(outputPath, JSON.stringify(plans, null, 2), "utf-8");

  console.log(`[pfSense] Règles générées : ${outputPath}`);
}