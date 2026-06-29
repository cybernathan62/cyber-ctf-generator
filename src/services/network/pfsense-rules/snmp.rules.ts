import type { NetworkPlanHost } from "../../core/type.js";
import type { PfSenseFirewallRule } from "../../core/pfsenseTypes.js";

import {
  addRuleOnce,
  findHostsByRoles,
  firstIp,
  ipOnly
} from "./helpers.js";

export function addPfSenseSnmpRules(
  rules: PfSenseFirewallRule[],
  seen: Set<string>,
  firewallHost: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): void {
  const zabbixHosts = findHostsByRoles(allHosts, ["zabbix_server"]);
  const zabbixIps = zabbixHosts
    .map(firstIp)
    .filter((ip): ip is string => Boolean(ip));

  if (zabbixIps.length === 0) return;

  const interfaces = (firewallHost.interfaces ?? []).filter(
    (iface: any) => iface.name && iface.ip && iface.name !== "wan"
  );

  for (const iface of interfaces) {
    const firewallInterfaceIp = ipOnly(String(iface.ip));

    for (const zabbixIp of zabbixIps) {
      addRuleOnce(rules, seen, {
        interface: iface.name,
        action: "pass",
        protocol: "udp",
        source: zabbixIp,
        destination: firewallInterfaceIp,
        destinationPort: "161",
        description: `Allow Zabbix SNMP polling to ${firewallHost.id}/${iface.name}`
      });

      addRuleOnce(rules, seen, {
        interface: iface.name,
        action: "pass",
        protocol: "icmp",
        source: zabbixIp,
        destination: firewallInterfaceIp,
        description: `Allow Zabbix ICMP ping to ${firewallHost.id}/${iface.name}`
      });
    }
  }
}

export const generatePfSenseSnmpRules = addPfSenseSnmpRules;