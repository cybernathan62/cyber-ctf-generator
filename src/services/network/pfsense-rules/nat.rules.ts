import type { NetworkPlanHost } from "../../core/type.js";
import type { PfSenseNatRule } from "../../core/pfsenseTypes.js";

import { ipOnly } from "./helpers.js";

function findReverseProxy(allHosts: NetworkPlanHost[]): NetworkPlanHost | null {
  return allHosts.find((host) => host.role === "reverse_proxy") ?? null;
}

function findDmzInterface(host: NetworkPlanHost): any | null {
  return (
    host.interfaces?.find((iface: any) =>
      String(iface.network_id ?? "").includes("dmz")
    ) ??
    host.interfaces?.find((iface: any) =>
      String(iface.name ?? "").includes("dmz")
    ) ??
    null
  );
}

export function generateNatRules(
  firewallHost: NetworkPlanHost,
  allHosts: NetworkPlanHost[]
): PfSenseNatRule[] {
  const nat: PfSenseNatRule[] = [];

  if (firewallHost.role !== "edge_firewall") {
    return nat;
  }

  const reverseProxy = findReverseProxy(allHosts);
  if (!reverseProxy) {
    return nat;
  }

  const dmzInterface = findDmzInterface(reverseProxy);
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

export const generateNat = generateNatRules;