import * as fs from "node:fs";
import * as path from "node:path";

type HostInterface = {
  name: string;
  network_id: string;
  ip?: string;
  gateway?: string | null;
  dns?: string[];
  mode?: "dhcp";
};

type Host = {
  id: string;
  role: string;
  profile: string;
  interfaces: HostInterface[];
};

type ZoneDefinition = {
  network_id: string;
  vlan_id: number;
  cidr: string;
  gateway: string;
  zone_type: string;
};

type NetworkPlan = {
  hosts: Host[];
  zone_definitions: ZoneDefinition[];
};

type Alias = {
  name: string;
  type: "host" | "network";
  values: string[];
  description: string;
};

function ipOnly(cidr?: string): string | null {
  if (!cidr) return null;
  return cidr.split("/")[0] || null;
}

function hostIpsByRole(plan: NetworkPlan, role: string): string[] {
  const ips: string[] = [];

  for (const host of plan.hosts) {
    if (host.role !== role) continue;

    for (const iface of host.interfaces) {
      const ip = ipOnly(iface.ip);
      if (ip) ips.push(ip);
    }
  }

  return [...new Set(ips)];
}

function zoneCidrs(plan: NetworkPlan, networkId: string): string[] {
  return plan.zone_definitions
    .filter((z) => z.network_id === networkId)
    .map((z) => z.cidr);
}

function buildAliases(plan: NetworkPlan): Alias[] {
  const aliases: Alias[] = [];

  const wazuhIps = hostIpsByRole(plan, "wazuh_server");
  if (wazuhIps.length > 0) {
    aliases.push({
      name: "ALIAS_WAZUH_SERVERS",
      type: "host",
      values: wazuhIps,
      description: "All Wazuh server IPs"
    });
  }

  const dbIps = hostIpsByRole(plan, "db_server");
  if (dbIps.length > 0) {
    aliases.push({
      name: "ALIAS_DB_SERVERS",
      type: "host",
      values: dbIps,
      description: "All DB server IPs"
    });
  }

  const bastionIps = hostIpsByRole(plan, "bastion");
  if (bastionIps.length > 0) {
    aliases.push({
      name: "ALIAS_BASTION_HOSTS",
      type: "host",
      values: bastionIps,
      description: "All bastion host IPs"
    });
  }

  const mgmtCidrs = zoneCidrs(plan, "management-net");
  if (mgmtCidrs.length > 0) {
    aliases.push({
      name: "ALIAS_MGMT_NET",
      type: "network",
      values: mgmtCidrs,
      description: "Management network CIDRs"
    });
  }

  const socCidrs = zoneCidrs(plan, "soc-net");
  if (socCidrs.length > 0) {
    aliases.push({
      name: "ALIAS_SOC_NET",
      type: "network",
      values: socCidrs,
      description: "SOC network CIDRs"
    });
  }

  const dataCidrs = zoneCidrs(plan, "data-net");
  if (dataCidrs.length > 0) {
    aliases.push({
      name: "ALIAS_DATA_NET",
      type: "network",
      values: dataCidrs,
      description: "Data network CIDRs"
    });
  }

  const dmzCidrs = zoneCidrs(plan, "dmz-net");
  if (dmzCidrs.length > 0) {
    aliases.push({
      name: "ALIAS_DMZ_NET",
      type: "network",
      values: dmzCidrs,
      description: "DMZ network CIDRs"
    });
  }

  const transitCidrs = zoneCidrs(plan, "core-transit-net");
  if (transitCidrs.length > 0) {
    aliases.push({
      name: "ALIAS_TRANSIT_NET",
      type: "network",
      values: transitCidrs,
      description: "Transit network CIDRs"
    });
  }

  return aliases;
}

function main() {
  const outputRoot = path.join(process.cwd(), "outputs");
  const networkPlanPath = path.join(outputRoot, "network-plan.json");
  const aliasesPath = path.join(outputRoot, "pfsense-aliases-plan.json");

  if (!fs.existsSync(networkPlanPath)) {
    throw new Error(`network-plan.json introuvable: ${networkPlanPath}`);
  }

  const raw = fs.readFileSync(networkPlanPath, "utf-8");
  const plan = JSON.parse(raw) as NetworkPlan;

  const aliases = buildAliases(plan);

  fs.writeFileSync(
    aliasesPath,
    JSON.stringify({ aliases }, null, 2),
    "utf-8"
  );

  console.log(`Aliases pfSense générés : ${aliasesPath}`);
  console.log(JSON.stringify({ aliases }, null, 2));
}

main();