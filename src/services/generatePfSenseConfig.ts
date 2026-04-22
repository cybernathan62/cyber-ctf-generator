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

type HostEntry = {
  id: string;
  role: string;
  profile: string;
  interfaces: HostInterface[];
};

type NetworkPlan = {
  lab_name: string;
  lab_id: number;
  generation_mode: string;
  rules: {
    ip_schema: string;
    gateway_strategy: string;
    host_strategy: string;
    vlan_range: [number, number];
    host_range: [number, number];
    reserved_hosts: number[];
  };
  zone_definitions: Array<{
    network_id: string;
    vlan_id: number;
    cidr: string;
    gateway: string;
    zone_type: string;
  }>;
  hosts: HostEntry[];
};

type PfSenseInterfacePlan = {
  pf_name: string;
  iface_name: string;
  network_id: string;
  mode: "dhcp" | "static";
  ip: string | null;
  gateway: string | null;
  role_hint: string;
};

type PfSenseHostPlan = {
  host_id: string;
  role: string;
  interfaces: PfSenseInterfacePlan[];
};

type PfSenseConfigPlan = {
  generated_from: string;
  pf_hosts: PfSenseHostPlan[];
};

function roleHintFromNetworkId(networkId: string): string {
  switch (networkId) {
    case "edge-wan":
      return "wan";
    case "management-net":
      return "lan_or_mgmt";
    case "dmz-net":
      return "dmz";
    case "soc-net":
      return "soc";
    case "data-net":
      return "data";
    case "core-transit-net":
      return "transit";
    default:
      return "other";
  }
}

function main() {
  const outputRoot = path.join(process.cwd(), "outputs");
  const networkPlanPath = path.join(outputRoot, "network-plan.json");
  const pfSensePlanPath = path.join(outputRoot, "pfsense-config-plan.json");

  if (!fs.existsSync(networkPlanPath)) {
    throw new Error(`network-plan.json introuvable: ${networkPlanPath}`);
  }

  const raw = fs.readFileSync(networkPlanPath, "utf-8");
  const networkPlan = JSON.parse(raw) as NetworkPlan;

  const pfHosts = networkPlan.hosts
    .filter((host) => host.profile === "pfsense")
    .map((host) => {
      const interfaces: PfSenseInterfacePlan[] = host.interfaces.map((iface) => ({
        pf_name: host.id,
        iface_name: iface.name,
        network_id: iface.network_id,
        mode: iface.mode === "dhcp" ? "dhcp" : "static",
        ip: iface.ip ?? null,
        gateway: iface.gateway ?? null,
        role_hint: roleHintFromNetworkId(iface.network_id)
      }));

      return {
        host_id: host.id,
        role: host.role,
        interfaces
      };
    });

  const plan: PfSenseConfigPlan = {
    generated_from: networkPlanPath,
    pf_hosts: pfHosts
  };

  fs.writeFileSync(pfSensePlanPath, JSON.stringify(plan, null, 2), "utf-8");

  console.log(`Plan pfSense généré : ${pfSensePlanPath}`);
  console.log(JSON.stringify(plan, null, 2));
}

main();