import * as fs from "node:fs";
import * as path from "node:path";
import {
  LabDefinition,
  RequestedRole,
  RoleType,
  RoleVariant,
  ZoneType
} from "./type.js";

type ZoneDefinition = {
  network_id: string;
  vlan_id: number;
  cidr: string;
  gateway: string;
  zone_type: string;
};

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

export type NetworkPlan = {
  lab_name: string;
  lab_id: number;
  generation_mode: "randomized_definition";
  rules: {
    ip_schema: string;
    gateway_strategy: string;
    host_strategy: string;
    vlan_range: [number, number];
    host_range: [number, number];
    reserved_hosts: number[];
  };
  zone_definitions: ZoneDefinition[];
  hosts: HostEntry[];
};

const RESERVED_HOSTS = new Set([1, 254, 255]);
const HOST_MIN = 10;
const HOST_MAX = 240;
const VLAN_MIN = 10;
const VLAN_MAX = 200;
const DNS_DEFAULT = ["1.1.1.1", "8.8.8.8"];

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pickUniqueLabId(): number {
  return randomInt(1, 5);
}

function pickUniqueVlan(usedVlans: Set<number>): number {
  while (true) {
    const vlan = randomInt(VLAN_MIN, VLAN_MAX);
    if (!usedVlans.has(vlan)) {
      usedVlans.add(vlan);
      return vlan;
    }
  }
}

function cidrFromLabAndVlan(labId: number, vlanId: number): string {
  return `10.${labId}.${vlanId}.0/24`;
}

function gatewayFromLabAndVlan(labId: number, vlanId: number, hostOctet: number): string {
  return `10.${labId}.${vlanId}.${hostOctet}`;
}

function hostIpFromLabVlanHost(labId: number, vlanId: number, hostId: number): string {
  return `10.${labId}.${vlanId}.${hostId}`;
}

function pickUniqueHostIp(labId: number, vlanId: number, usedIps: Set<string>): string {
  while (true) {
    const host = randomInt(HOST_MIN, HOST_MAX);
    if (RESERVED_HOSTS.has(host)) continue;

    const ip = hostIpFromLabVlanHost(labId, vlanId, host);
    if (!usedIps.has(ip)) {
      usedIps.add(ip);
      return ip;
    }
  }
}

function reserveIp(ip: string, usedIps: Set<string>): void {
  if (usedIps.has(ip)) {
    throw new Error(`IP dupliquée réservée: ${ip}`);
  }
  usedIps.add(ip);
}

function getRolesByType(roles: RequestedRole[], role: RoleType): RequestedRole[] {
  return roles.filter((r) => r.role === role);
}

function hasRoleType(roles: RequestedRole[], role: RoleType): boolean {
  return roles.some((r) => r.role === role);
}

function networkIdFromZone(zone: ZoneType): string {
  switch (zone) {
    case "management":
      return "management-net";
    case "dmz":
      return "dmz-net";
    case "soc":
      return "soc-net";
    case "data":
      return "data-net";
    case "ad":
      return "ad-net";
    case "transit":
      return "core-transit-net";
    case "sync":
      return "sync-net";
    case "edge":
      return "edge-wan";
    default:
      return `${zone}-net`;
  }
}

function zoneFromNetworkId(networkId: string): ZoneType {
  switch (networkId) {
    case "management-net":
      return "management";
    case "dmz-net":
      return "dmz";
    case "soc-net":
      return "soc";
    case "data-net":
      return "data";
    case "ad-net":
      return "ad";
    case "core-transit-net":
      return "transit";
    case "sync-net":
      return "sync";
    case "edge-wan":
      return "edge";
    default:
      throw new Error(`networkId non supporté: ${networkId}`);
  }
}

function zoneTypeFromNetworkId(networkId: string): string {
  switch (networkId) {
    case "management-net":
      return "management";
    case "dmz-net":
      return "dmz";
    case "soc-net":
      return "soc";
    case "data-net":
      return "data";
    case "ad-net":
      return "ad";
    case "core-transit-net":
      return "transit";
    case "sync-net":
      return "sync";
    case "edge-wan":
      return "wan";
    default:
      return "internal";
  }
}

function getTotalNodes(requested: RequestedRole): number {
  return requested.count * requested.node_count;
}

function validateFirewallVariants(roles: RequestedRole[]): void {
  for (const requested of roles) {
    if (requested.role !== "edge_firewall" && requested.role !== "internal_firewall") {
      continue;
    }

    const totalNodes = getTotalNodes(requested);

    if (requested.variant === "simple" && totalNodes !== 1) {
      throw new Error(
        `${requested.role} (${requested.zone}) en variant simple doit avoir exactement 1 nœud. Reçu: ${totalNodes}`
      );
    }

    if (requested.variant === "ha" && totalNodes !== 2) {
      throw new Error(
        `${requested.role} (${requested.zone}) en variant ha doit avoir exactement 2 nœuds. Reçu: ${totalNodes}`
      );
    }

    if (requested.variant === "cluster" && totalNodes < 3) {
      throw new Error(
        `${requested.role} (${requested.zone}) en variant cluster doit avoir au moins 3 nœuds. Reçu: ${totalNodes}`
      );
    }
  }
}

function isServiceZoneNetworkId(networkId: string): boolean {
  return [
    "management-net",
    "dmz-net",
    "soc-net",
    "data-net",
    "ad-net"
  ].includes(networkId);
}

function getServiceZoneNetworkIds(roles: RequestedRole[]): string[] {
  const networks = new Set<string>();

  for (const requested of roles) {
    if (requested.role === "edge_firewall" || requested.role === "internal_firewall") {
      continue;
    }

    if (requested.zone === "edge" || requested.zone === "transit" || requested.zone === "sync") {
      continue;
    }

    networks.add(networkIdFromZone(requested.zone));
  }

  return [...networks];
}

function getEdgeFirewallRequest(roles: RequestedRole[]): RequestedRole | undefined {
  return getRolesByType(roles, "edge_firewall")[0];
}

function getInternalFirewallForZone(
  roles: RequestedRole[],
  zone: ZoneType
): RequestedRole | undefined {
  return getRolesByType(roles, "internal_firewall").find((r) => r.zone === zone);
}

function getServingFirewallForNetworkId(
  roles: RequestedRole[],
  networkId: string
): RequestedRole | undefined {
  const zone = zoneFromNetworkId(networkId);

  if (zone === "management" || zone === "dmz") {
    return getEdgeFirewallRequest(roles);
  }

  if (zone === "soc" || zone === "data" || zone === "ad") {
    return getInternalFirewallForZone(roles, zone) ?? getEdgeFirewallRequest(roles);
  }

  return undefined;
}

function getGatewayOctetForVariant(variant: RoleVariant): number {
  switch (variant) {
    case "simple":
      return 1;
    case "ha":
      return 1;
    case "cluster":
      return 10;
    default:
      return 1;
  }
}

function getZoneNodeOctetForVariant(variant: RoleVariant, nodeIndex: number): number {
  switch (variant) {
    case "simple":
      return 1;
    case "ha":
      return nodeIndex + 1; // 1=>2, 2=>3
    case "cluster":
      return 10 + nodeIndex; // 1=>11, 2=>12, 3=>13
    default:
      return 1;
  }
}

function buildRequiredZones(roles: RequestedRole[]): string[] {
  const zones = new Set<string>();

  if (hasRoleType(roles, "edge_firewall")) {
    zones.add("edge-wan");
  }

  const serviceZoneNetworkIds = getServiceZoneNetworkIds(roles);
  for (const networkId of serviceZoneNetworkIds) {
    zones.add(networkId);
  }

  if (hasRoleType(roles, "internal_firewall")) {
    zones.add("core-transit-net");
  }

  return [...zones];
}

function buildZoneDefinitions(
  labId: number,
  zones: string[],
  roles: RequestedRole[]
): ZoneDefinition[] {
  const usedVlans = new Set<number>();
  const result: ZoneDefinition[] = [];

  for (const zone of zones) {
    if (zone === "edge-wan") continue;

    const vlanId = pickUniqueVlan(usedVlans);

    let gatewayOctet = 1;

    if (isServiceZoneNetworkId(zone)) {
      const servingFirewall = getServingFirewallForNetworkId(roles, zone);
      if (!servingFirewall) {
        throw new Error(`Aucun firewall porteur trouvé pour la zone ${zone}`);
      }
      gatewayOctet = getGatewayOctetForVariant(servingFirewall.variant);
    } else if (zone === "core-transit-net") {
      gatewayOctet = 1;
    }

    result.push({
      network_id: zone,
      vlan_id: vlanId,
      cidr: cidrFromLabAndVlan(labId, vlanId),
      gateway: gatewayFromLabAndVlan(labId, vlanId, gatewayOctet),
      zone_type: zoneTypeFromNetworkId(zone)
    });
  }

  return result;
}

function getZone(zoneDefs: ZoneDefinition[], networkId: string): ZoneDefinition {
  const zone = zoneDefs.find((z) => z.network_id === networkId);
  if (!zone) {
    throw new Error(`Zone introuvable: ${networkId}`);
  }
  return zone;
}

function buildInstanceId(
  role: RoleType,
  zone: ZoneType,
  nodeIndex: number,
  totalNodes: number
): string {
  switch (role) {
    case "edge_firewall":
      return totalNodes > 1 ? `pfsense-edge-${nodeIndex}` : "pfsense-edge-1";

    case "internal_firewall":
      if (zone === "soc") {
        return totalNodes > 1 ? `pfsense-soc-${nodeIndex}` : "pfsense-soc-1";
      }
      if (zone === "data") {
        return totalNodes > 1 ? `pfsense-data-${nodeIndex}` : "pfsense-data-1";
      }
      if (zone === "ad") {
        return totalNodes > 1 ? `pfsense-ad-${nodeIndex}` : "pfsense-ad-1";
      }
      return totalNodes > 1
        ? `pfsense-internal-${nodeIndex}`
        : "pfsense-internal-1";

    case "bastion":
      return totalNodes > 1 ? `bastion-${nodeIndex}` : "bastion-1";

    case "reverse_proxy":
      return totalNodes > 1 ? `reverse-proxy-${nodeIndex}` : "reverse-proxy-1";

    case "wazuh_server":
      return totalNodes > 1 ? `wazuh-${nodeIndex}` : "wazuh-1";

    case "zabbix_server":
      return totalNodes > 1 ? `zabbix-${nodeIndex}` : "zabbix-1";

    case "db_server":
      return totalNodes > 1 ? `db-server-${nodeIndex}` : "db-server-1";

    case "windows_server":
      return totalNodes > 1 ? `windows-server-${nodeIndex}` : "windows-server-1";

    default:
      return `${role}-${nodeIndex}`;
  }
}

function addServiceHosts(
  hosts: HostEntry[],
  usedIps: Set<string>,
  zoneDefs: ZoneDefinition[],
  labId: number,
  requested: RequestedRole
): void {
  const networkId = networkIdFromZone(requested.zone);
  const zone = getZone(zoneDefs, networkId);
  const totalNodes = getTotalNodes(requested);

  for (let i = 1; i <= totalNodes; i++) {
    const ip = pickUniqueHostIp(labId, zone.vlan_id, usedIps);

    hosts.push({
      id: buildInstanceId(requested.role, requested.zone, i, totalNodes),
      role: requested.role,
      profile: requested.role === "windows_server" ? "windows-server" : "debian-wazuh",
      interfaces: [
        {
          name: "eth1",
          network_id: networkId,
          ip: `${ip}/24`,
          gateway: zone.gateway,
          dns: DNS_DEFAULT
        }
      ]
    });
  }
}

function buildEdgeAttachedNetworks(
  roles: RequestedRole[],
  zoneDefs: ZoneDefinition[]
): string[] {
  const attached = new Set<string>();
  const serviceZoneNetworkIds = getServiceZoneNetworkIds(roles);
  const internalFirewalls = getRolesByType(roles, "internal_firewall");

  if (internalFirewalls.length === 0) {
    for (const networkId of serviceZoneNetworkIds) {
      if (zoneDefs.some((z) => z.network_id === networkId)) {
        attached.add(networkId);
      }
    }
  } else {
    for (const networkId of ["management-net", "dmz-net"]) {
      if (zoneDefs.some((z) => z.network_id === networkId)) {
        attached.add(networkId);
      }
    }

    for (const networkId of serviceZoneNetworkIds) {
      if (!isServiceZoneNetworkId(networkId)) continue;

      const zone = zoneFromNetworkId(networkId);
      const coveredByInternal =
        (zone === "soc" || zone === "data" || zone === "ad") &&
        internalFirewalls.some((fw) => fw.zone === zone);

      if (!coveredByInternal && zoneDefs.some((z) => z.network_id === networkId)) {
        attached.add(networkId);
      }
    }

    if (zoneDefs.some((z) => z.network_id === "core-transit-net")) {
      attached.add("core-transit-net");
    }
  }

  return [...attached];
}

function ifaceNameFromNetworkId(networkId: string): string {
  if (networkId === "management-net") return "management";
  if (networkId === "dmz-net") return "dmz";
  if (networkId === "core-transit-net") return "transit";
  return networkId.replace("-net", "");
}

function buildHosts(roles: RequestedRole[], zoneDefs: ZoneDefinition[], labId: number): HostEntry[] {
  const hosts: HostEntry[] = [];
  const usedIps = new Set<string>();
  let transitOctetCounter = 1;

  // EDGE FIREWALL
  for (const requested of getRolesByType(roles, "edge_firewall")) {
    const totalNodes = getTotalNodes(requested);
    const edgeAttachedNetworks = buildEdgeAttachedNetworks(roles, zoneDefs);

    for (let i = 1; i <= totalNodes; i++) {
      const interfaces: HostInterface[] = [
        {
          name: "wan",
          network_id: "edge-wan",
          mode: "dhcp"
        }
      ];

      for (const networkId of edgeAttachedNetworks) {
        const zone = zoneDefs.find((z) => z.network_id === networkId);
        if (!zone) continue;

        const hostOctet =
          networkId === "core-transit-net"
            ? transitOctetCounter++
            : getZoneNodeOctetForVariant(requested.variant, i);

        const ip = hostIpFromLabVlanHost(labId, zone.vlan_id, hostOctet);
        reserveIp(ip, usedIps);

        interfaces.push({
          name: ifaceNameFromNetworkId(networkId),
          network_id: networkId,
          ip: `${ip}/24`,
          gateway: null
        });
      }

      hosts.push({
        id: buildInstanceId("edge_firewall", requested.zone, i, totalNodes),
        role: "edge_firewall",
        profile: "pfsense",
        interfaces
      });
    }
  }

  // INTERNAL FIREWALL
  for (const requested of getRolesByType(roles, "internal_firewall")) {
    const totalNodes = getTotalNodes(requested);
    const zoneNetworkId = networkIdFromZone(requested.zone);

    for (let i = 1; i <= totalNodes; i++) {
      const interfaces: HostInterface[] = [];

      const transitZone = zoneDefs.find((z) => z.network_id === "core-transit-net");
      if (transitZone) {
        const transitIp = hostIpFromLabVlanHost(labId, transitZone.vlan_id, transitOctetCounter++);
        reserveIp(transitIp, usedIps);

        interfaces.push({
          name: "transit",
          network_id: "core-transit-net",
          ip: `${transitIp}/24`,
          gateway: null
        });
      }

      const zone = zoneDefs.find((z) => z.network_id === zoneNetworkId);
      if (zone) {
        const zoneOctet = getZoneNodeOctetForVariant(requested.variant, i);
        const zoneIp = hostIpFromLabVlanHost(labId, zone.vlan_id, zoneOctet);
        reserveIp(zoneIp, usedIps);

        interfaces.push({
          name: requested.zone,
          network_id: zoneNetworkId,
          ip: `${zoneIp}/24`,
          gateway: null
        });
      }

      hosts.push({
        id: buildInstanceId("internal_firewall", requested.zone, i, totalNodes),
        role: "internal_firewall",
        profile: "pfsense",
        interfaces
      });
    }
  }

  // SERVICES
  for (const requested of roles) {
    if (requested.role === "edge_firewall" || requested.role === "internal_firewall") {
      continue;
    }
    addServiceHosts(hosts, usedIps, zoneDefs, labId, requested);
  }

  return hosts;
}

function validatePlan(plan: NetworkPlan): void {
  const seenCidrs = new Set<string>();
  const seenVlans = new Set<number>();
  const seenIps = new Set<string>();

  for (const zone of plan.zone_definitions) {
    if (seenCidrs.has(zone.cidr)) {
      throw new Error(`CIDR dupliqué: ${zone.cidr}`);
    }
    seenCidrs.add(zone.cidr);

    if (seenVlans.has(zone.vlan_id)) {
      throw new Error(`VLAN dupliqué: ${zone.vlan_id}`);
    }
    seenVlans.add(zone.vlan_id);
  }

  for (const host of plan.hosts) {
    for (const iface of host.interfaces) {
      if (!iface.ip) continue;
      const ipOnly = iface.ip.split("/")[0];

      if (seenIps.has(ipOnly)) {
        throw new Error(`IP dupliquée: ${ipOnly}`);
      }
      seenIps.add(ipOnly);
    }
  }
}

export function generateNetworkPlanFromDefinition(
  definition: LabDefinition,
  outputRoot: string
): NetworkPlan {
  const roles = definition.required_roles ?? [];

  if (roles.length === 0) {
    throw new Error("Aucun rôle trouvé dans lab-definition.json");
  }

  validateFirewallVariants(roles);

  const labId = pickUniqueLabId();
  const requiredZones = buildRequiredZones(roles);
  const zoneDefinitions = buildZoneDefinitions(labId, requiredZones, roles);
  const hosts = buildHosts(roles, zoneDefinitions, labId);

  const plan: NetworkPlan = {
    lab_name: definition.name || "prompt-generated-lab",
    lab_id: labId,
    generation_mode: "randomized_definition",
    rules: {
      ip_schema: "10.<lab_id>.<random_vlan_id>.<host_octet_by_firewall_variant_or_random_service_host>",
      gateway_strategy: "simple=.1 | ha=VIP .1 | cluster=service/VIP .10 | transit=unique per firewall node",
      host_strategy: "random host between .10 and .240 for service VMs",
      vlan_range: [VLAN_MIN, VLAN_MAX],
      host_range: [HOST_MIN, HOST_MAX],
      reserved_hosts: [...RESERVED_HOSTS]
    },
    zone_definitions: zoneDefinitions,
    hosts
  };

  validatePlan(plan);

  const networkPlanPath = path.join(outputRoot, "network-plan.json");
  fs.writeFileSync(networkPlanPath, JSON.stringify(plan, null, 2), "utf-8");

  return plan;
}

function main() {
  const outputRoot = path.join(process.cwd(), "outputs");
  const definitionPath = path.join(outputRoot, "lab-definition.json");

  if (!fs.existsSync(definitionPath)) {
    throw new Error(`Fichier introuvable: ${definitionPath}`);
  }

  const raw = fs.readFileSync(definitionPath, "utf-8");
  const definition: LabDefinition = JSON.parse(raw);

  const plan = generateNetworkPlanFromDefinition(definition, outputRoot);

  console.log(`Network plan généré : ${path.join(outputRoot, "network-plan.json")}`);
  console.log(JSON.stringify(plan, null, 2));
}

if (process.argv[1] && process.argv[1].includes("generateNetworkPlan.ts")) {
  main();
}