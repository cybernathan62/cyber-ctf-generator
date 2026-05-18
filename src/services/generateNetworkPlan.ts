import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { LabDefinition, NetworkPlanHost } from "./type.js";

function secureRandom(min: number, max: number): number {
  return crypto.randomInt(min, max + 1);
}

function randomVlan(used: Set<number>): number {
  let vlan = 0;
  do {
    vlan = secureRandom(10, 200);
  } while (used.has(vlan));
  used.add(vlan);
  return vlan;
}

function cidr(labId: number, vlan: number, prefix = 24): string {
  return `10.${labId}.${vlan}.0/${prefix}`;
}

function ip(labId: number, vlan: number, host: number, prefix: number): string {
  return `10.${labId}.${vlan}.${host}/${prefix}`;
}

function gateway(labId: number, vlan: number): string {
  return `10.${labId}.${vlan}.1`;
}

function randomHost(usedHosts: Set<number>): number {
  let host = 0;
  do {
    host = secureRandom(10, 240);
  } while (usedHosts.has(host));
  usedHosts.add(host);
  return host;
}

export function generateNetworkPlanFromDefinition(
  labDefinition: LabDefinition,
  outputDir: string
) {
  if (!Array.isArray(labDefinition.required_roles)) {
  throw new Error("[network-plan] required_roles invalide.");
}
  const roles = labDefinition.required_roles;

  const edgeRole = roles.find((r) => r.role === "edge_firewall");
  const socFwRole = roles.find(
    (r) => r.role === "internal_firewall" && r.zone === "soc"
  );
  const dataFwRole = roles.find(
    (r) => r.role === "internal_firewall" && r.zone === "data"
  );

  const wantsEdgeHa = edgeRole?.variant === "ha" && edgeRole.node_count >= 2;
  const edgeNodeCount = wantsEdgeHa ? 2 : 1;

  const wantsSoc = Boolean(socFwRole) || roles.some((r) => r.zone === "soc");
  const wantsData = Boolean(dataFwRole) || roles.some((r) => r.zone === "data");
  const wantsDmz = roles.some((r) => r.role === "reverse_proxy");
  const wantsBastion = roles.some((r) => r.role === "bastion");

  const socFwNodeCount =
    socFwRole?.variant === "ha" ? Math.max(2, socFwRole.node_count) : socFwRole ? 1 : 0;

  const dataFwNodeCount =
    dataFwRole?.variant === "ha" ? Math.max(2, dataFwRole.node_count) : dataFwRole ? 1 : 0;

  const labId = secureRandom(1, 9);
  const usedVlans = new Set<number>();

  const managementVlan = randomVlan(usedVlans);
  const dmzVlan = wantsDmz ? randomVlan(usedVlans) : null;
  const socVlan = wantsSoc ? randomVlan(usedVlans) : null;
  const dataVlan = wantsData ? randomVlan(usedVlans) : null;
  const transitSocVlan = socFwNodeCount > 0 ? randomVlan(usedVlans) : null;
  const transitDataVlan = dataFwNodeCount > 0 ? randomVlan(usedVlans) : null;

  const mgmtGw = gateway(labId, managementVlan);
  const dmzGw = dmzVlan !== null ? gateway(labId, dmzVlan) : null;
  const socGw = socVlan !== null ? gateway(labId, socVlan) : null;
  const dataGw = dataVlan !== null ? gateway(labId, dataVlan) : null;

  const transitSocPrefix = edgeNodeCount + socFwNodeCount > 2 ? 29 : 30;
  const transitDataPrefix = edgeNodeCount + dataFwNodeCount > 2 ? 29 : 30;

  const zoneDefinitions: any[] = [
    {
      network_id: "management-net",
      vlan_id: managementVlan,
      cidr: cidr(labId, managementVlan),
      gateway: mgmtGw,
      zone_type: "management"
    }
  ];

  if (wantsDmz && dmzVlan !== null && dmzGw) {
    zoneDefinitions.push({
      network_id: "dmz-net",
      vlan_id: dmzVlan,
      cidr: cidr(labId, dmzVlan),
      gateway: dmzGw,
      zone_type: "dmz"
    });
  }

  if (wantsSoc && socVlan !== null && socGw) {
    zoneDefinitions.push({
      network_id: "soc-net",
      vlan_id: socVlan,
      cidr: cidr(labId, socVlan),
      gateway: socGw,
      zone_type: "soc"
    });
  }

  if (wantsData && dataVlan !== null && dataGw) {
    zoneDefinitions.push({
      network_id: "data-net",
      vlan_id: dataVlan,
      cidr: cidr(labId, dataVlan),
      gateway: dataGw,
      zone_type: "data"
    });
  }

  if (transitSocVlan !== null) {
    zoneDefinitions.push({
      network_id: "transit-edge-soc-net",
      vlan_id: transitSocVlan,
      cidr: cidr(labId, transitSocVlan, transitSocPrefix),
      gateway: gateway(labId, transitSocVlan),
      zone_type: "transit"
    });
  }

  if (transitDataVlan !== null) {
    zoneDefinitions.push({
      network_id: "transit-edge-data-net",
      vlan_id: transitDataVlan,
      cidr: cidr(labId, transitDataVlan, transitDataPrefix),
      gateway: gateway(labId, transitDataVlan),
      zone_type: "transit"
    });
  }

  const hosts: NetworkPlanHost[] = [];

  function buildEdgeInterfaces(edgeIndex: number) {
    const physicalIndex = wantsEdgeHa ? edgeIndex + 1 : 1;

    const interfaces: any[] = [
      { name: "wan", network_id: "edge-wan", mode: "dhcp" },
      {
        name: "management",
        network_id: "management-net",
        ip: ip(labId, managementVlan, physicalIndex, 24),
        gateway: null
      }
    ];

    if (wantsDmz && dmzVlan !== null) {
      interfaces.push({
        name: "dmz",
        network_id: "dmz-net",
        ip: ip(labId, dmzVlan, physicalIndex, 24),
        gateway: null
      });
    }

    if (transitSocVlan !== null) {
      interfaces.push({
        name: "transit_soc",
        network_id: "transit-edge-soc-net",
        ip: ip(labId, transitSocVlan, edgeIndex, transitSocPrefix),
        gateway: null
      });
    }

    if (transitDataVlan !== null) {
      interfaces.push({
        name: "transit_data",
        network_id: "transit-edge-data-net",
        ip: ip(labId, transitDataVlan, edgeIndex, transitDataPrefix),
        gateway: null
      });
    }

    return interfaces;
  }

  const edgeStaticRoutes: any[] = [];

  if (socFwNodeCount > 0 && socVlan !== null && transitSocVlan !== null) {
    edgeStaticRoutes.push({
      name: "route_soc_net",
      destination: cidr(labId, socVlan),
      gateway: `10.${labId}.${transitSocVlan}.${edgeNodeCount + 1}`
    });
  }

  if (dataFwNodeCount > 0 && dataVlan !== null && transitDataVlan !== null) {
    edgeStaticRoutes.push({
      name: "route_data_net",
      destination: cidr(labId, dataVlan),
      gateway: `10.${labId}.${transitDataVlan}.${edgeNodeCount + 1}`
    });
  }

  for (let i = 1; i <= edgeNodeCount; i++) {
    hosts.push({
      id: `pfsense-edge-${i}`,
      role: "edge_firewall",
      variant: wantsEdgeHa ? "ha" : "simple",
      zone: "edge",
      profile: "pfsense",
      interfaces: buildEdgeInterfaces(i),
      static_routes: edgeStaticRoutes
    });
  }

  if (socFwNodeCount > 0 && socVlan !== null && socGw && transitSocVlan !== null) {
    for (let i = 1; i <= socFwNodeCount; i++) {
      hosts.push({
        id: `pfsense-soc-${i}`,
        role: "internal_firewall",
        variant: socFwNodeCount > 1 ? "ha" : "simple",
        zone: "soc",
        profile: "pfsense",
        interfaces: [
          {
            name: "transit",
            network_id: "transit-edge-soc-net",
            ip: ip(labId, transitSocVlan, edgeNodeCount + i, transitSocPrefix),
            gateway: gateway(labId, transitSocVlan)
          },
          {
            name: "soc",
            network_id: "soc-net",
            ip: socFwNodeCount > 1 ? ip(labId, socVlan, i + 1, 24) : `${socGw}/24`,
            gateway: null
          }
        ],
        default_gateway: gateway(labId, transitSocVlan)
      });
    }
  }

  if (dataFwNodeCount > 0 && dataVlan !== null && dataGw && transitDataVlan !== null) {
    for (let i = 1; i <= dataFwNodeCount; i++) {
      hosts.push({
        id: `pfsense-data-${i}`,
        role: "internal_firewall",
        variant: dataFwNodeCount > 1 ? "ha" : "simple",
        zone: "data",
        profile: "pfsense",
        interfaces: [
          {
            name: "transit",
            network_id: "transit-edge-data-net",
            ip: ip(labId, transitDataVlan, edgeNodeCount + i, transitDataPrefix),
            gateway: gateway(labId, transitDataVlan)
          },
          {
            name: "data",
            network_id: "data-net",
            ip: dataFwNodeCount > 1 ? ip(labId, dataVlan, i + 1, 24) : `${dataGw}/24`,
            gateway: null
          }
        ],
        default_gateway: gateway(labId, transitDataVlan)
      });
    }
  }

  const usedMgmtHosts = new Set<number>([1, 2, 3]);
  const usedDmzHosts = new Set<number>([1, 2, 3]);
  const usedSocHosts = new Set<number>([1, 2, 3]);
  const usedDataHosts = new Set<number>([1, 2, 3]);

  if (wantsBastion) {
    hosts.push({
      id: "bastion-1",
      role: "bastion",
      variant: "simple",
      zone: "management",
      profile: "debian-wazuh",
      interfaces: [
        {
          name: "eth1",
          network_id: "management-net",
          ip: ip(labId, managementVlan, randomHost(usedMgmtHosts), 24),
          gateway: mgmtGw,
          dns: ["1.1.1.1", "8.8.8.8"]
        }
      ]
    });
  }

  if (wantsDmz && dmzVlan !== null && dmzGw) {
    hosts.push({
      id: "reverse-proxy-1",
      role: "reverse_proxy",
      variant: "simple",
      zone: "dmz",
      profile: "debian-wazuh",
      interfaces: [
        {
          name: "eth1",
          network_id: "dmz-net",
          ip: ip(labId, dmzVlan, randomHost(usedDmzHosts), 24),
          gateway: dmzGw,
          dns: ["1.1.1.1", "8.8.8.8"]
        }
      ]
    });
  }

  const wazuhRole = roles.find((r) => r.role === "wazuh_server");
  const wazuhNodes =
    wazuhRole?.variant === "cluster" ? Math.max(3, wazuhRole.node_count) : wazuhRole ? 1 : 0;

  if (wazuhNodes > 0 && socVlan !== null && socGw) {
    for (let i = 1; i <= wazuhNodes; i++) {
      hosts.push({
        id: `wazuh-${i}`,
        role: "wazuh_server",
        variant: wazuhNodes > 1 ? "cluster" : "simple",
        zone: "soc",
        profile: "debian-wazuh",
        interfaces: [
          {
            name: "eth1",
            network_id: "soc-net",
            ip: ip(labId, socVlan, randomHost(usedSocHosts), 24),
            gateway: socGw,
            dns: ["1.1.1.1", "8.8.8.8"]
          }
        ]
      });
    }
  }

  const zabbixRole = roles.find((r) => r.role === "zabbix_server");

  if (zabbixRole && socVlan !== null && socGw) {
    hosts.push({
      id: "zabbix-1",
      role: "zabbix_server",
      variant: "simple",
      zone: "soc",
      profile: "debian-wazuh",
      interfaces: [
        {
          name: "eth1",
          network_id: "soc-net",
          ip: ip(labId, socVlan, randomHost(usedSocHosts), 24),
          gateway: socGw,
          dns: ["1.1.1.1", "8.8.8.8"]
        }
      ]
    });
  }
    const socAiRole = roles.find((r) => r.role === "soc_ai_agent");

  if (socAiRole && socVlan !== null && socGw) {
    hosts.push({
      id: "soc-ai-1",
      role: "soc_ai_agent",
      variant: "simple",
      zone: "soc",
      profile: "debian-wazuh",
      interfaces: [
        {
          name: "eth1",
          network_id: "soc-net",
          ip: ip(labId, socVlan, randomHost(usedSocHosts), 24),
          gateway: socGw,
          dns: ["1.1.1.1", "8.8.8.8"]
        }
      ]
    });
  }

  const dbRole = roles.find((r) => r.role === "db_server");
  const dbNodes =
    dbRole?.variant === "cluster" ? Math.max(2, dbRole.node_count) : dbRole ? 1 : 0;

  if (dbNodes > 0 && dataVlan !== null && dataGw) {
    for (let i = 1; i <= dbNodes; i++) {
      hosts.push({
        id: `db-server-${i}`,
        role: "db_server",
        variant: dbNodes > 1 ? "cluster" : "simple",
        zone: "data",
        profile: "debian-wazuh",
        interfaces: [
          {
            name: "eth1",
            network_id: "data-net",
            ip: ip(labId, dataVlan, randomHost(usedDataHosts), 24),
            gateway: dataGw,
            dns: ["1.1.1.1", "8.8.8.8"]
          }
        ]
      });
    }
  }

  const plan = {
    lab_name: labDefinition.name,
    lab_id: labId,
    generation_mode: "randomized_definition" as const,
    rules: {
      ip_schema: "10.<lab_id>.<random_vlan_id>.<host_octet>",
      gateway_strategy:
        "simple=.1 | HA uses .1 as future VIP and .2/.3 as physical firewall IPs",
      host_strategy: "random host between .10 and .240 for service VMs",
      vlan_range: [10, 200] as [number, number],
      host_range: [10, 240] as [number, number],
      reserved_hosts: [1, 2, 3, 254, 255]
    },
    zone_definitions: zoneDefinitions,
    hosts
  };

  fs.mkdirSync(outputDir, { recursive: true });

const planPath = path.join(outputDir, "network-plan.json");
const tmpPath = `${planPath}.tmp`;

fs.writeFileSync(
  tmpPath,
  JSON.stringify(plan, null, 2),
  {
    encoding: "utf-8",
    mode: 0o600
  }
);

fs.renameSync(tmpPath, planPath);

  return plan;
}