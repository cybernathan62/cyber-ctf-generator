import * as fs from "node:fs";
import * as path from "node:path";

type Rule = {
  firewall: string;
  interface: string;
  action: "pass";
  protocol: string;
  source: string;
  destination: string;
  destination_ports?: number[];
  description: string;
};

type Host = {
  id: string;
  profile: string;
  interfaces: { name: string }[];
};

type NetworkPlan = {
  hosts: Host[];
};

type AliasPlan = {
  aliases: {
    name: string;
    type: string;
    values: string[];
  }[];
};

// ============================
// MAPPING LOGIQUE → ALIAS
// ============================

const SOURCE_ALIAS_MAP: Record<string, string> = {
  "management-net": "ALIAS_MGMT_NET",
  "soc-net": "ALIAS_SOC_NET",
  "data-net": "ALIAS_DATA_NET"
};

const DEST_ALIAS_MAP: Record<string, string> = {
  wazuh_server: "ALIAS_WAZUH_SERVERS",
  db_server: "ALIAS_DB_SERVERS"
};

function mapSource(src: string): string {
  return SOURCE_ALIAS_MAP[src] || src;
}

function mapDestination(dst: string): string {
  return DEST_ALIAS_MAP[dst] || dst;
}

// ============================
// HELPERS
// ============================

function isPfSense(host: Host) {
  return host.profile === "pfsense";
}

function hasInterface(host: Host, iface: string) {
  return host.interfaces.some((i) => i.name === iface);
}

// ============================
// BUILD RULES
// ============================

function buildRules(plan: NetworkPlan): Rule[] {
  const rules: Rule[] = [];

  for (const fw of plan.hosts) {
    if (!isPfSense(fw)) continue;

    // ================= MANAGEMENT
    if (hasInterface(fw, "management")) {
      rules.push(
        {
          firewall: fw.id,
          interface: "management",
          action: "pass",
          protocol: "icmp",
          source: mapSource("management-net"),
          destination: "any",
          description: "Allow ICMP from management"
        },
        {
          firewall: fw.id,
          interface: "management",
          action: "pass",
          protocol: "tcp",
          source: mapSource("management-net"),
          destination: "any",
          destination_ports: [22, 443],
          description: "Allow SSH + HTTPS from management"
        },
        {
          firewall: fw.id,
          interface: "management",
          action: "pass",
          protocol: "tcp_udp",
          source: mapSource("management-net"),
          destination: "any",
          destination_ports: [53],
          description: "Allow DNS from management"
        }
      );
    }

    // ================= SOC
    if (hasInterface(fw, "soc")) {
      rules.push(
        {
          firewall: fw.id,
          interface: "soc",
          action: "pass",
          protocol: "tcp",
          source: mapSource("soc-net"),
          destination: mapDestination("wazuh_server"),
          destination_ports: [1514, 1515, 55000, 443],
          description: "Allow Wazuh traffic"
        },
        {
          firewall: fw.id,
          interface: "soc",
          action: "pass",
          protocol: "icmp",
          source: mapSource("soc-net"),
          destination: "any",
          description: "Allow ICMP from SOC"
        }
      );
    }

    // ================= DATA
    if (hasInterface(fw, "data")) {
      rules.push({
        firewall: fw.id,
        interface: "data",
        action: "pass",
        protocol: "tcp",
        source: mapSource("management-net"),
        destination: mapDestination("db_server"),
        destination_ports: [3306, 22],
        description: "Allow DB + SSH from management"
      });
    }

    // ================= WAN
    if (hasInterface(fw, "wan")) {
      rules.push({
        firewall: fw.id,
        interface: "wan",
        action: "pass",
        protocol: "icmp",
        source: "any",
        destination: "wan",
        description: "Allow ICMP to WAN"
      });
    }
  }

  return rules;
}

// ============================
// MAIN
// ============================

function main() {
  const outputRoot = path.join(process.cwd(), "outputs");

  const networkPath = path.join(outputRoot, "network-plan.json");
  const rulesPath = path.join(outputRoot, "pfsense-rules-plan.json");

  if (!fs.existsSync(networkPath)) {
    throw new Error("network-plan.json introuvable");
  }

  const raw = fs.readFileSync(networkPath, "utf-8");
  const plan: NetworkPlan = JSON.parse(raw);

  const rules = buildRules(plan);

  fs.writeFileSync(
    rulesPath,
    JSON.stringify({ pf_rules: rules }, null, 2),
    "utf-8"
  );

  console.log("Règles pfSense générées :", rulesPath);
  console.log(JSON.stringify({ pf_rules: rules }, null, 2));
}

main();