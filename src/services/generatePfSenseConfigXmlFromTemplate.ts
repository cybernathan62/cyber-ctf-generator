import * as fs from "node:fs";
import * as path from "node:path";

type PfSenseConfigPlan = {
  pf_hosts: Array<{
    host_id: string;
    role: string;
    interfaces: Array<{
      pf_name: string;
      iface_name: string;
      network_id: string;
      mode: "dhcp" | "static";
      ip: string | null;
      gateway: string | null;
      role_hint: string;
    }>;
  }>;
};

type AliasPlan = {
  aliases: Array<{
    name: string;
    type: "host" | "network";
    values: string[];
    description: string;
  }>;
};

type RulesPlan = {
  pf_rules: Array<{
    firewall: string;
    interface: string;
    action: "pass";
    protocol: string;
    source: string;
    destination: string;
    destination_ports?: number[];
    description: string;
  }>;
};

function escapeXml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function splitCidr(ipCidr: string | null): { ip: string; subnet: string } {
  if (!ipCidr) return { ip: "", subnet: "" };
  const [ip, subnet] = ipCidr.split("/");
  return { ip, subnet: subnet ?? "" };
}

function ifaceTagFromName(ifaceName: string): string {
  switch (ifaceName) {
    case "wan":
      return "wan";
    case "management":
      return "lan";
    case "soc":
      return "opt1";
    case "data":
      return "opt2";
    case "transit":
      return "opt3";
    case "dmz":
      return "opt4";
    default:
      return "opt9";
  }
}

function nicNameFromHostAndIface(hostId: string, ifaceName: string): string {
  const isEdge = hostId.startsWith("pfsense-edge-");
  const isInternal = hostId.startsWith("pfsense-internal-");

  if (isEdge) {
    switch (ifaceName) {
      case "wan":
        return "em0";
      case "management":
        return "em1";
      case "soc":
        return "em2";
      case "data":
        return "em3";
      case "transit":
        return "em4";
      case "dmz":
        return "em5";
      default:
        return "em9";
    }
  }

  if (isInternal) {
    switch (ifaceName) {
      case "wan":
        return "em0";
      case "transit":
        return "em1";
      case "soc":
        return "em2";
      case "data":
        return "em3";
      case "management":
        return "em4";
      default:
        return "em9";
    }
  }

  return "em9";
}

function renderInterfacesXml(host: PfSenseConfigPlan["pf_hosts"][number]): string {
  return host.interfaces
    .map((iface) => {
      const tag = ifaceTagFromName(iface.iface_name);
      const nic = nicNameFromHostAndIface(host.host_id, iface.iface_name);

      if (iface.mode === "dhcp") {
        return `    <${tag}>
      <enable></enable>
      <if>${escapeXml(nic)}</if>
      <descr><![CDATA[${iface.iface_name.toUpperCase()}]]></descr>
      <ipaddr>dhcp</ipaddr>
    </${tag}>`;
      }

      const { ip, subnet } = splitCidr(iface.ip);

      return `    <${tag}>
      <descr><![CDATA[${iface.iface_name.toUpperCase()}]]></descr>
      <if>${escapeXml(nic)}</if>
      <enable></enable>
      <ipaddr>${escapeXml(ip)}</ipaddr>
      <subnet>${escapeXml(subnet)}</subnet>
      <gateway></gateway>
      <ipaddrv6></ipaddrv6>
      <subnetv6></subnetv6>
      <gatewayv6></gatewayv6>
    </${tag}>`;
    })
    .join("\n");
}

function renderAliasesXml(aliasPlan: AliasPlan): string {
  return aliasPlan.aliases
    .map((alias) => `    <alias>
      <name>${escapeXml(alias.name)}</name>
      <type>${escapeXml(alias.type)}</type>
      <address>${escapeXml(alias.values.join(" "))}</address>
      <descr><![CDATA[${alias.description}]]></descr>
      <detail><![CDATA[Generated automatically]]></detail>
    </alias>`)
    .join("\n");
}

function mapProtocol(protocol: string): string[] {
  if (protocol === "tcp_udp") return ["tcp", "udp"];
  return [protocol];
}

function nextTrackerFactory(): () => string {
  let counter = Date.now();
  return () => String(counter++);
}

function renderRuleXml(
  rule: RulesPlan["pf_rules"][number],
  tracker: string
): string {
  const sourceXml =
    rule.source === "any"
      ? "<any></any>"
      : `<address>${escapeXml(rule.source)}</address>`;

  const destinationXml =
    rule.destination === "any"
      ? "<any></any>"
      : `<address>${escapeXml(rule.destination)}</address>`;

  const portXml = rule.destination_ports?.length
    ? `<port>${escapeXml(rule.destination_ports.join(","))}</port>`
    : "";

  const icmpTypeXml = rule.protocol === "icmp" ? "<icmptype>any</icmptype>" : "";

  return `    <rule>
      <id></id>
      <tracker>${tracker}</tracker>
      <type>${escapeXml(rule.action)}</type>
      <interface>${escapeXml(ifaceTagFromName(rule.interface))}</interface>
      <ipprotocol>inet</ipprotocol>
      <tag></tag>
      <tagged></tagged>
      <max></max>
      <max-src-nodes></max-src-nodes>
      <max-src-conn></max-src-conn>
      <max-src-states></max-src-states>
      <statetimeout></statetimeout>
      <statepolicy></statepolicy>
      <statetype><![CDATA[keep state]]></statetype>
      <os></os>
      <protocol>${escapeXml(rule.protocol)}</protocol>
      ${icmpTypeXml}
      <source>
        ${sourceXml}
      </source>
      <destination>
        ${destinationXml}
        ${portXml}
      </destination>
      <log></log>
      <descr><![CDATA[${rule.description}]]></descr>
      <created>
        <time>${Math.floor(Date.now() / 1000)}</time>
        <username><![CDATA[automation]]></username>
      </created>
    </rule>`;
}

function renderRulesXml(hostId: string, rulesPlan: RulesPlan): string {
  const nextTracker = nextTrackerFactory();

  return rulesPlan.pf_rules
    .filter((rule) => rule.firewall === hostId)
    .flatMap((rule) =>
      mapProtocol(rule.protocol).map((proto) =>
        renderRuleXml({ ...rule, protocol: proto }, nextTracker())
      )
    )
    .join("\n");
}

function renderGatewaysXml(host: PfSenseConfigPlan["pf_hosts"][number]): string {
  const wan = host.interfaces.find((i) => i.iface_name === "wan");
  const gateways: string[] = [];

  if (wan && wan.mode === "dhcp") {
    gateways.push(`    <gateway_item>
      <interface>wan</interface>
      <gateway>dynamic</gateway>
      <name>WAN_DHCP</name>
      <weight>1</weight>
      <ipprotocol>inet</ipprotocol>
      <descr><![CDATA[Interface WAN_DHCP Gateway]]></descr>
      <gw_down_kill_states></gw_down_kill_states>
    </gateway_item>`);
  }

  return gateways.join("\n");
}

function buildHostXml(
  template: string,
  host: PfSenseConfigPlan["pf_hosts"][number],
  aliasPlan: AliasPlan,
  rulesPlan: RulesPlan
): string {
  const hostname = host.host_id;

  return template
    .replace("<hostname>pfSense</hostname>", `<hostname>${escapeXml(hostname)}</hostname>`)
    .replace("<!-- GENERATED_INTERFACES -->", renderInterfacesXml(host))
    .replace("<!-- GENERATED_ALIASES -->", renderAliasesXml(aliasPlan))
    .replace("<!-- GENERATED_FILTER_RULES -->", renderRulesXml(host.host_id, rulesPlan))
    .replace("<!-- GENERATED_GATEWAYS -->", renderGatewaysXml(host))
    .replace("<!-- GENERATED_NAT_RULES -->", "");
}

function main() {
  const root = process.cwd();
  const outputRoot = path.join(root, "outputs");

  const templatePath = path.join(root, "templates", "pfsense", "config-template.xml");
  const configPlanPath = path.join(outputRoot, "pfsense-config-plan.json");
  const aliasPlanPath = path.join(outputRoot, "pfsense-aliases-plan.json");
  const rulesPlanPath = path.join(outputRoot, "pfsense-rules-plan.json");
  const outDir = path.join(outputRoot, "pfsense-config-xml");

  for (const file of [templatePath, configPlanPath, aliasPlanPath, rulesPlanPath]) {
    if (!fs.existsSync(file)) {
      throw new Error(`Introuvable: ${file}`);
    }
  }

  if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const template = fs.readFileSync(templatePath, "utf-8");
  const configPlan = JSON.parse(fs.readFileSync(configPlanPath, "utf-8")) as PfSenseConfigPlan;
  const aliasPlan = JSON.parse(fs.readFileSync(aliasPlanPath, "utf-8")) as AliasPlan;
  const rulesPlan = JSON.parse(fs.readFileSync(rulesPlanPath, "utf-8")) as RulesPlan;

  for (const host of configPlan.pf_hosts) {
    const xml = buildHostXml(template, host, aliasPlan, rulesPlan);
    const outPath = path.join(outDir, `${host.host_id}-config.xml`);
    fs.writeFileSync(outPath, xml, "utf-8");
    console.log(`Config pfSense générée : ${outPath}`);
  }
}

main();