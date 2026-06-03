import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { NetworkPlan, NetworkPlanHost } from "./type.js";
import {
  PfSensePlan,
  PfSenseAlias,
  PfSenseFirewallRule,
  PfSenseNatRule
} from "./pfsenseTypes.js";

type SshConfig = {
  hostName: string;
  port: string;
  user: string;
  identityFile: string;
};

function run(
  command: string,
  args: string[],
  cwd: string,
  label: string,
  allowFailure = false
): string {
  console.log(`\n[pfSense patch] ${label}`);
  console.log(`${command} ${args.join(" ")}`);

  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf-8",
    shell: false,
    maxBuffer: 1024 * 1024 * 20
  });

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error) throw result.error;

  if (!allowFailure && result.status !== 0) {
    throw new Error(`[pfSense patch] Échec ${label} avec code ${result.status}`);
  }

  return result.stdout ?? "";
}

function sleepMs(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function getVagrantSshConfig(generatedLabDir: string, vmName: string): SshConfig {
  const command = process.platform === "win32" ? "vagrant.exe" : "vagrant";

  const raw = run(command, ["ssh-config", vmName], generatedLabDir, `Lecture ssh-config ${vmName}`);

  const get = (key: string): string => {
    const line = raw
      .split(/\r?\n/)
      .find((l) => l.trim().toLowerCase().startsWith(key.toLowerCase()));

    if (!line) throw new Error(`ssh-config: clé manquante ${key} pour ${vmName}`);

    return line.trim().replace(new RegExp(`^${key}\\s+`, "i"), "").replace(/^"|"$/g, "");
  };

  return {
    hostName: get("HostName"),
    port: get("Port"),
    user: get("User"),
    identityFile: get("IdentityFile")
  };
}

function sshArgs(cfg: SshConfig, remoteCommand: string): string[] {
  return [
    "-i",
    cfg.identityFile,
    "-p",
    cfg.port,
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=ERROR",
    `${cfg.user}@${cfg.hostName}`,
    remoteCommand
  ];
}

function scpArgs(cfg: SshConfig, localPath: string, remotePath: string): string[] {
  return [
    "-i",
    cfg.identityFile,
    "-P",
    cfg.port,
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=ERROR",
    localPath,
    `${cfg.user}@${cfg.hostName}:${remotePath}`
  ];
}

function replaceTag(xml: string, tag: string, replacement: string): string {
  const regex = new RegExp(`<${tag}>[\\s\\S]*?<\\/${tag}>`, "m");

  if (!regex.test(xml)) {
    throw new Error(`Bloc XML introuvable: <${tag}>`);
  }

  return xml.replace(regex, replacement);
}

function patchSystemGateway(xml: string, host: NetworkPlanHost): string {
  const gateway =
    host.role === "edge_firewall"
      ? "WAN_DHCP"
      : host.role === "internal_firewall"
        ? "GW_EDGE"
        : "";

  let patched = xml.replace(
    /<hostname>[\s\S]*?<\/hostname>/,
    `<hostname>${host.id}</hostname>`
  );

  if (!gateway) return patched;

  patched = patched.replace(/<defaultgw4>[\s\S]*?<\/defaultgw4>/g, "");

  patched = patched.replace(
    /<\/system>/,
    `\t\t<defaultgw4>${gateway}</defaultgw4>\n\t</system>`
  );

  patched = patched.replace(/<gateway>[\s\S]*?<\/gateway>/g, "");

  patched = patched.replace(
    /<\/system>/,
    `\t\t<gateway>${gateway}</gateway>\n\t</system>`
  );

  return patched;
}

function ipOnly(ip: string): string {
  return ip.split("/")[0];
}

function subnetOnly(ip: string): string {
  const subnet = ip.split("/")[1];
  if (!subnet) throw new Error(`CIDR invalide: ${ip}`);
  return subnet;
}

function xmlNameByIndex(index: number): string {
  if (index === 0) return "lan";
  return `opt${index}`;
}

function renderInterface(xmlName: string, em: string, iface: any): string {
  if (iface.mode === "dhcp") {
    return `
\t\t<${xmlName}>
\t\t\t<enable></enable>
\t\t\t<if>${em}</if>
\t\t\t<descr><![CDATA[${iface.name.toUpperCase()}]]></descr>
\t\t\t<ipaddr>dhcp</ipaddr>
\t\t</${xmlName}>`;
  }

  if (!iface.ip) {
    throw new Error(`Interface sans IP: ${iface.name}`);
  }

  return `
\t\t<${xmlName}>
\t\t\t<enable></enable>
\t\t\t<if>${em}</if>
\t\t\t<descr><![CDATA[${iface.name.toUpperCase()}]]></descr>
\t\t\t<ipaddr>${ipOnly(iface.ip)}</ipaddr>
\t\t\t<subnet>${subnetOnly(iface.ip)}</subnet>
\t\t\t<spoofmac></spoofmac>
\t\t</${xmlName}>`;
}

function renderDisabledWanTemp(): string {
  return `
\t\t<wan>
\t\t\t<if>em0</if>
\t\t\t<descr><![CDATA[WAN_TEMP]]></descr>
\t\t\t<ipaddr>none</ipaddr>
\t\t\t<subnet></subnet>
\t\t</wan>`;
}

function generateInterfaces(host: NetworkPlanHost): string {
  let body = "";
  const hasWan = host.interfaces.some((i: any) => i.name === "wan");

  if (hasWan) {
    host.interfaces.forEach((iface: any, index: number) => {
      const xmlName = index === 0 ? "wan" : xmlNameByIndex(index - 1);
      body += renderInterface(xmlName, `em${index}`, iface);
    });
  } else {
    body += host.role === "internal_firewall"
      ? renderDisabledWanTemp()
      : renderInterface("wan", "em0", {
          name: "wan_temp",
          network_id: "edge-wan",
          mode: "dhcp"
        });

    host.interfaces.forEach((iface: any, index: number) => {
      body += renderInterface(xmlNameByIndex(index), `em${index + 1}`, iface);
    });
  }

  return `\t<interfaces>${body}
\t</interfaces>`;
}

/** Map logical interface names (dmz, management) → pfSense XML names (lan, opt1, wan). */
function buildLogicalToPfSenseInterfaceMap(host: NetworkPlanHost): Map<string, string> {
  const map = new Map<string, string>();
  const hasWan = host.interfaces.some((i: { name?: string }) => i.name === "wan");

  if (hasWan) {
    host.interfaces.forEach((iface: { name: string }, index: number) => {
      const xmlName = index === 0 ? "wan" : xmlNameByIndex(index - 1);
      map.set(iface.name, xmlName);
    });
  } else {
    host.interfaces.forEach((iface: { name: string }, index: number) => {
      map.set(iface.name, xmlNameByIndex(index));
    });
  }

  return map;
}

function resolvePfSenseInterface(
  logicalName: string,
  interfaceMap: Map<string, string>
): string {
  const resolved = interfaceMap.get(logicalName);

  if (!resolved) {
    throw new Error(
      `[pfSense patch] Interface logique inconnue "${logicalName}". ` +
        `Interfaces connues: ${[...interfaceMap.keys()].join(", ")}`
    );
  }

  return resolved;
}

function gatewayName(routeName: string): string {
  return `GW_${routeName.toUpperCase()}`;
}

function gatewayInterfaceForEdge(host: NetworkPlanHost, gatewayIp: string): string {
  const gatewayPrefix = gatewayIp.split(".").slice(0, 3).join(".");
  const nonWanInterfaces = host.interfaces.filter((i: any) => i.name !== "wan");

  const index = nonWanInterfaces.findIndex((iface: any) => {
    if (!iface.ip) return false;
    return iface.ip.split(".").slice(0, 3).join(".") === gatewayPrefix;
  });

  if (index === -1) {
    throw new Error(`Impossible de mapper la gateway ${gatewayIp} sur une interface edge`);
  }

  return xmlNameByIndex(index);
}

function gatewayInterfaceForInternal(host: NetworkPlanHost, gatewayIp: string): string {
  const gatewayPrefix = gatewayIp.split(".").slice(0, 3).join(".");

  const index = host.interfaces.findIndex((iface: any) => {
    if (!iface.ip) return false;
    return iface.ip.split(".").slice(0, 3).join(".") === gatewayPrefix;
  });

  if (index === -1) {
    throw new Error(
      `Impossible de mapper la gateway interne ${gatewayIp} sur une interface de ${host.id}`
    );
  }

  return xmlNameByIndex(index);
}

function generateGateways(host: NetworkPlanHost): string {
  let body = "";

  if (host.role === "edge_firewall") {
    body += `
\t\t<gateway_item>
\t\t\t<interface>wan</interface>
\t\t\t<gateway>dynamic</gateway>
\t\t\t<name>WAN_DHCP</name>
\t\t\t<weight>1</weight>
\t\t\t<ipprotocol>inet</ipprotocol>
\t\t\t<descr><![CDATA[WAN DHCP Gateway]]></descr>
\t\t</gateway_item>`;

    host.static_routes?.forEach((route: any) => {
      const iface = gatewayInterfaceForEdge(host, route.gateway);

      body += `
\t\t<gateway_item>
\t\t\t<interface>${iface}</interface>
\t\t\t<gateway>${route.gateway}</gateway>
\t\t\t<name>${gatewayName(route.name)}</name>
\t\t\t<weight>1</weight>
\t\t\t<ipprotocol>inet</ipprotocol>
\t\t\t<descr><![CDATA[Gateway ${route.name}]]></descr>
\t\t</gateway_item>`;
    });
  }

  if (host.role === "internal_firewall") {
    if (!host.default_gateway) {
      throw new Error(`default_gateway manquant pour ${host.id}`);
    }

    const iface = gatewayInterfaceForInternal(host, host.default_gateway);

    body += `
\t\t<gateway_item>
\t\t\t<interface>${iface}</interface>
\t\t\t<gateway>${host.default_gateway}</gateway>
\t\t\t<name>GW_EDGE</name>
\t\t\t<weight>1</weight>
\t\t\t<ipprotocol>inet</ipprotocol>
\t\t\t<descr><![CDATA[Gateway vers edge via TRANSIT]]></descr>
\t\t</gateway_item>`;
  }

  return `\t<gateways>${body}
\t</gateways>`;
}

function generateStaticRoutes(host: NetworkPlanHost): string {
  if (!host.static_routes || host.static_routes.length === 0) {
    return `\t<staticroutes></staticroutes>`;
  }

  let body = "";

  host.static_routes.forEach((route: any) => {
    body += `
\t\t<route>
\t\t\t<network>${route.destination}</network>
\t\t\t<gateway>${gatewayName(route.name)}</gateway>
\t\t\t<descr><![CDATA[${route.name}]]></descr>
\t\t</route>`;
  });

  return `\t<staticroutes>${body}
\t</staticroutes>`;
}

function renderAddress(value: string): string {
  if (value === "any") {
    return `<any></any>`;
  }

  return `<address>${value}</address>`;
}

function renderAlias(alias: PfSenseAlias): string {
  const address = alias.values.join(" ");

  return `
\t\t<alias>
\t\t\t<name>${alias.name}</name>
\t\t\t<type>${alias.type}</type>
\t\t\t<address>${address}</address>
\t\t\t<descr><![CDATA[${alias.description ?? ""}]]></descr>
\t\t</alias>`;
}

function generateAliases(pfsensePlan: PfSensePlan): string {
  if (pfsensePlan.aliases.length === 0) {
    return `\t<aliases></aliases>`;
  }

  const body = pfsensePlan.aliases.map(renderAlias).join("");

  return `\t<aliases>${body}
\t</aliases>`;
}

function renderFirewallRule(
  rule: PfSenseFirewallRule,
  interfaceMap: Map<string, string>
): string {
  const protocol =
    rule.protocol === "any"
      ? ""
      : `\n\t\t\t<protocol>${rule.protocol}</protocol>`;

  const destinationPort =
    rule.destinationPort
      ? `\n\t\t\t\t<port>${rule.destinationPort}</port>`
      : "";

  const destinationPorts =
    rule.destinationPorts
      ? `\n\t\t\t\t<port>${rule.destinationPorts}</port>`
      : "";

  const pfsenseInterface = resolvePfSenseInterface(rule.interface, interfaceMap);

  return `
\t\t<rule>
\t\t\t<type>${rule.action}</type>
\t\t\t<interface>${pfsenseInterface}</interface>
\t\t\t<ipprotocol>inet</ipprotocol>${protocol}
\t\t\t<statetype><![CDATA[keep state]]></statetype>
\t\t\t<source>${renderAddress(rule.source)}</source>
\t\t\t<destination>
\t\t\t\t${renderAddress(rule.destination)}${destinationPort}${destinationPorts}
\t\t\t</destination>
\t\t\t<descr><![CDATA[${rule.description}]]></descr>
\t\t</rule>`;
}

function renderAntiLockoutRule(pfsenseInterface: string): string {
  return `
\t\t<rule>
\t\t\t<type>pass</type>
\t\t\t<interface>${pfsenseInterface}</interface>
\t\t\t<ipprotocol>inet</ipprotocol>
\t\t\t<statetype><![CDATA[keep state]]></statetype>
\t\t\t<source><any></any></source>
\t\t\t<destination><any></any></destination>
\t\t\t<descr><![CDATA[Anti-lockout management access]]></descr>
\t\t</rule>`;
}

function generateFilter(host: NetworkPlanHost, pfsensePlan: PfSensePlan): string {
  const interfaceMap = buildLogicalToPfSenseInterfaceMap(host);

  const antiLockout =
    interfaceMap.has("management")
      ? renderAntiLockoutRule(interfaceMap.get("management")!)
      : "";

  const rules = pfsensePlan.rules
    .map((rule) => renderFirewallRule(rule, interfaceMap))
    .join("");

  return `\t<filter>${antiLockout}${rules}
\t</filter>`;
}

function renderInboundNatRule(rule: PfSenseNatRule): string {
  return `
\t\t<rule>
\t\t\t<interface>${rule.interface}</interface>
\t\t\t<protocol>${rule.protocol}</protocol>
\t\t\t<source>
\t\t\t\t<any></any>
\t\t\t</source>
\t\t\t<destination>
\t\t\t\t<any></any>
\t\t\t\t<port>${rule.externalPort}</port>
\t\t\t</destination>
\t\t\t<target>${rule.internalIp}</target>
\t\t\t<local-port>${rule.internalPort}</local-port>
\t\t\t<descr><![CDATA[${rule.description}]]></descr>
\t\t\t<natreflection>default</natreflection>
\t\t\t<associated-rule-id>pass</associated-rule-id>
\t\t</rule>`;
}

function generateNat(host: NetworkPlanHost, pfsensePlan: PfSensePlan): string {
  const inboundRules = pfsensePlan.nat.map(renderInboundNatRule).join("");

  if (host.role !== "edge_firewall") {
    return `\t<nat>${inboundRules}
\t\t<outbound>
\t\t\t<mode>disabled</mode>
\t\t</outbound>
\t</nat>`;
  }

  const outboundRules = `
\t\t<outbound>
\t\t\t<mode>automatic</mode>
\t\t</outbound>`;

  return `\t<nat>${inboundRules}${outboundRules}
\t</nat>`;
}

/** Exposed for local validation without SSH (see testPfsensePatchLocal.ts). */
export function buildPatchedConfigXml(
  baseXml: string,
  host: NetworkPlanHost,
  pfsensePlan: PfSensePlan
): string {
  let xml = baseXml;

  xml = patchSystemGateway(xml, host);
  xml = replaceTag(xml, "interfaces", generateInterfaces(host));
  xml = replaceTag(xml, "gateways", generateGateways(host));
  xml = replaceTag(xml, "staticroutes", generateStaticRoutes(host));
  xml = replaceTag(xml, "nat", generateNat(host, pfsensePlan));
  xml = replaceTag(xml, "aliases", generateAliases(pfsensePlan));
  xml = replaceTag(xml, "filter", generateFilter(host, pfsensePlan));

  return xml;
}

function runInternalPfSenseCutover(
  generatedLabDir: string,
  cfg: SshConfig,
  host: NetworkPlanHost
): void {
  if (host.role !== "internal_firewall") return;

  if (!host.default_gateway) {
    throw new Error(`default_gateway manquant pour ${host.id}`);
  }

  const sshCommand = process.platform === "win32" ? "ssh.exe" : "ssh";

  run(
    sshCommand,
    sshArgs(
      cfg,
      [
        "sudo /etc/rc.reload_all || true",
        "sleep 10",
        "sudo ifconfig em0 down || true",
        "sudo route delete default >/dev/null 2>&1 || true",
        `sudo route add default ${host.default_gateway} || true`,
        "netstat -rn",
        "ping -c 2 8.8.8.8 || true"
      ].join(" && ")
    ),
    generatedLabDir,
    `Cutover gateway pfSense interne ${host.id}`,
    true
  );
}

export function patchLivePfSenseConfigs(
  generatedLabDir: string,
  networkPlanPath: string,
  pfsensePlanPath: string,
  outputDir: string
): void {
  const networkPlan = JSON.parse(
    fs.readFileSync(networkPlanPath, "utf-8")
  ) as NetworkPlan;

  const pfsensePlans = JSON.parse(
    fs.readFileSync(pfsensePlanPath, "utf-8")
  ) as PfSensePlan[];

  fs.mkdirSync(outputDir, { recursive: true });

  const pfsenseHosts = networkPlan.hosts.filter((h) => h.profile === "pfsense");

  for (const host of pfsenseHosts) {
    const pfsensePlan = pfsensePlans.find((p) => p.firewall === host.id);

    if (!pfsensePlan) {
      throw new Error(`Plan pfSense introuvable pour ${host.id}`);
    }

    const vmName = host.id;
    const cfg = getVagrantSshConfig(generatedLabDir, vmName);

    const backupPath = path.join(outputDir, `${vmName}.live-backup.xml`);
    const patchedPath = path.join(outputDir, `${vmName}.patched.xml`);

    const sshCommand = process.platform === "win32" ? "ssh.exe" : "ssh";
    const scpCommand = process.platform === "win32" ? "scp.exe" : "scp";

    const liveXml = run(
      sshCommand,
      sshArgs(cfg, "cat /cf/conf/config.xml"),
      generatedLabDir,
      `Récupération config.xml live ${vmName}`
    );

    fs.writeFileSync(backupPath, liveXml, "utf-8");

    const patchedXml = buildPatchedConfigXml(liveXml, host, pfsensePlan);

    fs.writeFileSync(patchedPath, patchedXml, "utf-8");

    run(
      scpCommand,
      scpArgs(cfg, patchedPath, "/tmp/config.xml"),
      generatedLabDir,
      `Upload config.xml patché ${vmName}`
    );

    run(
      sshCommand,
      sshArgs(
        cfg,
        "sudo cp /tmp/config.xml /cf/conf/config.xml && sudo chmod 600 /cf/conf/config.xml"
      ),
      generatedLabDir,
      `Application config.xml patché ${vmName}`
    );

    run(
      sshCommand,
      sshArgs(cfg, "sudo reboot"),
      generatedLabDir,
      `Reboot pfSense ${vmName}`,
      true
    );

    if (host.role === "internal_firewall") {
      console.log(`[pfSense patch] Attente reboot ${vmName} avant cutover runtime...`);
      sleepMs(45000);

      const cfgAfterReboot = getVagrantSshConfig(generatedLabDir, vmName);
      runInternalPfSenseCutover(generatedLabDir, cfgAfterReboot, host);
    }
  }
}