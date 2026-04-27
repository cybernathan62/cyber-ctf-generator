import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { NetworkPlan, NetworkPlanHost } from "./type.js";

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
    shell: false
  });

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);

  if (result.error) throw result.error;

  if (!allowFailure && result.status !== 0) {
    throw new Error(`[pfSense patch] Échec ${label} avec code ${result.status}`);
  }

  return result.stdout ?? "";
}

function getVagrantSshConfig(generatedLabDir: string, vmName: string): SshConfig {
  const command = process.platform === "win32" ? "vagrant.exe" : "vagrant";

  const raw = run(
    command,
    ["ssh-config", vmName],
    generatedLabDir,
    `Lecture ssh-config ${vmName}`
  );

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

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function replaceTag(xml: string, tag: string, replacement: string): string {
  const regex = new RegExp(`<${tag}>[\\s\\S]*?<\\/${tag}>`, "m");

  if (!regex.test(xml)) {
    throw new Error(`Bloc XML introuvable: <${tag}>`);
  }

  return xml.replace(regex, replacement);
}

function replaceSystemHostnameAndGateway(xml: string, host: NetworkPlanHost): string {
  let patched = xml;

  patched = patched.replace(
    /<hostname>[\s\S]*?<\/hostname>/,
    `<hostname>${host.id}</hostname>`
  );

  if (host.role === "internal_firewall") {
    if (/<gateway>[\s\S]*?<\/gateway>/.test(patched)) {
      patched = patched.replace(/<gateway>[\s\S]*?<\/gateway>/, `<gateway>GW_EDGE</gateway>`);
    } else {
      patched = patched.replace(
        /<domain>[\s\S]*?<\/domain>/,
        (match) => `${match}\n\t\t<gateway>GW_EDGE</gateway>`
      );
    }
  }

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

function generateInterfaces(host: NetworkPlanHost): string {
  let body = "";

  const hasWan = host.interfaces.some((i) => i.name === "wan");

  if (hasWan) {
    host.interfaces.forEach((iface, index) => {
      const xmlName = index === 0 ? "wan" : xmlNameByIndex(index - 1);
      body += renderInterface(xmlName, `em${index}`, iface);
    });
  } else {
    body += renderInterface("wan", "em0", {
      name: "wan_temp",
      network_id: "edge-wan",
      mode: "dhcp"
    });

    host.interfaces.forEach((iface, index) => {
      body += renderInterface(xmlNameByIndex(index), `em${index + 1}`, iface);
    });
  }

  return `\t<interfaces>${body}
\t</interfaces>`;
}

function gatewayName(routeName: string): string {
  return `GW_${routeName.toUpperCase()}`;
}

function gatewayInterfaceForEdge(host: NetworkPlanHost, gatewayIp: string): string {
  const gatewayPrefix = gatewayIp.split(".").slice(0, 3).join(".");

  const nonWanInterfaces = host.interfaces.filter((i) => i.name !== "wan");

  const index = nonWanInterfaces.findIndex((iface) => {
    if (!iface.ip) return false;
    return iface.ip.split(".").slice(0, 3).join(".") === gatewayPrefix;
  });

  if (index === -1) {
    throw new Error(`Impossible de mapper la gateway ${gatewayIp} sur une interface edge`);
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
\t\t</gateway_item>`;

    host.static_routes?.forEach((route) => {
      const iface = gatewayInterfaceForEdge(host, route.gateway);

      body += `
\t\t<gateway_item>
\t\t\t<interface>${iface}</interface>
\t\t\t<gateway>${route.gateway}</gateway>
\t\t\t<name>${gatewayName(route.name)}</name>
\t\t\t<weight>1</weight>
\t\t\t<ipprotocol>inet</ipprotocol>
\t\t</gateway_item>`;
    });
  }

  if (host.role === "internal_firewall") {
    if (!host.default_gateway) {
      throw new Error(`default_gateway manquant pour ${host.id}`);
    }

    body += `
\t\t<gateway_item>
\t\t\t<interface>lan</interface>
\t\t\t<gateway>${host.default_gateway}</gateway>
\t\t\t<name>GW_EDGE</name>
\t\t\t<weight>1</weight>
\t\t\t<ipprotocol>inet</ipprotocol>
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

  host.static_routes.forEach((route) => {
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

function generateNat(host: NetworkPlanHost): string {
  return `\t<nat>
\t\t<outbound>
\t\t\t<mode>${host.role === "edge_firewall" ? "automatic" : "disabled"}</mode>
\t\t</outbound>
\t</nat>`;
}

function generateFilter(host: NetworkPlanHost): string {
  const hasWan = host.interfaces.some((i) => i.name === "wan");
  const count = hasWan ? host.interfaces.length - 1 : host.interfaces.length;

  let body = "";

  for (let index = 0; index < count; index++) {
    const iface = xmlNameByIndex(index);

    body += `
\t\t<rule>
\t\t\t<type>pass</type>
\t\t\t<interface>${iface}</interface>
\t\t\t<ipprotocol>inet</ipprotocol>
\t\t\t<statetype><![CDATA[keep state]]></statetype>
\t\t\t<source><any></any></source>
\t\t\t<destination><any></any></destination>
\t\t\t<descr><![CDATA[TEMP allow any on ${iface}]]></descr>
\t\t</rule>`;
  }

  return `\t<filter>${body}
\t</filter>`;
}

function patchConfigXml(baseXml: string, host: NetworkPlanHost): string {
  let xml = baseXml;

  xml = replaceSystemHostnameAndGateway(xml, host);
  xml = replaceTag(xml, "interfaces", generateInterfaces(host));
  xml = replaceTag(xml, "gateways", generateGateways(host));
  xml = replaceTag(xml, "staticroutes", generateStaticRoutes(host));
  xml = replaceTag(xml, "nat", generateNat(host));
  xml = replaceTag(xml, "filter", generateFilter(host));

  return xml;
}

export function patchLivePfSenseConfigs(
  generatedLabDir: string,
  networkPlanPath: string,
  outputDir: string
): void {
  const plan = JSON.parse(fs.readFileSync(networkPlanPath, "utf-8")) as NetworkPlan;

  fs.mkdirSync(outputDir, { recursive: true });

  const pfsenseHosts = plan.hosts.filter((h) => h.profile === "pfsense");

  for (const host of pfsenseHosts) {
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

    const patchedXml = patchConfigXml(liveXml, host);

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
      `Application config.xml patché ${vmName}`,
      false
    );

    run(
      sshCommand,
      sshArgs(cfg, "sudo reboot"),
      generatedLabDir,
      `Reboot pfSense ${vmName}`,
      true
    );
  }
}