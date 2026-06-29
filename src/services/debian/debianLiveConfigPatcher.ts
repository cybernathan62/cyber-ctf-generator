import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { NetworkPlan, NetworkPlanHost } from "../core/type.js";

type SshConfig = {
  hostName: string;
  port: string;
  user: string;
  identityFile: string;
};

type InternalInterface = {
  name: string;
  network_id: string;
  ip?: string;
  gateway?: string | null;
  dns?: string[];
  mode?: "dhcp";
};

function sleepSeconds(seconds: number): void {
  if (process.platform === "win32") {
    spawnSync("powershell.exe", ["-NoProfile", "-Command", `Start-Sleep -Seconds ${seconds}`], {
      stdio: "inherit",
      shell: false
    });
    return;
  }

  spawnSync("sleep", [String(seconds)], {
    stdio: "inherit",
    shell: false
  });
}

function run(command: string, args: string[], cwd: string, label: string, allowFailure = false): string {
  console.log(`\n[Debian patch] ${label}`);
  console.log(`${command} ${args.join(" ")}`);

  const maxAttempts = 30;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const result = spawnSync(command, args, {
      cwd,
      encoding: "utf-8",
      shell: false,
      maxBuffer: 1024 * 1024 * 50
    });

    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);

    if (!result.error && result.status === 0) return result.stdout ?? "";

    const stderr = String(result.stderr ?? "");
    const retryable =
      result.status === 255 ||
      stderr.includes("Connection closed") ||
      stderr.includes("Connection reset") ||
      stderr.includes("No route to host") ||
      stderr.includes("Connection timed out");

    if (retryable && attempt < maxAttempts) {
      console.log(`[Debian patch] SSH/SCP pas prêt, retry ${attempt}/${maxAttempts} dans 15s...`);
      sleepSeconds(15);
      continue;
    }

    if (result.error) throw result.error;

    if (!allowFailure && result.status !== 0) {
      throw new Error(`[Debian patch] Échec ${label} avec code ${result.status}`);
    }

    return result.stdout ?? "";
  }

  return "";
}

function getVagrantSshConfig(generatedLabDir: string, vmName: string): SshConfig {
  const command = process.platform === "win32" ? "vagrant.exe" : "vagrant";
  const raw = run(command, ["ssh-config", vmName], generatedLabDir, `Lecture ssh-config ${vmName}`);

  const get = (key: string): string => {
    const line = raw.split(/\r?\n/).find((l) => l.trim().toLowerCase().startsWith(key.toLowerCase()));
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

function resolveVagrantVmName(planHostId: string): string {
  /*
    Compatibilité avec les anciens IDs générés dans network-plan.json.

    Le générateur réseau peut encore produire des noms de type:
    - ids-sensor-1-1
    - passbolt_server-1-1

    Alors que le Vagrantfile corrigé expose:
    - ids-sensor-1
    - passbolt-1

    Cette normalisation évite un échec sur:
    vagrant ssh-config <ancien-nom>
  */
  const aliases: Record<string, string> = {
    "ids-sensor-1-1": "ids-sensor-1",
    "passbolt_server-1-1": "passbolt-1",
    "passbolt-server-1-1": "passbolt-1"
  };

  return aliases[planHostId] ?? planHostId;
}

function sshSecurityOptions(): string[] {
  const mode = process.env.SSH_TRUST_MODE ?? "lab";

  if (mode === "production") {
    return ["-o", "StrictHostKeyChecking=yes"];
  }

  return [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null"
  ];
}

function sshArgs(cfg: SshConfig, remoteCommand: string): string[] {
  return [
    "-i", cfg.identityFile,
    "-p", cfg.port,
    ...sshSecurityOptions(),
    "-o", "LogLevel=ERROR",
    `${cfg.user}@${cfg.hostName}`,
    remoteCommand
  ];
}

function scpArgs(cfg: SshConfig, localPath: string, remotePath: string): string[] {
  return [
    "-i", cfg.identityFile,
    "-P", cfg.port,
    ...sshSecurityOptions(),
    "-o", "LogLevel=ERROR",
    localPath,
    `${cfg.user}@${cfg.hostName}:${remotePath}`
  ];
}

function ipOnly(ip: string): string {
  return ip.split("/")[0];
}

function cidrOnly(ip: string): number {
  const subnet = ip.split("/")[1];
  if (!subnet) throw new Error(`CIDR invalide: ${ip}`);

  const cidr = Number(subnet);

  if (!Number.isInteger(cidr) || cidr < 1 || cidr > 32) {
    throw new Error(`CIDR invalide: ${ip}`);
  }

  return cidr;
}

function cidrToNetmask(cidr: number): string {
  if (!Number.isInteger(cidr) || cidr < 1 || cidr > 32) {
    throw new Error(`CIDR invalide: ${cidr}`);
  }

  const mask = cidr === 32 ? 0xffffffff : (0xffffffff << (32 - cidr)) >>> 0;

  return [
    (mask >>> 24) & 255,
    (mask >>> 16) & 255,
    (mask >>> 8) & 255,
    mask & 255
  ].join(".");
}

function assertIpv4(value: string, label: string): void {
  const parts = value.split(".");
  const valid =
    parts.length === 4 &&
    parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);

  if (!valid) {
    throw new Error(`[Debian patch] IPv4 invalide pour ${label}: ${value}`);
  }
}

function getInternalInterfaces(host: NetworkPlanHost): InternalInterface[] {
  return (host.interfaces ?? []).filter((iface: any) => {
    return iface.name !== "wan" && iface.ip && iface.mode !== "dhcp";
  }) as InternalInterface[];
}

function findPrimaryInternalInterface(host: NetworkPlanHost): InternalInterface {
  const interfaces = getInternalInterfaces(host);

  const primary =
    interfaces.find((i) => i.network_id !== "monitor-net" && i.gateway) ??
    interfaces.find((i) => i.network_id !== "monitor-net") ??
    interfaces[0];

  if (!primary) {
    throw new Error(`Aucune interface interne avec IP trouvée pour ${host.id}`);
  }

  return primary;
}

function findPrimaryLinuxInterfaceName(host: NetworkPlanHost): string {
  const interfaces = getInternalInterfaces(host);
  const primary = findPrimaryInternalInterface(host);
  const index = interfaces.findIndex((iface) => iface === primary);

  if (index < 0) {
    throw new Error(`Interface primaire introuvable pour ${host.id}`);
  }

  return linuxInterfaceName(index);
}

function findGatewayForHost(host: NetworkPlanHost): string {
  const iface = findPrimaryInternalInterface(host);

  if (iface.gateway) return iface.gateway;

  const ip = ipOnly(iface.ip as string);
  const [a, b, c] = ip.split(".");
  return `${a}.${b}.${c}.1`;
}

function linuxInterfaceName(index: number): string {
  return `enp0s${8 + index}`;
}

function generateStaticInterfaceBlock(
  linuxName: string,
  iface: InternalInterface,
  includeDefaultGateway: boolean,
  defaultGateway: string
): string {
  if (!iface.ip) {
    throw new Error(`[Debian patch] IP absente pour interface ${iface.network_id}`);
  }

  const address = ipOnly(iface.ip);
  const netmask = cidrToNetmask(cidrOnly(iface.ip));

  assertIpv4(address, `${iface.network_id}.address`);

  const lines = [
    `auto ${linuxName}`,
    `iface ${linuxName} inet static`,
    `    address ${address}`,
    `    netmask ${netmask}`
  ];

  if (includeDefaultGateway) {
    assertIpv4(defaultGateway, `${iface.network_id}.gateway`);

    lines.push(`    gateway ${defaultGateway}`);
    lines.push(`    dns-nameservers ${defaultGateway} 8.8.8.8 1.1.1.1`);
    lines.push(`    post-up ip route del default dev enp0s3 || true`);
    lines.push(`    post-up ip route del default via 10.0.2.2 dev enp0s3 || true`);
    lines.push(`    post-up ip route replace default via ${defaultGateway} dev ${linuxName} || true`);
    lines.push(
      `    post-up /bin/sh -c 'printf "nameserver ${defaultGateway}\\nnameserver 8.8.8.8\\nnameserver 1.1.1.1\\n" > /etc/resolv.conf'`
    );
  } else {
    lines.push(`    post-up ip link set ${linuxName} up || true`);
  }

  return lines.join("\n");
}

function generateInterfacesFile(host: NetworkPlanHost): string {
  const interfaces = getInternalInterfaces(host);
  const primary = findPrimaryInternalInterface(host);
  const gateway = findGatewayForHost(host);

  const blocks: string[] = [];

  interfaces.forEach((iface, index) => {
    const linuxName = linuxInterfaceName(index);
    const isPrimary = iface === primary;
    const isMonitor = iface.network_id === "monitor-net";

    blocks.push(
      generateStaticInterfaceBlock(
        linuxName,
        iface,
        isPrimary && !isMonitor,
        gateway
      )
    );
  });

  return `# Generated by Cyber CTF Generator
# ${host.id}
# enp0s3 = NAT Vagrant DHCP pour SSH/provisioning uniquement
# enp0s8+ = interfaces internes lab selon network-plan.json
# gateway uniquement sur l'interface primaire, jamais sur monitor-net

auto lo
iface lo inet loopback

allow-hotplug enp0s3
iface enp0s3 inet dhcp
    post-up ip route del default dev enp0s3 || true
    post-up ip route del default via 10.0.2.2 dev enp0s3 || true

${blocks.join("\n\n")}
`;
}

function isDebianHost(host: NetworkPlanHost): boolean {
  return host.profile !== "pfsense";
}

function patchDebianPackageHealth(
  sshCommand: string,
  cfg: SshConfig,
  generatedLabDir: string,
  vmName: string
): void {
  /*
    Important :
    Les mises à jour lourdes Debian doivent être faites pendant la fabrication
    de la box Vagrant, pas pendant le déploiement live du lab.

    On évite volontairement ici :
    - apt upgrade
    - apt full-upgrade
    - apt dist-upgrade
    - grub-install
    - update-grub

    Raison :
    grub-pc peut ouvrir une question interactive "GRUB install devices"
    et laisser dpkg en état half-configured, ce qui casse ensuite Wazuh/APT.
  */
  run(
    sshCommand,
    sshArgs(
      cfg,
      [
        "export DEBIAN_FRONTEND=noninteractive",
        "sudo dpkg --configure -a",
        "sudo apt-get -f install -y",
        "sudo apt-get update",
        "sudo dpkg --audit",
        "if dpkg -l | grep -E '^(iF|iU)'; then echo '[Debian patch] ERREUR: paquets cassés détectés'; exit 1; fi",
        "apt list --upgradable 2>/dev/null || true",
        "apt-cache policy libfreerdp3-3 || true",
        "uname -r || true"
      ].join("; ")
    ),
    generatedLabDir,
    `Contrôle santé APT/DPKG Debian ${vmName}`,
    false
  );
}

export function patchLiveDebianConfigs(
  generatedLabDir: string,
  networkPlanPath: string,
  outputDir: string
): void {
  const plan = JSON.parse(fs.readFileSync(networkPlanPath, "utf-8")) as NetworkPlan;

  fs.mkdirSync(outputDir, { recursive: true });

  const debianHosts = plan.hosts.filter(isDebianHost);

  const sshCommand = process.platform === "win32" ? "ssh.exe" : "ssh";
  const scpCommand = process.platform === "win32" ? "scp.exe" : "scp";

  for (const host of debianHosts) {
    const planHostId = host.id;
    const vmName = resolveVagrantVmName(planHostId);

    if (vmName !== planHostId) {
      console.warn(
        `[Debian patch] Alias VM détecté: ${planHostId} dans network-plan.json -> ${vmName} dans Vagrantfile`
      );
    }

    const cfg = getVagrantSshConfig(generatedLabDir, vmName);

    const gateway = findGatewayForHost(host);
    const primaryLinuxInterface = findPrimaryLinuxInterfaceName(host);
    const interfacesContent = generateInterfacesFile(host);
    const interfacesPath = path.join(outputDir, `${vmName}.interfaces`);

    fs.writeFileSync(interfacesPath, interfacesContent, "utf-8");

    run(
      scpCommand,
      scpArgs(cfg, interfacesPath, "/tmp/interfaces"),
      generatedLabDir,
      `Upload /etc/network/interfaces ${vmName}`
    );

    run(
      sshCommand,
      sshArgs(
        cfg,
        "sudo cp /etc/network/interfaces /etc/network/interfaces.bak.$(date +%Y%m%d%H%M%S) && sudo cp /tmp/interfaces /etc/network/interfaces && sudo chmod 644 /etc/network/interfaces"
      ),
      generatedLabDir,
      `Application /etc/network/interfaces ${vmName}`
    );

    const internalInterfaces = getInternalInterfaces(host);

    const runtimeInterfaceCommands = internalInterfaces.flatMap((iface, index) => {
      const linuxName = linuxInterfaceName(index);

      if (!iface.ip) return [];

      return [
        `sudo ip link set ${linuxName} up || true`,
        `sudo ip addr replace ${iface.ip} dev ${linuxName} || true`
      ];
    });

    const interfaceBringUpCommands = internalInterfaces.flatMap((_, index) => {
      const linuxName = linuxInterfaceName(index);

      return [
        `sudo ip link set ${linuxName} up || true`,
        `sudo ifdown ${linuxName} >/dev/null 2>&1 || true`,
        `sudo ifup ${linuxName} >/dev/null 2>&1 || true`
      ];
    });

    const interfaceDebugCommands = internalInterfaces.flatMap((_, index) => {
      const linuxName = linuxInterfaceName(index);

      return [
        `ip addr show ${linuxName} || true`
      ];
    });

    run(
      sshCommand,
      sshArgs(
        cfg,
        [
          ...interfaceBringUpCommands,
          "sleep 2",
          ...runtimeInterfaceCommands,

          "sudo ip route del default via 10.0.2.2 dev enp0s3 >/dev/null 2>&1 || true",
          "sudo ip route del default dev enp0s3 >/dev/null 2>&1 || true",

          `sudo ip route replace default via ${gateway} dev ${primaryLinuxInterface} || true`,

          "sudo rm -f /etc/resolv.conf",
          `sudo /bin/sh -c 'printf "nameserver ${gateway}\\nnameserver 8.8.8.8\\nnameserver 1.1.1.1\\n" > /etc/resolv.conf'`,

          ...interfaceDebugCommands,
          "ip route",
          "ip route get 8.8.8.8 || true",
          "cat /etc/resolv.conf",
          "ping -c 2 8.8.8.8 || true",
          "ping -c 2 deb.debian.org || true"
        ].join("; ")
      ),
      generatedLabDir,
      `Activation interfaces + gateway + DNS ${vmName}`,
      true
    );

    patchDebianPackageHealth(
      sshCommand,
      cfg,
      generatedLabDir,
      vmName
    );
  }
}
