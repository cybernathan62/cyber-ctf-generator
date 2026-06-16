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

type SshAccessMap = Record<string, SshConfig>;

type AgentTarget = {
  vmName: string;
  host: NetworkPlanHost;
  ssh: SshConfig;
  managerIp: string;
};

function run(command: string, args: string[], cwd: string, label: string, allowFailure = false): string {
  console.log(`\n[Wazuh agent] ${label}`);
  console.log(`${command} ${args.join(" ")}`);

  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf-8",
    shell: false,
    maxBuffer: 1024 * 1024 * 120
  });

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);

  if (result.error) {
    if (allowFailure) {
      console.warn(`[Wazuh agent] Warning ${label}: ${result.error.message}`);
      return `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    }
    throw result.error;
  }

  if (!allowFailure && result.status !== 0) {
    throw new Error(`[Wazuh agent] Échec ${label} avec code ${result.status}`);
  }

  if (allowFailure && result.status !== 0) {
    console.warn(`[Wazuh agent] Warning ${label}: code ${result.status}`);
  }

  return `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function writeTextAtomic(filePath: string, content: string, mode = 0o600): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });

  const tmpPath = `${filePath}.tmp`;

  fs.writeFileSync(tmpPath, content, {
    encoding: "utf-8",
    mode
  });

  fs.renameSync(tmpPath, filePath);
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

function readJsonFile<T>(filePath: string): T {
  if (!fs.existsSync(filePath)) {
    throw new Error(`[Wazuh agent] Fichier introuvable: ${filePath}`);
  }

  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`[Wazuh agent] JSON invalide dans ${filePath}: ${message}`);
  }
}

function cleanIp(value: unknown): string {
  return String(value).split("/")[0].trim();
}

function getValueIp(value: unknown): string | null {
  if (value === undefined || value === null || value === "") return null;
  return cleanIp(value);
}

function findHostIp(host: NetworkPlanHost): string {
  const h = host as any;

  const directIp =
    getValueIp(h.ip) ??
    getValueIp(h.ip_address) ??
    getValueIp(h.address) ??
    getValueIp(h.ipv4) ??
    getValueIp(h.private_ip);

  if (directIp) return directIp;

  if (Array.isArray(h.interfaces)) {
    const getIfaceIp = (i: any): string | null => {
      return (
        getValueIp(i.ip) ??
        getValueIp(i.ip_address) ??
        getValueIp(i.address) ??
        getValueIp(i.ipv4) ??
        getValueIp(i.private_ip)
      );
    };

    const preferredIface = h.interfaces.find((i: any) => {
      const marker = String(
        i.name ??
          i.network_id ??
          i.network ??
          i.zone ??
          i.zone_id ??
          i.label ??
          ""
      ).toLowerCase();

      return marker.includes("soc") || marker.includes("wazuh") || marker.includes("management");
    });

    const preferredIp = preferredIface ? getIfaceIp(preferredIface) : null;
    if (preferredIp) return preferredIp;

    const firstWithIp = h.interfaces.find((i: any) => getIfaceIp(i));
    const firstIp = firstWithIp ? getIfaceIp(firstWithIp) : null;
    if (firstIp) return firstIp;
  }

  throw new Error(`[Wazuh agent] IP introuvable ou ambiguë pour host: ${JSON.stringify(host, null, 2)}`);
}

function getHostName(host: NetworkPlanHost): string {
  const h = host as any;
  return String(h.name ?? h.hostname ?? h.vmName ?? h.vm_name ?? h.id ?? "");
}

function getHostRole(host: NetworkPlanHost): string {
  const h = host as any;
  return String(h.role ?? h.service ?? h.profile ?? h.vm_profile ?? h.type ?? "").toLowerCase();
}

function isWazuhHost(host: NetworkPlanHost): boolean {
  const name = getHostName(host).toLowerCase();
  const role = getHostRole(host);

  return (
    name === "wazuh-1" ||
    name.startsWith("wazuh") ||
    role === "wazuh" ||
    role === "wazuh_server" ||
    role === "wazuh-server"
  );
}

function isFirewallHost(host: NetworkPlanHost): boolean {
  const name = getHostName(host).toLowerCase();
  const role = getHostRole(host);

  return (
    name.includes("pfsense") ||
    name.includes("firewall") ||
    role.includes("firewall") ||
    role.includes("pfsense") ||
    role === "edge_firewall" ||
    role === "internal_firewall"
  );
}

function isAgentEligibleHost(host: NetworkPlanHost): boolean {
  const name = getHostName(host).toLowerCase();
  const role = getHostRole(host);

  if (!name) return false;
  if (isWazuhHost(host)) return false;
  if (isFirewallHost(host)) return false;

  const excludedRoles = new Set([
    "switch",
    "router",
    "network_device",
    "unknown"
  ]);

  if (excludedRoles.has(role)) return false;

  return true;
}

function expandIdentityFile(identityFile: string): string {
  const cleaned = identityFile.replace(/^"|"$/g, "");

  if (cleaned.startsWith("~/") || cleaned.startsWith("~\\")) {
    const home = process.env.USERPROFILE ?? process.env.HOME;
    if (!home) return cleaned;
    return path.join(home, cleaned.slice(2));
  }

  return cleaned;
}

function normalizeSshConfig(raw: any): SshConfig {
  const hostName = String(
    raw.HostName ??
      raw.hostname ??
      raw.hostName ??
      raw.host ??
      raw.ssh_host ??
      "127.0.0.1"
  );

  const port = String(raw.Port ?? raw.port ?? raw.ssh_port ?? "22");
  const user = String(raw.User ?? raw.user ?? raw.ssh_user ?? "vagrant");

  const identityFile = expandIdentityFile(
    String(raw.IdentityFile ?? raw.identityFile ?? raw.identity_file ?? raw.key ?? "")
  );

  if (!identityFile) {
    throw new Error("[Wazuh agent] IdentityFile SSH manquant dans ssh-access.local.json");
  }

  return { hostName, port, user, identityFile };
}

function loadSshAccess(outputsDir: string): SshAccessMap {
  const filePath = path.join(outputsDir, "ssh-access.local.json");
  const raw = readJsonFile<any>(filePath);
  const result: SshAccessMap = {};

  if (Array.isArray(raw)) {
    for (const item of raw) {
      const name = String(item.name ?? item.vmName ?? item.vm_name ?? item.host ?? item.hostname ?? "");
      if (name) result[name] = normalizeSshConfig(item);
    }
    return result;
  }

  for (const [key, value] of Object.entries(raw)) {
    result[key] = normalizeSshConfig(value);
  }

  return result;
}

function getNetworkHosts(networkPlan: NetworkPlan): NetworkPlanHost[] {
  const n = networkPlan as any;

  if (Array.isArray(n.hosts)) return n.hosts as NetworkPlanHost[];
  if (Array.isArray(n.instances)) return n.instances as NetworkPlanHost[];
  if (Array.isArray(n.vms)) return n.vms as NetworkPlanHost[];

  if (Array.isArray(n.zone_definitions)) {
    const hosts: NetworkPlanHost[] = [];

    for (const zone of n.zone_definitions) {
      if (Array.isArray(zone.hosts)) hosts.push(...zone.hosts);
      if (Array.isArray(zone.instances)) hosts.push(...zone.instances);
    }

    if (hosts.length > 0) return hosts;
  }

  throw new Error("[Wazuh agent] Aucun host trouvé dans network-plan.json");
}

function resolveOutputsDir(outputsDir: string): string {
  return fs.existsSync(path.join(outputsDir, "network-plan.json"))
    ? outputsDir
    : path.dirname(outputsDir);
}

function sshArgs(ssh: SshConfig, remoteCommand: string): string[] {
  return [
    "-i",
    ssh.identityFile,
    "-p",
    ssh.port,
    ...sshSecurityOptions(),
    "-o",
    "LogLevel=ERROR",
    `${ssh.user}@${ssh.hostName}`,
    remoteCommand
  ];
}

function scpArgs(ssh: SshConfig, localPath: string, remotePath: string): string[] {
  return [
    "-i",
    ssh.identityFile,
    "-P",
    ssh.port,
    ...sshSecurityOptions(),
    "-o",
    "LogLevel=ERROR",
    localPath,
    `${ssh.user}@${ssh.hostName}:${remotePath}`
  ];
}

function buildAgentInstallScript(target: AgentTarget): string {
  const agentName = target.vmName;

  const script = `#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

WAZUH_MANAGER="__WAZUH_MANAGER__"
WAZUH_AGENT_NAME="__WAZUH_AGENT_NAME__"

log() {
  echo
  echo "--- $* ---"
}

wait_manager_ports() {
  local timeout=180
  local elapsed=0

  while [ "$elapsed" -lt "$timeout" ]; do
    if nc -z "$WAZUH_MANAGER" 1514 >/dev/null 2>&1 && nc -z "$WAZUH_MANAGER" 1515 >/dev/null 2>&1; then
      echo "[OK] Manager reachable on $WAZUH_MANAGER:1514/1515"
      return 0
    fi

    echo "waiting Wazuh manager $WAZUH_MANAGER:1514/1515..."
    sleep 5
    elapsed=$((elapsed + 5))
  done

  echo "[ERROR] Wazuh manager unreachable from agent"
  ip -br a || true
  ip route || true
  nc -vz "$WAZUH_MANAGER" 1514 || true
  nc -vz "$WAZUH_MANAGER" 1515 || true
  exit 1
}

log "APT REPAIR"
apt-get clean || true
apt-get update -y
apt-get install -f -y || true

log "INSTALL PREREQUISITES"
apt-get install -y curl gnupg ca-certificates apt-transport-https procps netcat-openbsd

log "CONFIGURE WAZUH REPOSITORY"
install -d -m 0755 /usr/share/keyrings
rm -f /usr/share/keyrings/wazuh.gpg
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 0644 /usr/share/keyrings/wazuh.gpg

cat > /etc/apt/sources.list.d/wazuh.list <<'EOF'
deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main
EOF

apt-get update -y

log "WAIT MANAGER BEFORE INSTALL"
wait_manager_ports

log "INSTALL WAZUH AGENT ONLY"
WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" apt-get install -y wazuh-agent

log "CONFIGURE AGENT MANAGER"
python3 - <<PY
from pathlib import Path
import re

p = Path("/var/ossec/etc/ossec.conf")
s = p.read_text()

if "<client>" not in s:
    raise SystemExit("[ERROR] /var/ossec/etc/ossec.conf does not contain <client>")

s = re.sub(r"<address>[^<]+</address>", "<address>$WAZUH_MANAGER</address>", s, count=1)
p.write_text(s)
PY

log "ENABLE AND START AGENT"
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent
sleep 5

log "VALIDATE AGENT"
systemctl status wazuh-agent --no-pager -l || true
/var/ossec/bin/wazuh-control status || true

echo "--- AGENT CONFIG ---"
grep -nA8 -B2 "<client>" /var/ossec/etc/ossec.conf || true

echo "--- AGENT LOGS ---"
grep -iE "connected|manager|error|failed|denied|invalid|auth|enroll" /var/ossec/logs/ossec.log | tail -n 120 || true

log "DONE WAZUH AGENT INSTALL"
exit 0
`;

  return script
    .replaceAll("__WAZUH_MANAGER__", target.managerIp)
    .replaceAll("__WAZUH_AGENT_NAME__", agentName);
}

function createRuntimeFiles(generatedLabDir: string, target: AgentTarget, script: string): string {
  const runtimeDir = path.join(generatedLabDir, "wazuh-agent-live-patcher-runtime");
  ensureDir(runtimeDir);

  const scriptPath = path.join(runtimeDir, `${target.vmName}-install-wazuh-agent.sh`);
    writeTextAtomic(scriptPath, script, 0o700);

  return scriptPath;
}

function resolveTargets(outputsDir: string, generatedLabDir: string): AgentTarget[] {
  const realOutputsDir = resolveOutputsDir(outputsDir);
  const networkPlanPath = path.join(realOutputsDir, "network-plan.json");
  const networkPlan = readJsonFile<NetworkPlan>(networkPlanPath);
  const hosts = getNetworkHosts(networkPlan);
  const sshAccess = loadSshAccess(realOutputsDir);

  const wazuhHost = hosts.find(isWazuhHost);

  if (!wazuhHost) {
    console.log("[Wazuh agent] Aucun serveur Wazuh trouvé dans network-plan.json, skip agents.");
    return [];
  }

  const managerIp = findHostIp(wazuhHost);
  console.log(`[Wazuh agent] Manager Wazuh détecté: ${managerIp}`);

  const agentHosts = hosts.filter(isAgentEligibleHost);

  if (agentHosts.length === 0) {
    console.log("[Wazuh agent] Aucun host éligible agent trouvé dans network-plan.json, skip.");
    return [];
  }

  return agentHosts.map((host) => {
    const vmName = getHostName(host);
    const ssh = sshAccess[vmName];

    if (!ssh) {
      throw new Error(`[Wazuh agent] SSH config introuvable pour ${vmName} dans ssh-access.local.json`);
    }

    return {
      vmName,
      host,
      ssh,
      managerIp
    };
  });
}

export function patchLiveWazuhAgents(outputsDir = path.join(process.cwd(), "outputs")): void {
  const generatedLabDir = resolveOutputsDir(outputsDir);
  ensureDir(generatedLabDir);

  const targets = resolveTargets(outputsDir, generatedLabDir);
  if (targets.length === 0) return;

  const sshCommand = process.platform === "win32" ? "ssh.exe" : "ssh";
  const scpCommand = process.platform === "win32" ? "scp.exe" : "scp";

  for (const target of targets) {
    const script = buildAgentInstallScript(target);
    const localScriptPath = createRuntimeFiles(generatedLabDir, target, script);
    const remoteScriptPath = `/tmp/${target.vmName}-install-wazuh-agent.sh`;

    console.log(`\n[Wazuh agent] Cible agent: ${target.vmName}`);
    console.log(`[Wazuh agent] Manager: ${target.managerIp}`);

    run(
      scpCommand,
      scpArgs(target.ssh, localScriptPath, remoteScriptPath),
      generatedLabDir,
      `Upload script agent ${target.vmName}`
    );

    run(
      sshCommand,
      sshArgs(
        target.ssh,
        `sudo chmod 700 ${shellQuote(remoteScriptPath)} && sudo bash ${shellQuote(remoteScriptPath)}`
      ),
      generatedLabDir,
      `Installation agent Wazuh ${target.vmName}`
    );
  }
}

export const patchLiveWazuhAgentConfigs = patchLiveWazuhAgents;

export default patchLiveWazuhAgents;