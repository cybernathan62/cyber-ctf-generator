import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { NetworkPlan, NetworkPlanHost } from "./type.js";

type SshAccessEntry = {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  identity_file: string;
  access_method?: string;
};

type SshAccessMap = Record<string, SshAccessEntry>;

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

  return `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function sshArgs(access: SshAccessEntry, remoteCommand: string): string[] {
  return [
    "-i", access.identity_file,
    "-p", String(access.ssh_port),
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    `${access.ssh_user}@${access.ssh_host}`,
    remoteCommand
  ];
}

function scpArgs(access: SshAccessEntry, localPath: string, remotePath: string): string[] {
  return [
    "-i", access.identity_file,
    "-P", String(access.ssh_port),
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    localPath,
    `${access.ssh_user}@${access.ssh_host}:${remotePath}`
  ];
}

function getPrimaryIp(host: NetworkPlanHost): string {
  const h = host as any;

  if (h.ip) return String(h.ip).split("/")[0];

  const iface = h.interfaces?.find((i: any) => i.name !== "wan" && i.ip);
  if (!iface?.ip) throw new Error(`IP interne manquante pour ${h.id ?? h.name}`);

  return String(iface.ip).split("/")[0];
}

function isWazuhServer(host: NetworkPlanHost): boolean {
  const h = host as any;
  return String(h.role ?? "").toLowerCase() === "wazuh_server";
}

function isPfSenseHost(host: NetworkPlanHost): boolean {
  const h = host as any;
  const role = String(h.role ?? "").toLowerCase();
  const id = String(h.id ?? h.name ?? "").toLowerCase();
  const profile = String(h.profile ?? h.vm_profile ?? "").toLowerCase();

  return role.includes("firewall") || role.includes("pfsense") || id.includes("pfsense") || profile.includes("pfsense");
}

function isDebianLike(host: NetworkPlanHost): boolean {
  const h = host as any;
  const profile = String(h.profile ?? h.vm_profile ?? "").toLowerCase();
  return profile.includes("debian") || profile.includes("wazuh");
}

function isAgentTarget(host: NetworkPlanHost): boolean {
  if (isWazuhServer(host)) return false;
  if (isPfSenseHost(host)) return false;

  const h = host as any;
  const role = String(h.role ?? "").toLowerCase();

  const allowedRoles = [
    "bastion",
    "reverse_proxy",
    "dmz",
    "zabbix_server",
    "db_server",
    "ad_server",
    "file_server",
    "backup_server",
    "web_server",
    "linux_server"
  ];

  return allowedRoles.includes(role) || isDebianLike(host);
}

function normalizeIdentityFile(value: string): string {
  const cleaned = value.replace(/^"|"$/g, "");

  if (cleaned.startsWith("~/") || cleaned.startsWith("~\\")) {
    const home = process.env.USERPROFILE || process.env.HOME;
    if (!home) throw new Error("Impossible de résoudre ~ dans identity_file");
    return path.join(home, cleaned.slice(2));
  }

  return cleaned;
}

function loadSshAccess(sshAccessPath: string): SshAccessMap {
  if (!sshAccessPath.endsWith(".local.json")) {
    throw new Error(`Refus sécurité: le fichier SSH doit être un .local.json non versionné: ${sshAccessPath}`);
  }

  if (!fs.existsSync(sshAccessPath)) {
    throw new Error(`Fichier SSH introuvable: ${sshAccessPath}`);
  }

  const raw = JSON.parse(fs.readFileSync(sshAccessPath, "utf-8")) as SshAccessMap;

  for (const entry of Object.values(raw)) {
    entry.identity_file = normalizeIdentityFile(entry.identity_file);
  }

  return raw;
}

function writeAgentInstallScript(outputDir: string, wazuhIp: string): string {
  const runtimeDir = path.join(outputDir, "wazuh-agent-runtime");
  fs.mkdirSync(runtimeDir, { recursive: true });

  const scriptPath = path.join(runtimeDir, "install-wazuh-agent.sh");

  const content = `#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

WAZUH_MANAGER="${wazuhIp}"
AGENT_NAME="$1"

log() {
  echo
  echo "--- $* ---"
}

wait_port() {
  local host="$1"
  local port="$2"
  local timeout="180"
  local elapsed="0"

  until nc -z -w 3 "$host" "$port" >/dev/null 2>&1; do
    echo "Waiting for Wazuh manager $host:$port..."
    sleep 5
    elapsed=$((elapsed + 5))

    if [ "$elapsed" -ge "$timeout" ]; then
      echo "[ERROR] Wazuh manager port $port unreachable after timeout"
      ip route || true
      cat /etc/resolv.conf || true
      nc -vz "$host" "$port" || true
      exit 1
    fi
  done
}

log "WAZUH AGENT INSTALL: $AGENT_NAME -> $WAZUH_MANAGER"

log "NETWORK CHECK"
ip route || true
cat /etc/resolv.conf || true
ping -c 2 "$WAZUH_MANAGER" || true

log "INSTALL PREREQUISITES"
apt-get update -y || true
apt-get install -y curl ca-certificates gnupg apt-transport-https netcat-openbsd

log "WAIT MANAGER PORTS"
wait_port "$WAZUH_MANAGER" 1515
wait_port "$WAZUH_MANAGER" 1514

log "CONFIGURE WAZUH REPOSITORY"
install -d -m 0755 /usr/share/keyrings
rm -f /usr/share/keyrings/wazuh.gpg
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 0644 /usr/share/keyrings/wazuh.gpg

cat > /etc/apt/sources.list.d/wazuh.list <<'EOF'
deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main
EOF

apt-get update -y

log "INSTALL OR RECONFIGURE WAZUH AGENT"
if dpkg -s wazuh-agent >/dev/null 2>&1; then
  echo "wazuh-agent already installed, reconfiguring."
else
  WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" apt-get install -y wazuh-agent
fi

log "FORCE MANAGER CONFIG"
if [ -f /var/ossec/etc/ossec.conf ]; then
  sed -i "s|<address>.*</address>|<address>$WAZUH_MANAGER</address>|g" /var/ossec/etc/ossec.conf || true
fi

log "FIX AGENT PERMISSIONS"
chown -R root:wazuh /var/ossec 2>/dev/null || true
chmod 750 /var/ossec 2>/dev/null || true

log "ENABLE + START AGENT"
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

sleep 8

log "AGENT STATUS"
systemctl is-active wazuh-agent
systemctl status wazuh-agent --no-pager -l || true

log "AGENT LOG TAIL"
tail -n 100 /var/ossec/logs/ossec.log || true

log "DONE AGENT"
`;

  fs.writeFileSync(scriptPath, content, { encoding: "utf-8", mode: 0o700 });
  return scriptPath;
}

export function patchLiveWazuhAgents(
  generatedLabDir: string,
  networkPlanPath: string,
  outputDir: string,
  sshAccessPath = path.join(process.cwd(), "outputs", "ssh-access.local.json")
): void {
  const plan = JSON.parse(fs.readFileSync(networkPlanPath, "utf-8")) as NetworkPlan;
  fs.mkdirSync(outputDir, { recursive: true });

  const sshAccess = loadSshAccess(sshAccessPath);

  const wazuhHost = plan.hosts.find(isWazuhServer);
  if (!wazuhHost) throw new Error("Aucun host role=wazuh_server trouvé dans network-plan.json");

  const wazuhIp = getPrimaryIp(wazuhHost);
  const wazuhAccess = sshAccess[(wazuhHost as any).id];

  const targets = plan.hosts.filter(isAgentTarget);

  if (targets.length === 0) {
    console.log("[Wazuh agent] Aucun agent cible trouvé.");
    return;
  }

  const sshCommand = process.platform === "win32" ? "ssh.exe" : "ssh";
  const scpCommand = process.platform === "win32" ? "scp.exe" : "scp";

  if (wazuhAccess) {
    run(
      sshCommand,
      sshArgs(
        wazuhAccess,
        [
          "echo '--- MANAGER PRECHECK ---'",
          "sudo /var/ossec/bin/wazuh-control status || true",
          "sudo ss -lntp | grep -E ':1514|:1515|:55000|:9200' || true",
          "sudo ss -lntp | grep -q ':1515' || { echo '[ERROR] Manager authd 1515 fermé'; exit 1; }",
          "sudo ss -lntp | grep -q ':1514' || { echo '[ERROR] Manager remoted 1514 fermé'; exit 1; }"
        ].join("; ")
      ),
      generatedLabDir,
      `Pré-check manager ${String((wazuhHost as any).id)}`
    );
  }

  const scriptPath = writeAgentInstallScript(outputDir, wazuhIp);

  console.log(`\n===== WAZUH AGENTS DEPLOYMENT =====`);
  console.log(`[Wazuh agent] Manager: ${(wazuhHost as any).id} ${wazuhIp}`);
  console.log(`[Wazuh agent] Targets: ${targets.map((h: any) => h.id).join(", ")}`);

  for (const host of targets as any[]) {
    const access = sshAccess[host.id];

    if (!access) {
      throw new Error(`Aucun accès SSH local trouvé pour ${host.id} dans ${sshAccessPath}`);
    }

    console.log(`\n===== INSTALL AGENT ${host.id} =====`);

    run(
      scpCommand,
      scpArgs(access, scriptPath, "/tmp/install-wazuh-agent.sh"),
      generatedLabDir,
      `Upload script agent ${host.id}`
    );

    run(
      sshCommand,
      sshArgs(
        access,
        `sudo chmod 700 /tmp/install-wazuh-agent.sh && sudo /tmp/install-wazuh-agent.sh ${shellQuote(host.id)}`
      ),
      generatedLabDir,
      `Installation agent Wazuh ${host.id}`
    );

    run(
      sshCommand,
      sshArgs(
        access,
        "sudo systemctl is-active wazuh-agent && sudo tail -n 50 /var/ossec/logs/ossec.log || true"
      ),
      generatedLabDir,
      `Validation locale agent ${host.id}`,
      true
    );
  }

  if (wazuhAccess) {
    run(
      sshCommand,
      sshArgs(
        wazuhAccess,
        "sudo /var/ossec/bin/agent_control -l || true"
      ),
      generatedLabDir,
      `Liste agents côté manager ${(wazuhHost as any).id}`,
      true
    );
  }
}