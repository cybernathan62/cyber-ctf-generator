import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { NetworkPlan, NetworkPlanHost } from "./type.js";

type SshConfig = {
  hostName: string;
  port: string;
  user: string;
  identityFile: string;
};

type WazuhSecrets = {
  indexer_admin_user: string;
  indexer_admin_password: string;
  dashboard_user: string;
  dashboard_password: string;
};

type WazuhTarget = {
  vmName: string;
  host: NetworkPlanHost;
  ssh: SshConfig;
  secrets: WazuhSecrets;
};

function run(
  command: string,
  args: string[],
  cwd: string,
  label: string,
  allowFailure = false
): string {
  console.log(`\n[Wazuh patch] ${label}`);
  console.log(`${command} ${args.join(" ")}`);

  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf-8",
    shell: false,
    maxBuffer: 1024 * 1024 * 260
  });

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);

  if (result.error) {
    if (allowFailure) {
      console.warn(`[Wazuh patch] Warning ${label}: ${result.error.message}`);
      return `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    }
    throw result.error;
  }

  if (!allowFailure && result.status !== 0) {
    throw new Error(`[Wazuh patch] Échec ${label} avec code ${result.status}`);
  }

  if (allowFailure && result.status !== 0) {
    console.warn(`[Wazuh patch] Warning ${label}: code ${result.status}`);
  }

  return `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function randomPassword(length = 28): string {
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const digits = "23456789";
  const symbols = ".*+?-";
  const alphabet = lower + upper + digits + symbols;

  const chars = [
    lower[crypto.randomInt(lower.length)],
    upper[crypto.randomInt(upper.length)],
    digits[crypto.randomInt(digits.length)],
    symbols[crypto.randomInt(symbols.length)]
  ];

  while (chars.length < length) {
    chars.push(alphabet[crypto.randomInt(alphabet.length)]);
  }

  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join("");
}

function isValidWazuhPassword(value: string): boolean {
  return (
    value.length >= 8 &&
    value.length <= 64 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /[0-9]/.test(value) &&
    /[.*+?-]/.test(value)
  );
}

function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function readJsonFile<T>(filePath: string): T {
  if (!fs.existsSync(filePath)) {
    throw new Error(`[Wazuh patch] Fichier introuvable: ${filePath}`);
  }

  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
}

function writeJsonFile(filePath: string, data: unknown): void {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
}

function cleanIp(value: unknown): string {
  return String(value).split("/")[0].trim();
}

function findHostIp(host: NetworkPlanHost): string {
  const h = host as any;

  if (h.ip) return cleanIp(h.ip);

  if (Array.isArray(h.interfaces)) {
    const socIface = h.interfaces.find((i: any) =>
      String(i.name ?? i.network_id ?? i.zone ?? "").toLowerCase().includes("soc") ||
      String(i.network_id ?? "").toLowerCase().includes("soc-net")
    );

    if (socIface?.ip) return cleanIp(socIface.ip);

    const firstWithIp = h.interfaces.find((i: any) => i?.ip);
    if (firstWithIp?.ip) return cleanIp(firstWithIp.ip);
  }

  throw new Error(`[Wazuh patch] IP Wazuh introuvable ou ambiguë: ${JSON.stringify(host, null, 2)}`);
}

function getHostName(host: NetworkPlanHost): string {
  const h = host as any;
  return String(h.name ?? h.hostname ?? h.vmName ?? h.vm_name ?? h.id ?? "");
}

function isWazuhHost(host: NetworkPlanHost): boolean {
  const h = host as any;

  const name = String(h.name ?? h.hostname ?? h.vmName ?? h.vm_name ?? h.id ?? "").toLowerCase();
  const role = String(h.role ?? h.service ?? h.profile ?? h.vm_profile ?? "").toLowerCase();

  return (
    name === "wazuh-1" ||
    name.startsWith("wazuh") ||
    role === "wazuh" ||
    role === "wazuh_server" ||
    role === "wazuh-server"
  );
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
    throw new Error("[Wazuh patch] IdentityFile SSH manquant dans ssh-access.local.json");
  }

  return { hostName, port, user, identityFile };
}

function loadSshAccess(outputsDir: string): Record<string, SshConfig> {
  const filePath = path.join(outputsDir, "ssh-access.local.json");
  const raw = readJsonFile<any>(filePath);
  const result: Record<string, SshConfig> = {};

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

  throw new Error("[Wazuh patch] Aucun host trouvé dans network-plan.json");
}

function loadOrCreateSecrets(generatedLabDir: string, vmName: string): WazuhSecrets {
  const secretsDir = path.join(generatedLabDir, "secrets");
  const filePath = path.join(secretsDir, `${vmName}-credentials.json`);

  if (fs.existsSync(filePath)) {
    const existing = readJsonFile<Partial<WazuhSecrets>>(filePath);

    const secrets: WazuhSecrets = {
      indexer_admin_user: existing.indexer_admin_user || "admin",
      indexer_admin_password: existing.indexer_admin_password || randomPassword(),
      dashboard_user: existing.dashboard_user || "kibanaserver",
      dashboard_password: existing.dashboard_password || randomPassword()
    };

    if (!isValidWazuhPassword(secrets.indexer_admin_password)) {
      secrets.indexer_admin_password = randomPassword();
    }

    if (!isValidWazuhPassword(secrets.dashboard_password)) {
      secrets.dashboard_password = randomPassword();
    }

    writeJsonFile(filePath, secrets);
    return secrets;
  }

  const secrets: WazuhSecrets = {
    indexer_admin_user: "admin",
    indexer_admin_password: randomPassword(),
    dashboard_user: "kibanaserver",
    dashboard_password: randomPassword()
  };

  writeJsonFile(filePath, secrets);
  return secrets;
}

function sshArgs(ssh: SshConfig, remoteCommand: string): string[] {
  return [
    "-i",
    ssh.identityFile,
    "-p",
    ssh.port,
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
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
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=ERROR",
    localPath,
    `${ssh.user}@${ssh.hostName}:${remotePath}`
  ];
}

function buildInstallScript(target: WazuhTarget): string {
  const wazuhIp = findHostIp(target.host);

  const script = `#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

WAZUH_IP="__WAZUH_IP__"
INDEXER_ADMIN_USER="__INDEXER_ADMIN_USER__"
INDEXER_ADMIN_PASSWORD="__INDEXER_ADMIN_PASSWORD__"
DASHBOARD_USER="__DASHBOARD_USER__"
DASHBOARD_PASSWORD="__DASHBOARD_PASSWORD__"

log() {
  echo
  echo "--- $* ---"
}

stop_wazuh_manager_cleanly() {
  systemctl stop wazuh-manager 2>/dev/null || true
  /var/ossec/bin/wazuh-control stop 2>/dev/null || true

  # Ne surtout pas faire: pkill -f wazuh
  # Sinon on tue aussi le script courant /tmp/wazuh-1-install-wazuh.sh.
  for proc in \
    wazuh-apid \
    wazuh-csyslogd \
    wazuh-dbd \
    wazuh-integratord \
    wazuh-agentlessd \
    wazuh-authd \
    wazuh-db \
    wazuh-execd \
    wazuh-analysisd \
    wazuh-syscheckd \
    wazuh-remoted \
    wazuh-logcollector \
    wazuh-monitord \
    wazuh-modulesd \
    wazuh-clusterd; do
    pkill -x "$proc" 2>/dev/null || true
  done

  sleep 3
  rm -rf /var/ossec/var/start-script-lock
  rm -f /var/ossec/var/run/*.start /var/ossec/var/run/*.failed /var/ossec/var/run/*.pid 2>/dev/null || true
}

fix_manager_permissions() {
  chown -R root:wazuh /var/ossec 2>/dev/null || true

  if [ -d /var/ossec/etc/lists ]; then
    chown -R root:wazuh /var/ossec/etc/lists || true
    chmod -R 770 /var/ossec/etc/lists || true
    find /var/ossec/etc/lists -type f -exec chmod 660 {} \\; || true
    find /var/ossec/etc/lists -type d -exec chmod 770 {} \\; || true
  fi

  if [ -d /data/wazuh-manager/etc/lists ]; then
    chown -R root:wazuh /data/wazuh-manager/etc/lists || true
    chmod -R 770 /data/wazuh-manager/etc/lists || true
    find /data/wazuh-manager/etc/lists -type f -exec chmod 660 {} \\; || true
    find /data/wazuh-manager/etc/lists -type d -exec chmod 770 {} \\; || true
  fi
}

fix_wazuh_manager_runtime() {
  log "FIX WAZUH MANAGER RUNTIME DIRS"

  stop_wazuh_manager_cleanly

  mkdir -p \
    /var/ossec/queue/db \
    /var/ossec/queue/syscheck \
    /var/ossec/queue/alerts \
    /var/ossec/queue/sockets \
    /var/ossec/queue/fts \
    /var/ossec/stats \
    /var/ossec/backup/db \
    /var/ossec/tmp \
    /var/ossec/logs \
    /var/ossec/etc/shared/default \
    /var/ossec/api/configuration/security \
    /var/ossec/api/configuration/ssl

  touch /var/ossec/etc/shared/default/merged.mg
  touch /var/ossec/queue/fts/hostinfo
  touch /var/ossec/queue/fts/fts-queue

  rm -f /var/ossec/stats/weekly-average

  chown -R root:wazuh /var/ossec/queue
  chown -R root:wazuh /var/ossec/stats
  chown -R root:wazuh /var/ossec/backup
  chown -R root:wazuh /var/ossec/tmp
  chown -R root:wazuh /var/ossec/var
  chown -R root:wazuh /var/ossec/etc/shared
  chown -R root:wazuh /var/ossec/etc/lists 2>/dev/null || true

  chown -R wazuh:wazuh /var/ossec/api/configuration/security
  chown -R wazuh:wazuh /var/ossec/api/configuration/ssl
  chown -R wazuh:wazuh /var/ossec/logs

  chmod 750 /var/ossec
  chmod -R 770 /var/ossec/queue
  chmod -R 770 /var/ossec/stats
  chmod -R 770 /var/ossec/backup
  chmod -R 770 /var/ossec/tmp
  chmod -R 770 /var/ossec/var
  chmod -R 770 /var/ossec/logs
  chmod -R 750 /var/ossec/etc/shared
  chmod -R 750 /var/ossec/api
  chmod -R 770 /var/ossec/etc/lists 2>/dev/null || true

  chmod 600 /var/ossec/api/configuration/ssl/server.key 2>/dev/null || true
  chmod 644 /var/ossec/api/configuration/ssl/server.crt 2>/dev/null || true

  fix_manager_permissions
}

wait_indexer() {
  local timeout=360
  local elapsed=0

  until curl -sk "https://$WAZUH_IP:9200" >/dev/null 2>&1; do
    echo "waiting indexer https://$WAZUH_IP:9200..."
    sleep 5
    elapsed=$((elapsed + 5))

    if [ "$elapsed" -ge "$timeout" ]; then
      echo "[ERROR] Timeout attente indexer"
      systemctl status wazuh-indexer --no-pager -l || true
      journalctl -u wazuh-indexer --no-pager -n 120 || true
      tail -n 120 /var/log/wazuh-indexer/wazuh-cluster.log 2>/dev/null || true
      exit 1
    fi
  done
}

wait_manager_ports() {
  local timeout=180
  local elapsed=0

  while [ "$elapsed" -lt "$timeout" ]; do
    if ss -lntp | grep -q ':1514' && ss -lntp | grep -q ':1515' && ss -lntp | grep -q ':55000'; then
      echo "[OK] Wazuh manager ports ready: 1514/1515/55000"
      return 0
    fi

    echo "waiting manager ports 1514/1515/55000..."
    /var/ossec/bin/wazuh-control status || true
    ss -lntp | grep -E ':1514|:1515|:55000' || true
    sleep 5
    elapsed=$((elapsed + 5))
  done

  echo "[ERROR] Wazuh manager ports not ready after timeout"
  /var/ossec/bin/wazuh-control status || true
  ss -lntp | grep -E ':1514|:1515|:55000|:9200' || true
  tail -n 180 /var/ossec/logs/ossec.log || true
  tail -n 120 /var/ossec/logs/api.log || true
  exit 1
}

validate_password_policy() {
  local p="$1"

  if [ "\${#p}" -lt 8 ] || [ "\${#p}" -gt 64 ]; then
    echo "[ERROR] Password Wazuh invalide: longueur hors limites"
    exit 1
  fi

  echo "$p" | grep -q '[a-z]' || { echo "[ERROR] Password Wazuh invalide: minuscule manquante"; exit 1; }
  echo "$p" | grep -q '[A-Z]' || { echo "[ERROR] Password Wazuh invalide: majuscule manquante"; exit 1; }
  echo "$p" | grep -q '[0-9]' || { echo "[ERROR] Password Wazuh invalide: chiffre manquant"; exit 1; }
  echo "$p" | grep -q '[.*+?-]' || { echo "[ERROR] Password Wazuh invalide: symbole autorisé manquant . * + ? -"; exit 1; }
}

log "VALIDATE GENERATED PASSWORDS"
validate_password_policy "$INDEXER_ADMIN_PASSWORD"
validate_password_policy "$DASHBOARD_PASSWORD"

log "APT REPAIR"
apt-get clean || true
apt-get update -y
apt-get install -f -y || true

log "INSTALL PREREQUISITES"
apt-get install -y curl gnupg ca-certificates debconf adduser procps tar rsync gawk apt-transport-https openjdk-21-jre-headless

log "CONFIGURE WAZUH REPOSITORY"
install -d -m 0755 /usr/share/keyrings
rm -f /usr/share/keyrings/wazuh.gpg
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
chmod 0644 /usr/share/keyrings/wazuh.gpg

cat > /etc/apt/sources.list.d/wazuh.list <<'EOF'
deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main
EOF

apt-get update -y

log "INSTALL WAZUH PACKAGES"
apt-get install -y wazuh-indexer wazuh-manager wazuh-dashboard filebeat

log "STOP SERVICES"
systemctl stop filebeat wazuh-dashboard wazuh-manager wazuh-indexer 2>/dev/null || true

log "PREPARE /data"
mkdir -p /data/wazuh-indexer /data/wazuh-manager

log "OFFLOAD INDEXER DATA"
if [ -d /var/lib/wazuh-indexer ] && [ ! -L /var/lib/wazuh-indexer ]; then
  rsync -a /var/lib/wazuh-indexer/ /data/wazuh-indexer/ || true
  rm -rf /var/lib/wazuh-indexer
fi

ln -sfn /data/wazuh-indexer /var/lib/wazuh-indexer
chown -R wazuh-indexer:wazuh-indexer /data/wazuh-indexer /var/lib/wazuh-indexer || true

log "OFFLOAD MANAGER DATA"
if [ -d /var/ossec ] && [ ! -L /var/ossec ]; then
  rsync -a /var/ossec/ /data/wazuh-manager/ || true
  rm -rf /var/ossec
fi

ln -sfn /data/wazuh-manager /var/ossec
chown -R root:wazuh /data/wazuh-manager /var/ossec || true
chmod -R 750 /data/wazuh-manager || true
fix_manager_permissions

log "GENERATE CERTIFICATES"
cat > /root/config.yml <<EOF
nodes:
  indexer:
    - name: wazuh-indexer
      ip: $WAZUH_IP
  server:
    - name: wazuh-manager
      ip: $WAZUH_IP
  dashboard:
    - name: wazuh-dashboard
      ip: $WAZUH_IP
EOF

rm -rf /root/wazuh-certificates /root/wazuh-certificates.tar /root/wazuh-certs-tool.sh
curl -fsSL https://packages.wazuh.com/4.14/wazuh-certs-tool.sh -o /root/wazuh-certs-tool.sh
bash /root/wazuh-certs-tool.sh -A -v

log "DEPLOY INDEXER CERTIFICATES"
mkdir -p /etc/wazuh-indexer/certs
cp -f /root/wazuh-certificates/wazuh-indexer.pem /etc/wazuh-indexer/certs/wazuh-indexer.pem
cp -f /root/wazuh-certificates/wazuh-indexer-key.pem /etc/wazuh-indexer/certs/wazuh-indexer-key.pem
cp -f /root/wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/admin.pem
cp -f /root/wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/admin-key.pem
cp -f /root/wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/root-ca.pem
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*.pem

log "DEPLOY DASHBOARD CERTIFICATES"
mkdir -p /etc/wazuh-dashboard/certs
cp -f /root/wazuh-certificates/wazuh-dashboard.pem /etc/wazuh-dashboard/certs/wazuh-dashboard.pem
cp -f /root/wazuh-certificates/wazuh-dashboard-key.pem /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem
cp -f /root/wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/root-ca.pem
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*.pem

log "DEPLOY FILEBEAT CERTIFICATES"
mkdir -p /etc/filebeat/certs
cp -f /root/wazuh-certificates/wazuh-manager.pem /etc/filebeat/certs/filebeat.pem
cp -f /root/wazuh-certificates/wazuh-manager-key.pem /etc/filebeat/certs/filebeat-key.pem
cp -f /root/wazuh-certificates/root-ca.pem /etc/filebeat/certs/root-ca.pem
chown -R root:root /etc/filebeat/certs
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*.pem

log "CONFIGURE INDEXER"
cat > /etc/wazuh-indexer/opensearch.yml <<EOF
network.host: "$WAZUH_IP"
node.name: "wazuh-indexer"
cluster.name: "wazuh-cluster"
cluster.initial_cluster_manager_nodes:
  - "wazuh-indexer"
discovery.seed_hosts:
  - "$WAZUH_IP"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
bootstrap.memory_lock: false
plugins.security.ssl.http.pemcert_filepath: certs/wazuh-indexer.pem
plugins.security.ssl.http.pemkey_filepath: certs/wazuh-indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: certs/wazuh-indexer.pem
plugins.security.ssl.transport.pemkey_filepath: certs/wazuh-indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.nodes_dn:
  - "CN=wazuh-indexer,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
  - "all_access"
  - "security_rest_api_access"
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]
compatibility.override_main_response_version: true
EOF

chown root:wazuh-indexer /etc/wazuh-indexer/opensearch.yml
chmod 640 /etc/wazuh-indexer/opensearch.yml

log "CONFIGURE MANAGER INDEXER HOST"
python3 - <<PY
from pathlib import Path
import re

p = Path("/var/ossec/etc/ossec.conf")
s = p.read_text()

s = s.replace("https://0.0.0.0:9200", "https://$WAZUH_IP:9200")
s = s.replace("https://127.0.0.1:9200", "https://$WAZUH_IP:9200")
s = s.replace("https://localhost:9200", "https://$WAZUH_IP:9200")

if "<indexer>" in s:
    s = re.sub(r"<host>https://[^<]+:9200</host>", "<host>https://$WAZUH_IP:9200</host>", s)

p.write_text(s)
PY

log "START INDEXER"
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl restart wazuh-indexer
wait_indexer

log "SET INDEXER USERS BEFORE SECURITY INIT"
HASH_TOOL="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"
ADMIN_HASH=$(bash "$HASH_TOOL" -p "$INDEXER_ADMIN_PASSWORD" | tail -n 1)
DASHBOARD_HASH=$(bash "$HASH_TOOL" -p "$DASHBOARD_PASSWORD" | tail -n 1)

cat > /etc/wazuh-indexer/opensearch-security/internal_users.yml <<EOF
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "$ADMIN_HASH"
  reserved: true
  backend_roles:
    - "admin"
  description: "Admin user"

kibanaserver:
  hash: "$DASHBOARD_HASH"
  reserved: true
  description: "Wazuh dashboard server user"
EOF

chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-security/internal_users.yml
chmod 640 /etc/wazuh-indexer/opensearch-security/internal_users.yml

log "INITIALIZE INDEXER SECURITY"
mkdir -p /etc/wazuh-indexer/backup /etc/wazuh-indexer/internalusers-backup
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/backup /etc/wazuh-indexer/internalusers-backup || true
chmod -R u+rwX,g+rX,o-rwx /etc/wazuh-indexer/backup /etc/wazuh-indexer/internalusers-backup || true

cd /etc/wazuh-indexer

if ! /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security/ \
  -icl \
  -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -h "$WAZUH_IP"; then
  echo "[ERROR] securityadmin.sh failed"
  journalctl -u wazuh-indexer --no-pager -n 120 || true
  tail -n 120 /var/log/wazuh-indexer/wazuh-cluster.log 2>/dev/null || true
  exit 1
fi

log "WAIT INDEXER SECURITY READY"
SECURITY_READY=0

for i in $(seq 1 36); do
  RESPONSE=$(curl -sk -u "$INDEXER_ADMIN_USER:$INDEXER_ADMIN_PASSWORD" "https://$WAZUH_IP:9200" || true)

  echo "$RESPONSE" | grep -E "cluster_name|tagline|version" >/dev/null 2>&1 && {
    SECURITY_READY=1
    echo "$RESPONSE"
    break
  }

  echo "$RESPONSE" | grep -q "OpenSearch Security not initialized" && {
    echo "security not initialized yet, waiting..."
    sleep 5
    continue
  }

  echo "$RESPONSE" | grep -q "Unauthorized" && {
    echo "[ERROR] Auth admin indexer KO"
    echo "$RESPONSE"
    exit 1
  }

  echo "waiting indexer security..."
  echo "$RESPONSE"
  sleep 5
done

if [ "$SECURITY_READY" -ne 1 ]; then
  echo "[ERROR] Indexer security not ready after timeout"
  curl -sk -u "$INDEXER_ADMIN_USER:$INDEXER_ADMIN_PASSWORD" "https://$WAZUH_IP:9200" || true
  journalctl -u wazuh-indexer --no-pager -n 120 || true
  exit 1
fi

log "CONFIGURE MANAGER KEYSTORE"
if [ -x /var/ossec/bin/wazuh-keystore ]; then
  /var/ossec/bin/wazuh-keystore -f indexer -k username -v "$INDEXER_ADMIN_USER"
  /var/ossec/bin/wazuh-keystore -f indexer -k password -v "$INDEXER_ADMIN_PASSWORD"
fi

fix_manager_permissions

log "CONFIGURE DASHBOARD"
cat > /etc/wazuh-dashboard/opensearch_dashboards.yml <<EOF
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: ["https://$WAZUH_IP:9200"]
opensearch.ssl.verificationMode: certificate
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
opensearch.username: "$DASHBOARD_USER"
opensearch.password: "$DASHBOARD_PASSWORD"
server.ssl.enabled: true
server.ssl.certificate: "/etc/wazuh-dashboard/certs/wazuh-dashboard.pem"
server.ssl.key: "/etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
uiSettings.overrides.defaultRoute: /app/wazuh
EOF

chown root:wazuh-dashboard /etc/wazuh-dashboard/opensearch_dashboards.yml
chmod 640 /etc/wazuh-dashboard/opensearch_dashboards.yml

log "CONFIGURE FILEBEAT"
mkdir -p /etc/filebeat/modules.d

cat > /etc/filebeat/modules.d/wazuh.yml <<'EOF'
- module: wazuh
  alerts:
    enabled: true
    var.paths: ["/var/ossec/logs/alerts/alerts.json"]
  archives:
    enabled: false
EOF

cat > /etc/filebeat/filebeat.yml <<EOF
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
      var.paths: ["/var/ossec/logs/alerts/alerts.json"]
    archives:
      enabled: false

setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.enabled: false
setup.template.overwrite: true

output.elasticsearch:
  hosts: ["https://$WAZUH_IP:9200"]
  username: "$INDEXER_ADMIN_USER"
  password: "$INDEXER_ADMIN_PASSWORD"
  ssl.certificate_authorities: ["/etc/filebeat/certs/root-ca.pem"]
  ssl.certificate: "/etc/filebeat/certs/filebeat.pem"
  ssl.key: "/etc/filebeat/certs/filebeat-key.pem"

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
EOF

chmod 600 /etc/filebeat/filebeat.yml

if [ ! -f /etc/filebeat/wazuh-template.json ]; then
  curl -fsSL https://packages.wazuh.com/4.x/filebeat/wazuh-template.json -o /etc/filebeat/wazuh-template.json || true
fi

log "FIX + START WAZUH MANAGER"
fix_wazuh_manager_runtime

systemctl daemon-reload
systemctl reset-failed wazuh-manager || true
systemctl enable wazuh-manager || true
systemctl enable wazuh-indexer wazuh-dashboard filebeat || true

set +e
systemctl restart wazuh-manager
MANAGER_CODE=$?
set -e

if [ "$MANAGER_CODE" -ne 0 ]; then
  echo "[WARN] systemctl restart wazuh-manager KO, tentative via wazuh-control"
  fix_wazuh_manager_runtime
  /var/ossec/bin/wazuh-control start || true
fi

wait_manager_ports

log "START DASHBOARD + FILEBEAT"
systemctl restart filebeat || true
systemctl restart wazuh-dashboard || true
sleep 12

log "VALIDATE MANAGER TO INDEXER"
grep -iE "indexer|unauthorized|auth|failed|error|connection|initialized successfully" /var/ossec/logs/ossec.log | tail -n 180 || true

log "VALIDATE FILEBEAT"
set +e
filebeat test output
FB_CODE=$?
set -e

if [ "$FB_CODE" -ne 0 ]; then
  echo "[WARN] filebeat test output KO. Non bloquant."
  journalctl -u filebeat --no-pager -n 80 || true
fi

log "FINAL STATUS"
echo "--- WAZUH CONTROL ---"
/var/ossec/bin/wazuh-control status || true

echo "--- SERVICES ---"
systemctl is-active wazuh-indexer || true
systemctl is-active wazuh-manager || true
systemctl is-active wazuh-dashboard || true
systemctl is-active filebeat || true

echo "--- PORTS ---"
ss -lntp | grep -E ':9200|:55000|:5601|:443|:1514|:1515' || true

echo "--- INDEXER CURL ---"
curl -sk -u "$INDEXER_ADMIN_USER:$INDEXER_ADMIN_PASSWORD" "https://$WAZUH_IP:9200" || true

log "DONE WAZUH INSTALL"
exit 0
`;

  return script
    .replaceAll("__WAZUH_IP__", wazuhIp)
    .replaceAll("__INDEXER_ADMIN_USER__", target.secrets.indexer_admin_user)
    .replaceAll("__INDEXER_ADMIN_PASSWORD__", target.secrets.indexer_admin_password)
    .replaceAll("__DASHBOARD_USER__", target.secrets.dashboard_user)
    .replaceAll("__DASHBOARD_PASSWORD__", target.secrets.dashboard_password);
}

function createRuntimeFiles(generatedLabDir: string, target: WazuhTarget, script: string): string {
  const runtimeDir = path.join(generatedLabDir, "wazuh-live-patcher-runtime");
  ensureDir(runtimeDir);

  const scriptPath = path.join(runtimeDir, `${target.vmName}-install.sh`);
  fs.writeFileSync(scriptPath, script, "utf-8");

  const envPath = path.join(runtimeDir, `${target.vmName}-secrets.env`);
  fs.writeFileSync(
    envPath,
    [
      `INDEXER_ADMIN_USER=${target.secrets.indexer_admin_user}`,
      `INDEXER_ADMIN_PASSWORD=${target.secrets.indexer_admin_password}`,
      `DASHBOARD_USER=${target.secrets.dashboard_user}`,
      `DASHBOARD_PASSWORD=${target.secrets.dashboard_password}`,
      ""
    ].join("\n"),
    "utf-8"
  );

  return scriptPath;
}

function resolveOutputsDir(outputsDir: string): string {
  return fs.existsSync(path.join(outputsDir, "network-plan.json"))
    ? outputsDir
    : path.dirname(outputsDir);
}

function resolveTargets(outputsDir: string, generatedLabDir: string): WazuhTarget[] {
  const realOutputsDir = resolveOutputsDir(outputsDir);
  const networkPlanPath = path.join(realOutputsDir, "network-plan.json");
  const networkPlan = readJsonFile<NetworkPlan>(networkPlanPath);
  const hosts = getNetworkHosts(networkPlan);
  const sshAccess = loadSshAccess(realOutputsDir);

  const wazuhHosts = hosts.filter(isWazuhHost);

  if (wazuhHosts.length === 0) {
    console.log("[Wazuh patch] Aucun host Wazuh trouvé dans network-plan.json, skip.");
    return [];
  }

  return wazuhHosts.map((host, index) => {
    const detectedName = getHostName(host);
    const vmName = detectedName || `wazuh-${index + 1}`;
    const ssh = sshAccess[vmName] ?? sshAccess[detectedName] ?? sshAccess[`wazuh-${index + 1}`];

    if (!ssh) {
      throw new Error(`[Wazuh patch] SSH config introuvable pour ${vmName} dans ssh-access.local.json`);
    }

    const secrets = loadOrCreateSecrets(generatedLabDir, "wazuh-global");

    return { vmName, host, ssh, secrets };
  });
}

export function patchLiveWazuhConfigs(outputsDir = path.join(process.cwd(), "outputs")): void {
  const generatedLabDir = resolveOutputsDir(outputsDir);
  ensureDir(generatedLabDir);

  const targets = resolveTargets(outputsDir, generatedLabDir);
  if (targets.length === 0) return;

  const sshCommand = process.platform === "win32" ? "ssh.exe" : "ssh";
  const scpCommand = process.platform === "win32" ? "scp.exe" : "scp";

  for (const target of targets) {
    const script = buildInstallScript(target);
    const localScriptPath = createRuntimeFiles(generatedLabDir, target, script);
    const remoteScriptPath = `/tmp/${target.vmName}-install-wazuh.sh`;

    run(
      scpCommand,
      scpArgs(target.ssh, localScriptPath, remoteScriptPath),
      generatedLabDir,
      `Upload script Wazuh ${target.vmName}`
    );

    run(
      sshCommand,
      sshArgs(
        target.ssh,
        `sudo chmod 700 ${shellQuote(remoteScriptPath)} && sudo bash ${shellQuote(remoteScriptPath)}`
      ),
      generatedLabDir,
      `Installation Wazuh par paquets APT ${target.vmName}`
    );

    const wazuhIp = findHostIp(target.host);

    console.log(`\n[Wazuh patch] Résumé ${target.vmName}`);
    console.log(`- IP Wazuh: ${wazuhIp}`);
    console.log(`- Dashboard: https://${wazuhIp}/`);
    console.log(`- User indexer/dashboard: ${target.secrets.indexer_admin_user}`);
    console.log(`- Password: ${target.secrets.indexer_admin_password}`);
    console.log(`- Secrets: ${path.join(generatedLabDir, "secrets", "wazuh-global-credentials.json")}`);
  }
}

export default patchLiveWazuhConfigs;
