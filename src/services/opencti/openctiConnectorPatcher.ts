import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

import {
  CVE_REMOTE_CONFIG,
  CVE_REMOTE_DIR,
  CVE_SERVICE_NAME,
  buildCveEnv,
  buildCveConfig,
  type EnvMap
} from "./connectors/cve.connector.js";

import { installMitreConnector } from "./connectors/mitre.connector.js";
import { installD3fendConnector } from "./connectors/d3fend.connector.js";
import { installUrlhausConnector } from "./connectors/urlhaus.connector.js";
import { installMalwareBazaarConnector } from "./connectors/malwarebazaar.connector.js";
import { installAlienVaultConnector } from "./connectors/alienvault.connector.js";
import { installWazuhConnector } from "./connectors/wazuh.connector.js";
import { installZabbixConnector } from "./connectors/zabbix.connector.js";

type SshAccessEntry = {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  identity_file: string;
  access_method?: string;
};

type SshAccessMap = Record<string, SshAccessEntry>;

const PROJECT_ROOT = process.cwd();
const DEFAULT_OUTPUT_ROOT = path.join(PROJECT_ROOT, "outputs");
const SECRETS_DIR = path.join(PROJECT_ROOT, "secrets");
const SECRETS_FILE = path.join(SECRETS_DIR, "opencti.env");
const NVD_KEY_FILE = path.join(SECRETS_DIR, "nvd-api-key.txt");

const CONNECTOR_PYTHON_BIN = "/opt/python/3.12.8/bin/python";

function readJson<T>(filePath: string): T {
  if (!fs.existsSync(filePath)) {
    throw new Error(`[OpenCTI Connector Patcher] Fichier introuvable: ${filePath}`);
  }

  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
}

function resolveSshAccessPath(outputRoot: string): string {
  const candidates = [
    path.join(outputRoot, "ssh-access.local.json"),
    path.join(outputRoot, "generated-lab", "ssh-access.local.json"),
    path.join(PROJECT_ROOT, "outputs", "ssh-access.local.json"),
    path.join(PROJECT_ROOT, "outputs", "generated-lab", "ssh-access.local.json")
  ];

  const found = candidates.find((candidate) => fs.existsSync(candidate));

  if (!found) {
    throw new Error(
      [
        "[OpenCTI Connector Patcher] ssh-access.local.json introuvable.",
        "Chemins testés :",
        ...candidates.map((candidate) => `- ${candidate}`)
      ].join("\n")
    );
  }

  return found;
}

function readEnvFile(filePath: string): EnvMap {
  if (!fs.existsSync(filePath)) return {};

  const env: EnvMap = {};
  const content = fs.readFileSync(filePath, "utf-8");

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const index = line.indexOf("=");
    if (index === -1) continue;

    const key = line.slice(0, index).trim();
    const value = line.slice(index + 1).trim().replace(/^['"]|['"]$/g, "");

    env[key] = value;
  }

  return env;
}

function readTextIfExists(filePath: string): string {
  if (!fs.existsSync(filePath)) return "";
  return fs.readFileSync(filePath, "utf-8").trim();
}

function normalizeNvdApiKey(value: string): string {
  return value
    .trim()
    .replace(/^Your API Key:\s*/i, "")
    .replace(/^NVD_API_KEY\s*=\s*/i, "")
    .replace(/^['"]|['"]$/g, "")
    .trim();
}

function ensureSecretsFile(): EnvMap {
  fs.mkdirSync(SECRETS_DIR, { recursive: true });

  const existing = readEnvFile(SECRETS_FILE);
  const nvdFromTxt = normalizeNvdApiKey(readTextIfExists(NVD_KEY_FILE));

  const env = buildCveEnv(
    existing,
    normalizeNvdApiKey(nvdFromTxt || existing.NVD_API_KEY || "CHANGE_ME")
  );

  fs.writeFileSync(
    SECRETS_FILE,
    Object.entries(env)
      .map(([key, value]) => `${key}=${value}`)
      .join("\n") + "\n",
    { mode: 0o600 }
  );

  return env;
}

function assertRequiredSecrets(env: EnvMap): void {
  const missing = ["OPENCTI_TOKEN", "NVD_API_KEY"].filter(
    (key) => !env[key] || env[key] === "CHANGE_ME"
  );

  if (missing.length > 0) {
    throw new Error(
      [
        "[OpenCTI Connector Patcher] Secrets manquants.",
        `Fichier à compléter : ${SECRETS_FILE}`,
        `Valeurs manquantes : ${missing.join(", ")}`
      ].join("\n")
    );
  }

  if (/^Your API Key:/i.test(env.NVD_API_KEY)) {
    throw new Error(
      "[OpenCTI Connector Patcher] NVD_API_KEY invalide: retire le préfixe 'Your API Key:'."
    );
  }
}

function resolveIdentityFile(identityFile: string): string {
  if (identityFile.startsWith("~/")) {
    const home = process.env.USERPROFILE || process.env.HOME || "";
    return path.join(home, identityFile.slice(2));
  }

  return identityFile;
}

function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function yamlQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function isLocalhostUrl(value: string): boolean {
  try {
    const url = new URL(value);
    const hostname = url.hostname.toLowerCase();

    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
  } catch {
    return false;
  }
}

function normalizeUrl(value: string): string {
  return value.trim().replace(/\/+$/g, "");
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback;

  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;

  return parsed;
}

function runSsh(
  target: SshAccessEntry,
  script: string,
  label: string,
  timeoutMs = 900_000
): void {
  console.log(`\n[OpenCTI Connector Patcher] ${label}`);

  const sshKey = resolveIdentityFile(target.identity_file);
  const command = process.platform === "win32" ? "ssh.exe" : "ssh";
  const knownHostsFile = process.platform === "win32" ? "NUL" : "/dev/null";

  const result = spawnSync(
    command,
    [
      "-i",
      sshKey,
      "-p",
      String(target.ssh_port),
      "-o",
      "BatchMode=yes",
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      `UserKnownHostsFile=${knownHostsFile}`,
      "-o",
      "ConnectTimeout=30",
      `${target.ssh_user}@${target.ssh_host}`,
      `bash -lc ${shQuote(script)}`
    ],
    {
      encoding: "utf-8",
      shell: false,
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024 * 200
    }
  );

  if (result.stdout) console.log(result.stdout.trim());
  if (result.stderr) console.warn(result.stderr.trim());

  if (result.error) {
    throw new Error(
      `[OpenCTI Connector Patcher] Erreur SSH ${label}: ${result.error.message}`
    );
  }

  if (result.status !== 0) {
    throw new Error(
      `[OpenCTI Connector Patcher] Échec ${label} code=${result.status}`
    );
  }
}

function runSshCapture(
  target: SshAccessEntry,
  script: string,
  label: string,
  timeoutMs = 300_000
): string {
  console.log(`\n[OpenCTI Connector Patcher] ${label}`);

  const sshKey = resolveIdentityFile(target.identity_file);
  const command = process.platform === "win32" ? "ssh.exe" : "ssh";
  const knownHostsFile = process.platform === "win32" ? "NUL" : "/dev/null";

  const result = spawnSync(
    command,
    [
      "-i",
      sshKey,
      "-p",
      String(target.ssh_port),
      "-o",
      "BatchMode=yes",
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      `UserKnownHostsFile=${knownHostsFile}`,
      "-o",
      "ConnectTimeout=30",
      `${target.ssh_user}@${target.ssh_host}`,
      `bash -lc ${shQuote(script)}`
    ],
    {
      encoding: "utf-8",
      shell: false,
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024 * 20
    }
  );

  if (result.stderr) console.warn(result.stderr.trim());

  if (result.error) {
    throw new Error(
      `[OpenCTI Connector Patcher] Erreur SSH ${label}: ${result.error.message}`
    );
  }

  if (result.status !== 0) {
    throw new Error(
      `[OpenCTI Connector Patcher] Échec ${label} code=${result.status}`
    );
  }

  return (result.stdout || "").trim();
}

function uploadFile(
  target: SshAccessEntry,
  localPath: string,
  remotePath: string
): void {
  if (!fs.existsSync(localPath)) {
    throw new Error(
      `[OpenCTI Connector Patcher] Fichier local introuvable: ${localPath}`
    );
  }

  const remoteTmp = `/tmp/${path.basename(localPath)}`;
  const remoteDir = path.posix.dirname(remotePath);
  const sshKey = resolveIdentityFile(target.identity_file);
  const scpCommand = process.platform === "win32" ? "scp.exe" : "scp";
  const knownHostsFile = process.platform === "win32" ? "NUL" : "/dev/null";

  const scpResult = spawnSync(
    scpCommand,
    [
      "-i",
      sshKey,
      "-P",
      String(target.ssh_port),
      "-o",
      "BatchMode=yes",
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      `UserKnownHostsFile=${knownHostsFile}`,
      localPath,
      `${target.ssh_user}@${target.ssh_host}:${remoteTmp}`
    ],
    {
      stdio: "inherit",
      shell: false,
      timeout: 300_000
    }
  );

  if (scpResult.error) {
    throw new Error(
      `[OpenCTI Connector Patcher] Erreur SCP: ${scpResult.error.message}`
    );
  }

  if (scpResult.status !== 0) {
    throw new Error(`[OpenCTI Connector Patcher] Upload échoué: ${localPath}`);
  }

  runSsh(
    target,
    [
      `sudo mkdir -p ${shQuote(remoteDir)}`,
      `sudo mv ${shQuote(remoteTmp)} ${shQuote(remotePath)}`,
      `sudo chown -R opencti:opencti ${shQuote(remoteDir)}`,
      `sudo chmod 600 ${shQuote(remotePath)}`
    ].join(" && "),
    "Upload fichier distant"
  );
}

function assertOpenCTIReady(target: SshAccessEntry): void {
  runSsh(
    target,
    [
      "set -e",
      "id opencti >/dev/null",
      "test -d /opt/opencti",
      `test -d ${shQuote(CVE_REMOTE_DIR)}`,
      "systemctl is-active --quiet opencti",
      "systemctl is-active --quiet rabbitmq-server",
      "curl -fsS http://127.0.0.1:8080 >/dev/null"
    ].join(" && "),
    "Vérification prérequis OpenCTI",
    300_000
  );
}

function ensureOpenCTIWorker(target: SshAccessEntry, env: EnvMap): void {
  const workerConfig = `opencti:
  url: ${yamlQuote(env.OPENCTI_URL)}
  token: ${yamlQuote(env.OPENCTI_TOKEN)}
  json_logging: true

worker:
  log_level: 'info'
  telemetry_enabled: false
  objects_max_refs: 500
`;

  const workerConfigPath = path.join(SECRETS_DIR, "opencti-worker-config.yml");

  fs.writeFileSync(workerConfigPath, workerConfig, {
    encoding: "utf-8",
    mode: 0o600
  });

  uploadFile(target, workerConfigPath, "/opt/opencti/worker/config.yml");

  runSsh(
    target,
    `set -e
if [ ! -f /opt/opencti/worker/worker.py ]; then
  echo "[WARN] Worker OpenCTI introuvable: /opt/opencti/worker/worker.py"
  exit 0
fi

sudo -u opencti bash -lc '
cd /opt/opencti/worker
if [ ! -d .venv ]; then python3 -m venv .venv; fi
. .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
'

sudo tee /etc/systemd/system/opencti-worker.service >/dev/null <<'SERVICE'
[Unit]
Description=OpenCTI Python worker
After=network-online.target opencti.service rabbitmq-server.service
Wants=network-online.target opencti.service rabbitmq-server.service

[Service]
User=opencti
Group=opencti
WorkingDirectory=/opt/opencti/worker
Environment=PATH=/opt/opencti/worker/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/opt/opencti/worker/.venv/bin/python worker.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable opencti-worker
sudo systemctl restart opencti-worker
sleep 5
sudo systemctl status opencti-worker --no-pager || true`,
    "Installation et démarrage worker OpenCTI",
    1_800_000
  );
}

function installCveConnector(target: SshAccessEntry, env: EnvMap): void {
  const secretsConnectorsDir = path.join(SECRETS_DIR, "opencti-connectors");
  fs.mkdirSync(secretsConnectorsDir, { recursive: true });

  const localConfig = path.join(secretsConnectorsDir, "cve-config.yml");

  fs.writeFileSync(localConfig, buildCveConfig(env), {
    encoding: "utf-8",
    mode: 0o600
  });

  uploadFile(target, localConfig, CVE_REMOTE_CONFIG);

  runSsh(
    target,
    `set -e
PYTHON_BIN="${CONNECTOR_PYTHON_BIN}"

if [ ! -x "$PYTHON_BIN" ]; then
  echo "[ERROR] Python 3.12 introuvable: $PYTHON_BIN"
  echo "[INFO] Les connecteurs OpenCTI exigent Python >=3.11 et <3.13."
  echo "[INFO] Installer Python 3.12 dans /opt/python/3.12.8 ou utiliser Debian 12."
  exit 1
fi

sudo -u opencti bash -lc '
cd ${CVE_REMOTE_DIR}
rm -rf src/.venv
${CONNECTOR_PYTHON_BIN} -m venv src/.venv
. src/.venv/bin/activate
python --version
pip install --upgrade pip setuptools wheel
pip install -r src/requirements.txt
'`,
    "Installation dépendances Python connecteur CVE",
    1_800_000
  );

  runSsh(
    target,
    `set -e
sudo tee /etc/systemd/system/${CVE_SERVICE_NAME}.service >/dev/null <<SERVICE
[Unit]
Description=OpenCTI NVD CVE Connector
After=network-online.target opencti.service opencti-worker.service rabbitmq-server.service
Wants=network-online.target opencti-worker.service

[Service]
User=opencti
Group=opencti
WorkingDirectory=${CVE_REMOTE_DIR}
Environment=PATH=${CVE_REMOTE_DIR}/src/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=${CVE_REMOTE_DIR}/src/.venv/bin/python -m src
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable ${CVE_SERVICE_NAME}
sudo systemctl restart ${CVE_SERVICE_NAME}
sleep 5
sudo systemctl status ${CVE_SERVICE_NAME} --no-pager || true
sudo journalctl -u ${CVE_SERVICE_NAME} -n 80 --no-pager || true`,
    "Création service systemd connecteur CVE",
    300_000
  );
}

function ensureMainPyConnectorEntrypoints(target: SshAccessEntry): void {
  runSsh(
    target,
    `set -e

write_main_py_connector_service() {
  SERVICE_NAME="$1"
  DESCRIPTION="$2"
  REMOTE_SRC_DIR="$3"

  if [ ! -d "\${REMOTE_SRC_DIR}" ]; then
    echo "[WARN] Dossier connecteur introuvable: \${REMOTE_SRC_DIR}"
    return 0
  fi

  if [ ! -f "\${REMOTE_SRC_DIR}/main.py" ]; then
    echo "[WARN] Entrée main.py introuvable pour \${SERVICE_NAME}: \${REMOTE_SRC_DIR}/main.py"
    return 0
  fi

  if [ ! -x "\${REMOTE_SRC_DIR}/.venv/bin/python" ]; then
    echo "[ERROR] Python venv introuvable pour \${SERVICE_NAME}: \${REMOTE_SRC_DIR}/.venv/bin/python"
    exit 1
  fi

  sudo tee "/etc/systemd/system/\${SERVICE_NAME}.service" >/dev/null <<SERVICE
[Unit]
Description=\${DESCRIPTION}
After=network-online.target opencti.service opencti-worker.service rabbitmq-server.service
Wants=network-online.target opencti-worker.service

[Service]
User=opencti
Group=opencti
WorkingDirectory=\${REMOTE_SRC_DIR}
Environment=PATH=\${REMOTE_SRC_DIR}/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=\${REMOTE_SRC_DIR}/.venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

  sudo systemctl daemon-reload
  sudo systemctl enable "\${SERVICE_NAME}"
  sudo systemctl restart "\${SERVICE_NAME}"
}

write_main_py_connector_service \
  "opencti-connector-urlhaus" \
  "OpenCTI URLHaus Connector" \
  "/opt/opencti/connectors/external-import/urlhaus/src"

write_main_py_connector_service \
  "opencti-connector-malwarebazaar" \
  "OpenCTI MalwareBazaar Connector" \
  "/opt/opencti/connectors/external-import/malwarebazaar/src"

sleep 10

systemctl status opencti-connector-urlhaus --no-pager -l || true
systemctl status opencti-connector-malwarebazaar --no-pager -l || true

systemctl is-active --quiet opencti-connector-urlhaus
systemctl is-active --quiet opencti-connector-malwarebazaar
`,
    "Correction entrypoint main.py connecteurs URLHaus/MalwareBazaar",
    300_000
  );
}

function resolveOpenCTIUrlForWazuh(
  openctiTarget: SshAccessEntry,
  env: EnvMap
): string {
  const explicitUrl =
    env.OPENCTI_WAZUH_URL ||
    env.OPENCTI_INTERNAL_URL ||
    env.OPENCTI_LAB_URL ||
    "";

  if (explicitUrl && !isLocalhostUrl(explicitUrl)) {
    return normalizeUrl(explicitUrl);
  }

  if (env.OPENCTI_URL && !isLocalhostUrl(env.OPENCTI_URL)) {
    return normalizeUrl(env.OPENCTI_URL);
  }

  const detectedIp = runSshCapture(
    openctiTarget,
    `
set -euo pipefail

ip_candidate="$(ip -o -4 addr show dev enp0s8 scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1 || true)"

if [ -n "$ip_candidate" ]; then
  echo "$ip_candidate"
  exit 0
fi

for ip in $(hostname -I); do
  case "$ip" in
    127.*|10.0.2.*|169.254.*)
      continue
      ;;
    *)
      echo "$ip"
      exit 0
      ;;
  esac
done

echo "[ERROR] Impossible de détecter l'IP interne OpenCTI" >&2
exit 1
`.trim(),
    "Détection IP interne OpenCTI pour Wazuh",
    300_000
  )
    .split(/\s+/)
    .find(Boolean);

  if (!detectedIp) {
    throw new Error(
      "[OpenCTI Connector Patcher] Impossible de détecter l'IP interne OpenCTI pour Wazuh."
    );
  }

  return `http://${detectedIp}:8080`;
}

function installWazuhOpenCTIIntegration(
  sshAccess: SshAccessMap,
  openctiTarget: SshAccessEntry,
  env: EnvMap
): void {
  const wazuhTarget = sshAccess["wazuh-1"];

  if (!wazuhTarget) {
    console.log(
      "[Wazuh OpenCTI] wazuh-1 absent de ssh-access.local.json, intégration ignorée."
    );
    return;
  }

  const openctiUrl = resolveOpenCTIUrlForWazuh(openctiTarget, env);
  const minLevel = parsePositiveInt(env.WAZUH_OPENCTI_MIN_LEVEL, 10);
  const timeoutSeconds = parsePositiveInt(env.WAZUH_OPENCTI_TIMEOUT, 60);

  console.log(`[Wazuh OpenCTI] URL OpenCTI utilisée par Wazuh: ${openctiUrl}`);
  console.log(`[Wazuh OpenCTI] Niveau minimum Wazuh: ${minLevel}`);
  console.log(`[Wazuh OpenCTI] Timeout OpenCTI: ${timeoutSeconds}s`);

  installWazuhConnector({
    runSsh: (entry, command) =>
      runSsh(
        entry,
        command,
        "Installation intégration Wazuh -> OpenCTI",
        900_000
      ),
    wazuhSsh: wazuhTarget,
    openctiUrl,
    openctiToken: env.OPENCTI_TOKEN,
    minLevel,
    timeoutSeconds,
    restartWazuh: true
  });
}

export function patchLiveOpenCTIConnectors(
  outputRoot = DEFAULT_OUTPUT_ROOT
): void {
  const sshAccessPath = resolveSshAccessPath(outputRoot);
  const sshAccess = readJson<SshAccessMap>(sshAccessPath);
  const target = sshAccess["opencti-1"];

  if (!target) {
    throw new Error(
      "[OpenCTI Connector Patcher] opencti-1 introuvable dans ssh-access.local.json"
    );
  }

  console.log("[OpenCTI Connector Patcher] Host cible: opencti-1");

  const env = ensureSecretsFile();

  assertRequiredSecrets(env);
  assertOpenCTIReady(target);
  ensureOpenCTIWorker(target, env);

  installCveConnector(target, env);
  installMitreConnector(target, env);
  installD3fendConnector(target, env);
  installUrlhausConnector(target, env);
  installMalwareBazaarConnector(target, env);
  ensureMainPyConnectorEntrypoints(target);
  installAlienVaultConnector(target, env);

  installWazuhOpenCTIIntegration(sshAccess, target, env);
  installZabbixConnector(target, env);

  runSsh(
    target,
    "sudo rabbitmqctl list_queues | grep -E 'push_|listen_' || true",
    "Contrôle files RabbitMQ OpenCTI",
    300_000
  );

  console.log(
    "[OpenCTI Connector Patcher] Worker OpenCTI + connecteurs OpenCTI + MITRE D3FEND + intégration Wazuh installés et démarrés."
  );
}

if (process.argv[1]?.endsWith("openctiConnectorPatcher.ts")) {
  patchLiveOpenCTIConnectors();
}
