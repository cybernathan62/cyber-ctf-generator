import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import type { EnvMap } from "./cve.connector.js";

type SshAccessEntry = {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  identity_file: string;
};

export const ALIENVAULT_REMOTE_DIR =
  "/opt/opencti/connectors/external-import/alienvault";

export const ALIENVAULT_REMOTE_CONFIG =
  `${ALIENVAULT_REMOTE_DIR}/src/config.yml`;

export const ALIENVAULT_SERVICE_NAME = "opencti-connector-alienvault";

const PROJECT_ROOT = process.cwd();
const SECRETS_DIR = path.join(PROJECT_ROOT, "secrets");
const CONNECTOR_PYTHON_BIN = "/opt/python/3.12.8/bin/python";

function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function yamlQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function resolveIdentityFile(identityFile: string): string {
  if (identityFile.startsWith("~/")) {
    const home = process.env.USERPROFILE || process.env.HOME || "";
    return path.join(home, identityFile.slice(2));
  }

  return identityFile;
}

function runSsh(
  target: SshAccessEntry,
  script: string,
  label: string,
  timeoutMs = 900_000
): void {
  console.log(`\n[AlienVault Connector] ${label}`);

  const sshKey = resolveIdentityFile(target.identity_file);
  const command = process.platform === "win32" ? "ssh.exe" : "ssh";
  const knownHostsFile = process.platform === "win32" ? "NUL" : "/dev/null";

  const result = require("node:child_process").spawnSync(
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
    throw new Error(`[AlienVault Connector] Erreur SSH ${label}: ${result.error.message}`);
  }

  if (result.status !== 0) {
    throw new Error(`[AlienVault Connector] Échec ${label} code=${result.status}`);
  }
}

function uploadFile(
  target: SshAccessEntry,
  localPath: string,
  remotePath: string
): void {
  const remoteTmp = `/tmp/${path.basename(localPath)}`;
  const remoteDir = path.posix.dirname(remotePath);
  const sshKey = resolveIdentityFile(target.identity_file);
  const scpCommand = process.platform === "win32" ? "scp.exe" : "scp";
  const knownHostsFile = process.platform === "win32" ? "NUL" : "/dev/null";

  const result = require("node:child_process").spawnSync(
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

  if (result.error || result.status !== 0) {
    throw new Error(`[AlienVault Connector] Upload échoué: ${localPath}`);
  }

  runSsh(
    target,
    [
      `sudo mkdir -p ${shQuote(remoteDir)}`,
      `sudo mv ${shQuote(remoteTmp)} ${shQuote(remotePath)}`,
      `sudo chown -R opencti:opencti ${shQuote(remoteDir)}`,
      `sudo chmod 600 ${shQuote(remotePath)}`
    ].join(" && "),
    "Upload configuration AlienVault"
  );
}

function buildAlienVaultConfig(env: EnvMap): string {
  const connectorId =
    env.OPENCTI_CONNECTOR_ALIENVAULT_ID ||
    env.ALIENVAULT_CONNECTOR_ID ||
    randomUUID();

  return `opencti:
  url: ${yamlQuote(env.OPENCTI_URL)}
  token: ${yamlQuote(env.OPENCTI_TOKEN)}

connector:
  id: ${yamlQuote(connectorId)}
  type: 'EXTERNAL_IMPORT'
  name: 'AlienVault'
  scope: 'alienvault'
  confidence_level: 60
  log_level: 'info'
  run_and_terminate: false

alienvault:
  base_url: 'https://otx.alienvault.com'
  api_key: ${yamlQuote(env.ALIENVAULT_API_KEY || "CHANGE_ME")}
  pulse_start_timestamp: ${yamlQuote(env.ALIENVAULT_PULSE_START_TIMESTAMP || "2024-01-01T00:00:00")}
  interval_sec: ${env.ALIENVAULT_INTERVAL_SEC || "1800"}
`;
}

export function installAlienVaultConnector(
  target: SshAccessEntry,
  env: EnvMap
): void {
  if (!env.ALIENVAULT_API_KEY || env.ALIENVAULT_API_KEY === "CHANGE_ME") {
    console.warn("[AlienVault Connector] ALIENVAULT_API_KEY absent, connecteur ignoré.");
    return;
  }

  const secretsConnectorsDir = path.join(SECRETS_DIR, "opencti-connectors");
  fs.mkdirSync(secretsConnectorsDir, { recursive: true });

  const localConfig = path.join(secretsConnectorsDir, "alienvault-config.yml");

  fs.writeFileSync(localConfig, buildAlienVaultConfig(env), {
    encoding: "utf-8",
    mode: 0o600
  });

  uploadFile(target, localConfig, ALIENVAULT_REMOTE_CONFIG);

  runSsh(
    target,
    `set -e
PYTHON_BIN="${CONNECTOR_PYTHON_BIN}"

if [ ! -d "${ALIENVAULT_REMOTE_DIR}" ]; then
  echo "[WARN] Connecteur AlienVault introuvable: ${ALIENVAULT_REMOTE_DIR}"
  exit 0
fi

if [ ! -x "$PYTHON_BIN" ]; then
  echo "[ERROR] Python 3.12 introuvable: $PYTHON_BIN"
  exit 1
fi

sudo -u opencti bash -lc '
cd ${ALIENVAULT_REMOTE_DIR}
rm -rf src/.venv
${CONNECTOR_PYTHON_BIN} -m venv src/.venv
. src/.venv/bin/activate
python --version
pip install --upgrade pip setuptools wheel
pip install -r src/requirements.txt
'`,
    "Installation dépendances AlienVault",
    1_800_000
  );

  runSsh(
    target,
    `set -e
sudo tee /etc/systemd/system/${ALIENVAULT_SERVICE_NAME}.service >/dev/null <<SERVICE
[Unit]
Description=OpenCTI AlienVault OTX Connector
After=network-online.target opencti.service opencti-worker.service rabbitmq-server.service
Wants=network-online.target opencti-worker.service

[Service]
User=opencti
Group=opencti
WorkingDirectory=${ALIENVAULT_REMOTE_DIR}
Environment=PATH=${ALIENVAULT_REMOTE_DIR}/src/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=${ALIENVAULT_REMOTE_DIR}/src/.venv/bin/python -m src
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable ${ALIENVAULT_SERVICE_NAME}
sudo systemctl restart ${ALIENVAULT_SERVICE_NAME}
sleep 5
sudo systemctl status ${ALIENVAULT_SERVICE_NAME} --no-pager || true`,
    "Création service AlienVault",
    300_000
  );
}