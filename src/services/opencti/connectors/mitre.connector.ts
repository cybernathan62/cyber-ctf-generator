import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

import type { EnvMap } from "./cve.connector.js";

type SshAccessEntry = {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  identity_file: string;
};

export const MITRE_REMOTE_DIR =
  "/opt/opencti/connectors/external-import/mitre";

export const MITRE_REMOTE_CONFIG =
  `${MITRE_REMOTE_DIR}/src/config.yml`;

export const MITRE_SERVICE_NAME =
  "opencti-connector-mitre";

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
  timeoutMs = 900000
): void {
  console.log(`\n[MITRE Connector] ${label}`);

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
      `[MITRE Connector] Erreur SSH ${label}: ${result.error.message}`
    );
  }

  if (result.status !== 0) {
    throw new Error(
      `[MITRE Connector] Échec ${label} code=${result.status}`
    );
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

  const result = spawnSync(
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
      timeout: 300000
    }
  );

  if (result.error || result.status !== 0) {
    throw new Error("[MITRE Connector] Upload impossible.");
  }

  runSsh(
    target,
    [
      `sudo mkdir -p ${shQuote(remoteDir)}`,
      `sudo mv ${shQuote(remoteTmp)} ${shQuote(remotePath)}`,
      `sudo chown -R opencti:opencti ${shQuote(remoteDir)}`,
      `sudo chmod 600 ${shQuote(remotePath)}`
    ].join(" && "),
    "Upload configuration"
  );
}

function buildMitreConfig(env: EnvMap): string {
  const connectorId =
    env.OPENCTI_CONNECTOR_MITRE_ID ||
    randomUUID();

  return `opencti:
  url: ${yamlQuote(env.OPENCTI_URL)}
  token: ${yamlQuote(env.OPENCTI_TOKEN)}

connector:
  id: ${yamlQuote(connectorId)}
  type: 'EXTERNAL_IMPORT'
  name: 'MITRE ATT&CK'
  scope: 'mitre-attack'
  confidence_level: 100
  log_level: 'info'
  run_and_terminate: false

mitre:
  interval_sec: ${env.MITRE_INTERVAL_SEC || "86400"}
  enterprise_attack: true
  mobile_attack: true
  ics_attack: true
  capec: true
  cwe: true
`;
}

export function installMitreConnector(
  target: SshAccessEntry,
  env: EnvMap
): void {

  const secretsDir =
    path.join(SECRETS_DIR, "opencti-connectors");

  fs.mkdirSync(secretsDir, { recursive: true });

  const localConfig =
    path.join(secretsDir, "mitre-config.yml");

  fs.writeFileSync(
    localConfig,
    buildMitreConfig(env),
    {
      encoding: "utf-8",
      mode: 0o600
    }
  );

  uploadFile(
    target,
    localConfig,
    MITRE_REMOTE_CONFIG
  );

  runSsh(
    target,
`set -e

PYTHON_BIN="${CONNECTOR_PYTHON_BIN}"

if [ ! -d "${MITRE_REMOTE_DIR}" ]; then
  echo "[WARN] Connecteur MITRE absent."
  exit 0
fi

sudo -u opencti bash -lc '
cd ${MITRE_REMOTE_DIR}
rm -rf src/.venv
${CONNECTOR_PYTHON_BIN} -m venv src/.venv
. src/.venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r src/requirements.txt
'`,
    "Installation dépendances",
    1800000
  );

  runSsh(
    target,
`set -e

sudo tee /etc/systemd/system/${MITRE_SERVICE_NAME}.service >/dev/null <<SERVICE
[Unit]
Description=OpenCTI MITRE ATT&CK Connector
After=network-online.target opencti.service opencti-worker.service rabbitmq-server.service

[Service]
User=opencti
Group=opencti
WorkingDirectory=${MITRE_REMOTE_DIR}
Environment=PATH=${MITRE_REMOTE_DIR}/src/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=${MITRE_REMOTE_DIR}/src/.venv/bin/python -m src
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable ${MITRE_SERVICE_NAME}
sudo systemctl restart ${MITRE_SERVICE_NAME}
sleep 5
sudo systemctl status ${MITRE_SERVICE_NAME} --no-pager || true`,
    "Création service MITRE",
    300000
  );
}