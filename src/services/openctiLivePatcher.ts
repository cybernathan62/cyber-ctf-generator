import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

type SshAccessEntry = {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  identity_file: string;
};

type SshAccessMap = Record<string, SshAccessEntry>;

const OPENCTI_VERSION = "7.260619.0";

function readJson<T>(filePath: string): T {
  if (!fs.existsSync(filePath)) {
    throw new Error(`[OpenCTI patch] Fichier introuvable: ${filePath}`);
  }

  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
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
  timeoutMs = 60 * 60 * 1000
): void {
  console.log(`\n[OpenCTI patch] ${label}`);

  const sshKey = resolveIdentityFile(target.identity_file);
  const command = process.platform === "win32" ? "ssh.exe" : "ssh";

  const result = spawnSync(
    command,
    [
      "-i",
      sshKey,
      "-p",
      String(target.ssh_port),
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      "UserKnownHostsFile=/dev/null",
      "-o",
      "ConnectTimeout=20",
      `${target.ssh_user}@${target.ssh_host}`,
      script
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

  if (result.error) throw result.error;

  if (result.status !== 0) {
    throw new Error(`[OpenCTI patch] Échec ${label} code=${result.status}`);
  }
}

function randomSecret(length = 48): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let value = "";

  for (let i = 0; i < length; i++) {
    value += chars[Math.floor(Math.random() * chars.length)];
  }

  return value;
}

export function patchLiveOpenCTI(outputRoot: string): void {
  const sshAccessPath = path.join(outputRoot, "ssh-access.local.json");
  const sshAccess = readJson<SshAccessMap>(sshAccessPath);
  const target = sshAccess["opencti-1"];

  if (!target) {
    throw new Error("[OpenCTI patch] opencti-1 introuvable dans ssh-access.local.json");
  }

  const adminPassword = "Admin123!";
  const appSecret = randomSecret(64);
  const minioPassword = randomSecret(32);
  const rabbitPassword = randomSecret(32);
  const adminToken = randomUUID();

  const installScript = `set -eu

export DEBIAN_FRONTEND=noninteractive
export OPENCTI_VERSION="${OPENCTI_VERSION}"
export OPENSEARCH_VERSION="2.18.0"

log() { echo "[OpenCTI patch] $1"; }

get_primary_ip() {
  hostname -I 2>/dev/null | awk '{print $1}'
}

OPENCTI_VM_IP="\$(get_primary_ip)"
if [ -z "\$OPENCTI_VM_IP" ]; then
  OPENCTI_VM_IP="127.0.0.1"
fi

log "[1/10] Préparation système"
sudo sysctl -w vm.max_map_count=262144 >/dev/null
sudo tee /etc/sysctl.d/99-opencti.conf >/dev/null <<'SYSCTL'
vm.max_map_count=262144
SYSCTL

sudo apt-get update
sudo apt-get install -y ca-certificates curl jq tar unzip git gnupg uuid-runtime openssl \
  build-essential python3 python3-full python3-pip python3-venv python3-dev \
  openjdk-21-jre-headless redis-server rabbitmq-server nginx nodejs npm

log "[1b/10] Corepack / Yarn 4"
sudo npm remove -g yarn >/dev/null 2>&1 || true
sudo npm install -g corepack >/dev/null 2>&1 || true
sudo corepack enable
corepack prepare yarn@4.16.0 --activate

yarn --version

log "[2/10] Installation OpenSearch mono-node"
if [ ! -x /opt/opensearch/bin/opensearch ]; then
  cd /tmp
  rm -rf opensearch-* opensearch.tar.gz
  curl -fL -o opensearch.tar.gz "https://artifacts.opensearch.org/releases/bundle/opensearch/\$OPENSEARCH_VERSION/opensearch-\$OPENSEARCH_VERSION-linux-x64.tar.gz"
  tar -xzf opensearch.tar.gz

  sudo systemctl stop opensearch >/dev/null 2>&1 || true
  sudo rm -rf /opt/opensearch /etc/opensearch
  sudo mv "opensearch-\$OPENSEARCH_VERSION" /opt/opensearch
  sudo useradd --system --home /opt/opensearch --shell /usr/sbin/nologin opensearch 2>/dev/null || true
  sudo mkdir -p /var/lib/opensearch /var/log/opensearch /etc/opensearch /tmp/opensearch
  sudo cp -a /opt/opensearch/config/. /etc/opensearch/
fi

sudo tee /etc/opensearch/opensearch.yml >/dev/null <<'OPENSEARCH_YML'
cluster.name: opencti-lab
node.name: opencti-1
path.data: /var/lib/opensearch
path.logs: /var/log/opensearch
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
bootstrap.memory_lock: false
plugins.security.disabled: true
OPENSEARCH_YML

sudo tee /etc/opensearch/jvm.options >/dev/null <<'JVM'
-Xms1g
-Xmx1g
-Djava.io.tmpdir=/tmp/opensearch
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/lib/opensearch
-XX:ErrorFile=/var/log/opensearch/hs_err_pid%p.log
JVM

sudo chown -R opensearch:opensearch /opt/opensearch /etc/opensearch /var/lib/opensearch /var/log/opensearch /tmp/opensearch

sudo tee /etc/systemd/system/opensearch.service >/dev/null <<'OPENSEARCH_SERVICE'
[Unit]
Description=OpenSearch single-node for OpenCTI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=opensearch
Group=opensearch
WorkingDirectory=/opt/opensearch
Environment=OPENSEARCH_HOME=/opt/opensearch
Environment=OPENSEARCH_PATH_CONF=/etc/opensearch
Environment=OPENSEARCH_TMPDIR=/tmp/opensearch
Environment="OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
ExecStartPre=/bin/mkdir -p /tmp/opensearch
ExecStartPre=/bin/chown opensearch:opensearch /tmp/opensearch
ExecStart=/opt/opensearch/bin/opensearch
Restart=always
RestartSec=10
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
OPENSEARCH_SERVICE

sudo systemctl daemon-reload
sudo systemctl enable --now redis-server rabbitmq-server
sudo systemctl restart opensearch

log "[3/10] Attente OpenSearch"
for i in \$(seq 1 90); do
  if curl -fsS http://127.0.0.1:9200 >/dev/null 2>&1; then
    echo "OpenSearch OK"
    break
  fi

  if [ "\$i" -eq 90 ]; then
    echo "OpenSearch ne répond pas"
    sudo journalctl -u opensearch -n 200 --no-pager || true
    exit 1
  fi

  sleep 5
done

log "[4/10] Configuration RabbitMQ"
sudo rabbitmqctl add_user opencti '${rabbitPassword}' 2>/dev/null || true
sudo rabbitmqctl change_password opencti '${rabbitPassword}'
sudo rabbitmqctl set_permissions -p / opencti ".*" ".*" ".*"

log "[5/10] Installation MinIO sans Docker"
if ! command -v minio >/dev/null 2>&1; then
  sudo curl -fsSL -o /usr/local/bin/minio https://dl.min.io/server/minio/release/linux-amd64/minio
  sudo chmod +x /usr/local/bin/minio
fi

sudo useradd --system --home /var/lib/minio --shell /usr/sbin/nologin minio 2>/dev/null || true
sudo mkdir -p /var/lib/minio /etc/minio
sudo chown -R minio:minio /var/lib/minio /etc/minio

sudo tee /etc/default/minio >/dev/null <<MINIO_ENV
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=${minioPassword}
MINIO_VOLUMES="/var/lib/minio"
MINIO_OPTS="--address 127.0.0.1:9000 --console-address 127.0.0.1:9001"
MINIO_ENV

sudo tee /etc/systemd/system/minio.service >/dev/null <<'MINIO_SERVICE'
[Unit]
Description=MinIO object storage for OpenCTI
After=network-online.target
Wants=network-online.target

[Service]
User=minio
Group=minio
EnvironmentFile=/etc/default/minio
ExecStart=/usr/local/bin/minio server $MINIO_OPTS $MINIO_VOLUMES
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
MINIO_SERVICE

sudo systemctl daemon-reload
sudo systemctl enable --now minio

log "[6/10] Téléchargement OpenCTI release GitHub"
sudo useradd --system --home /opt/opencti --shell /bin/bash opencti 2>/dev/null || true
sudo systemctl stop opencti >/dev/null 2>&1 || true
sudo systemctl stop opencti-worker >/dev/null 2>&1 || true
sudo rm -rf /opt/opencti
sudo mkdir -p /opt/opencti /etc/opencti /var/log/opencti

cd /tmp
rm -rf opencti-release.tar.gz opencti-extract
mkdir -p opencti-extract
curl -fL -o opencti-release.tar.gz "https://github.com/OpenCTI-Platform/opencti/releases/download/\$OPENCTI_VERSION/opencti-release-\$OPENCTI_VERSION.tar.gz"
tar -xzf opencti-release.tar.gz -C opencti-extract --strip-components=1
sudo cp -a opencti-extract/. /opt/opencti/
sudo chown -R opencti:opencti /opt/opencti /etc/opencti /var/log/opencti

log "[7/10] Configuration OpenCTI .env"
OPENCTI_ENCRYPTION_KEY="\$(openssl rand -base64 32)"

sudo tee /opt/opencti/.env >/dev/null <<OPENCTI_ENV
NODE_ENV=production
APP__PORT=8080
APP__BASE_URL=http://\$OPENCTI_VM_IP:8080
APP__ADMIN__EMAIL=admin@opencti.local
APP__ADMIN__PASSWORD=${adminPassword}
APP__ADMIN__TOKEN=${adminToken}
APP__APP_LOGS__LOGS_LEVEL=info
APP__SECRET=${appSecret}
APP__ENCRYPTION_KEY=\$OPENCTI_ENCRYPTION_KEY

REDIS__HOSTNAME=127.0.0.1
REDIS__PORT=6379

RABBITMQ__HOSTNAME=127.0.0.1
RABBITMQ__PORT=5672
RABBITMQ__PORT_MANAGEMENT=15672
RABBITMQ__MANAGEMENT_SSL=false
RABBITMQ__USERNAME=opencti
RABBITMQ__PASSWORD=${rabbitPassword}

ELASTICSEARCH__URL=http://127.0.0.1:9200

MINIO__ENDPOINT=127.0.0.1
MINIO__PORT=9000
MINIO__USE_SSL=false
MINIO__ACCESS_KEY=opencti
MINIO__SECRET_KEY=${minioPassword}
OPENCTI_ENV

sudo chown opencti:opencti /opt/opencti/.env
sudo chmod 600 /opt/opencti/.env

# production.json reste créé pour compatibilité, mais le service démarre avec --env-file.
sudo -u opencti cp /opt/opencti/config/default.json /opt/opencti/config/production.json
sudo chown opencti:opencti /opt/opencti/config/production.json
sudo chmod 600 /opt/opencti/config/production.json

log "[8/10] Venv Python, Yarn install et build OpenCTI"
sudo chown -R opencti:opencti /opt/opencti
sudo -u opencti bash -lc '
cd /opt/opencti
corepack prepare yarn@4.16.0 --activate
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r src/python/requirements.txt
pip install eql
yarn install
yarn build:prod
'

OPENCTI_NODE_ENTRY="/opt/opencti/build/back.js"
if [ ! -f "\$OPENCTI_NODE_ENTRY" ]; then
  OPENCTI_NODE_ENTRY="\$(find /opt/opencti -type f -path '*/build/back.js' | head -n 1 || true)"
fi

if [ -z "\$OPENCTI_NODE_ENTRY" ] || [ ! -f "\$OPENCTI_NODE_ENTRY" ]; then
  echo "Entrée Node OpenCTI introuvable après build"
  find /opt/opencti -maxdepth 3 -type f | sed -n '1,120p'
  exit 1
fi

log "[8b/10] Service systemd OpenCTI"
sudo tee /etc/systemd/system/opencti.service >/dev/null <<OPENCTI_SERVICE
[Unit]
Description=OpenCTI threat intelligence platform
After=network-online.target redis-server.service rabbitmq-server.service opensearch.service minio.service
Wants=network-online.target

[Service]
User=opencti
Group=opencti
WorkingDirectory=/opt/opencti
Environment=NODE_ENV=production
Environment=PATH=/opt/opencti/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/bin/node --env-file=/opt/opencti/.env \$OPENCTI_NODE_ENTRY
Restart=always
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
OPENCTI_SERVICE

log "[9/10] Worker OpenCTI systemd"
WORKER_PATH=""
if [ -f /opt/opencti/worker.py ]; then
  WORKER_PATH="/opt/opencti/worker.py"
elif [ -f /opt/opencti/src/python/worker.py ]; then
  WORKER_PATH="/opt/opencti/src/python/worker.py"
fi

if [ -n "\$WORKER_PATH" ]; then
  sudo tee /etc/systemd/system/opencti-worker.service >/dev/null <<WORKER_SERVICE
[Unit]
Description=OpenCTI Python worker
After=opencti.service
Wants=opencti.service

[Service]
User=opencti
Group=opencti
WorkingDirectory=/opt/opencti
Environment=NODE_ENV=production
Environment=PATH=/opt/opencti/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EnvironmentFile=/opt/opencti/.env
ExecStart=/opt/opencti/.venv/bin/python \$WORKER_PATH
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
WORKER_SERVICE
fi

log "[10/10] Nginx reverse proxy"
sudo tee /etc/nginx/sites-available/opencti >/dev/null <<'NGINX'
server {
  listen 80 default_server;
  server_name _;

  client_max_body_size 50m;

  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}
NGINX

sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/opencti /etc/nginx/sites-enabled/opencti
sudo nginx -t

sudo systemctl daemon-reload
sudo systemctl enable --now nginx
sudo systemctl enable opencti
sudo systemctl restart opencti

if [ -n "\$WORKER_PATH" ]; then
  sudo systemctl enable opencti-worker
  sudo systemctl restart opencti-worker
else
  echo "[WARN] worker.py introuvable dans la release, service worker non créé."
fi

log "Validation OpenCTI"
OPENCTI_OK=0
for i in \$(seq 1 90); do
  if curl -fsS http://127.0.0.1:8080 >/dev/null 2>&1; then
    OPENCTI_OK=1
    break
  fi
  sleep 5
done

if [ "\$OPENCTI_OK" != "1" ]; then
  echo "OpenCTI KO"
  sudo systemctl status opencti --no-pager || true
  sudo journalctl -u opencti -n 200 --no-pager || true
  exit 1
fi

echo
echo "=== Services ==="
systemctl --no-pager --full status redis-server rabbitmq-server opensearch minio opencti nginx | sed -n '1,260p' || true
if [ -n "\$WORKER_PATH" ]; then
  systemctl --no-pager --full status opencti-worker | sed -n '1,120p' || true
fi

echo
echo "=== Tests locaux ==="
curl -fsS http://127.0.0.1:9200 >/dev/null && echo "OpenSearch OK" || echo "OpenSearch KO"
curl -fsS http://127.0.0.1:8080 >/dev/null && echo "OpenCTI OK" || echo "OpenCTI KO"
curl -I http://127.0.0.1:80 || true

echo
echo "=== Accès OpenCTI ==="
echo "URL VM: http://\$OPENCTI_VM_IP:8080 ou http://\$OPENCTI_VM_IP"
echo "Port forward Vagrant attendu: http://127.0.0.1:9080"
echo "Login: admin@opencti.local"
echo "Password: ${adminPassword}"
echo "Admin token: ${adminToken}"
echo
echo "Debug si besoin:"
echo "sudo journalctl -u opencti -n 200 --no-pager"
echo "sudo journalctl -u opensearch -n 200 --no-pager"
`;

  runSsh(target, installScript, "Installation OpenCTI natif Debian via release GitHub", 120 * 60 * 1000);
}
