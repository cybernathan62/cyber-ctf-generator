import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

type SshAccessEntry = {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  identity_file: string;
};

type SshAccessMap = Record<string, SshAccessEntry>;

function runSsh(
  target: SshAccessEntry,
  script: string,
  label: string
): void {
  console.log(`\n[MariaDB patch] ${label}`);

  const result = spawnSync(
    process.platform === "win32" ? "ssh.exe" : "ssh",
    [
      "-i",
      target.identity_file,
      "-p",
      String(target.ssh_port),
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      "UserKnownHostsFile=/dev/null",
      "-o",
      "LogLevel=ERROR",
      `${target.ssh_user}@${target.ssh_host}`,
      script
    ],
    {
      encoding: "utf-8",
      shell: false,
      maxBuffer: 1024 * 1024 * 80
    }
  );

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    throw new Error(
      `[MariaDB patch] ${label} a échoué avec le code ${result.status}`
    );
  }
}

function readSshAccess(outputRoot: string): SshAccessMap {
  const filePath = path.join(outputRoot, "ssh-access.local.json");

  if (!fs.existsSync(filePath)) {
    throw new Error(`[MariaDB patch] Fichier introuvable: ${filePath}`);
  }

  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as SshAccessMap;
}

function resolveMariaDbTarget(sshAccess: SshAccessMap): SshAccessEntry | null {
  const exactNames = [
    "db-server-1",
    "db-server",
    "database-1",
    "database",
    "mariadb-1",
    "mariadb",
    "db-1",
    "db"
  ];

  for (const name of exactNames) {
    if (sshAccess[name]) {
      console.log(`[MariaDB patch] Serveur DB détecté: ${name}`);
      return sshAccess[name];
    }
  }

  const fuzzyName = Object.keys(sshAccess).find((name) => {
    const normalized = name.toLowerCase();

    return (
      normalized.includes("db-server") ||
      normalized.includes("database") ||
      normalized.includes("mariadb") ||
      normalized === "db" ||
      normalized.startsWith("db-")
    );
  });

  if (fuzzyName) {
    console.log(`[MariaDB patch] Serveur DB détecté: ${fuzzyName}`);
    return sshAccess[fuzzyName];
  }

  return null;
}

export function patchLiveMariaDB(outputRoot: string): void {
  const sshAccess = readSshAccess(outputRoot);
  const target = resolveMariaDbTarget(sshAccess);

  if (!target) {
    console.log("[MariaDB patch] Aucun serveur DB trouvé, skip.");
    console.log("[MariaDB patch] Hôtes disponibles:");
    console.log(Object.keys(sshAccess).join(", "));
    return;
  }

  const installScript = `
set -euo pipefail

DB_NAME="zabbix"
DB_USER="zabbix"
DB_PASSWORD="Admin123!"

echo "[MariaDB] Installation..."

sudo apt-get update -y

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \\
  mariadb-server \\
  mariadb-client

echo "[MariaDB] Activation..."

sudo systemctl daemon-reload
sudo systemctl enable mariadb
sudo systemctl restart mariadb

sleep 5

if ! sudo systemctl is-active --quiet mariadb; then
  echo "[MariaDB] ERREUR: mariadb non actif"
  sudo systemctl status mariadb --no-pager || true
  exit 1
fi

echo "[MariaDB] Configuration bind-address..."

if [ -f /etc/mysql/mariadb.conf.d/50-server.cnf ]; then
  sudo sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf

  if ! grep -q "^bind-address = 0.0.0.0" /etc/mysql/mariadb.conf.d/50-server.cnf; then
    echo "bind-address = 0.0.0.0" | sudo tee -a /etc/mysql/mariadb.conf.d/50-server.cnf >/dev/null
  fi
fi

sudo systemctl restart mariadb

sleep 3

echo "[MariaDB] Création base..."

sudo mysql <<SQL
CREATE DATABASE IF NOT EXISTS \\\`$\{DB_NAME}\\\`
CHARACTER SET utf8mb4
COLLATE utf8mb4_bin;

CREATE USER IF NOT EXISTS '$\{DB_USER}'@'%'
IDENTIFIED BY '$\{DB_PASSWORD}';

ALTER USER '$\{DB_USER}'@'%'
IDENTIFIED BY '$\{DB_PASSWORD}';

GRANT ALL PRIVILEGES
ON $\{DB_NAME}.*
TO '$\{DB_USER}'@'%';

FLUSH PRIVILEGES;
SQL

echo "[MariaDB] Validation locale..."

sudo mysql -e "SHOW DATABASES;" | grep zabbix

sudo mysql -e "
SELECT user,host
FROM mysql.user
WHERE user = 'zabbix';
"

DB_IP=$(ip -o -4 addr show scope global \\
| awk '{print $4}' \\
| cut -d/ -f1 \\
| grep -v '^10.0.2.' \\
| head -n1)

echo "[MariaDB] Test écoute TCP..."

sudo ss -lntp | grep 3306 || {
  echo "[MariaDB] ERREUR: MariaDB n'écoute pas sur 3306"
  exit 1
}

echo ""
echo "======================================="
echo "[MariaDB] READY"
echo "[MariaDB] DB_NAME=$\{DB_NAME}"
echo "[MariaDB] DB_USER=$\{DB_USER}"
echo "[MariaDB] DB_PASSWORD=$\{DB_PASSWORD}"
echo "[MariaDB] DB_IP=$\{DB_IP}"
echo "======================================="

exit 0
`;

  runSsh(target, installScript, "installation MariaDB et base Zabbix");
}