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

function runSsh(target: SshAccessEntry, script: string, label: string): string {
  console.log(`\n[Zabbix patch] ${label}`);

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

  if (result.error) throw result.error;

  if (result.status !== 0) {
    throw new Error(`[Zabbix patch] ${label} a échoué avec le code ${result.status}`);
  }

  return result.stdout.trim();
}

function readSshAccess(outputRoot: string): SshAccessMap {
  const filePath = path.join(outputRoot, "ssh-access.local.json");

  if (!fs.existsSync(filePath)) {
    throw new Error(`[Zabbix patch] Fichier introuvable: ${filePath}`);
  }

  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as SshAccessMap;
}

function getInternalIp(target: SshAccessEntry, label: string): string {
  const script = `
set -euo pipefail

ip -o -4 addr show scope global \\
| awk '{print $2, $4}' \\
| awk '$2 !~ /^10\\.0\\.2\\./ && $2 !~ /^127\\./ {print $2; exit}' \\
| cut -d/ -f1
`;

  const ip = runSsh(target, script, `détection IP interne ${label}`);

  if (!ip) {
    throw new Error(`[Zabbix patch] Impossible de détecter l'IP interne de ${label}`);
  }

  console.log(`[Zabbix patch] IP interne ${label}: ${ip}`);
  return ip;
}

export function patchLiveZabbix(outputRoot: string): void {
  const sshAccess = readSshAccess(outputRoot);

  const zabbixTarget = sshAccess["zabbix-1"];
  const dbTarget =
    sshAccess["db-server-1"] ??
    sshAccess["db-server"] ??
    sshAccess["database-1"] ??
    sshAccess["db-1"];

  if (!zabbixTarget) {
    console.log("[Zabbix patch] Aucun zabbix-1 trouvé, skip.");
    return;
  }

  if (!dbTarget) {
    console.log("[Zabbix patch] Aucun db-server trouvé, skip.");
    return;
  }

  const dbIp = getInternalIp(dbTarget, "db-server");

  const installScript = `
set -euo pipefail

DB_HOST="${dbIp}"
DB_PORT="3306"
DB_NAME="zabbix"
DB_USER="zabbix"
DB_PASSWORD="Admin123!"

ZABBIX_SERVER_NAME="SOC-LAB"
ZABBIX_TIMEZONE="Europe/Paris"

echo "[Zabbix] DB distante utilisée: $DB_HOST:$DB_PORT"

echo "[Zabbix] Installation prérequis..."

sudo apt-get update -y

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \\
  wget \\
  curl \\
  gnupg \\
  ca-certificates \\
  nginx \\
  php-fpm \\
  php-mysql \\
  mariadb-client \\
  lsof

echo "[Zabbix] Installation dépôt Zabbix Debian 13..."

cd /tmp
rm -f zabbix-release*.deb

sudo rm -f /etc/apt/sources.list.d/zabbix.list
sudo rm -f /etc/apt/sources.list.d/zabbix*.list
sudo rm -f /etc/apt/sources.list.d/zabbix*.sources

wget \\
  https://repo.zabbix.com/zabbix/7.0/debian/pool/main/z/zabbix-release/zabbix-release_latest_7.0+debian13_all.deb \\
  -O zabbix-release.deb

sudo dpkg -i zabbix-release.deb
sudo apt-get update -y

echo "[Zabbix] Installation paquets Zabbix..."

if ! dpkg -s zabbix-server-mysql >/dev/null 2>&1; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \\
    zabbix-server-mysql \\
    zabbix-frontend-php \\
    zabbix-nginx-conf \\
    zabbix-sql-scripts \\
    zabbix-agent
else
  echo "[Zabbix] Paquets Zabbix déjà installés, skip."
fi

echo "[Zabbix] Test connexion MariaDB distante..."

DB_OK=0

for i in 1 2 3 4 5 6 7 8 9 10; do
  if mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SELECT 1;" >/dev/null 2>&1; then
    echo "[Zabbix] Connexion DB OK"
    DB_OK=1
    break
  fi

  echo "[Zabbix] Attente MariaDB distante $i/10..."
  sleep 5
done

if [ "$DB_OK" -ne 1 ]; then
  echo "[Zabbix] ERREUR: connexion MariaDB impossible"
  mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SELECT 1;" || true
  exit 1
fi

echo "[Zabbix] Vérification schéma DB..."

TABLE_COUNT="$(mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -Nse "SHOW TABLES;" | wc -l | tr -d ' ')"

if [ "$TABLE_COUNT" -eq 0 ]; then
  echo "[Zabbix] Import initial du schéma..."

  if [ ! -f /usr/share/zabbix-sql-scripts/mysql/server.sql.gz ]; then
    echo "[Zabbix] ERREUR: server.sql.gz introuvable"
    find /usr/share/zabbix-sql-scripts -type f | sort || true
    exit 1
  fi

  zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz \\
  | mysql --default-character-set=utf8mb4 -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME"
else
  echo "[Zabbix] Schéma déjà présent ($TABLE_COUNT tables), skip import."
fi

echo "[Zabbix] Configuration zabbix_server.conf..."

if [ -f /etc/zabbix/zabbix_server.conf ]; then
  sudo cp /etc/zabbix/zabbix_server.conf /etc/zabbix/zabbix_server.conf.bak.$(date +%Y%m%d%H%M%S)
fi

sudo sed -i "s/^#*DBHost=.*/DBHost=$DB_HOST/" /etc/zabbix/zabbix_server.conf
sudo sed -i "s/^#*DBPort=.*/DBPort=$DB_PORT/" /etc/zabbix/zabbix_server.conf
sudo sed -i "s/^DBName=.*/DBName=$DB_NAME/" /etc/zabbix/zabbix_server.conf
sudo sed -i "s/^DBUser=.*/DBUser=$DB_USER/" /etc/zabbix/zabbix_server.conf
sudo sed -i "s/^#*DBPassword=.*/DBPassword=$DB_PASSWORD/" /etc/zabbix/zabbix_server.conf

grep -q "^DBHost=" /etc/zabbix/zabbix_server.conf || echo "DBHost=$DB_HOST" | sudo tee -a /etc/zabbix/zabbix_server.conf >/dev/null
grep -q "^DBPort=" /etc/zabbix/zabbix_server.conf || echo "DBPort=$DB_PORT" | sudo tee -a /etc/zabbix/zabbix_server.conf >/dev/null
grep -q "^DBName=" /etc/zabbix/zabbix_server.conf || echo "DBName=$DB_NAME" | sudo tee -a /etc/zabbix/zabbix_server.conf >/dev/null
grep -q "^DBUser=" /etc/zabbix/zabbix_server.conf || echo "DBUser=$DB_USER" | sudo tee -a /etc/zabbix/zabbix_server.conf >/dev/null
grep -q "^DBPassword=" /etc/zabbix/zabbix_server.conf || echo "DBPassword=$DB_PASSWORD" | sudo tee -a /etc/zabbix/zabbix_server.conf >/dev/null

echo "[Zabbix] Configuration frontend automatique..."

sudo mkdir -p /etc/zabbix/web

sudo tee /etc/zabbix/web/zabbix.conf.php >/dev/null <<PHP
<?php
// Zabbix GUI configuration file.

\\$DB['TYPE'] = 'MYSQL';
\\$DB['SERVER'] = '$DB_HOST';
\\$DB['PORT'] = '$DB_PORT';
\\$DB['DATABASE'] = '$DB_NAME';
\\$DB['USER'] = '$DB_USER';
\\$DB['PASSWORD'] = '$DB_PASSWORD';

\\$DB['SCHEMA'] = '';
\\$DB['ENCRYPTION'] = false;
\\$DB['KEY_FILE'] = '';
\\$DB['CERT_FILE'] = '';
\\$DB['CA_FILE'] = '';
\\$DB['VERIFY_HOST'] = false;
\\$DB['CIPHER_LIST'] = '';

\\$ZBX_SERVER = 'localhost';
\\$ZBX_SERVER_PORT = '10051';
\\$ZBX_SERVER_NAME = '$ZABBIX_SERVER_NAME';

\\$IMAGE_FORMAT_DEFAULT = IMAGE_FORMAT_PNG;
PHP

sudo chown www-data:www-data /etc/zabbix/web/zabbix.conf.php
sudo chmod 640 /etc/zabbix/web/zabbix.conf.php

echo "[Zabbix] Configuration timezone PHP..."

PHP_FPM_SERVICE="$(systemctl list-unit-files | awk '/php.*-fpm.service/ {print $1; exit}' || true)"
PHP_VERSION="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)"

if [ -n "$PHP_VERSION" ]; then
  if [ -f "/etc/php/$PHP_VERSION/fpm/php.ini" ]; then
    sudo sed -i "s|^;*date.timezone =.*|date.timezone = $ZABBIX_TIMEZONE|" "/etc/php/$PHP_VERSION/fpm/php.ini"
    grep -q "^date.timezone = $ZABBIX_TIMEZONE" "/etc/php/$PHP_VERSION/fpm/php.ini" || echo "date.timezone = $ZABBIX_TIMEZONE" | sudo tee -a "/etc/php/$PHP_VERSION/fpm/php.ini" >/dev/null
  fi

  if [ -f "/etc/php/$PHP_VERSION/cli/php.ini" ]; then
    sudo sed -i "s|^;*date.timezone =.*|date.timezone = $ZABBIX_TIMEZONE|" "/etc/php/$PHP_VERSION/cli/php.ini"
    grep -q "^date.timezone = $ZABBIX_TIMEZONE" "/etc/php/$PHP_VERSION/cli/php.ini" || echo "date.timezone = $ZABBIX_TIMEZONE" | sudo tee -a "/etc/php/$PHP_VERSION/cli/php.ini" >/dev/null
  fi
fi

echo "[Zabbix] Configuration agent local..."

ZABBIX_IP="$(ip -o -4 addr show scope global | awk '{print $2, $4}' | awk '$2 !~ /^10\\.0\\.2\\./ && $2 !~ /^127\\./ {print $2; exit}' | cut -d/ -f1)"

if [ -f /etc/zabbix/zabbix_agentd.conf ]; then
  sudo cp /etc/zabbix/zabbix_agentd.conf /etc/zabbix/zabbix_agentd.conf.bak.$(date +%Y%m%d%H%M%S) || true

  sudo sed -i "s/^Server=.*/Server=127.0.0.1,$ZABBIX_IP/" /etc/zabbix/zabbix_agentd.conf || true
  sudo sed -i "s/^ServerActive=.*/ServerActive=127.0.0.1,$ZABBIX_IP/" /etc/zabbix/zabbix_agentd.conf || true
  sudo sed -i "s/^Hostname=.*/Hostname=zabbix-1/" /etc/zabbix/zabbix_agentd.conf || true

  grep -q "^Server=" /etc/zabbix/zabbix_agentd.conf || echo "Server=127.0.0.1,$ZABBIX_IP" | sudo tee -a /etc/zabbix/zabbix_agentd.conf >/dev/null
  grep -q "^ServerActive=" /etc/zabbix/zabbix_agentd.conf || echo "ServerActive=127.0.0.1,$ZABBIX_IP" | sudo tee -a /etc/zabbix/zabbix_agentd.conf >/dev/null
  grep -q "^Hostname=" /etc/zabbix/zabbix_agentd.conf || echo "Hostname=zabbix-1" | sudo tee -a /etc/zabbix/zabbix_agentd.conf >/dev/null
fi

echo "[Zabbix] Configuration Nginx..."

if [ -f /etc/zabbix/nginx.conf ]; then
  sudo cp /etc/zabbix/nginx.conf /etc/zabbix/nginx.conf.bak.$(date +%Y%m%d%H%M%S) || true

  sudo sed -i "s|#\\s*listen\\s*8080;|listen 8080;|" /etc/zabbix/nginx.conf || true
  sudo sed -i "s|#\\s*server_name\\s*example.com;|server_name _;|" /etc/zabbix/nginx.conf || true

  grep -q "listen 8080;" /etc/zabbix/nginx.conf || sudo sed -i "/server {/a\\        listen 8080;" /etc/zabbix/nginx.conf
  grep -q "server_name _;" /etc/zabbix/nginx.conf || sudo sed -i "/server {/a\\        server_name _;" /etc/zabbix/nginx.conf

  sudo rm -f /etc/nginx/sites-enabled/default || true
  sudo ln -sf /etc/zabbix/nginx.conf /etc/nginx/conf.d/zabbix.conf
fi

echo "[Zabbix] Démarrage services..."

sudo systemctl daemon-reload
sudo systemctl enable zabbix-server zabbix-agent nginx || true

if [ -n "$PHP_FPM_SERVICE" ]; then
  sudo systemctl enable "$PHP_FPM_SERVICE" || true
  sudo systemctl restart "$PHP_FPM_SERVICE"
fi

sudo systemctl restart zabbix-server zabbix-agent nginx

sleep 8

echo "[Zabbix] Validation services..."

sudo systemctl --no-pager --full status zabbix-server || true
sudo systemctl --no-pager --full status zabbix-agent || true
sudo systemctl --no-pager --full status nginx || true

if [ -n "$PHP_FPM_SERVICE" ]; then
  sudo systemctl --no-pager --full status "$PHP_FPM_SERVICE" || true
fi

sudo ss -lntp | grep -E '10051|10050|8080|80' || true

if ! sudo systemctl is-active --quiet zabbix-server; then
  echo "[Zabbix] ERREUR: zabbix-server non actif"
  sudo journalctl -u zabbix-server -n 160 --no-pager || true
  tail -n 160 /var/log/zabbix/zabbix_server.log || true
  exit 1
fi

if ! sudo systemctl is-active --quiet nginx; then
  echo "[Zabbix] ERREUR: nginx non actif"
  sudo journalctl -u nginx -n 160 --no-pager || true
  sudo nginx -t || true
  exit 1
fi

echo "[Zabbix] Test HTTP local..."

HTTP_CODE="$(curl -s -o /tmp/zabbix-http.out -w "%{http_code}" http://127.0.0.1:8080/ || true)"
echo "[Zabbix] HTTP local code: $HTTP_CODE"
head -n 5 /tmp/zabbix-http.out || true

if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "302" ]; then
  echo "[Zabbix] WARNING: HTTP local inattendu"
fi

echo ""
echo "======================================="
echo "[Zabbix] READY"
echo "[Zabbix] URL interne: http://$ZABBIX_IP:8080"
echo "[Zabbix] Login par défaut: Admin / zabbix"
echo "[Zabbix] DBHost: $DB_HOST"
echo "[Zabbix] DBPort: $DB_PORT"
echo "[Zabbix] Server name: $ZABBIX_SERVER_NAME"
echo "[Zabbix] Timezone: $ZABBIX_TIMEZONE"
echo "======================================="

exit 0
`;

  runSsh(zabbixTarget, installScript, "installation et configuration Zabbix");
}