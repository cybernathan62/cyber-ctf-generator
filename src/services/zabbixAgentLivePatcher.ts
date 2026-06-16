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

type ZabbixHost = {
  name: string;
  ip: string;
};

const AGENT_TARGETS = [
  "bastion-1",
  "reverse-proxy-1",
  "db-server-1",
  "wazuh-1",
  "ids-sensor-1-1",
  "soc-ai-1"
];

function readSshAccess(outputRoot: string): SshAccessMap {
  const filePath = path.join(outputRoot, "ssh-access.local.json");

  if (!fs.existsSync(filePath)) {
    throw new Error(`[Zabbix agent] Fichier introuvable: ${filePath}`);
  }

  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as SshAccessMap;
}

function runSsh(target: SshAccessEntry, script: string, label: string): void {
  console.log(`\n[Zabbix agent] ${label}`);

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
    throw new Error(`[Zabbix agent] ${label} a échoué avec le code ${result.status}`);
  }
}

function getInternalIp(target: SshAccessEntry, vmName: string): string {
  const script = `
set -euo pipefail

ip -o -4 addr show scope global \
| awk '{print $4}' \
| cut -d/ -f1 \
| grep -v '^10.0.2.' \
| head -n1
`;

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
      maxBuffer: 1024 * 1024 * 10
    }
  );

  if (result.error) throw result.error;

  if (result.status !== 0) {
    if (result.stderr) process.stderr.write(result.stderr);
    throw new Error(`[Zabbix agent] Impossible de détecter l'IP interne de ${vmName}`);
  }

  const ip = result.stdout.trim();

  if (!ip) {
    throw new Error(`[Zabbix agent] IP interne vide pour ${vmName}`);
  }

  return ip;
}

function createHostsInZabbix(
  zabbixTarget: SshAccessEntry,
  zabbixIp: string,
  hosts: ZabbixHost[]
): void {
  if (hosts.length === 0) {
    console.log("[Zabbix agent] Aucun host à créer dans Zabbix.");
    return;
  }

  const hostsBase64 = Buffer.from(JSON.stringify(hosts), "utf-8").toString("base64");

  const script = `
set -euo pipefail

API_URL="http://${zabbixIp}:8080/api_jsonrpc.php"
ZABBIX_USER="Admin"
ZABBIX_PASSWORD="zabbix"
HOSTS_JSON="$(echo "${hostsBase64}" | base64 -d)"

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl python3 >/dev/null 2>&1 || true

echo "[Zabbix API] URL: $API_URL"
echo "[Zabbix API] Attente disponibilité API..."

for i in $(seq 1 60); do
  API_TEST="$(curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}' "$API_URL" || true)"

  if echo "$API_TEST" | python3 -c "import sys,json; data=json.load(sys.stdin); print(data.get('result',''))" >/dev/null 2>&1; then
    echo "[Zabbix API] API disponible"
    break
  fi

  if [ "$i" = "60" ]; then
    echo "[Zabbix API] ERREUR: API indisponible ou URL incorrecte"
    echo "$API_TEST" | head -c 500
    echo
    exit 1
  fi

  sleep 2
done

api_call() {
  local payload="$1"
  local response

  response="$(curl -s -X POST \
    -H "Content-Type: application/json-rpc" \
    -d "$payload" \
    "$API_URL" || true)"

  if ! echo "$response" | python3 -c "import sys,json; json.load(sys.stdin)" >/dev/null 2>&1; then
    echo "[Zabbix API] ERREUR: réponse non JSON"
    echo "$response" | head -c 500
    echo
    return 1
  fi

  echo "$response"
}

AUTH_PAYLOAD_USERNAME=$(cat <<JSON
{
  "jsonrpc": "2.0",
  "method": "user.login",
  "params": {
    "username": "$ZABBIX_USER",
    "password": "$ZABBIX_PASSWORD"
  },
  "id": 1
}
JSON
)

AUTH_RESPONSE="$(api_call "$AUTH_PAYLOAD_USERNAME")"
AUTH_TOKEN="$(echo "$AUTH_RESPONSE" | python3 -c "import sys,json; data=json.load(sys.stdin); print(data.get('result',''))")"

if [ -z "$AUTH_TOKEN" ] || [ "$AUTH_TOKEN" = "None" ]; then
  AUTH_PAYLOAD_USER=$(cat <<JSON
{
  "jsonrpc": "2.0",
  "method": "user.login",
  "params": {
    "user": "$ZABBIX_USER",
    "password": "$ZABBIX_PASSWORD"
  },
  "id": 1
}
JSON
)

  AUTH_RESPONSE="$(api_call "$AUTH_PAYLOAD_USER")"
  AUTH_TOKEN="$(echo "$AUTH_RESPONSE" | python3 -c "import sys,json; data=json.load(sys.stdin); print(data.get('result',''))")"
fi

if [ -z "$AUTH_TOKEN" ] || [ "$AUTH_TOKEN" = "None" ]; then
  echo "[Zabbix API] ERREUR: authentification impossible avec Admin/zabbix"
  echo "$AUTH_RESPONSE"
  exit 1
fi

echo "[Zabbix API] Authentification OK"

GROUP_RESPONSE="$(api_call "$(cat <<JSON
{
  "jsonrpc": "2.0",
  "method": "hostgroup.get",
  "params": {
    "filter": {
      "name": ["Linux servers"]
    }
  },
  "auth": "$AUTH_TOKEN",
  "id": 2
}
JSON
)")"

GROUP_ID="$(echo "$GROUP_RESPONSE" | python3 -c "import sys,json; data=json.load(sys.stdin).get('result', []); print(data[0]['groupid'] if data else '')")"

if [ -z "$GROUP_ID" ]; then
  GROUP_CREATE_RESPONSE="$(api_call "$(cat <<JSON
{
  "jsonrpc": "2.0",
  "method": "hostgroup.create",
  "params": {
    "name": "Linux servers"
  },
  "auth": "$AUTH_TOKEN",
  "id": 3
}
JSON
)")"

  GROUP_ID="$(echo "$GROUP_CREATE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['groupids'][0])")"
fi

echo "[Zabbix API] Group ID: $GROUP_ID"

TEMPLATE_RESPONSE="$(api_call "$(cat <<JSON
{
  "jsonrpc": "2.0",
  "method": "template.get",
  "params": {
    "filter": {
      "host": ["Linux by Zabbix agent"]
    }
  },
  "auth": "$AUTH_TOKEN",
  "id": 4
}
JSON
)")"

TEMPLATE_ID="$(echo "$TEMPLATE_RESPONSE" | python3 -c "import sys,json; data=json.load(sys.stdin).get('result', []); print(data[0]['templateid'] if data else '')")"

if [ -z "$TEMPLATE_ID" ]; then
  echo "[Zabbix API] ERREUR: template introuvable: Linux by Zabbix agent"
  echo "$TEMPLATE_RESPONSE"
  exit 1
fi

echo "[Zabbix API] Template ID: $TEMPLATE_ID"

echo "$HOSTS_JSON" | python3 -c '
import json, sys
hosts = json.load(sys.stdin)
for h in hosts:
    print(h["name"] + "|" + h["ip"])
' | while IFS="|" read -r HOST_NAME HOST_IP; do

  EXISTING_RESPONSE="$(api_call "$(cat <<JSON
{
  "jsonrpc": "2.0",
  "method": "host.get",
  "params": {
    "filter": {
      "host": ["$HOST_NAME"]
    }
  },
  "auth": "$AUTH_TOKEN",
  "id": 10
}
JSON
)")"

  EXISTING_ID="$(echo "$EXISTING_RESPONSE" | python3 -c "import sys,json; data=json.load(sys.stdin).get('result', []); print(data[0]['hostid'] if data else '')")"

  if [ -n "$EXISTING_ID" ]; then
    echo "[Zabbix API] Host déjà existant: $HOST_NAME ($HOST_IP)"
    continue
  fi

  echo "[Zabbix API] Création host: $HOST_NAME ($HOST_IP)"

  CREATE_RESPONSE="$(api_call "$(cat <<JSON
{
  "jsonrpc": "2.0",
  "method": "host.create",
  "params": {
    "host": "$HOST_NAME",
    "name": "$HOST_NAME",
    "interfaces": [
      {
        "type": 1,
        "main": 1,
        "useip": 1,
        "ip": "$HOST_IP",
        "dns": "",
        "port": "10050"
      }
    ],
    "groups": [
      {
        "groupid": "$GROUP_ID"
      }
    ],
    "templates": [
      {
        "templateid": "$TEMPLATE_ID"
      }
    ]
  },
  "auth": "$AUTH_TOKEN",
  "id": 11
}
JSON
)")"

  CREATED_ID="$(echo "$CREATE_RESPONSE" | python3 -c "import sys,json; data=json.load(sys.stdin); print(data.get('result', {}).get('hostids', [''])[0] if data.get('result') else '')")"

  if [ -z "$CREATED_ID" ]; then
    echo "[Zabbix API] ERREUR: création échouée pour $HOST_NAME"
    echo "$CREATE_RESPONSE"
    exit 1
  fi

  echo "[Zabbix API] Host créé: $HOST_NAME hostid=$CREATED_ID"

done

echo "[Zabbix API] Création automatique des hosts terminée."
`;

  runSsh(zabbixTarget, script, "création automatique des hosts dans Zabbix");
}

export function patchLiveZabbixAgents(outputRoot: string): void {
  const sshAccess = readSshAccess(outputRoot);
  const zabbixTarget = sshAccess["zabbix-1"];

  if (!zabbixTarget) {
    console.log("[Zabbix agent] Aucun serveur Zabbix trouvé, skip agents.");
    return;
  }

  const zabbixIp = getInternalIp(zabbixTarget, "zabbix-1");

  console.log(`[Zabbix agent] Serveur Zabbix détecté: ${zabbixIp}`);

  const hostsToCreate: ZabbixHost[] = [
    {
      name: "zabbix-1",
      ip: zabbixIp
    }
  ];

  for (const vmName of AGENT_TARGETS) {
    const target = sshAccess[vmName];

    if (!target) {
      console.log(`[Zabbix agent] VM absente, skip: ${vmName}`);
      continue;
    }

    const vmIp = getInternalIp(target, vmName);

    hostsToCreate.push({
      name: vmName,
      ip: vmIp
    });

    const installScript = `
set -euo pipefail

ZABBIX_SERVER="${zabbixIp}"
HOSTNAME="${vmName}"

echo "[Zabbix agent] Installation agent2 sur ${vmName}"
echo "[Zabbix agent] IP agent: ${vmIp}"
echo "[Zabbix agent] Serveur Zabbix: $ZABBIX_SERVER"

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y netcat-openbsd >/dev/null 2>&1 || true

if ! command -v zabbix_agent2 >/dev/null 2>&1; then
  echo "[Zabbix agent] zabbix-agent2 absent, tentative installation"

  sudo apt-get update -y || true

  if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing zabbix-agent2 netcat-openbsd; then
    echo "[Zabbix agent] ERREUR: impossible d'installer zabbix-agent2 sur ${vmName}"
    echo "[Zabbix agent] Diagnostic réseau/DNS"
    ip route || true
    cat /etc/resolv.conf || true
    getent hosts deb.debian.org || true
    ping -c 2 "$ZABBIX_SERVER" || true
    exit 1
  fi
else
  echo "[Zabbix agent] zabbix-agent2 déjà présent sur ${vmName}, pas de téléchargement"
fi

CONF="/etc/zabbix/zabbix_agent2.conf"

sudo cp "$CONF" "$CONF.bak.$(date +%s)" || true

sudo sed -i "s/^Server=.*/Server=$ZABBIX_SERVER/" "$CONF"
sudo sed -i "s/^ServerActive=.*/ServerActive=$ZABBIX_SERVER/" "$CONF"
sudo sed -i "s/^Hostname=.*/Hostname=$HOSTNAME/" "$CONF"

grep -q "^Server=$ZABBIX_SERVER" "$CONF" || echo "Server=$ZABBIX_SERVER" | sudo tee -a "$CONF" >/dev/null
grep -q "^ServerActive=$ZABBIX_SERVER" "$CONF" || echo "ServerActive=$ZABBIX_SERVER" | sudo tee -a "$CONF" >/dev/null
grep -q "^Hostname=$HOSTNAME" "$CONF" || echo "Hostname=$HOSTNAME" | sudo tee -a "$CONF" >/dev/null

sudo systemctl daemon-reload
sudo systemctl enable zabbix-agent2
sudo systemctl restart zabbix-agent2

sleep 3

echo "[Zabbix agent] Validation service"

if ! sudo systemctl is-active --quiet zabbix-agent2; then
  echo "[Zabbix agent] ERREUR: zabbix-agent2 non actif sur ${vmName}"
  sudo systemctl status zabbix-agent2 --no-pager || true
  exit 1
fi

echo "[Zabbix agent] Ports locaux"
sudo ss -lntp | grep 10050 || true

echo "[Zabbix agent] Test vers serveur Zabbix TCP/10051"
timeout 5 nc -zv "$ZABBIX_SERVER" 10051 || true

echo "[Zabbix agent] Configuration finale"
grep -E "^(Server|ServerActive|Hostname)=" "$CONF"

echo "[Zabbix agent] OK sur ${vmName}"

exit 0
`;

    runSsh(target, installScript, `installation agent Zabbix sur ${vmName}`);
  }

  createHostsInZabbix(zabbixTarget, zabbixIp, hostsToCreate);

  console.log("\n[Zabbix agent] Installation des agents + création des hosts terminée.");
}