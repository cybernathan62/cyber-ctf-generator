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

function runSsh(target: SshAccessEntry, script: string, label: string): void {
  console.log(`\n[Suricata patch] ${label}`);

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
    throw new Error(`[Suricata patch] ${label} a échoué avec le code ${result.status}`);
  }
}

function readSshAccess(outputRoot: string): SshAccessMap {
  const filePath = path.join(outputRoot, "ssh-access.local.json");

  if (!fs.existsSync(filePath)) {
    throw new Error(`[Suricata patch] Fichier introuvable: ${filePath}`);
  }

  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as SshAccessMap;
}

export function patchLiveSuricataSensor(outputRoot: string): void {
  const sshAccess = readSshAccess(outputRoot);
  const target = sshAccess["ids-sensor-1-1"];

  if (!target) {
    console.log("[Suricata patch] Aucun ids-sensor-1-1 trouvé, skip.");
    return;
  }

  const installScript = `
set -euo pipefail

echo "[Suricata] Installation..."

sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \\
  suricata \\
  suricata-update \\
  jq \\
  netcat-openbsd \\
  tcpdump \\
  dnsutils \\
  python3

echo "[Suricata] Détection interface IDS..."

IFACE="$(ip -o -4 addr show scope global | awk '{print $2, $4}' | awk '$2 !~ /^10\\.0\\.2\\./ && $2 !~ /^127\\./ {print $1; exit}' || true)"

if [ -z "$IFACE" ]; then
  IFACE="$(ip route | awk '/default/ {print $5; exit}')"
fi

if [ -z "$IFACE" ]; then
  echo "[Suricata] ERREUR: interface introuvable"
  ip -br a || true
  exit 1
fi

echo "[Suricata] Interface utilisée: $IFACE"

echo "[Suricata] Préparation des répertoires..."

sudo mkdir -p /var/log/suricata
sudo mkdir -p /var/lib/suricata/rules
sudo mkdir -p /etc/suricata/rules

sudo chown -R root:adm /var/log/suricata || true
sudo chmod 750 /var/log/suricata || true

echo "[Suricata] Mise à jour des règles Emerging Threats..."

set +e
timeout 300 sudo suricata-update
SURICATA_UPDATE_CODE=$?
set -e

if [ "$SURICATA_UPDATE_CODE" -ne 0 ]; then
  echo "[Suricata] WARNING: suricata-update KO ou timeout, deuxième tentative courte..."
  set +e
  timeout 180 sudo suricata-update
  SURICATA_UPDATE_CODE=$?
  set -e
fi

if [ "$SURICATA_UPDATE_CODE" -ne 0 ]; then
  echo "[Suricata] WARNING: téléchargement des règles KO, création fichier fallback vide"
  sudo touch /var/lib/suricata/rules/suricata.rules
fi

if [ ! -f /var/lib/suricata/rules/suricata.rules ]; then
  echo "[Suricata] WARNING: suricata.rules absent après update, création fallback"
  sudo touch /var/lib/suricata/rules/suricata.rules
fi

echo "[Suricata] Ajout règle locale de validation DNS..."

sudo tee /var/lib/suricata/rules/local.rules >/dev/null <<'EOF'
alert dns any any -> any any (msg:"LOCAL TEST DNS example.com"; dns.query; content:"example.com"; nocase; sid:1000002; rev:1;)
EOF

sudo cp /var/lib/suricata/rules/local.rules /etc/suricata/rules/local.rules || true

echo "[Suricata] Configuration suricata.yaml..."

if [ -f /etc/suricata/suricata.yaml ]; then
  sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak.$(date +%Y%m%d%H%M%S)
fi

sudo python3 - <<'PY'
from pathlib import Path
import re

p = Path("/etc/suricata/suricata.yaml")
s = p.read_text()

s = re.sub(
    r'HOME_NET:\\s*"\\[[^"]+\\]"',
    'HOME_NET: "[10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12]"',
    s
)

s = re.sub(
    r'default-rule-path:\\s*.*',
    'default-rule-path: /var/lib/suricata/rules',
    s
)

if "rule-files:" not in s:
    s += "\\n\\nrule-files:\\n  - suricata.rules\\n  - local.rules\\n"
else:
    s = re.sub(r'\\n\\s*-\\s*local\\.rules\\s*', '\\n', s)
    s = re.sub(
        r'(rule-files:\\s*\\n(?:\\s*-\\s*[^\\n]+\\n)*)',
        lambda m: m.group(1) + "  - local.rules\\n" if "- local.rules" not in m.group(1) else m.group(1),
        s,
        count=1
    )

if "eve-log:" not in s:
    s += """

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - dns
        - http
        - tls
        - flow
"""
else:
    s = re.sub(r'(eve-log:\\s*\\n\\s*)enabled:\\s*no', r'\\1enabled: yes', s, count=1)

p.write_text(s)
PY

echo "[Suricata] Configuration /etc/default/suricata..."

if [ -f /etc/default/suricata ]; then
  sudo sed -i "s/^LISTENMODE=.*/LISTENMODE=af-packet/" /etc/default/suricata || true
  sudo sed -i "s/^IFACE=.*/IFACE=$IFACE/" /etc/default/suricata || true

  grep -q "^IFACE=" /etc/default/suricata || echo "IFACE=$IFACE" | sudo tee -a /etc/default/suricata >/dev/null
  grep -q "^LISTENMODE=" /etc/default/suricata || echo "LISTENMODE=af-packet" | sudo tee -a /etc/default/suricata >/dev/null
fi

echo "[Suricata] Correction service systemd..."

SERVICE_FILE="/lib/systemd/system/suricata.service"

if [ -f "$SERVICE_FILE" ]; then
  sudo cp "$SERVICE_FILE" "$SERVICE_FILE.bak.$(date +%Y%m%d%H%M%S)"
  sudo sed -i "s|^ExecStart=.*|ExecStart=/usr/bin/suricata -D --af-packet=$IFACE -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid|" "$SERVICE_FILE"
else
  echo "[Suricata] ERREUR: service systemd introuvable: $SERVICE_FILE"
  exit 1
fi

echo "[Suricata] Test configuration..."

sudo suricata -T -c /etc/suricata/suricata.yaml || {
  echo "[Suricata] ERREUR: configuration Suricata invalide"
  exit 1
}

echo "[Suricata] Démarrage service..."

sudo systemctl stop suricata || true
sudo rm -f /run/suricata.pid
sudo rm -f /var/run/suricata-command.socket || true

sudo systemctl daemon-reload
sudo systemctl reset-failed suricata || true
sudo systemctl enable suricata || true

RESTART_TS="$(date '+%Y-%m-%d %H:%M:%S')"
sudo systemctl restart suricata

sleep 5

if ! sudo systemctl is-active --quiet suricata; then
  echo "[Suricata] ERREUR: service Suricata non actif"
  sudo systemctl --no-pager --full status suricata || true
  sudo journalctl -u suricata --since "$RESTART_TS" --no-pager || true
  exit 1
fi

echo "[Suricata] Service actif"

echo "[Suricata] Attente socket Suricata..."

SOCKET_OK=0

for i in $(seq 1 30); do
  if sudo test -S /var/run/suricata-command.socket; then
    echo "[Suricata] Socket présent, test suricatasc..."
    set +e
    sudo suricatasc -c uptime >/tmp/suricata_uptime.json 2>/tmp/suricata_uptime.err
    SURICATASC_CODE=$?
    set -e

    if [ "$SURICATASC_CODE" -eq 0 ]; then
      echo "[Suricata] Socket OK"
      cat /tmp/suricata_uptime.json || true
      SOCKET_OK=1
      break
    fi

    echo "[Suricata] Socket présent mais pas encore prêt, tentative $i/30..."
    cat /tmp/suricata_uptime.err || true
  else
    echo "[Suricata] Socket non présent, tentative $i/30..."
  fi

  sleep 2
done

if [ "$SOCKET_OK" -ne 1 ]; then
  echo "[Suricata] WARNING: socket Suricata non joignable après attente."
  echo "[Suricata] Le service est actif, le déploiement continue."
  sudo ls -l /var/run/suricata* || true
  sudo journalctl -u suricata --since "$RESTART_TS" --no-pager | tail -80 || true
fi

test -f /var/log/suricata/eve.json || sudo touch /var/log/suricata/eve.json
sudo chmod 640 /var/log/suricata/eve.json || true

echo "[Suricata] Connexion eve.json vers Wazuh agent..."

if [ -f /var/ossec/etc/ossec.conf ]; then
  sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.suricata.$(date +%Y%m%d%H%M%S)

  sudo python3 - <<'PY'
from pathlib import Path
import re

p = Path("/var/ossec/etc/ossec.conf")
s = p.read_text()

s = re.sub(
    r'\\s*<localfile>\\s*<log_format>json</log_format>\\s*<location>/var/log/suricata/eve\\.json</location>\\s*</localfile>\\s*',
    '\\n',
    s,
    flags=re.S
)

block = """
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
"""

idx = s.rfind("</ossec_config>")
if idx == -1:
    raise SystemExit("[Suricata] ERREUR: </ossec_config> introuvable dans ossec.conf")

s = s[:idx] + block + "\\n" + s[idx:]
p.write_text(s)
PY

  sudo systemctl restart wazuh-agent || {
    echo "[Suricata] ERREUR: restart wazuh-agent KO"
    sudo systemctl --no-pager --full status wazuh-agent || true
    sudo tail -n 120 /var/ossec/logs/ossec.log || true
    exit 1
  }

  sudo systemctl is-active --quiet wazuh-agent || {
    echo "[Suricata] ERREUR: wazuh-agent non actif"
    sudo systemctl --no-pager --full status wazuh-agent || true
    exit 1
  }

  echo "[Suricata] Wazuh agent actif"
  sudo tail -n 50 /var/ossec/logs/ossec.log | grep -iE "suricata|eve|localfile|error" || true
else
  echo "[Suricata] WARNING: Wazuh agent absent, skip intégration eve.json."
fi

echo "[Suricata] Validation DNS locale..."

set +e
dig example.com >/dev/null 2>&1 || getent hosts example.com >/dev/null 2>&1
sleep 8
sudo grep '"event_type":"alert"' /var/log/suricata/eve.json | tail -5
set -e

echo "[Suricata] Validation fichiers..."
sudo ls -l /var/log/suricata || true
sudo tail -n 5 /var/log/suricata/eve.json || true

echo "[Suricata] OK - service actif, règles présentes"
exit 0
`;

  runSsh(target, installScript, "installation et configuration Suricata");
}