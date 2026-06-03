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
    "ssh.exe",
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
      maxBuffer: 1024 * 1024 * 50
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
set -eu

echo "[Suricata] Installation..."

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \\
  suricata \\
  suricata-update \\
  jq

echo "[Suricata] Mise à jour des règles..."

sudo suricata-update || {
  echo "[Suricata] WARNING: suricata-update a échoué, création fallback rules file"
  sudo mkdir -p /var/lib/suricata/rules
  sudo touch /var/lib/suricata/rules/suricata.rules
}

echo "[Suricata] Activation eve.json..."

sudo mkdir -p /var/log/suricata
sudo chown -R suricata:suricata /var/log/suricata || true

if [ -f /etc/suricata/suricata.yaml ]; then
  sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak.$(date +%Y%m%d%H%M%S)
fi

sudo python3 - <<'PY'
from pathlib import Path

p = Path("/etc/suricata/suricata.yaml")
s = p.read_text()

s = s.replace('HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"', 'HOME_NET: "[10.0.0.0/8]"')

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

p.write_text(s)
PY

echo "[Suricata] Configuration interface..."

IFACE="$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^eth1$|^enp0s8$' | head -n1 || true)"

if [ -z "$IFACE" ]; then
  IFACE="$(ip route | awk '/default/ {print $5; exit}')"
fi

if [ -z "$IFACE" ]; then
  echo "[Suricata] ERREUR: interface introuvable"
  exit 1
fi

echo "[Suricata] Interface utilisée: $IFACE"

sudo sed -i "s/^LISTENMODE=.*/LISTENMODE=af-packet/" /etc/default/suricata || true
sudo sed -i "s/^IFACE=.*/IFACE=$IFACE/" /etc/default/suricata || true

sudo systemctl enable suricata
sudo systemctl restart suricata

sleep 5

sudo systemctl is-active --quiet suricata
sudo systemctl --no-pager --full status suricata

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

s = s.replace("</ossec_config>", block + "\\n</ossec_config>")

p.write_text(s)
PY

  sudo systemctl restart wazuh-agent
  sudo systemctl is-active --quiet wazuh-agent
  sudo tail -n 50 /var/ossec/logs/ossec.log | grep -iE "suricata|eve|localfile|error" || true
else
  echo "[Suricata] WARNING: Wazuh agent absent, skip intégration eve.json."
fi

echo "[Suricata] OK"
`;

  runSsh(target, installScript, "installation et configuration Suricata");
}