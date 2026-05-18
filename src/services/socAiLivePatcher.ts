import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { NetworkPlan } from "./type.js";

type WazuhCredentials = {
  wazuh_api_user?: string;
  wazuh_api_password?: string;
  api_user?: string;
  api_password?: string;
  username?: string;
  password?: string;
};

function run(
  command: string,
  args: string[],
  cwd: string,
  label: string,
  input?: string
): string {
  console.log(`\n[SOC-AI patch] ${label}`);
  console.log(`${command} ${args.join(" ")}`);

  const result = spawnSync(command, args, {
    cwd,
    input,
    encoding: "utf-8",
    shell: false,
    maxBuffer: 1024 * 1024 * 20
  });

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    throw new Error(`[SOC-AI patch] ${label} failed with code ${result.status}`);
  }

  return result.stdout ?? "";
}

function stripCidr(ip?: string): string | null {
  if (!ip) return null;
  return ip.split("/")[0];
}

function assertIpv4(value: string, label: string): void {
  const parts = value.split(".");
  const valid =
    parts.length === 4 &&
    parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);

  if (!valid) {
    throw new Error(`[SOC-AI patch] IPv4 invalide pour ${label}: ${value}`);
  }
}

function shellSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function readJsonIfExists<T>(file: string): T | null {
  if (!fs.existsSync(file)) return null;

  try {
    return JSON.parse(fs.readFileSync(file, "utf-8")) as T;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`[SOC-AI patch] JSON invalide dans ${file}: ${message}`);
  }
}

function findWazuhIp(networkPlan: NetworkPlan): string {
  const wazuh = networkPlan.hosts.find((h) => h.id === "wazuh-1");

  if (!wazuh) {
    throw new Error("[SOC-AI patch] wazuh-1 introuvable dans network-plan.json");
  }

  const socIface = wazuh.interfaces.find((i) => i.network_id === "soc-net");
  const ip = stripCidr(socIface?.ip);

  if (!ip) {
    throw new Error("[SOC-AI patch] IP SOC de wazuh-1 introuvable");
  }

  assertIpv4(ip, "wazuh-1.soc");

  return ip;
}

function findSocAi(networkPlan: NetworkPlan): void {
  const socAi = networkPlan.hosts.find((h) => h.id === "soc-ai-1");

  if (!socAi) {
    throw new Error("[SOC-AI patch] soc-ai-1 introuvable dans network-plan.json");
  }
}

function loadWazuhCredentials(outputRoot: string): {
  user: string;
  password: string;
} {
  const candidates = [
    path.join(outputRoot, "secrets", "wazuh-global-credentials.json"),
    path.join(outputRoot, "generated-lab", "secrets", "wazuh-1-credentials.json"),
    path.join(outputRoot, "wazuh-runtime", "wazuh-1-secrets.json"),
    path.join(outputRoot, "wazuh-runtime", "wazuh-1-credentials.json")
  ];

  for (const file of candidates) {
    const data = readJsonIfExists<WazuhCredentials>(file);
    if (!data) continue;

    const user = data.wazuh_api_user ?? data.api_user ?? data.username;
    const password = data.wazuh_api_password ?? data.api_password ?? data.password;

    if (user && password) {
      console.log("[SOC-AI patch] Credentials Wazuh chargés depuis un fichier runtime.");
      return { user, password };
    }
  }

  throw new Error(
    [
      "[SOC-AI patch] Aucun credential API Wazuh trouvé.",
      "Déploiement SOC-AI refusé pour éviter un agent actif mais inutilisable.",
      "Chemins testés:",
      ...candidates.map((file) => `- ${file}`)
    ].join("\n")
  );
}

function buildRemoteInstaller(wazuhIp: string, apiUser: string, apiPassword: string): string {
  const tlsVerify = process.env.SOC_AI_TLS_VERIFY ?? "false";

  return `#!/usr/bin/env bash
set -euo pipefail

WAZUH_IP=${shellSingleQuote(wazuhIp)}
WAZUH_API_USER_VALUE=${shellSingleQuote(apiUser)}
WAZUH_API_PASSWORD_VALUE=${shellSingleQuote(apiPassword)}
SOC_AI_TLS_VERIFY_VALUE=${shellSingleQuote(tlsVerify)}

echo "[SOC-AI] Installing packages..."
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip python3-requests curl jq

echo "[SOC-AI] Creating system user..."
if ! id soc-ai >/dev/null 2>&1; then
  sudo useradd --system --home /opt/soc-ai-agent --shell /usr/sbin/nologin soc-ai
fi

echo "[SOC-AI] Creating directories..."
sudo mkdir -p /opt/soc-ai-agent
sudo mkdir -p /etc/soc-ai-agent
sudo mkdir -p /var/log/soc-ai-agent
sudo chown -R root:root /etc/soc-ai-agent
sudo chown -R soc-ai:soc-ai /opt/soc-ai-agent
sudo chown -R soc-ai:soc-ai /var/log/soc-ai-agent
sudo chmod 750 /opt/soc-ai-agent
sudo chmod 750 /var/log/soc-ai-agent
sudo chmod 700 /etc/soc-ai-agent

echo "[SOC-AI] Writing config..."
sudo tee /etc/soc-ai-agent/config.env >/dev/null <<EOF
WAZUH_API_URL=https://$WAZUH_IP:55000
WAZUH_API_USER=$WAZUH_API_USER_VALUE
WAZUH_API_PASSWORD=$WAZUH_API_PASSWORD_VALUE
WAZUH_TLS_VERIFY=$SOC_AI_TLS_VERIFY_VALUE
SOC_AI_MODE=read_only
SOC_AI_MIN_LEVEL=7
SOC_AI_AUTO_REMEDIATE=false
EOF

sudo chmod 600 /etc/soc-ai-agent/config.env
sudo chown root:soc-ai /etc/soc-ai-agent/config.env

echo "[SOC-AI] Writing Python agent..."
sudo tee /opt/soc-ai-agent/main.py >/dev/null <<'PY'
#!/usr/bin/env python3
import base64
import json
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CONFIG_FILE = "/etc/soc-ai-agent/config.env"
LOG_FILE = Path("/var/log/soc-ai-agent/soc-ai-agent.log")
REPORT_FILE = Path("/var/log/soc-ai-agent/latest-report.json")

def load_env(path):
    env = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env

def log(message):
    ts = datetime.now(timezone.utc).isoformat()
    line = f"{ts} {message}"
    print(line, flush=True)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\\n")

def ssl_context(env):
    verify = env.get("WAZUH_TLS_VERIFY", "false").lower() == "true"
    if verify:
        return ssl.create_default_context()
    return ssl._create_unverified_context()

def request_json(method, url, env, headers=None, body=None):
    data = None

    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers=headers or {}
    )

    with urllib.request.urlopen(req, context=ssl_context(env), timeout=15) as resp:
        raw = resp.read().decode("utf-8", errors="replace")

        if not raw:
            return {}

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}

def get_token(env, api_url, user, password):
    basic = base64.b64encode(f"{user}:{password}".encode()).decode()

    headers = {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/json"
    }

    result = request_json(
        "POST",
        f"{api_url}/security/user/authenticate?raw=true",
        env,
        headers=headers
    )

    if isinstance(result, str):
        return result

    if "data" in result and isinstance(result["data"], dict):
        token = result["data"].get("token")
        if token:
            return token

    if "raw" in result:
        return result["raw"].strip().replace('"', "")

    raise RuntimeError("Unable to obtain Wazuh token")

def wazuh_get(env, api_url, token, endpoint):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    return request_json("GET", f"{api_url}{endpoint}", env, headers=headers)

def classify_agent_status(agents_payload):
    agents = (
        agents_payload
        .get("data", {})
        .get("affected_items", [])
    )

    total = len(agents)
    active = len([a for a in agents if a.get("status") == "active"])
    disconnected = len([a for a in agents if a.get("status") != "active"])

    severity = "low"

    if disconnected > 0:
        severity = "medium"

    if total > 0 and disconnected == total:
        severity = "high"

    return {
        "total_agents": total,
        "active_agents": active,
        "disconnected_agents": disconnected,
        "severity": severity,
        "agents": [
            {
                "id": a.get("id"),
                "name": a.get("name"),
                "ip": a.get("ip"),
                "status": a.get("status"),
                "os": a.get("os", {}).get("name")
            }
            for a in agents
        ]
    }

def main_once():
    env = load_env(CONFIG_FILE)

    api_url = env["WAZUH_API_URL"]
    user = env["WAZUH_API_USER"]
    password = env["WAZUH_API_PASSWORD"]
    mode = env.get("SOC_AI_MODE", "read_only")
    auto_remediate = env.get("SOC_AI_AUTO_REMEDIATE", "false").lower() == "true"

    if auto_remediate:
        raise RuntimeError("Auto-remediation is forbidden in V1")

    token = get_token(env, api_url, user, password)

    manager_status = wazuh_get(env, api_url, token, "/manager/status")
    agents = wazuh_get(env, api_url, token, "/agents?limit=100")

    agent_summary = classify_agent_status(agents)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "auto_remediate": auto_remediate,
        "wazuh_api": api_url,
        "manager_status": manager_status.get("data", {}),
        "agent_summary": agent_summary,
        "recommendations": []
    }

    if agent_summary["disconnected_agents"] > 0:
        report["recommendations"].append(
            "Investigate disconnected Wazuh agents before enabling remediation."
        )

    if agent_summary["active_agents"] > 0:
        report["recommendations"].append(
            "SOC-AI read-only baseline is healthy. Next step: add alert/indexer ingestion."
        )

    REPORT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")

    log(
        f"Report written: severity={agent_summary['severity']} "
        f"active={agent_summary['active_agents']} "
        f"disconnected={agent_summary['disconnected_agents']}"
    )

def main_loop():
    while True:
        try:
            main_once()
        except Exception as exc:
            log(f"ERROR: {exc}")

        time.sleep(60)

if __name__ == "__main__":
    main_loop()
PY

sudo chmod 750 /opt/soc-ai-agent/main.py
sudo chown soc-ai:soc-ai /opt/soc-ai-agent/main.py

echo "[SOC-AI] Writing systemd service..."
sudo tee /etc/systemd/system/soc-ai-agent.service >/dev/null <<'EOF'
[Unit]
Description=SOC AI Agent - Wazuh read-only analyst
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/soc-ai-agent/main.py
Restart=always
RestartSec=10
User=soc-ai
Group=soc-ai
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/soc-ai-agent
ReadOnlyPaths=/etc/soc-ai-agent /opt/soc-ai-agent

[Install]
WantedBy=multi-user.target
EOF

echo "[SOC-AI] Enabling service..."
sudo systemctl daemon-reload
sudo systemctl enable soc-ai-agent
sudo systemctl restart soc-ai-agent

sleep 5

echo "[SOC-AI] Service status:"
sudo systemctl --no-pager --full status soc-ai-agent || true

echo "[SOC-AI] Last logs:"
sudo journalctl -u soc-ai-agent --no-pager -n 30 || true
`;
}

export function patchLiveSocAiAgent(outputRoot: string): void {
  const generatedLabDir = path.join(outputRoot, "generated-lab");
  const networkPlanFile = path.join(outputRoot, "network-plan.json");

  if (!fs.existsSync(generatedLabDir)) {
    throw new Error(`[SOC-AI patch] generated-lab introuvable: ${generatedLabDir}`);
  }

  if (!fs.existsSync(networkPlanFile)) {
    throw new Error(`[SOC-AI patch] network-plan.json introuvable: ${networkPlanFile}`);
  }

  const networkPlan = JSON.parse(
    fs.readFileSync(networkPlanFile, "utf-8")
  ) as NetworkPlan;

  findSocAi(networkPlan);

  const wazuhIp = findWazuhIp(networkPlan);
  const credentials = loadWazuhCredentials(outputRoot);

  console.log(`[SOC-AI patch] Wazuh API cible: https://${wazuhIp}:55000`);
  console.log("[SOC-AI patch] Credentials API chargés.");
  console.log("[SOC-AI patch] Mode: read_only");

  const command = process.platform === "win32" ? "vagrant.exe" : "vagrant";

  const installer = buildRemoteInstaller(
    wazuhIp,
    credentials.user,
    credentials.password
  );

  run(
    command,
    ["ssh", "soc-ai-1", "-c", "sudo bash -s"],
    generatedLabDir,
    "install soc-ai-agent on soc-ai-1",
    installer
  );

  console.log("\n[SOC-AI patch] Installation terminée.");
}