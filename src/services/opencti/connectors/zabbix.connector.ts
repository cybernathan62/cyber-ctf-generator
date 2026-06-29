import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

type EnvMap = Record<string, string>;

type SshAccessEntry = {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  identity_file: string;
};

type NetworkPlanHost = {
  id?: string;
  hostname?: string;
  role?: string;
  interfaces?: Array<{
    network_id?: string;
    ip?: string;
    gateway?: string | null;
  }>;
};

type NetworkPlan = {
  hosts?: NetworkPlanHost[];
  zone_definitions?: Array<{
    hosts?: NetworkPlanHost[];
    instances?: NetworkPlanHost[];
  }>;
};

const PROJECT_ROOT = process.cwd();
const SECRETS_DIR = path.join(PROJECT_ROOT, "secrets");
const CONNECTORS_SECRETS_DIR = path.join(SECRETS_DIR, "opencti-connectors");

const ZABBIX_CONNECTOR_NAME = "zabbix";
const ZABBIX_SERVICE_NAME = "opencti-connector-zabbix";
const ZABBIX_REMOTE_DIR = "/opt/opencti/custom-connectors/zabbix";
const ZABBIX_REMOTE_CONFIG = `${ZABBIX_REMOTE_DIR}/config.yml`;

const PYTHON_BIN_CANDIDATES = [
  "/opt/python/3.12.8/bin/python",
  "/usr/bin/python3",
  "/usr/local/bin/python3"
];

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

function runSsh(
  target: SshAccessEntry,
  script: string,
  label: string,
  timeoutMs = 900_000
): void {
  console.log(`\n[OpenCTI Zabbix Connector] ${label}`);

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
      `[OpenCTI Zabbix Connector] Erreur SSH ${label}: ${result.error.message}`
    );
  }

  if (result.status !== 0) {
    throw new Error(`[OpenCTI Zabbix Connector] Échec ${label} code=${result.status}`);
  }
}

function uploadFile(
  target: SshAccessEntry,
  localPath: string,
  remotePath: string,
  mode = "0600"
): void {
  if (!fs.existsSync(localPath)) {
    throw new Error(`[OpenCTI Zabbix Connector] Fichier local introuvable: ${localPath}`);
  }

  const remoteTmp = `/tmp/${path.basename(localPath)}-${Date.now()}`;
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
    throw new Error(`[OpenCTI Zabbix Connector] Erreur SCP: ${scpResult.error.message}`);
  }

  if (scpResult.status !== 0) {
    throw new Error(`[OpenCTI Zabbix Connector] Upload échoué: ${localPath}`);
  }

  runSsh(
    target,
    [
      `sudo mkdir -p ${shQuote(remoteDir)}`,
      `sudo mv ${shQuote(remoteTmp)} ${shQuote(remotePath)}`,
      `sudo chown -R opencti:opencti ${shQuote(remoteDir)}`,
      `sudo chmod ${mode} ${shQuote(remotePath)}`
    ].join(" && "),
    `Upload ${path.basename(remotePath)}`,
    300_000
  );
}

function readJsonIfExists<T>(filePath: string): T | null {
  if (!fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
}

function getNetworkPlanHosts(plan: NetworkPlan): NetworkPlanHost[] {
  const hosts: NetworkPlanHost[] = [];

  if (Array.isArray(plan.hosts)) hosts.push(...plan.hosts);

  for (const zone of plan.zone_definitions ?? []) {
    if (Array.isArray(zone.hosts)) hosts.push(...zone.hosts);
    if (Array.isArray(zone.instances)) hosts.push(...zone.instances);
  }

  return hosts;
}

function getPrimaryIp(host?: NetworkPlanHost): string | null {
  if (!host) return null;

  const iface = (host.interfaces ?? []).find(
    (item) => item.ip && item.network_id !== "edge-wan"
  );

  return iface?.ip ?? null;
}

function resolveZabbixUrl(env: EnvMap): string {
  if (env.ZABBIX_URL) return env.ZABBIX_URL;
  if (env.ZABBIX_API_URL) return env.ZABBIX_API_URL;

  const candidates = [
    path.join(PROJECT_ROOT, "outputs", "network-plan.json"),
    path.join(PROJECT_ROOT, "outputs", "generated-lab", "network-plan.json")
  ];

  for (const candidate of candidates) {
    const plan = readJsonIfExists<NetworkPlan>(candidate);
    if (!plan) continue;

    const zabbixHost = getNetworkPlanHosts(plan).find((host) => {
      const id = host.id ?? host.hostname ?? "";
      return id === "zabbix-1" || host.role === "zabbix_server";
    });

    const zabbixIp = getPrimaryIp(zabbixHost);
    if (zabbixIp) return `http://${zabbixIp}`;
  }

  return "http://zabbix-1";
}

function normalizeOpenCtiUrl(env: EnvMap): string {
  return env.OPENCTI_URL || "http://127.0.0.1:8080";
}

function buildZabbixConfig(env: EnvMap): string {
  const connectorId = env.ZABBIX_CONNECTOR_ID || randomUUID();
  const zabbixUrl = resolveZabbixUrl(env);
  const zabbixUsername = env.ZABBIX_USERNAME || "Admin";
  const zabbixPassword = env.ZABBIX_PASSWORD || "zabbix";
  const zabbixToken = env.ZABBIX_API_TOKEN || "";

  return `opencti:
  url: ${yamlQuote(normalizeOpenCtiUrl(env))}
  token: ${yamlQuote(env.OPENCTI_TOKEN || "CHANGE_ME")}
  json_logging: true

connector:
  id: ${yamlQuote(connectorId)}
  type: 'EXTERNAL_IMPORT'
  name: 'Zabbix'
  scope: 'zabbix,host,ipv4-addr,infrastructure,incident'
  confidence_level: 70
  log_level: 'info'
  duration_period: ${yamlQuote(env.ZABBIX_INTERVAL || "PT5M")}
  queue_threshold: 500
  run_and_terminate: false

zabbix:
  url: ${yamlQuote(zabbixUrl)}
  api_token: ${yamlQuote(zabbixToken)}
  username: ${yamlQuote(zabbixUsername)}
  password: ${yamlQuote(zabbixPassword)}
  verify_ssl: ${env.ZABBIX_VERIFY_SSL === "true" ? "true" : "false"}
  import_hosts: ${env.ZABBIX_IMPORT_HOSTS === "false" ? "false" : "true"}
  import_problems: ${env.ZABBIX_IMPORT_PROBLEMS === "false" ? "false" : "true"}
  severity_min: ${Number(env.ZABBIX_SEVERITY_MIN || "3")}
  problem_age_hours: ${Number(env.ZABBIX_PROBLEM_AGE_HOURS || "24")}
`;
}

function buildZabbixMainPy(): string {
  return String.raw`#!/usr/bin/env python3
import datetime as dt
import json
import ssl
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

import requests
import yaml
from pycti import OpenCTIConnectorHelper

CONFIG_PATH = "config.yml"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stix_id(stix_type: str, value: str) -> str:
    return f"{stix_type}--{uuid.uuid5(uuid.NAMESPACE_URL, value)}"


def load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


class ZabbixClient:
    def __init__(self, config: Dict[str, Any], helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.base_url = str(config["url"]).rstrip("/")
        self.username = config.get("username") or "Admin"
        self.password = config.get("password") or "zabbix"
        self.api_token = config.get("api_token") or ""
        self.verify_ssl = bool(config.get("verify_ssl", False))
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.auth: Optional[str] = self.api_token or None
        self.endpoint = self._resolve_endpoint()

        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    def _candidate_endpoints(self) -> List[str]:
        if self.base_url.endswith("api_jsonrpc.php"):
            return [self.base_url]
        return [
            f"{self.base_url}/api_jsonrpc.php",
            f"{self.base_url}/zabbix/api_jsonrpc.php",
        ]

    def _rpc_at(self, endpoint: str, method: str, params: Dict[str, Any], auth: Any = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }

        if auth is not None:
            payload["auth"] = auth

        response = self.session.post(endpoint, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()

        if "error" in data:
            raise RuntimeError(json.dumps(data["error"], ensure_ascii=False))

        return data

    def _resolve_endpoint(self) -> str:
        last_error: Optional[Exception] = None

        for endpoint in self._candidate_endpoints():
            try:
                self._rpc_at(endpoint, "apiinfo.version", {}, None)
                self.helper.connector_logger.info(f"Zabbix API endpoint: {endpoint}")
                return endpoint
            except Exception as exc:  # noqa: BLE001
                last_error = exc

        raise RuntimeError(f"Unable to reach Zabbix API. Last error: {last_error}")

    def login(self) -> None:
        if self.api_token:
            self.auth = self.api_token
            return

        result = self._rpc_at(
            self.endpoint,
            "user.login",
            {"username": self.username, "password": self.password},
            None,
        )
        self.auth = result["result"]

    def rpc(self, method: str, params: Dict[str, Any]) -> Any:
        if not self.auth:
            self.login()

        return self._rpc_at(self.endpoint, method, params, self.auth)["result"]

    def get_hosts(self) -> List[Dict[str, Any]]:
        return self.rpc(
            "host.get",
            {
                "output": ["hostid", "host", "name", "status"],
                "selectInterfaces": ["interfaceid", "ip", "dns", "type", "main", "useip", "port"],
                "selectGroups": ["name"],
                "selectTags": ["tag", "value"],
            },
        )

    def get_recent_problems(self, severity_min: int, age_hours: int) -> List[Dict[str, Any]]:
        since = int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=age_hours)).timestamp())
        return self.rpc(
            "problem.get",
            {
                "output": "extend",
                "selectTags": "extend",
                "recent": True,
                "time_from": since,
                "severities": list(range(severity_min, 6)),
                "sortfield": ["eventid"],
                "sortorder": "DESC",
                "limit": 100,
            },
        )


def stix_ipv4(ip: str) -> Dict[str, Any]:
    return {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": stix_id("ipv4-addr", ip),
        "value": ip,
        "object_marking_refs": [],
    }


def stix_infrastructure(host: Dict[str, Any]) -> Dict[str, Any]:
    name = host.get("name") or host.get("host") or f"zabbix-host-{host.get('hostid')}"
    groups = [group.get("name") for group in host.get("groups", []) if group.get("name")]
    labels = ["zabbix", "monitored-host"] + [f"zabbix-group:{group}" for group in groups]

    return {
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": stix_id("infrastructure", f"zabbix-host:{host.get('hostid')}:{name}"),
        "created": now_iso(),
        "modified": now_iso(),
        "name": name,
        "description": f"Host imported from Zabbix. Zabbix hostid={host.get('hostid')}, technical host={host.get('host')}",
        "labels": labels,
        "external_references": [
            {
                "source_name": "zabbix",
                "external_id": str(host.get("hostid")),
                "description": "Zabbix host identifier",
            }
        ],
        "object_marking_refs": [],
    }


def stix_relationship(source_id: str, target_id: str, rel_type: str, seed: str) -> Dict[str, Any]:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": stix_id("relationship", seed),
        "created": now_iso(),
        "modified": now_iso(),
        "relationship_type": rel_type,
        "source_ref": source_id,
        "target_ref": target_id,
        "object_marking_refs": [],
    }


def stix_incident(problem: Dict[str, Any]) -> Dict[str, Any]:
    event_id = str(problem.get("eventid"))
    clock = int(problem.get("clock", "0") or 0)
    created = dt.datetime.fromtimestamp(clock, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") if clock else now_iso()
    severity = str(problem.get("severity", "unknown"))
    name = problem.get("name") or f"Zabbix problem {event_id}"

    return {
        "type": "incident",
        "spec_version": "2.1",
        "id": stix_id("incident", f"zabbix-problem:{event_id}"),
        "created": created,
        "modified": now_iso(),
        "name": f"Zabbix: {name}",
        "description": f"Zabbix problem imported from monitoring. Event ID={event_id}, severity={severity}, acknowledged={problem.get('acknowledged')}",
        "labels": ["zabbix", "monitoring", f"zabbix-severity:{severity}"],
        "external_references": [
            {
                "source_name": "zabbix",
                "external_id": event_id,
                "description": "Zabbix problem event identifier",
            }
        ],
        "object_marking_refs": [],
    }


def build_bundle(hosts: List[Dict[str, Any]], problems: List[Dict[str, Any]]) -> Dict[str, Any]:
    objects: List[Dict[str, Any]] = []
    seen: set[str] = set()

    def add(obj: Dict[str, Any]) -> None:
        obj_id = obj.get("id")
        if obj_id and obj_id in seen:
            return
        if obj_id:
            seen.add(obj_id)
        objects.append(obj)

    for host in hosts:
        infra = stix_infrastructure(host)
        add(infra)

        for iface in host.get("interfaces", []) or []:
            ip = str(iface.get("ip") or "").strip()
            if not ip or ip in {"127.0.0.1", "0.0.0.0"}:
                continue

            ip_obj = stix_ipv4(ip)
            add(ip_obj)
            add(stix_relationship(infra["id"], ip_obj["id"], "related-to", f"zabbix:{host.get('hostid')}:{ip}"))

    for problem in problems:
        add(stix_incident(problem))

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


class ZabbixConnector:
    def __init__(self) -> None:
        self.config = load_config()
        self.helper = OpenCTIConnectorHelper(self.config)
        self.zabbix_config = self.config.get("zabbix", {})
        self.client = ZabbixClient(self.zabbix_config, self.helper)

    def run_once(self) -> None:
        import_hosts = bool(self.zabbix_config.get("import_hosts", True))
        import_problems = bool(self.zabbix_config.get("import_problems", True))
        severity_min = int(self.zabbix_config.get("severity_min", 3))
        problem_age_hours = int(self.zabbix_config.get("problem_age_hours", 24))

        hosts = self.client.get_hosts() if import_hosts else []
        problems = self.client.get_recent_problems(severity_min, problem_age_hours) if import_problems else []

        bundle = build_bundle(hosts, problems)
        object_count = len(bundle.get("objects", []))

        self.helper.connector_logger.info(
            f"Built Zabbix STIX bundle with {object_count} objects: hosts={len(hosts)}, problems={len(problems)}"
        )

        if object_count == 0:
            return

        self.helper.send_stix2_bundle(json.dumps(bundle), update=True)

    def start(self) -> None:
        self.helper.connector_logger.info("Starting Zabbix OpenCTI connector")
        self.client.login()
        self.helper.schedule_iso(
            message_callback=self.run_once,
            duration_period=self.config.get("connector", {}).get("duration_period", "PT5M"),
        )


if __name__ == "__main__":
    try:
        ZabbixConnector().start()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        print(f"[zabbix-connector] fatal: {exc}", file=sys.stderr)
        raise
`;
}

function buildRequirementsTxt(): string {
  return [
    "pycti",
    "requests",
    "PyYAML",
    "python-dateutil",
    "stix2",
    ""
  ].join("\n");
}

function writeLocalConnectorFiles(env: EnvMap): {
  configPath: string;
  mainPyPath: string;
  requirementsPath: string;
} {
  fs.mkdirSync(CONNECTORS_SECRETS_DIR, { recursive: true });

  const connectorDir = path.join(CONNECTORS_SECRETS_DIR, ZABBIX_CONNECTOR_NAME);
  fs.mkdirSync(connectorDir, { recursive: true });

  const configPath = path.join(connectorDir, "config.yml");
  const mainPyPath = path.join(connectorDir, "main.py");
  const requirementsPath = path.join(connectorDir, "requirements.txt");

  fs.writeFileSync(configPath, buildZabbixConfig(env), {
    encoding: "utf-8",
    mode: 0o600
  });

  fs.writeFileSync(mainPyPath, buildZabbixMainPy(), {
    encoding: "utf-8",
    mode: 0o600
  });

  fs.writeFileSync(requirementsPath, buildRequirementsTxt(), {
    encoding: "utf-8",
    mode: 0o600
  });

  return { configPath, mainPyPath, requirementsPath };
}

function assertRequiredEnv(env: EnvMap): void {
  if (!env.OPENCTI_TOKEN || env.OPENCTI_TOKEN === "CHANGE_ME") {
    throw new Error(
      "[OpenCTI Zabbix Connector] OPENCTI_TOKEN manquant dans secrets/opencti.env"
    );
  }
}

export function installZabbixConnector(target: SshAccessEntry, env: EnvMap): void {
  assertRequiredEnv(env);

  const files = writeLocalConnectorFiles(env);

  uploadFile(target, files.configPath, ZABBIX_REMOTE_CONFIG, "0600");
  uploadFile(target, files.mainPyPath, `${ZABBIX_REMOTE_DIR}/main.py`, "0750");
  uploadFile(target, files.requirementsPath, `${ZABBIX_REMOTE_DIR}/requirements.txt`, "0644");

  runSsh(
    target,
    `set -e
PYTHON_BIN=""
for candidate in ${PYTHON_BIN_CANDIDATES.map(shQuote).join(" ")}; do
  if [ -x "$candidate" ]; then
    PYTHON_BIN="$candidate"
    break
  fi
done

if [ -z "$PYTHON_BIN" ]; then
  echo "[ERROR] Aucun Python compatible trouvé. Candidats: ${PYTHON_BIN_CANDIDATES.join(" ")}"
  exit 1
fi

sudo mkdir -p ${shQuote(ZABBIX_REMOTE_DIR)}
sudo chown -R opencti:opencti ${shQuote(ZABBIX_REMOTE_DIR)}

sudo -u opencti bash -lc "
cd ${ZABBIX_REMOTE_DIR}
rm -rf .venv
$PYTHON_BIN -m venv .venv
. .venv/bin/activate
python --version
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
"

sudo tee /etc/systemd/system/${ZABBIX_SERVICE_NAME}.service >/dev/null <<SERVICE
[Unit]
Description=OpenCTI Zabbix Connector
After=network-online.target opencti.service opencti-worker.service rabbitmq-server.service
Wants=network-online.target opencti-worker.service

[Service]
User=opencti
Group=opencti
WorkingDirectory=${ZABBIX_REMOTE_DIR}
Environment=PATH=${ZABBIX_REMOTE_DIR}/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=${ZABBIX_REMOTE_DIR}/.venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable ${ZABBIX_SERVICE_NAME}
sudo systemctl restart ${ZABBIX_SERVICE_NAME}
sleep 8
sudo systemctl status ${ZABBIX_SERVICE_NAME} --no-pager -l || true
sudo journalctl -u ${ZABBIX_SERVICE_NAME} -n 120 --no-pager || true
systemctl is-active --quiet ${ZABBIX_SERVICE_NAME}
`,
    "Installation connecteur Zabbix",
    1_800_000
  );
}
