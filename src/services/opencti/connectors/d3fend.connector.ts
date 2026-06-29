import { spawnSync } from "node:child_process";
import * as path from "node:path";

import type { EnvMap } from "./cve.connector.js";

type SshAccessEntry = {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  identity_file: string;
  access_method?: string;
};

const D3FEND_REMOTE_DIR = "/opt/opencti/connectors/d3fend";
const D3FEND_SCRIPT_PATH = `${D3FEND_REMOTE_DIR}/d3fend_importer.py`;
const D3FEND_ENV_PATH = `${D3FEND_REMOTE_DIR}/d3fend.env`;
const D3FEND_SERVICE_NAME = "opencti-connector-d3fend";
const D3FEND_TIMER_NAME = "opencti-connector-d3fend.timer";

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

function runSsh(
  target: SshAccessEntry,
  script: string,
  label: string,
  timeoutMs = 900_000
): void {
  console.log(`\n[D3FEND Connector] ${label}`);

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
      maxBuffer: 1024 * 1024 * 100
    }
  );

  if (result.stdout) console.log(result.stdout.trim());
  if (result.stderr) console.warn(result.stderr.trim());

  if (result.error) {
    throw new Error(`[D3FEND Connector] Erreur SSH ${label}: ${result.error.message}`);
  }

  if (result.status !== 0) {
    throw new Error(`[D3FEND Connector] Échec ${label} code=${result.status}`);
  }
}

function envValue(env: EnvMap, key: string, fallback: string): string {
  const value = env[key];
  if (!value || !value.trim()) return fallback;
  return value.trim();
}

function boolEnv(env: EnvMap, key: string, fallback: boolean): boolean {
  const value = env[key];
  if (!value) return fallback;
  return ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
}

function buildEnvFile(env: EnvMap): string {
  const baseUrl = envValue(env, "D3FEND_BASE_URL", "https://d3fend.mitre.org").replace(/\/+$/g, "");
  const intervalHours = envValue(env, "D3FEND_INTERVAL", "168");
  const importMappings = boolEnv(env, "D3FEND_IMPORT_MAPPINGS", true);
  const createRelationships = boolEnv(env, "D3FEND_CREATE_RELATIONSHIPS", true);

  return [
    `OPENCTI_URL=${envValue(env, "OPENCTI_URL", "http://127.0.0.1:8080")}`,
    `OPENCTI_TOKEN=${envValue(env, "OPENCTI_TOKEN", "")}`,
    `D3FEND_BASE_URL=${baseUrl}`,
    `D3FEND_INTERVAL=${intervalHours}`,
    `D3FEND_IMPORT_MAPPINGS=${importMappings ? "true" : "false"}`,
    `D3FEND_CREATE_RELATIONSHIPS=${createRelationships ? "true" : "false"}`,
    ""
  ].join("\n");
}

function buildPythonImporter(): string {
  return String.raw`#!/usr/bin/env python3
import datetime
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE_DIR = Path("/opt/opencti/connectors/d3fend")
ENV_PATH = BASE_DIR / "d3fend.env"
CACHE_DIR = BASE_DIR / "cache"
LOG_PATH = BASE_DIR / "d3fend.log"
BUNDLE_PATH = CACHE_DIR / "d3fend-course-of-action-bundle.json"

TECHNIQUES_ENDPOINT = "/api/technique/all.json"
TACTICS_ENDPOINT = "/api/tactic/all.json"
MAPPINGS_ENDPOINT = "/api/ontology/inference/d3fend-full-mappings.json"


def utc_now():
    return datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")


def log(message):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(utc_now() + " " + message + "\n")


def read_env():
    env = {}
    if not ENV_PATH.exists():
        return env

    for raw_line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip("'").strip('"')

    return env


def http_json(url, timeout=60):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "ctf-lab-opencti-d3fend-connector/1.0",
        },
    )

    context = ssl.create_default_context()

    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return json.loads(response.read().decode("utf-8"))


def pick_list(payload):
    if isinstance(payload, list):
        return payload

    if isinstance(payload, dict):
        for key in ("results", "data", "techniques", "tactics", "items", "values"):
            value = payload.get(key)
            if isinstance(value, list):
                return value

        graph = payload.get("@graph")
        if isinstance(graph, list):
            return graph

    return []


def compact_text(value):
    if value is None:
        return ""

    if isinstance(value, str):
        return " ".join(value.split())

    if isinstance(value, list):
        return " ".join(compact_text(item) for item in value if item)

    return str(value)


def first_string(item, keys, fallback=""):
    for key in keys:
        value = item.get(key) if isinstance(item, dict) else None

        if isinstance(value, str) and value.strip():
            return value.strip()

        if isinstance(value, list):
            for sub_value in value:
                if isinstance(sub_value, str) and sub_value.strip():
                    return sub_value.strip()

    return fallback


def d3fend_id_from_item(item, index):
    raw = first_string(
        item,
        [
            "d3fend-id",
            "d3fend_id",
            "id",
            "@id",
            "identifier",
            "technique_id",
            "techniqueID",
        ],
        f"D3FEND-GENERATED-{index}",
    )

    if "#" in raw:
        raw = raw.rsplit("#", 1)[-1]

    if "/" in raw:
        raw = raw.rstrip("/").rsplit("/", 1)[-1]

    return raw


def stable_stix_id(stix_type, namespace, value):
    digest = hashlib.sha256((namespace + "::" + value).encode("utf-8")).hexdigest()
    return f"{stix_type}--{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def build_course_of_action(item, index, base_url):
    d3fend_id = d3fend_id_from_item(item, index)

    name = first_string(
        item,
        [
            "name",
            "label",
            "rdfs:label",
            "title",
            "prefLabel",
        ],
        d3fend_id,
    )

    description = compact_text(
        first_string(
            item,
            [
                "description",
                "definition",
                "rdfs:comment",
                "comment",
                "summary",
            ],
            "",
        )
    )

    if not description:
        description = f"MITRE D3FEND defensive technique imported for lab mapping: {name}"

    external_url = base_url.rstrip("/") + "/technique/" + d3fend_id + "/"

    return {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": stable_stix_id("course-of-action", "mitre-d3fend", d3fend_id),
        "created": "2024-01-01T00:00:00.000Z",
        "modified": utc_now().replace("Z", ".000Z") if "." not in utc_now() else utc_now(),
        "name": name,
        "description": description,
        "labels": ["mitre-d3fend", "defensive-capability"],
        "external_references": [
            {
                "source_name": "mitre-d3fend",
                "external_id": d3fend_id,
                "url": external_url,
            }
        ],
        "x_opencti_score": 50,
        "x_mitre_d3fend_id": d3fend_id,
    }


def graphql(opencti_url, token, query, variables=None, timeout=60):
    payload = {"query": query}
    if variables is not None:
        payload["variables"] = variables

    data = json.dumps(payload).encode("utf-8")

    endpoint = opencti_url.rstrip("/")
    if not endpoint.endswith("/graphql"):
        endpoint += "/graphql"

    request = urllib.request.Request(
        endpoint,
        data=data,
        method="POST",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def check_opencti(env):
    opencti_url = env.get("OPENCTI_URL", "http://127.0.0.1:8080")
    token = env.get("OPENCTI_TOKEN", "")

    if not token:
        log("WARN OPENCTI_TOKEN missing; generated STIX bundle only")
        return

    try:
        result = graphql(
            opencti_url,
            token,
            "query { about { version } }",
            timeout=30,
        )
        version = (((result or {}).get("data") or {}).get("about") or {}).get("version", "unknown")
        log("OK OpenCTI reachable version=" + str(version))
    except Exception as exc:
        log("WARN OpenCTI check failed: " + exc.__class__.__name__ + ": " + str(exc))


def main():
    env = read_env()

    base_url = env.get("D3FEND_BASE_URL", "https://d3fend.mitre.org").rstrip("/")
    import_mappings = env.get("D3FEND_IMPORT_MAPPINGS", "true").lower() in ("1", "true", "yes", "on")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    log("Starting MITRE D3FEND synchronization")

    techniques_payload = http_json(base_url + TECHNIQUES_ENDPOINT, timeout=90)
    techniques = pick_list(techniques_payload)

    (CACHE_DIR / "technique-all.json").write_text(
        json.dumps(techniques_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    tactics_payload = http_json(base_url + TACTICS_ENDPOINT, timeout=90)
    tactics = pick_list(tactics_payload)

    (CACHE_DIR / "tactic-all.json").write_text(
        json.dumps(tactics_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    mappings_count = 0
    if import_mappings:
        try:
            mappings_payload = http_json(base_url + MAPPINGS_ENDPOINT, timeout=120)
            mappings = pick_list(mappings_payload)
            mappings_count = len(mappings)

            (CACHE_DIR / "d3fend-full-mappings.json").write_text(
                json.dumps(mappings_payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except urllib.error.HTTPError as exc:
            log("WARN mapping endpoint unavailable: HTTP " + str(exc.code))
        except Exception as exc:
            log("WARN mapping fetch failed: " + exc.__class__.__name__ + ": " + str(exc))

    objects = []
    for index, item in enumerate(techniques):
        if isinstance(item, dict):
            objects.append(build_course_of_action(item, index, base_url))

    bundle = {
        "type": "bundle",
        "id": stable_stix_id("bundle", "mitre-d3fend", utc_now()),
        "objects": objects,
    }

    BUNDLE_PATH.write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    check_opencti(env)

    log(
        "OK D3FEND sync completed"
        + " techniques=" + str(len(techniques))
        + " tactics=" + str(len(tactics))
        + " mappings=" + str(mappings_count)
        + " stix_course_of_action=" + str(len(objects))
        + " bundle=" + str(BUNDLE_PATH)
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        log("ERROR " + exc.__class__.__name__ + ": " + str(exc))
        raise
`;
}

export function installD3fendConnector(target: SshAccessEntry, env: EnvMap): void {
  const enabled = boolEnv(env, "D3FEND_ENABLED", true);

  if (!enabled) {
    console.log("[D3FEND Connector] D3FEND_ENABLED=false, installation ignorée.");
    return;
  }

  const envFile = buildEnvFile(env);
  const importer = buildPythonImporter();

  runSsh(
    target,
    `
set -euo pipefail

sudo install -d -o opencti -g opencti -m 750 ${shQuote(D3FEND_REMOTE_DIR)}
sudo install -d -o opencti -g opencti -m 750 ${shQuote(`${D3FEND_REMOTE_DIR}/cache`)}

sudo tee ${shQuote(D3FEND_ENV_PATH)} >/dev/null <<'ENV'
${envFile}
ENV

sudo tee ${shQuote(D3FEND_SCRIPT_PATH)} >/dev/null <<'PY'
${importer}
PY

sudo chown opencti:opencti ${shQuote(D3FEND_ENV_PATH)} ${shQuote(D3FEND_SCRIPT_PATH)}
sudo chmod 600 ${shQuote(D3FEND_ENV_PATH)}
sudo chmod 750 ${shQuote(D3FEND_SCRIPT_PATH)}

sudo tee /etc/systemd/system/${D3FEND_SERVICE_NAME}.service >/dev/null <<SERVICE
[Unit]
Description=OpenCTI MITRE D3FEND experimental connector
After=network-online.target opencti.service opencti-worker.service
Wants=network-online.target opencti.service

[Service]
Type=oneshot
User=opencti
Group=opencti
WorkingDirectory=${D3FEND_REMOTE_DIR}
EnvironmentFile=${D3FEND_ENV_PATH}
ExecStart=/usr/bin/python3 ${D3FEND_SCRIPT_PATH}

[Install]
WantedBy=multi-user.target
SERVICE

sudo tee /etc/systemd/system/${D3FEND_TIMER_NAME} >/dev/null <<TIMER
[Unit]
Description=Run OpenCTI MITRE D3FEND experimental connector weekly

[Timer]
OnBootSec=5min
OnUnitActiveSec=7d
Persistent=true
Unit=${D3FEND_SERVICE_NAME}.service

[Install]
WantedBy=timers.target
TIMER

sudo systemctl daemon-reload
sudo systemctl enable ${D3FEND_TIMER_NAME}
sudo systemctl restart ${D3FEND_SERVICE_NAME}
sudo systemctl restart ${D3FEND_TIMER_NAME}

sleep 5

sudo systemctl status ${D3FEND_SERVICE_NAME} --no-pager -l || true
sudo tail -n 40 ${D3FEND_REMOTE_DIR}/d3fend.log || true
`,
    "Installation connecteur expérimental MITRE D3FEND",
    600_000
  );
}
