export type EnvMap = Record<string, string>;

export type SshAccessEntry = {
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  identity_file: string;
  access_method?: string;
};

export type RunSshFn = (entry: SshAccessEntry, command: string) => void;

export type InstallWazuhConnectorOptions = {
  runSsh: RunSshFn;
  wazuhSsh: SshAccessEntry;
  openctiUrl: string;
  openctiToken: string;
  minLevel?: number;
  timeoutSeconds?: number;
  restartWazuh?: boolean;
};

const WAZUH_ENV_DIR = "/etc/wazuh-opencti";
const WAZUH_ENV_FILE = `${WAZUH_ENV_DIR}/opencti.env`;

const WAZUH_WRAPPER_PATH = "/var/ossec/integrations/custom-opencti";
const WAZUH_SCRIPT_PATH = "/var/ossec/integrations/custom-opencti.py";
const WAZUH_OSSEC_CONF = "/var/ossec/etc/ossec.conf";

function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function assertNonEmpty(name: string, value: string): void {
  if (!value || !value.trim()) {
    throw new Error(`[Wazuh OpenCTI] ${name} est vide.`);
  }
}

function assertRemoteOpenCTIUrl(openctiUrl: string): void {
  assertNonEmpty("openctiUrl", openctiUrl);

  if (
    openctiUrl.includes("127.0.0.1") ||
    openctiUrl.includes("localhost")
  ) {
    throw new Error(
      [
        "[Wazuh OpenCTI] OPENCTI_URL ne doit pas être localhost.",
        "Depuis wazuh-1, 127.0.0.1 pointe vers wazuh-1, pas vers opencti-1.",
        "Utilise l'IP interne OpenCTI, par exemple: http://10.9.11.143:8080",
      ].join(" "),
    );
  }

  if (!/^https?:\/\//i.test(openctiUrl)) {
    throw new Error(
      `[Wazuh OpenCTI] URL invalide: ${openctiUrl}. Exemple attendu: http://10.9.11.143:8080`,
    );
  }
}

function writeRemoteFile(
  runSsh: RunSshFn,
  entry: SshAccessEntry,
  remotePath: string,
  content: string,
  owner: string,
  group: string,
  mode: string,
): void {
  const encoded = Buffer.from(content, "utf-8").toString("base64");

  runSsh(
    entry,
    `
set -euo pipefail

tmp_file="$(mktemp)"
printf '%s' ${shQuote(encoded)} | base64 -d > "$tmp_file"

sudo install -o ${shQuote(owner)} -g ${shQuote(group)} -m ${shQuote(mode)} "$tmp_file" ${shQuote(remotePath)}
rm -f "$tmp_file"
`.trim(),
  );
}

function buildEnvFile(options: {
  openctiUrl: string;
  openctiToken: string;
  timeoutSeconds: number;
}): string {
  return [
    `OPENCTI_URL=${options.openctiUrl}`,
    `OPENCTI_TOKEN=${options.openctiToken}`,
    `WAZUH_OPENCTI_TIMEOUT=${options.timeoutSeconds}`,
    "",
  ].join("\n");
}

function buildWrapper(): string {
  return `#!/bin/sh
exec /usr/bin/env python3 /var/ossec/integrations/custom-opencti.py "$@"
`;
}

function buildPythonIntegration(): string {
  return `#!/usr/bin/env python3
import datetime
import json
import os
import sys
import traceback
import urllib.error
import urllib.request

ENV_PATH = "/etc/wazuh-opencti/opencti.env"
LOG_PATH = "/var/ossec/logs/integrations.log"

NOISY_RULE_IDS = {
    "533",   # netstat/listened ports changed
    "5402",  # sudo command
    "5501",  # PAM session opened
    "5502",  # PAM session closed
}


def utc_now():
    return datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")


def log(message):
    line = utc_now() + " custom-opencti: " + message + "\\n"
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(line)


def read_env_file(path):
    env = {}

    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip("'").strip('"')

    return env


def graphql_endpoint(base_url):
    clean = base_url.rstrip("/")

    if clean.endswith("/graphql"):
        return clean

    return clean + "/graphql"


def graphql_query(opencti_url, token, query, timeout):
    payload = json.dumps({"query": query}).encode("utf-8")

    request = urllib.request.Request(
        graphql_endpoint(opencti_url),
        data=payload,
        method="POST",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8")

    return json.loads(body)


def load_alert(alert_path):
    with open(alert_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def get_nested(mapping, *keys):
    current = mapping

    for key in keys:
        if not isinstance(current, dict):
            return ""

        current = current.get(key)

    if current is None:
        return ""

    return str(current)


def extract_alert_summary(alert):
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}

    rule_id = str(rule.get("id", "unknown"))
    level = str(rule.get("level", "unknown"))
    description = str(rule.get("description", ""))

    agent_name = str(agent.get("name", "unknown"))

    srcip = (
        str(data.get("srcip") or "")
        or str(data.get("src_ip") or "")
        or str(alert.get("srcip") or "")
    )

    dstip = (
        str(data.get("dstip") or "")
        or str(data.get("dst_ip") or "")
        or str(alert.get("dstip") or "")
    )

    url = (
        str(data.get("url") or "")
        or str(data.get("request") or "")
        or str(data.get("http_request") or "")
    )

    domain = (
        str(data.get("domain") or "")
        or str(data.get("hostname") or "")
        or str(data.get("dns_query") or "")
    )

    file_hash = (
        str(data.get("sha256") or "")
        or str(data.get("md5") or "")
        or str(data.get("sha1") or "")
    )

    return {
        "rule_id": rule_id,
        "level": level,
        "description": description,
        "agent_name": agent_name,
        "srcip": srcip,
        "dstip": dstip,
        "url": url,
        "domain": domain,
        "file_hash": file_hash,
    }


def main():
    if len(sys.argv) < 2:
        log("ERROR missing alert file argument")
        return 0

    alert_path = sys.argv[1]

    try:
        env = read_env_file(ENV_PATH)

        opencti_url = env.get("OPENCTI_URL", "").strip()
        token = env.get("OPENCTI_TOKEN", "").strip()
        timeout = int(env.get("WAZUH_OPENCTI_TIMEOUT", "60"))

        if not opencti_url:
            log("ERROR OPENCTI_URL missing")
            return 0

        if not token:
            log("ERROR OPENCTI_TOKEN missing")
            return 0

        alert = load_alert(alert_path)
        summary = extract_alert_summary(alert)

        rule_id = summary["rule_id"]

        if rule_id in NOISY_RULE_IDS:
            log("SKIP noisy rule_id=" + rule_id)
            return 0

        result = graphql_query(
            opencti_url,
            token,
            "query { about { version } }",
            timeout,
        )

        version = get_nested(result, "data", "about", "version") or "unknown"

        log(
            "OK OpenCTI API reachable"
            + " version=" + version
            + " rule_id=" + summary["rule_id"]
            + " level=" + summary["level"]
            + " agent=" + summary["agent_name"]
            + " srcip=" + summary["srcip"]
            + " dstip=" + summary["dstip"]
            + " domain=" + summary["domain"]
            + " url=" + summary["url"]
            + " hash=" + summary["file_hash"]
            + " description=" + summary["description"][:180]
        )

        return 0

    except urllib.error.URLError as exc:
        log("ERROR OpenCTI connection failed: " + str(exc))
        return 0

    except TimeoutError as exc:
        log("ERROR OpenCTI timeout: " + str(exc))
        return 0

    except Exception as exc:
        log("ERROR " + exc.__class__.__name__ + ": " + str(exc))
        log("TRACE " + traceback.format_exc().replace("\\n", " | "))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
`;
}

function installOssecIntegrationBlock(
  runSsh: RunSshFn,
  entry: SshAccessEntry,
  minLevel: number,
): void {
  runSsh(
    entry,
    `
set -euo pipefail

sudo cp ${shQuote(WAZUH_OSSEC_CONF)} ${shQuote(`${WAZUH_OSSEC_CONF}.bak-opencti`)}

sudo python3 - <<'PY'
from pathlib import Path
import re

path = Path("/var/ossec/etc/ossec.conf")
content = path.read_text(encoding="utf-8")

level = "${minLevel}"

block = f"""
  <integration>
    <name>custom-opencti</name>
    <level>{level}</level>
    <alert_format>json</alert_format>
  </integration>
"""

pattern = r"\\n\\s*<integration>\\s*<name>custom-opencti</name>.*?</integration>"

if re.search(pattern, content, flags=re.S):
    content = re.sub(pattern, "\\n" + block.strip("\\n"), content, flags=re.S)
    print("[Wazuh OpenCTI] Bloc custom-opencti mis à jour.")
else:
    if "</ossec_config>" not in content:
        raise SystemExit("[Wazuh OpenCTI] Balise </ossec_config> introuvable.")

    content = content.replace("</ossec_config>", block + "\\n</ossec_config>")
    print("[Wazuh OpenCTI] Bloc custom-opencti ajouté.")

path.write_text(content, encoding="utf-8")
PY
`.trim(),
  );
}

export function installWazuhConnector(options: InstallWazuhConnectorOptions): void {
  const minLevel = options.minLevel ?? 10;
  const timeoutSeconds = options.timeoutSeconds ?? 60;
  const restartWazuh = options.restartWazuh ?? true;

  assertRemoteOpenCTIUrl(options.openctiUrl);
  assertNonEmpty("openctiToken", options.openctiToken);

  options.runSsh(
    options.wazuhSsh,
    `
set -euo pipefail

sudo test -d /var/ossec || {
  echo "[Wazuh OpenCTI] ERREUR: /var/ossec introuvable. wazuh-manager n'est probablement pas installé."
  exit 1
}

sudo test -f /var/ossec/etc/ossec.conf || {
  echo "[Wazuh OpenCTI] ERREUR: /var/ossec/etc/ossec.conf introuvable."
  exit 1
}

getent group wazuh >/dev/null || {
  echo "[Wazuh OpenCTI] ERREUR: groupe wazuh introuvable."
  exit 1
}

command -v python3 >/dev/null || {
  echo "[Wazuh OpenCTI] ERREUR: python3 introuvable."
  exit 1
}

sudo install -d -o root -g wazuh -m 750 ${shQuote(WAZUH_ENV_DIR)}
`.trim(),
  );

  writeRemoteFile(
    options.runSsh,
    options.wazuhSsh,
    WAZUH_ENV_FILE,
    buildEnvFile({
      openctiUrl: options.openctiUrl,
      openctiToken: options.openctiToken,
      timeoutSeconds,
    }),
    "root",
    "wazuh",
    "0640",
  );

  writeRemoteFile(
    options.runSsh,
    options.wazuhSsh,
    WAZUH_WRAPPER_PATH,
    buildWrapper(),
    "root",
    "wazuh",
    "0750",
  );

  writeRemoteFile(
    options.runSsh,
    options.wazuhSsh,
    WAZUH_SCRIPT_PATH,
    buildPythonIntegration(),
    "root",
    "wazuh",
    "0750",
  );

  installOssecIntegrationBlock(options.runSsh, options.wazuhSsh, minLevel);

  options.runSsh(
    options.wazuhSsh,
    `
set -euo pipefail

sudo chown root:wazuh ${shQuote(WAZUH_ENV_DIR)}
sudo chmod 750 ${shQuote(WAZUH_ENV_DIR)}

sudo chown root:wazuh ${shQuote(WAZUH_ENV_FILE)}
sudo chmod 640 ${shQuote(WAZUH_ENV_FILE)}

sudo chown root:wazuh ${shQuote(WAZUH_WRAPPER_PATH)} ${shQuote(WAZUH_SCRIPT_PATH)}
sudo chmod 750 ${shQuote(WAZUH_WRAPPER_PATH)} ${shQuote(WAZUH_SCRIPT_PATH)}

sudo grep -n -A6 -B2 "custom-opencti" ${shQuote(WAZUH_OSSEC_CONF)}
`.trim(),
  );

  if (restartWazuh) {
    options.runSsh(
      options.wazuhSsh,
      `
set -euo pipefail

sudo systemctl restart wazuh-manager
sleep 10
sudo systemctl status wazuh-manager --no-pager -l | sed -n '1,80p'
`.trim(),
    );
  }

  console.log("[Wazuh OpenCTI] Intégration Wazuh -> OpenCTI installée.");
}