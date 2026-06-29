import { randomUUID } from "node:crypto";

export type EnvMap = Record<string, string>;

export const CVE_REMOTE_DIR = "/opt/opencti/connectors/external-import/cve";
export const CVE_REMOTE_CONFIG = `${CVE_REMOTE_DIR}/src/config.yml`;
export const CVE_SERVICE_NAME = "opencti-connector-cve";

function yamlQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function yamlBool(value: string): string {
  return value.toLowerCase() === "true" ? "true" : "false";
}

export function buildCveEnv(existing: EnvMap, nvdApiKey: string): EnvMap {
  const connectorId =
    existing.OPENCTI_CONNECTOR_ID ||
    existing.OPENCTI_CONNECTOR_CVE_ID ||
    randomUUID();

  return {
    ...existing,
    OPENCTI_URL: existing.OPENCTI_URL || "http://127.0.0.1:8080",
    OPENCTI_TOKEN:
      existing.OPENCTI_TOKEN ||
      existing.OPENCTI_ADMIN_TOKEN ||
      "CHANGE_ME",
    OPENCTI_CONNECTOR_ID: connectorId,
    NVD_API_KEY: nvdApiKey || "CHANGE_ME",
    CVE_INTERVAL: existing.CVE_INTERVAL || "24",
    CVE_MAX_DATE_RANGE: existing.CVE_MAX_DATE_RANGE || "1",
    CVE_MAINTAIN_DATA: existing.CVE_MAINTAIN_DATA || "true",
    CVE_PULL_HISTORY: existing.CVE_PULL_HISTORY || "false",
    CVE_IMPORT_SOFTWARE: existing.CVE_IMPORT_SOFTWARE || "false",
    CVE_MAX_CONCURRENCY: existing.CVE_MAX_CONCURRENCY || "5"
  };
}

export function buildCveConfig(env: EnvMap): string {
  return `opencti:
  url: ${yamlQuote(env.OPENCTI_URL)}
  token: ${yamlQuote(env.OPENCTI_TOKEN)}

connector:
  id: ${yamlQuote(env.OPENCTI_CONNECTOR_ID)}
  type: 'EXTERNAL_IMPORT'
  name: 'NVD CVE'
  scope: 'identity,vulnerability,software'
  confidence_level: 80
  log_level: 'info'
  run_and_terminate: false

cve:
  base_url: 'https://services.nvd.nist.gov/rest/json/cves'
  api_key: ${yamlQuote(env.NVD_API_KEY)}
  interval: ${env.CVE_INTERVAL}
  max_date_range: ${env.CVE_MAX_DATE_RANGE}
  maintain_data: ${yamlBool(env.CVE_MAINTAIN_DATA)}
  pull_history: ${yamlBool(env.CVE_PULL_HISTORY)}
  import_software: ${yamlBool(env.CVE_IMPORT_SOFTWARE)}
  cve_max_concurrency: ${env.CVE_MAX_CONCURRENCY}
`;
}