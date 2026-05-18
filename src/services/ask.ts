import * as fs from "node:fs";
import * as path from "node:path";
import type {
  LabDefinition,
  RequestedRole,
  RoleType,
  RoleVariant,
  ZoneType
} from "./type.js";

function validatePrompt(input: string): void {
  if (input.length > 500) {
    throw new Error("[ask] Prompt trop long.");
  }

  if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(input)) {
    throw new Error("[ask] Prompt contient des caractères de contrôle interdits.");
  }
}

function hasAny(text: string, values: string[]): boolean {
  return values.some((value) => text.includes(value));
}

function pushRole(
  roles: RequestedRole[],
  role: RoleType,
  variant: RoleVariant,
  zone: ZoneType,
  count = 1,
  nodeCount = 1
): void {
  roles.push({
    role,
    variant,
    zone,
    count,
    node_count: nodeCount
  });
}

function detectRolesFromPrompt(input: string): RequestedRole[] {
  const text = input.toLowerCase();
  const roles: RequestedRole[] = [];

  if (hasAny(text, ["firewall", "pfsense", "edge", "pfsense edge"])) {
    pushRole(roles, "edge_firewall", "simple", "edge");
  }

  if (text.includes("bastion")) {
    pushRole(roles, "bastion", "simple", "management");
  }

  if (hasAny(text, ["dmz", "reverse proxy", "reverse_proxy", "proxy", "web"])) {
    pushRole(roles, "reverse_proxy", "simple", "dmz");
  }

  if (hasAny(text, [" db ", "database", "base de données", "base de donnees"])) {
    pushRole(roles, "db_server", "simple", "data");
  }

  if (text.includes("wazuh")) {
    pushRole(roles, "internal_firewall", "simple", "soc");
    pushRole(roles, "wazuh_server", "simple", "soc");
  }

  if (text.includes("zabbix")) {
    pushRole(roles, "zabbix_server", "simple", "soc");
  }

  if (hasAny(text, ["soc-ai", "soc ai", "agent ia", "ia soc", "ai soc"])) {
    pushRole(roles, "soc_ai_agent", "simple", "soc");
  }

  return roles;
}

function writeJsonFile(filePath: string, data: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });

  const tmpPath = `${filePath}.tmp`;

  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), {
    encoding: "utf-8",
    mode: 0o600
  });

  fs.renameSync(tmpPath, filePath);
}

function main(): void {
  const userPrompt = process.argv.slice(2).join(" ").trim();

  if (!userPrompt) {
    throw new Error(
      'Aucune demande fournie. Exemple: npm run ask -- "je veux une infra avec un pfsense edge, un bastion et un wazuh"'
    );
  }

  validatePrompt(userPrompt);

  const required_roles = detectRolesFromPrompt(userPrompt);

  if (required_roles.length === 0) {
    throw new Error("Aucun rôle reconnu dans la demande.");
  }

  const outputDir = path.resolve(process.cwd(), "outputs");
  const outputFile = path.join(outputDir, "lab-definition.json");

  const definition: LabDefinition = {
    name: "prompt-generated-lab",
    required_roles,
    instances: []
  };

  writeJsonFile(outputFile, definition);

  console.log("Lab definition généré :", outputFile);
  console.log(JSON.stringify(definition, null, 2));
}

main();