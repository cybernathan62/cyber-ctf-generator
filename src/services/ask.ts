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

function hasRole(
  roles: RequestedRole[],
  role: RoleType,
  zone?: ZoneType
): boolean {
  return roles.some((r) => r.role === role && (!zone || r.zone === zone));
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

function pushRoleOnce(
  roles: RequestedRole[],
  role: RoleType,
  variant: RoleVariant,
  zone: ZoneType,
  count = 1,
  nodeCount = 1
): void {
  if (hasRole(roles, role, zone)) return;
  pushRole(roles, role, variant, zone, count, nodeCount);
}

function ensureEdgeFirewall(roles: RequestedRole[]): void {
  pushRoleOnce(roles, "edge_firewall", "simple", "edge");
}

function ensureSocFirewall(roles: RequestedRole[]): void {
  pushRoleOnce(roles, "internal_firewall", "simple", "soc");
}

function ensureDataFirewall(roles: RequestedRole[]): void {
  pushRoleOnce(roles, "internal_firewall", "simple", "data");
}

function detectRolesFromPrompt(input: string): RequestedRole[] {
  const text = ` ${input.toLowerCase()} `;
  const roles: RequestedRole[] = [];

  if (hasAny(text, ["firewall", "pfsense", "edge", "pfsense edge"])) {
    ensureEdgeFirewall(roles);
  }

  if (
    hasAny(text, [
      "pfsense interne soc",
      "firewall interne soc",
      "pare-feu interne soc",
      "pfsense soc",
      "firewall soc"
    ])
  ) {
    ensureSocFirewall(roles);
  }

  if (
    hasAny(text, [
      "pfsense interne data",
      "firewall interne data",
      "pare-feu interne data",
      "pfsense data",
      "firewall data"
    ])
  ) {
    ensureDataFirewall(roles);
  }

  if (text.includes("bastion")) {
    pushRoleOnce(roles, "bastion", "simple", "management");
  }

  if (hasAny(text, ["dmz", "reverse proxy", "reverse_proxy", "proxy", "web"])) {
    pushRoleOnce(roles, "reverse_proxy", "simple", "dmz");
  }

  if (
    hasAny(text, [
      " db ",
      "database",
      "base de données",
      "base de donnees",
      "mariadb",
      "mysql"
    ])
  ) {
    ensureDataFirewall(roles);
    pushRoleOnce(roles, "db_server", "simple", "data");
  }

  if (text.includes("wazuh")) {
    ensureSocFirewall(roles);
    pushRoleOnce(roles, "wazuh_server", "simple", "soc");
  }

  if (text.includes("zabbix")) {
    ensureSocFirewall(roles);
    pushRoleOnce(roles, "zabbix_server", "simple", "soc");
  }

  if (
    hasAny(text, [
      "opencti",
      "open_cti",
      "open-cti",
      "open cti",
      "cti",
      "threat intelligence",
      "cyber threat intelligence"
    ])
  ) {
    ensureSocFirewall(roles);
    pushRoleOnce(roles, "opencti_server", "simple", "soc");
  }

  if (hasAny(text, ["soc-ai", "soc ai", "agent ia", "ia soc", "ai soc"])) {
    ensureSocFirewall(roles);
    pushRoleOnce(roles, "soc_ai_agent", "simple", "soc");
  }

  if (
    hasAny(text, [
      "suricata",
      "ids",
      "ids sensor",
      "sonde ids",
      "sonde suricata"
    ])
  ) {
    ensureSocFirewall(roles);
    pushRoleOnce(roles, "ids_sensor", "simple", "soc");
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