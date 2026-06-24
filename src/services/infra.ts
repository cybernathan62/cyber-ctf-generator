import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { LabGeneratorService } from "./labGenerator.js";
import { generateNetworkPlanFromDefinition } from "./generateNetworkPlan.js";
import { generatePfSenseMinimalPlan } from "./generatePfsenseMinimalPlan.js";
import { patchLivePfSenseConfigs } from "./pfsenseLiveConfigPatcher.js";
import { patchLiveDebianConfigs } from "./debianLiveConfigPatcher.js";
import { patchLiveWazuhConfigs } from "./wazuhLiveConfigPatcher.production-mode.js";
import { patchLiveWazuhAgents } from "./wazuhAgentLivePatcher.js";
import { patchLiveSocAiAgent } from "./socAiLivePatcher.js";
import { patchLiveSuricataSensor } from "./suricataLivePatcher.js";
import { patchLiveMariaDB } from "./mariadbLivePatcher.js";
import { patchLiveZabbix } from "./zabbixLivePatcher.js";
import { patchLiveZabbixAgents } from "./zabbixAgentLivePatcher.js";
import { patchLiveZabbixPfSense } from "./zabbixPfsensePatcher.js";
import { patchLiveOpenCTI } from "./openctiLivePatcher.js";
import { validateLabWithPolicies } from "./policyEngine.js";
import {
  LabDefinition,
  RequestedRole,
  RoleType,
  RoleVariant,
  ZoneType
} from "./type.js";

function parseNumericCount(text: string, keyword: string): number | null {
  const regex = new RegExp(`(\\d+)\\s*${keyword}`, "i");
  const match = text.match(regex);
  return match ? parseInt(match[1], 10) : null;
}

function parseWordCount(text: string, keyword: string): number | null {
  if (text.includes(`trois ${keyword}`)) return 3;
  if (text.includes(`deux ${keyword}`)) return 2;
  if (text.includes(`un ${keyword}`)) return 1;
  if (text.includes(`une ${keyword}`)) return 1;
  return null;
}

function parseCount(text: string, ...keywords: string[]): number {
  for (const keyword of keywords) {
    const numeric = parseNumericCount(text, keyword);
    if (numeric !== null) return numeric;

    const word = parseWordCount(text, keyword);
    if (word !== null) return word;
  }

  return 1;
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

function hasAny(text: string, values: string[]): boolean {
  return values.some((value) => text.includes(value));
}

function roleExists(
  roles: RequestedRole[],
  role: RoleType,
  zone: ZoneType
): boolean {
  return roles.some((item) => item.role === role && item.zone === zone);
}

function pushRoleOnce(
  roles: RequestedRole[],
  role: RoleType,
  variant: RoleVariant,
  zone: ZoneType,
  count = 1,
  nodeCount = 1
): void {
  if (roleExists(roles, role, zone)) return;
  pushRole(roles, role, variant, zone, count, nodeCount);
}

function detectRolesFromPrompt(input: string): RequestedRole[] {
  const text = input.toLowerCase();
  const roles: RequestedRole[] = [];

  const wantsEdge = hasAny(text, [
    "pfsense edge",
    "firewall edge",
    "edge firewall",
    "firewall en entree",
    "firewall d'entree",
    "firewall en bordure",
    "edge"
  ]);

  const wantsAnyFirewall = hasAny(text, ["pfsense", "firewall"]);

  if (wantsEdge || wantsAnyFirewall) {
    pushRoleOnce(roles, "edge_firewall", "simple", "edge", 1, 1);
  }

  const hasSocService = hasAny(text, [
    "soc",
    "wazuh",
    "zabbix",
    "opencti",
    "open cti",
    "threat intelligence",
    "cti",
    "supervision",
    "suricata",
    "ids",
    "soc ai",
    "agent ia",
    "ia soc"
  ]);

  const hasDataService = hasAny(text, [
    " db ",
    "database",
    "base de données",
    "base de donnees",
    " une db",
    " un db"
  ]);

  const hasAdService = hasAny(text, [
    "active directory",
    "windows server",
    "ad server"
  ]);

  const wantsSocFirewall = hasAny(text, [
  "pfsense interne",
  "firewall interne",
  "pare-feu interne",
  "pfsense interne soc",
  "firewall interne soc",
  "firewall soc",
  "pfsense soc",
  "pfsense interne avec wazuh",
  "pfsense interne avec zabbix",
  "pfsense interne avec opencti",
  "pfsense interne avec open cti",
  "pfsense interne avec open_cti",
  "pfsense interne avec cti",
  "pfsense interne avec suricata",
  "pfsense interne avec supervision"
]);

  const wantsDataFirewall = hasAny(text, [
    "pfsense data",
    "pfsense db",
    "pfsense interne data",
    "pfsense interne db",
    "firewall data",
    "firewall db",
    "firewall database",
    "pfsense interne avec une db",
    "pfsense interne avec un db",
    "pfsense interne avec database",
    "pfsense interne avec une base",
    "pfsense interne avec une base de donnees",
    "pfsense interne avec une base de données"
  ]);

  const wantsAdFirewall = hasAny(text, [
    "pfsense ad",
    "firewall ad",
    "firewall interne ad",
    "pfsense interne avec ad",
    "pfsense interne avec active directory"
  ]);

  if (hasSocService && wantsSocFirewall) {
    pushRoleOnce(roles, "internal_firewall", "simple", "soc", 1, 1);
  }

  if (hasDataService && wantsDataFirewall) {
    pushRoleOnce(roles, "internal_firewall", "simple", "data", 1, 1);
  }

  if (hasAdService && wantsAdFirewall) {
    pushRoleOnce(roles, "internal_firewall", "simple", "ad", 1, 1);
  }

  if (text.includes("bastion")) {
    pushRoleOnce(roles, "bastion", "simple", "management", 1, 1);
  }

  if (hasAny(text, ["dmz", "reverse proxy", "reverse_proxy", "proxy", "web"])) {
    pushRoleOnce(roles, "reverse_proxy", "simple", "dmz", 1, 1);
  }

  if (hasDataService) {
    pushRoleOnce(roles, "db_server", "simple", "data", 1, 1);
  }

  if (text.includes("wazuh") || text.includes("supervision")) {
    pushRoleOnce(roles, "wazuh_server", "simple", "soc", 1, 1);
  }

  if (text.includes("zabbix")) {
    pushRoleOnce(roles, "zabbix_server", "simple", "soc", 1, 1);
  }

  if (
    hasAny(text, [
      "opencti",
      "open cti",
      "threat intelligence",
      "threat intel",
      "cti",
      "plateforme cti",
      "renseignement sur les menaces",
      "renseignement menace",
      "ioc"
    ])
  ) {
    pushRoleOnce(roles, "opencti_server", "simple", "soc", 1, 1);
  }

  if (hasAny(text, ["soc ai", "agent ia", "ia soc", "ai soc", "agent soc"])) {
    pushRoleOnce(roles, "soc_ai_agent", "simple", "soc", 1, 1);
  }

  if (hasAny(text, ["suricata", "ids", "ids sensor", "sonde ids", "sonde suricata", "nids"])) {
    pushRoleOnce(roles, "ids_sensor", "simple", "soc", 1, 1);
  }

  if (hasAdService) {
    pushRoleOnce(roles, "windows_server", "simple", "ad", 1, 1);
  }

  return roles;
}

function waitSeconds(seconds: number): void {
  console.log(`\nAttente ${seconds}s...\n`);

  const command = process.platform === "win32" ? "timeout.exe" : "sleep";
  const args =
    process.platform === "win32"
      ? ["/T", String(seconds), "/NOBREAK"]
      : [String(seconds)];

  const result = spawnSync(command, args, {
    stdio: "inherit",
    shell: false
  });

  if (result.error) {
    throw result.error;
  }
}

function vagrantExists(vmName: string, generatedLabDir: string): boolean {
  const command = process.platform === "win32" ? "vagrant.exe" : "vagrant";

  const result = spawnSync(command, ["status", vmName], {
    cwd: generatedLabDir,
    encoding: "utf-8",
    shell: false
  });

  return result.status === 0 && !result.stdout.includes("The machine with the name");
}

function waitForVmSsh(vmName: string, generatedLabDir: string, timeoutSeconds = 300): void {
  const command = process.platform === "win32" ? "vagrant.exe" : "vagrant";

  if (!vagrantExists(vmName, generatedLabDir)) {
    console.log(`[infra] VM absente, skip wait SSH: ${vmName}`);
    return;
  }

  const startedAt = Date.now();

  while ((Date.now() - startedAt) / 1000 < timeoutSeconds) {
    console.log(`[infra] Test SSH ${vmName}...`);

    const result = spawnSync(command, ["ssh", "-c", "echo ready", vmName], {
      cwd: generatedLabDir,
      encoding: "utf-8",
      shell: false,
      timeout: 30000
    });

    if (result.status === 0 && result.stdout.includes("ready")) {
      console.log(`[infra] SSH OK pour ${vmName}`);
      return;
    }

    if (result.stdout) console.warn(result.stdout.trim());
    if (result.stderr) console.warn(result.stderr.trim());

    waitSeconds(10);
  }

  throw new Error(`[infra] SSH non prêt pour ${vmName} après ${timeoutSeconds}s`);
}

function waitForDebianSsh(generatedLabDir: string): void {
  const debianVms = [
    "bastion-1",
    "reverse-proxy-1",
    "db-server-1",
    "db-server",
    "wazuh-1",
    "zabbix-1",
    "opencti-1",
    "soc-ai-1",
    "ids-sensor-1-1"
  ];

  for (const vmName of debianVms) {
    waitForVmSsh(vmName, generatedLabDir, 900);
  }
}

function writeJsonAtomic(filePath: string, data: unknown): void {
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
      'Exemple: npm run infra -- "je veux un pfsense edge avec une dmz, un bastion, wazuh, zabbix, une db et une sonde suricata"'
    );
  }

  if (userPrompt.length > 500) {
    throw new Error("[infra] Prompt trop long.");
  }

  const required_roles = detectRolesFromPrompt(userPrompt);

  if (required_roles.length === 0) {
    throw new Error("Aucun rôle reconnu.");
  }

  const outputRoot = path.resolve(process.cwd(), "outputs");
  const definitionFile = path.join(outputRoot, "lab-definition.json");
  const policyValidationFile = path.join(outputRoot, "policy-validation.json");
  const networkPlanFile = path.join(outputRoot, "network-plan.json");

  const generatedLabDir = path.join(outputRoot, "generated-lab");
  const pfSensePlanFile = path.join(outputRoot, "pfsense-plan.json");
  const patchedPfSenseDir = path.join(outputRoot, "pfsense-live-patched");
  const patchedDebianDir = path.join(outputRoot, "debian-live-patched");

  fs.mkdirSync(outputRoot, { recursive: true });

  const definition: LabDefinition = {
    name: "prompt-generated-lab",
    required_roles,
    instances: []
  };

  writeJsonAtomic(definitionFile, definition);

  console.log("Demande du prof :", userPrompt);
  console.log("Lab definition généré :", definitionFile);
  console.log(JSON.stringify(definition, null, 2));

  const policyResult = validateLabWithPolicies(definition, {
    projectRoot: process.cwd()
  });

  writeJsonAtomic(policyValidationFile, policyResult);

  if (!policyResult.allowed) {
    console.error("\n[Policy Engine] Lab refusé :");
    console.error(JSON.stringify(policyResult.violations, null, 2));
    throw new Error("Lab refusé par le Policy Engine.");
  }

  if (policyResult.warnings.length > 0) {
    console.warn("\n[Policy Engine] Warnings :");
    console.warn(JSON.stringify(policyResult.warnings, null, 2));
  }

  console.log("Validation policies générée :", policyValidationFile);

  generateNetworkPlanFromDefinition(definition, outputRoot);

  if (!fs.existsSync(networkPlanFile)) {
    throw new Error(`[infra] network-plan.json non généré: ${networkPlanFile}`);
  }

  console.log("Network plan généré :", networkPlanFile);

  generatePfSenseMinimalPlan(networkPlanFile, pfSensePlanFile);

  if (!fs.existsSync(pfSensePlanFile)) {
    throw new Error(`[infra] pfsense-plan.json non généré: ${pfSensePlanFile}`);
  }

  console.log("pfSense minimal plan généré :", pfSensePlanFile);

  const generator = new LabGeneratorService();

  const result = generator.generateLab({
    ...definition,
    outputDir: generatedLabDir
  });

  console.log("Résultat génération :", result);
  console.log("Vagrantfile généré dans :", generatedLabDir);

  console.log("\nLancement de 'vagrant up'...\n");

  const command = process.platform === "win32" ? "vagrant.exe" : "vagrant";

  const upResult = spawnSync(command, ["up"], {
    cwd: generatedLabDir,
    stdio: "inherit",
    shell: false,
    timeout: 60 * 60 * 1000
  });

  if (upResult.error) {
    throw upResult.error;
  }

  if (upResult.status !== 0) {
    throw new Error(`vagrant up a échoué avec le code ${upResult.status}`);
  }

  waitSeconds(30);

  patchLivePfSenseConfigs(
    generatedLabDir,
    networkPlanFile,
    pfSensePlanFile,
    patchedPfSenseDir
  );

  waitSeconds(30);

  waitForDebianSsh(generatedLabDir);

  patchLiveDebianConfigs(
    generatedLabDir,
    networkPlanFile,
    patchedDebianDir
  );

  waitSeconds(30);

  if (vagrantExists("wazuh-1", generatedLabDir)) {
    waitForVmSsh("wazuh-1", generatedLabDir, 900);
    patchLiveWazuhConfigs(outputRoot);

    waitSeconds(10);

    waitForDebianSsh(generatedLabDir);
    patchLiveWazuhAgents(outputRoot);
  } else {
    console.log("[infra] Aucun Wazuh déployé, skip Wazuh.");
  }

  waitSeconds(10);

  if (vagrantExists("db-server-1", generatedLabDir) || vagrantExists("db-server", generatedLabDir)) {
    const dbVmName = vagrantExists("db-server-1", generatedLabDir) ? "db-server-1" : "db-server";
    waitForVmSsh(dbVmName, generatedLabDir, 900);
    patchLiveMariaDB(outputRoot);
  } else {
    console.log("[infra] Aucun serveur MariaDB déployé, skip.");
  }

  if (vagrantExists("zabbix-1", generatedLabDir)) {
    waitForVmSsh("zabbix-1", generatedLabDir, 900);
    patchLiveZabbix(outputRoot);

    waitSeconds(10);

    patchLiveZabbixAgents(outputRoot);
  } else {
    console.log("[infra] Aucun Zabbix déployé, skip.");
  }

  if (vagrantExists("opencti-1", generatedLabDir)) {
    waitForVmSsh("opencti-1", generatedLabDir, 1800);

    try {
      patchLiveOpenCTI(outputRoot);

      waitSeconds(30);

      console.log("[infra] OpenCTI configuré.");
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn(`[infra] OpenCTI non appliqué: ${message}`);
    }
  } else {
    console.log("[infra] Aucun OpenCTI déployé, skip.");
  }

  if (vagrantExists("soc-ai-1", generatedLabDir)) {
    waitForVmSsh("soc-ai-1", generatedLabDir, 900);

    try {
      patchLiveSocAiAgent(outputRoot);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);

      if (message.includes("soc-ai-1 introuvable")) {
        console.log("[infra] Aucun SOC-AI dans cette infra, skip.");
      } else {
        throw error;
      }
    }
  } else {
    console.log("[infra] Aucun SOC-AI déployé, skip.");
  }

  if (vagrantExists("ids-sensor-1-1", generatedLabDir)) {
    waitForVmSsh("ids-sensor-1-1", generatedLabDir, 900);
    patchLiveSuricataSensor(outputRoot);
  } else {
    console.log("[infra] Aucun IDS Suricata déployé, skip.");
  }

  if (vagrantExists("zabbix-1", generatedLabDir)) {
    try {
      patchLiveZabbixPfSense(outputRoot);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      console.warn(`[infra] Zabbix pfSense non appliqué: ${message}`);
    }
  } else {
    console.log("[infra] Aucun Zabbix déployé, skip pfSense dans Zabbix.");
  }

  console.log("\nInfra complète déployée : pfSense + Debian + Wazuh + agents + MariaDB + Zabbix + OpenCTI + SOC AI/IDS si demandés.");
}

main();