import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { LabGeneratorService } from "./labGenerator.js";
import { generateNetworkPlanFromDefinition } from "./generateNetworkPlan.js";
import { patchLivePfSenseConfigs } from "./pfsenseLiveConfigPatcher.js";
import { patchLiveDebianConfigs } from "./debianLiveConfigPatcher.js";
import { patchLiveWazuhConfigs } from "./wazuhLiveConfigPatcher.production-mode.js";
import { patchLiveWazuhAgents } from "./wazuhAgentLivePatcher.js";
import { patchLiveSocAiAgent } from "./socAiLivePatcher.js";
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

function detectRolesFromPrompt(input: string): RequestedRole[] {
  const text = input.toLowerCase();
  const roles: RequestedRole[] = [];

  const wantsEdge = hasAny(text, [
    "pfsense",
    "firewall",
    "firewall edge",
    "edge firewall",
    "firewall en entree",
    "firewall d'entree",
    "firewall en bordure",
    "pfsense edge",
    "edge"
  ]);

  const pfsenseCount = parseCount(text, "pfsense", "firewall");

  const mentionsInternalPfSense =
    text.includes("pfsense interne") ||
    text.includes("pfsense en interne") ||
    text.includes("firewall interne") ||
    text.includes("interne pour une supervision") ||
    text.includes("segmenter par un pfsense");

  const wantsEdgeCluster =
    !mentionsInternalPfSense &&
    (
      hasAny(text, [
        "cluster pfsense",
        "pfsense cluster",
        "cluster firewall",
        "firewall cluster",
        "cluster de pfsense",
        "cluster de firewall"
      ]) ||
      pfsenseCount >= 3
    );

  const wantsEdgeHa =
    !mentionsInternalPfSense &&
    !wantsEdgeCluster &&
    hasAny(text, [
      "deux pfsense en ha",
      "2 pfsense en ha",
      "pfsense edge ha",
      "edge ha",
      "firewall edge ha",
      "firewall en entree ha",
      "firewall d'entree ha",
      "pfsense redondant",
      "pfsense redondants"
    ]);

  if (wantsEdge) {
    pushRole(
      roles,
      "edge_firewall",
      wantsEdgeCluster ? "cluster" : wantsEdgeHa ? "ha" : "simple",
      "edge",
      1,
      wantsEdgeCluster ? pfsenseCount : wantsEdgeHa ? 2 : 1
    );
  }

  const wantsInternalSoc = hasAny(text, [
    "firewall interne soc",
    "firewall soc",
    "interne soc",
    "pfsense interne",
    "pfsense en interne",
    "segmenter par un pfsense",
    "firewall supervision",
    "firewall wazuh",
    "firewall zabbix",
    "supervision",
    "wazuh"
  ]);

  const wantsInternalSocHa = hasAny(text, [
    "pfsense en ha",
    "pfsense interne ha",
    "firewall interne soc ha",
    "firewall soc ha",
    "interne soc ha",
    "firewall supervision ha"
  ]);

  if (wantsInternalSoc) {
    pushRole(
      roles,
      "internal_firewall",
      wantsInternalSocHa ? "ha" : "simple",
      "soc",
      1,
      wantsInternalSocHa ? 2 : 1
    );
  }

  const wantsInternalData = hasAny(text, [
    "firewall data",
    "firewall db",
    "firewall database",
    "firewall base de données",
    "firewall base de donnees"
  ]);

  const wantsInternalDataHa = hasAny(text, [
    "firewall data ha",
    "firewall db ha",
    "firewall database ha",
    "firewall base de données ha",
    "firewall base de donnees ha"
  ]);

  if (wantsInternalData) {
    pushRole(
      roles,
      "internal_firewall",
      wantsInternalDataHa ? "ha" : "simple",
      "data",
      1,
      wantsInternalDataHa ? 2 : 1
    );
  }

  if (text.includes("bastion")) {
    pushRole(roles, "bastion", "simple", "management", 1, 1);
  }

  if (hasAny(text, ["dmz", "reverse proxy", "reverse_proxy", "proxy", "web"])) {
    pushRole(roles, "reverse_proxy", "simple", "dmz", 1, 1);
  }

  const wantsDb =
    hasAny(text, [" db ", "database", "base de données", "base de donnees"]) ||
    text.startsWith("db ") ||
    text.endsWith(" db") ||
    text.includes(" un db") ||
    text.includes(" une db");

  if (wantsDb) {
    const wantsDbCluster = hasAny(text, [
      "db cluster",
      "database cluster",
      "cluster db",
      "cluster database",
      "base de données cluster",
      "base de donnees cluster",
      "cluster base de données",
      "cluster base de donnees"
    ]);

    const nodeCount = wantsDbCluster
      ? Math.max(
          2,
          parseCount(text, "db", "database", "noeud", "nœud", "node", "nodes")
        )
      : 1;

    pushRole(
      roles,
      "db_server",
      wantsDbCluster ? "cluster" : "simple",
      "data",
      1,
      nodeCount
    );
  }

  if (text.includes("wazuh") || text.includes("supervision")) {
    const wantsWazuhCluster =
      text.includes("wazuh cluster") ||
      text.includes("cluster wazuh") ||
      text.includes("cluster de wazuh");

    const nodeCount = wantsWazuhCluster
      ? Math.max(
          3,
          parseCount(text, "wazuh", "noeud", "nœud", "node", "nodes")
        )
      : 1;

    pushRole(
      roles,
      "wazuh_server",
      wantsWazuhCluster ? "cluster" : "simple",
      "soc",
      1,
      nodeCount
    );
  }

  if (text.includes("zabbix")) {
    pushRole(roles, "zabbix_server", "simple", "soc", 1, 1);
  }
    if (
    hasAny(text, [
      "ia",
      "agent ia",
      "soc ai",
      "agent soc",
      "agent ia soc",
      "ia soc",
      "ai agent",
      "ai soc"
    ])
  ) {
    pushRole(roles, "soc_ai_agent", "simple", "soc", 1, 1);
  }

  if (
    hasAny(text, [
      "windows server",
      "windows servers",
      "active directory",
      "ad server"
    ])
  ) {
    pushRole(roles, "windows_server", "simple", "ad", 1, 1);
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
    "wazuh-1",
    "zabbix-1",
    "soc-ai-1"
  ];

  for (const vmName of debianVms) {
    waitForVmSsh(vmName, generatedLabDir, 300);
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
    'Exemple: npm run infra -- "je veux un pfsense avec un bastion segmenter par un pfsense en ha et un cluster wazuh"'
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
    timeout: 30 * 60 * 1000
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

  waitForVmSsh("wazuh-1", generatedLabDir, 300);

  patchLiveWazuhConfigs(outputRoot);

  waitSeconds(10);

  waitForDebianSsh(generatedLabDir);

  patchLiveWazuhAgents(outputRoot);

  waitSeconds(10);

  if (vagrantExists("soc-ai-1", generatedLabDir)) {
    waitForVmSsh("soc-ai-1", generatedLabDir, 300);

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
  console.log("\nInfra complète déployée : pfSense + Debian + Wazuh + agents Wazuh.");
}

main();