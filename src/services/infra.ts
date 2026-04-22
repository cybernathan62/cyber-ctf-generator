import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { LabGeneratorService } from "./labGenerator.js";
import { generateNetworkPlanFromDefinition } from "./generateNetworkPlan.js";
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
  if (match) {
    return parseInt(match[1], 10);
  }
  return null;
}

function parseWordCount(text: string, keyword: string): number | null {
  if (text.includes(`trois ${keyword}`)) return 3;
  if (text.includes(`deux ${keyword}`)) return 2;
  if (text.includes(`un ${keyword}`)) return 1;
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

  // =========================
  // EDGE FIREWALL
  // simple par défaut
  // ha seulement si explicitement demandé
  // =========================
  const wantsEdge = hasAny(text, [
    "pfsense",
    "firewall edge",
    "edge firewall",
    "firewall en entree",
    "firewall d'entree",
    "firewall en bordure",
    "pfsense edge",
    "edge"
  ]);

  const wantsEdgeHa = hasAny(text, [
    "pfsense ha",
    "firewall ha",
    "edge ha",
    "firewall edge ha",
    "firewall en ha",
    "firewall redondant",
    "pfsense redondant"
  ]);

  if (wantsEdge) {
    pushRole(
      roles,
      "edge_firewall",
      wantsEdgeHa ? "ha" : "simple",
      "edge",
      1,
      wantsEdgeHa ? 2 : 1
    );
  }

  // =========================
  // INTERNAL FIREWALL SOC
  // =========================
  const wantsInternalSoc = hasAny(text, [
    "firewall interne soc",
    "firewall soc",
    "interne soc",
    "firewall supervision",
    "firewall wazuh",
    "firewall zabbix"
  ]);

  const wantsInternalSocHa = hasAny(text, [
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

  // =========================
  // INTERNAL FIREWALL DATA
  // =========================
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

  // =========================
  // BASTION
  // =========================
  if (text.includes("bastion")) {
    pushRole(roles, "bastion", "simple", "management", 1, 1);
  }

  // =========================
  // DMZ / reverse proxy
  // =========================
  if (
    hasAny(text, [
      "dmz",
      "reverse proxy",
      "reverse_proxy",
      "proxy",
      "web"
    ])
  ) {
    pushRole(roles, "reverse_proxy", "simple", "dmz", 1, 1);
  }

  // =========================
  // DB
  // =========================
  const wantsDb = hasAny(text, [
    " db ",
    "database",
    "base de données",
    "base de donnees"
  ]) || text.startsWith("db ") || text.endsWith(" db");

  if (wantsDb) {
    const wantsDbCluster = hasAny(text, [
      "db cluster",
      "database cluster",
      "base de données cluster",
      "base de donnees cluster"
    ]);

    const nodeCount = wantsDbCluster
      ? Math.max(2, parseCount(text, "noeud", "nœud", "node", "nodes"))
      : 1;

    pushRole(
      roles,
      "db_server",
      wantsDbCluster ? "cluster" : "simple",
      "data",
      1,
      wantsDbCluster ? nodeCount : 1
    );
  }

  // =========================
  // WAZUH
  // =========================
  if (text.includes("wazuh")) {
    const wantsWazuhCluster = text.includes("wazuh cluster");
    const nodeCount = wantsWazuhCluster
      ? Math.max(2, parseCount(text, "noeud", "nœud", "node", "nodes"))
      : 1;

    pushRole(
      roles,
      "wazuh_server",
      wantsWazuhCluster ? "cluster" : "simple",
      "soc",
      1,
      wantsWazuhCluster ? nodeCount : 1
    );
  }

  // =========================
  // ZABBIX
  // =========================
  if (text.includes("zabbix")) {
    pushRole(roles, "zabbix_server", "simple", "soc", 1, 1);
  }

  // =========================
  // WINDOWS SERVER
  // =========================
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

function main() {
  const userPrompt = process.argv.slice(2).join(" ").trim();

  if (!userPrompt) {
    throw new Error(
      'Exemple: npm run infra -- "je veux une infra avec un pfsense, un bastion, une dmz, un firewall interne soc avec un wazuh et un zabbix, puis un firewall data avec une db"'
    );
  }

  const required_roles = detectRolesFromPrompt(userPrompt);

  if (required_roles.length === 0) {
    throw new Error("Aucun rôle reconnu.");
  }

  const outputRoot = path.join(process.cwd(), "outputs");
  const definitionFile = path.join(outputRoot, "lab-definition.json");
  const generatedLabDir = path.join(outputRoot, "generated-lab");

  if (!fs.existsSync(outputRoot)) {
    fs.mkdirSync(outputRoot, { recursive: true });
  }

  const definition: LabDefinition = {
    name: "prompt-generated-lab",
    required_roles,
    instances: []
  };

  fs.writeFileSync(
    definitionFile,
    JSON.stringify(definition, null, 2),
    "utf-8"
  );

  console.log("Demande du prof :", userPrompt);
  console.log("Lab definition généré :", definitionFile);
  console.log(JSON.stringify(definition, null, 2));

  generateNetworkPlanFromDefinition(definition, outputRoot);

  console.log(
    "Network plan généré :",
    path.join(outputRoot, "network-plan.json")
  );

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
    shell: true
  });

  if (upResult.error) {
    throw upResult.error;
  }

  if (upResult.status !== 0) {
    throw new Error(`vagrant up a échoué avec le code ${upResult.status}`);
  }

  console.log("\nInfra démarrée avec succès.");
}

main();