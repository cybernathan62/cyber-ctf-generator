import * as fs from "node:fs";
import * as path from "node:path";
import { generatePfSenseMinimalPlan } from "./generatePfsenseMinimalPlan.js";
import { buildPatchedConfigXml } from "./pfsenseLiveConfigPatcher.js";
import { NetworkPlan, NetworkPlanHost } from "./type.js";
import { PfSensePlan } from "./pfsenseTypes.js";

const LOGICAL_INTERFACE_NAMES = new Set([
  "management",
  "dmz",
  "transit_soc",
  "transit_data",
  "transit",
  "soc",
  "data"
]);

function extractFilterInterfaces(xml: string): string[] {
  const matches = xml.matchAll(/<interface>([^<]+)<\/interface>/g);
  return [...matches].map((m) => m[1]);
}

function main(): void {
  const root = process.cwd();
  const outputRoot = path.join(root, "outputs");
  const networkPlanPath = path.join(outputRoot, "network-plan.json");
  const planPath = path.join(outputRoot, "pfsense-plan.json");
  const backupDir = path.join(outputRoot, "pfsense-live-patched");
  const testOutDir = path.join(outputRoot, "pfsense-local-test");

  if (!fs.existsSync(networkPlanPath)) {
    throw new Error(`Fichier manquant: ${networkPlanPath}. Lance d'abord npm run infra.`);
  }

  generatePfSenseMinimalPlan(networkPlanPath, planPath);

  const networkPlan = JSON.parse(
    fs.readFileSync(networkPlanPath, "utf-8")
  ) as NetworkPlan;

  const plans = JSON.parse(fs.readFileSync(planPath, "utf-8")) as PfSensePlan[];

  fs.mkdirSync(testOutDir, { recursive: true });

  const errors: string[] = [];
  const pfsenseHosts = networkPlan.hosts.filter((h) => h.profile === "pfsense");

  console.log(`[test:pfsense-local] ${pfsenseHosts.length} firewall(s) à valider\n`);

  for (const host of pfsenseHosts) {
    const plan = plans.find((p) => p.firewall === host.id);

    if (!plan) {
      errors.push(`${host.id}: plan pfSense introuvable`);
      continue;
    }

    const backupPath = path.join(backupDir, `${host.id}.live-backup.xml`);

    if (!fs.existsSync(backupPath)) {
      errors.push(
        `${host.id}: backup XML manquant (${backupPath}). Déploie le lab une fois ou copie un config.xml.`
      );
      continue;
    }

    const baseXml = fs.readFileSync(backupPath, "utf-8");
    const patched = buildPatchedConfigXml(baseXml, host, plan);
    const outPath = path.join(testOutDir, `${host.id}.test-patched.xml`);

    fs.writeFileSync(outPath, patched, "utf-8");

    if (!patched.includes("<aliases>")) {
      errors.push(`${host.id}: section <aliases> absente`);
    }

    for (const alias of plan.aliases) {
      if (!patched.includes(`<name>${alias.name}</name>`)) {
        errors.push(`${host.id}: alias manquant <name>${alias.name}</name>`);
      }
    }

    const filterInterfaces = extractFilterInterfaces(patched);

    for (const logical of LOGICAL_INTERFACE_NAMES) {
      if (filterInterfaces.includes(logical)) {
        errors.push(
          `${host.id}: interface logique "${logical}" encore présente dans <filter> (mapping échoué)`
        );
      }
    }

    const expectedPfSenseIfaces = new Set(["wan", "lan", "opt1", "opt2", "opt3", "opt4"]);

    for (const iface of filterInterfaces) {
      if (!expectedPfSenseIfaces.has(iface)) {
        errors.push(`${host.id}: interface filter inattendue "${iface}"`);
      }
    }

    console.log(`  OK ${host.id}`);
    console.log(`     aliases: ${plan.aliases.length}, rules: ${plan.rules.length}`);
    console.log(`     filter interfaces: ${[...new Set(filterInterfaces)].join(", ")}`);
    console.log(`     → ${outPath}\n`);
  }

  if (errors.length > 0) {
    console.error("[test:pfsense-local] ÉCHEC:\n");
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  console.log("[test:pfsense-local] Tous les contrôles XML sont passés.");
  console.log(
    "\nProchaine étape live (VMs déjà up): ré-appliquer le patch SSH depuis infra ou relancer uniquement la phase pfSense."
  );
}

main();
