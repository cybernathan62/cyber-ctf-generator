import * as fs from "node:fs";
import * as path from "node:path";
import { LabGeneratorService } from "../lab/labGenerator.js";
import type { LabDefinition } from "./type.js";

function readJsonFile<T>(filePath: string): T {
  if (!fs.existsSync(filePath)) {
    throw new Error(`[generate] Fichier introuvable: ${filePath}`);
  }

  const raw = fs.readFileSync(filePath, "utf-8");

  try {
    return JSON.parse(raw) as T;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`[generate] JSON invalide dans ${filePath}: ${message}`);
  }
}

function validateLabDefinition(value: LabDefinition): void {
  if (!value || typeof value !== "object") {
    throw new Error("[generate] LabDefinition invalide.");
  }

  if (typeof value.name !== "string" || value.name.trim().length === 0) {
    throw new Error("[generate] LabDefinition.name invalide.");
  }

  if (!Array.isArray(value.required_roles)) {
    throw new Error("[generate] LabDefinition.required_roles invalide.");
  }

  if (!Array.isArray(value.instances)) {
    throw new Error("[generate] LabDefinition.instances invalide.");
  }
}

async function main(): Promise<void> {
  const outputRoot = path.resolve(process.cwd(), "outputs");
  const labPath = path.join(outputRoot, "lab-definition.json");
  const generatedLabDir = path.join(outputRoot, "generated-lab");

  const labModel = readJsonFile<LabDefinition>(labPath);
  validateLabDefinition(labModel);

  fs.mkdirSync(generatedLabDir, { recursive: true });

  const service = new LabGeneratorService();

  const result = service.generateLab({
    ...labModel,
    outputDir: generatedLabDir
  });

  console.log(JSON.stringify(result, null, 2));
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error("Erreur génération lab:", message);
  process.exit(1);
});