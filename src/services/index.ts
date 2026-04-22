import * as fs from "node:fs";
import * as path from "node:path";
import { LabGeneratorService } from "./labGenerator.js";

async function main() {
  const labPath = path.join(process.cwd(), "outputs", "lab-definition.json");

  const raw = fs.readFileSync(labPath, "utf-8");
  const labModel = JSON.parse(raw);

  const service = new LabGeneratorService();

  const result = service.generateLab({
    ...labModel,
    outputDir: path.join(process.cwd(), "outputs", "generated-lab")
  });

  console.log(JSON.stringify(result, null, 2));
}

main().catch((err) => {
  console.error("Erreur génération lab:", err);
  process.exit(1);
});