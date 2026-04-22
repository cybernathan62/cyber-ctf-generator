import * as fs from "node:fs";
import * as path from "node:path";

type LabDefinition = {
  name: string;
  required_roles: string[];
  instances: any[];
};

function detectRolesFromPrompt(input: string): string[] {
  const text = input.toLowerCase();
  const roles = new Set<string>();

  if (text.includes("firewall") || text.includes("pfsense") || text.includes("edge")) {
    roles.add("edge_firewall_cluster");
  }

  if (text.includes("bastion")) {
    roles.add("bastion");
  }

  if (text.includes("dmz") || text.includes("reverse proxy") || text.includes("proxy") || text.includes("web")) {
    roles.add("reverse_proxy");
  }

  if (text.includes("db") || text.includes("database") || text.includes("base de données")) {
    roles.add("db_server");
  }

  if (text.includes("wazuh")) {
    roles.add("wazuh_server");
  }

  if (text.includes("zabbix")) {
    roles.add("zabbix_server");
  }

  return [...roles];
}

function main() {
  const userPrompt = process.argv.slice(2).join(" ").trim();

  if (!userPrompt) {
    throw new Error("Aucune demande fournie. Exemple: npm run ask -- \"je veux une infra avec un bastion et un wazuh\"");
  }

  const required_roles = detectRolesFromPrompt(userPrompt);

  if (required_roles.length === 0) {
    throw new Error("Aucun rôle reconnu dans la demande.");
  }

  const outputDir = path.join(process.cwd(), "outputs");
  const outputFile = path.join(outputDir, "lab-definition.json");

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const definition: LabDefinition = {
    name: "prompt-generated-lab",
    required_roles,
    instances: []
  };

  fs.writeFileSync(outputFile, JSON.stringify(definition, null, 2), "utf-8");

  console.log("Lab definition généré :", outputFile);
  console.log(JSON.stringify(definition, null, 2));
}

main();