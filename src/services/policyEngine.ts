import * as fs from "node:fs";
import * as path from "node:path";
import YAML from "yaml";
import {
  LabDefinition,
  GeneratedInstance,
  RequestedRole,
  RoleType,
  ZoneType
} from "./type.js";

export type PolicySeverity = "error" | "warning";

export type PolicyViolation = {
  severity: PolicySeverity;
  code: string;
  message: string;
  instanceId?: string;
  role?: RoleType;
  zone?: ZoneType;
};

export type PolicyRoutingHint = {
  code: string;
  message: string;
  targetRole?: RoleType;
  targetZone?: ZoneType;
};

export type PolicyExposureHint = {
  code: string;
  message: string;
  serviceRole?: RoleType;
  mustUseEdge: boolean;
};

export type PolicyEngineResult = {
  allowed: boolean;
  violations: PolicyViolation[];
  warnings: PolicyViolation[];
  routingHints: PolicyRoutingHint[];
  exposureHints: PolicyExposureHint[];
};

function readYamlIfExists(filePath: string): unknown {
  if (!fs.existsSync(filePath)) return null;

  const raw = fs.readFileSync(filePath, "utf-8");
  if (!raw.trim()) return null;

  try {
    return YAML.parse(raw);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`[policy] YAML invalide ${filePath}: ${message}`);
  }
}

function loadPolicyDirectory(rootDir: string): void {
  function walk(currentDir: string): void {
    if (!fs.existsSync(currentDir)) return;

    for (const entry of fs.readdirSync(currentDir)) {
      const fullPath = path.join(currentDir, entry);
      const stat = fs.lstatSync(fullPath);

      if (stat.isSymbolicLink()) {
        continue;
      }

      if (stat.isDirectory()) {
        walk(fullPath);
        continue;
      }

      if (!entry.endsWith(".yml") && !entry.endsWith(".yaml")) continue;

      readYamlIfExists(fullPath);
    }
  }

  walk(rootDir);
}

function hasRole(lab: LabDefinition, role: RoleType): boolean {
  const instances = lab.instances ?? [];
  const requiredRoles = lab.required_roles ?? [];

  return (
    instances.some((instance) => instance.role === role) ||
    requiredRoles.some((requested) => requested.role === role)
  );
}

function findInstancesByRole(
  instances: GeneratedInstance[],
  role: RoleType
): GeneratedInstance[] {
  return instances.filter((instance) => instance.role === role);
}

function findRequestedByRole(
  requestedRoles: RequestedRole[],
  role: RoleType
): RequestedRole[] {
  return requestedRoles.filter((requested) => requested.role === role);
}

function getItemInstanceId(item?: GeneratedInstance | RequestedRole): string | undefined {
  if (!item) return undefined;
  if ("id" in item) return item.id;
  return undefined;
}

function pushError(
  violations: PolicyViolation[],
  code: string,
  message: string,
  item?: GeneratedInstance | RequestedRole
): void {
  violations.push({
    severity: "error",
    code,
    message,
    instanceId: getItemInstanceId(item),
    role: item?.role,
    zone: item?.zone
  });
}

function pushWarning(
  warnings: PolicyViolation[],
  code: string,
  message: string,
  item?: GeneratedInstance | RequestedRole
): void {
  warnings.push({
    severity: "warning",
    code,
    message,
    instanceId: getItemInstanceId(item),
    role: item?.role,
    zone: item?.zone
  });
}

export function validateLabWithPolicies(
  lab: LabDefinition,
  options?: {
    projectRoot?: string;
  }
): PolicyEngineResult {
  const projectRoot = path.resolve(options?.projectRoot ?? process.cwd());
  const policiesRoot = path.resolve(projectRoot, "schemas", "policies");

  if (!policiesRoot.startsWith(projectRoot)) {
    throw new Error("[policy] Chemin policies invalide.");
  }

  loadPolicyDirectory(policiesRoot);

  if (!Array.isArray(lab.required_roles)) {
    throw new Error("[policy] lab.required_roles invalide.");
  }

  if (!Array.isArray(lab.instances)) {
    throw new Error("[policy] lab.instances invalide.");
  }

  const instances = lab.instances ?? [];
  const requiredRoles = lab.required_roles ?? [];

  const violations: PolicyViolation[] = [];
  const warnings: PolicyViolation[] = [];
  const routingHints: PolicyRoutingHint[] = [];
  const exposureHints: PolicyExposureHint[] = [];

  const internalFirewallInstances = findInstancesByRole(
    instances,
    "internal_firewall"
  );

  const dbInstances = findInstancesByRole(instances, "db_server");
  const reverseProxyInstances = findInstancesByRole(instances, "reverse_proxy");
  const bastionInstances = findInstancesByRole(instances, "bastion");

  const requestedInternalFirewalls = findRequestedByRole(
    requiredRoles,
    "internal_firewall"
  );

  const requestedDbs = findRequestedByRole(requiredRoles, "db_server");
  const requestedReverseProxies = findRequestedByRole(
    requiredRoles,
    "reverse_proxy"
  );
  const requestedBastions = findRequestedByRole(requiredRoles, "bastion");

  if (instances.length === 0) {
    pushWarning(
      warnings,
      "POLICY_NO_INSTANCES",
      "Aucune instance générée dans lab.instances. Validation basée sur required_roles uniquement."
    );
  }

  if (!hasRole(lab, "edge_firewall")) {
    pushError(
      violations,
      "EDGE_REQUIRED",
      "Un lab routé doit contenir au moins un edge_firewall. Le NAT public et les expositions doivent passer par EDGE."
    );
  }

  for (const db of [...requestedDbs, ...dbInstances]) {
    if (db.zone === "dmz" || db.zone === "edge") {
      pushError(
        violations,
        "DB_FORBIDDEN_ZONE",
        `Une base de données est placée en zone ${db.zone}. Une DB doit être dans la zone data.`,
        db
      );
    }

    if (db.zone !== "data") {
      pushWarning(
        warnings,
        "DB_SHOULD_BE_DATA_ZONE",
        "Une base de données devrait être placée dans la zone data.",
        db
      );
    }
  }

  for (const rp of [...requestedReverseProxies, ...reverseProxyInstances]) {
    if (rp.zone !== "dmz") {
      pushWarning(
        warnings,
        "REVERSE_PROXY_SHOULD_BE_DMZ",
        "Le reverse proxy devrait être placé en DMZ.",
        rp
      );
    }
  }

  for (const bastion of [...requestedBastions, ...bastionInstances]) {
    if (bastion.zone !== "management") {
      pushWarning(
        warnings,
        "BASTION_SHOULD_BE_MANAGEMENT",
        "Le bastion devrait être placé en zone management.",
        bastion
      );
    }
  }

  for (const fw of internalFirewallInstances) {
    const hasWanLikeNic = fw.nics.some((nic) =>
      nic.networkId.toLowerCase().includes("wan")
    );

    if (hasWanLikeNic) {
      pushWarning(
        warnings,
        "INTERNAL_FW_WAN_SHOULD_BE_DISABLED",
        `Le firewall interne ${fw.id} semble avoir une interface WAN. Il doit sortir via EDGE/transit, pas via un WAN direct.`,
        fw
      );
    }
  }

  if (requestedInternalFirewalls.length > 0 && instances.length === 0) {
    pushWarning(
      warnings,
      "INTERNAL_FW_ROUTING_TO_EDGE_REQUIRED",
      "Firewall interne demandé : il devra utiliser EDGE comme route de sortie via transit, sans WAN direct."
    );
  }

  if (hasRole(lab, "db_server") && hasRole(lab, "reverse_proxy")) {
    routingHints.push({
      code: "APP_TO_DB_EXPLICIT_ONLY",
      message:
        "Autoriser uniquement les flux applicatifs nécessaires DMZ -> DATA, par exemple reverse_proxy -> db_server sur le port DB attendu. Refuser le reste."
    });
  }

  if (hasRole(lab, "bastion")) {
    routingHints.push({
      code: "ADMIN_VIA_BASTION",
      message:
        "Les flux d’administration doivent partir du bastion. Pas d’administration directe depuis WAN vers les VMs internes.",
      targetRole: "bastion",
      targetZone: "management"
    });
  }

  if (hasRole(lab, "internal_firewall")) {
    routingHints.push({
      code: "INTERNAL_FW_DEFAULT_ROUTE_TO_EDGE",
      message:
        "Les firewalls internes doivent utiliser EDGE comme route de sortie via les réseaux transit. Pas de default gateway WAN directe.",
      targetRole: "internal_firewall",
      targetZone: "transit"
    });
  }

  if (hasRole(lab, "reverse_proxy")) {
    exposureHints.push({
      code: "PUBLIC_WEB_EDGE_ONLY",
      message:
        "Les services web publiés doivent être exposés uniquement via un port forward sur EDGE vers le reverse_proxy en DMZ.",
      serviceRole: "reverse_proxy",
      mustUseEdge: true
    });
  }

  if (hasRole(lab, "wazuh_server")) {
    exposureHints.push({
      code: "WAZUH_DASHBOARD_EDGE_ADMIN_ONLY",
      message:
        "L’accès Wazuh doit passer par EDGE puis par une règle contrôlée. Éviter toute exposition large depuis WAN.",
      serviceRole: "wazuh_server",
      mustUseEdge: true
    });
  }

  if (hasRole(lab, "zabbix_server")) {
    exposureHints.push({
      code: "ZABBIX_UI_EDGE_ADMIN_ONLY",
      message:
        "L’accès Zabbix doit passer par EDGE puis par une règle contrôlée. Éviter toute exposition large depuis WAN.",
      serviceRole: "zabbix_server",
      mustUseEdge: true
    });
  }

  return {
    allowed: violations.length === 0,
    violations,
    warnings,
    routingHints,
    exposureHints
  };
}