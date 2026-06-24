import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

type NetworkInterface = {
  name: string;
  network_id: string;
  ip?: string;
  mode?: string;
  gateway?: string | null;
};

type NetworkHost = {
  id: string;
  role: string;
  zone: string;
  profile?: string;
  interfaces: NetworkInterface[];
};

type NetworkPlan = {
  hosts: NetworkHost[];
};

type ZabbixApiResponse<T = unknown> = {
  jsonrpc: "2.0";
  result?: T;
  error?: {
    code: number;
    message: string;
    data?: string;
  };
  id: number;
};

type ZabbixHostPayload = {
  host: string;
  ip: string;
};

type ZabbixTemplate = {
  templateid: string;
  name: string;
};

type ZabbixInterface = {
  interfaceid: string;
  type: string;
  ip: string;
  port: string;
};

function run(command: string, args: string[], cwd?: string): string {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf-8",
    shell: false,
    maxBuffer: 1024 * 1024 * 20
  });

  if (result.status !== 0) {
    const stderr = result.stderr?.trim() || "";
    const stdout = result.stdout?.trim() || "";
    throw new Error(
      `[zabbix-pfsense] Commande échouée: ${command} ${args.join(" ")}\n${stderr}\n${stdout}`
    );
  }

  return result.stdout;
}

function stripCidr(ipCidr: string): string {
  return ipCidr.split("/")[0];
}

function loadNetworkPlan(outputRoot: string): NetworkPlan {
  const networkPlanFile = path.join(outputRoot, "network-plan.json");

  if (!fs.existsSync(networkPlanFile)) {
    throw new Error(`[zabbix-pfsense] network-plan.json introuvable: ${networkPlanFile}`);
  }

  return JSON.parse(fs.readFileSync(networkPlanFile, "utf-8")) as NetworkPlan;
}

function getPrimaryIp(host: NetworkHost): string | null {
  const preferred =
    host.interfaces.find((iface) => iface.ip && iface.name !== "wan" && iface.mode !== "dhcp") ??
    host.interfaces.find((iface) => iface.ip);

  return preferred?.ip ? stripCidr(preferred.ip) : null;
}

function getZabbixServer(plan: NetworkPlan): ZabbixHostPayload {
  const zabbix = plan.hosts.find((host) => host.role === "zabbix_server" || host.id === "zabbix-1");

  if (!zabbix) {
    throw new Error("[zabbix-pfsense] Aucun host zabbix_server trouvé dans network-plan.json");
  }

  const ip = getPrimaryIp(zabbix);

  if (!ip) {
    throw new Error(`[zabbix-pfsense] Impossible de déterminer l'IP de ${zabbix.id}`);
  }

  return {
    host: zabbix.id,
    ip
  };
}

function getPfSenseHosts(plan: NetworkPlan): ZabbixHostPayload[] {
  return plan.hosts
    .filter((host) => host.profile === "pfsense" || host.role.includes("firewall"))
    .map((host) => {
      const ip = getPrimaryIp(host);

      if (!ip) {
        throw new Error(`[zabbix-pfsense] Impossible de déterminer l'IP de ${host.id}`);
      }

      return {
        host: host.id,
        ip
      };
    });
}

function sshToZabbix(outputRoot: string, command: string): string {
  const generatedLabDir = path.join(outputRoot, "generated-lab");
  const vagrant = process.platform === "win32" ? "vagrant.exe" : "vagrant";

  return run(vagrant, ["ssh", "zabbix-1", "-c", command], generatedLabDir);
}

function apiCallOnZabbix<T>(
  outputRoot: string,
  zabbixUrl: string,
  auth: string | null,
  method: string,
  params: unknown
): T {
  const payload = {
    jsonrpc: "2.0",
    method,
    params,
    auth,
    id: 1
  };

  const encoded = Buffer.from(JSON.stringify(payload), "utf-8").toString("base64");

  const command = [
    "set -e",
    `PAYLOAD="$(printf '%s' '${encoded}' | base64 -d)"`,
    `curl -sS -H 'Content-Type: application/json-rpc' -d "$PAYLOAD" '${zabbixUrl}'`
  ].join(" && ");

  const raw = sshToZabbix(outputRoot, command).trim();
  const response = JSON.parse(raw) as ZabbixApiResponse<T>;

  if (response.error) {
    throw new Error(
      `[zabbix-pfsense] Erreur API Zabbix ${method}: ${response.error.message} ${response.error.data ?? ""}`
    );
  }

  if (response.result === undefined) {
    throw new Error(`[zabbix-pfsense] Réponse API vide pour ${method}: ${raw}`);
  }

  return response.result;
}

function getAuthToken(outputRoot: string, zabbixUrl: string): string {
  return apiCallOnZabbix<string>(outputRoot, zabbixUrl, null, "user.login", {
    username: "Admin",
    password: "zabbix"
  });
}

function getOrCreateGroup(outputRoot: string, zabbixUrl: string, auth: string): string {
  const groups = apiCallOnZabbix<Array<{ groupid: string }>>(
    outputRoot,
    zabbixUrl,
    auth,
    "hostgroup.get",
    {
      output: ["groupid", "name"],
      filter: {
        name: ["pfSense Firewalls"]
      }
    }
  );

  if (groups.length > 0) return groups[0].groupid;

  const created = apiCallOnZabbix<{ groupids: string[] }>(
    outputRoot,
    zabbixUrl,
    auth,
    "hostgroup.create",
    {
      name: "pfSense Firewalls"
    }
  );

  return created.groupids[0];
}

function findTemplateIds(
  outputRoot: string,
  zabbixUrl: string,
  auth: string
): string[] {
  const snmpTemplates = [
    "Network Generic Device by SNMP",
    "Template Net Network Generic Device SNMP",
    "Generic by SNMP"
  ];

  for (const name of snmpTemplates) {
    const templates = apiCallOnZabbix<ZabbixTemplate[]>(
      outputRoot,
      zabbixUrl,
      auth,
      "template.get",
      {
        output: ["templateid", "name"],
        filter: {
          name: [name]
        }
      }
    );

    if (templates.length > 0) {
      console.log(
        `[Zabbix pfSense] Template SNMP retenu: ${templates[0].name}`
      );

      return [templates[0].templateid];
    }
  }

  const icmpTemplates = [
    "ICMP Ping",
    "Template Module ICMP Ping"
  ];

  for (const name of icmpTemplates) {
    const templates = apiCallOnZabbix<ZabbixTemplate[]>(
      outputRoot,
      zabbixUrl,
      auth,
      "template.get",
      {
        output: ["templateid", "name"],
        filter: {
          name: [name]
        }
      }
    );

    if (templates.length > 0) {
      console.log(
        `[Zabbix pfSense] Template fallback retenu: ${templates[0].name}`
      );

      return [templates[0].templateid];
    }
  }

  console.warn(
    "[Zabbix pfSense] Aucun template SNMP ou ICMP trouvé."
  );

  return [];
}
function getExistingHostId(
  outputRoot: string,
  zabbixUrl: string,
  auth: string,
  hostname: string
): string | null {
  const hosts = apiCallOnZabbix<Array<{ hostid: string }>>(
    outputRoot,
    zabbixUrl,
    auth,
    "host.get",
    {
      output: ["hostid", "host"],
      filter: {
        host: [hostname]
      }
    }
  );

  return hosts.length > 0 ? hosts[0].hostid : null;
}

function getHostInterfaces(
  outputRoot: string,
  zabbixUrl: string,
  auth: string,
  hostId: string
): ZabbixInterface[] {
  return apiCallOnZabbix<ZabbixInterface[]>(
    outputRoot,
    zabbixUrl,
    auth,
    "hostinterface.get",
    {
      output: ["interfaceid", "type", "ip", "port"],
      hostids: [hostId]
    }
  );
}

function ensureSnmpInterface(
  outputRoot: string,
  zabbixUrl: string,
  auth: string,
  hostId: string,
  ip: string
): void {
  const interfaces = getHostInterfaces(outputRoot, zabbixUrl, auth, hostId);
  const snmpInterface = interfaces.find((iface) => String(iface.type) === "2");

  if (snmpInterface) {
    apiCallOnZabbix(
      outputRoot,
      zabbixUrl,
      auth,
      "hostinterface.update",
      {
        interfaceid: snmpInterface.interfaceid,
        type: 2,
        main: 1,
        useip: 1,
        ip,
        dns: "",
        port: "161",
        details: {
          version: 2,
          community: "{$SNMP_COMMUNITY}",
          bulk: 1
        }
      }
    );

    console.log(`[Zabbix pfSense] Interface SNMP mise à jour: ${ip}:161`);
    return;
  }

  apiCallOnZabbix(
    outputRoot,
    zabbixUrl,
    auth,
    "hostinterface.create",
    {
      hostid: hostId,
      type: 2,
      main: 1,
      useip: 1,
      ip,
      dns: "",
      port: "161",
      details: {
        version: 2,
        community: "{$SNMP_COMMUNITY}",
        bulk: 1
      }
    }
  );

  console.log(`[Zabbix pfSense] Interface SNMP créée: ${ip}:161`);
}

function createOrUpdatePfSenseHost(
  outputRoot: string,
  zabbixUrl: string,
  auth: string,
  groupId: string,
  templateIds: string[],
  host: ZabbixHostPayload
): void {
  const existingHostId = getExistingHostId(outputRoot, zabbixUrl, auth, host.host);

  const interfaces = [
    {
      type: 2,
      main: 1,
      useip: 1,
      ip: host.ip,
      dns: "",
      port: "161",
      details: {
        version: 2,
        community: "{$SNMP_COMMUNITY}",
        bulk: 1
      }
    }
  ];

  const templates = templateIds.map((templateid) => ({ templateid }));

  if (existingHostId) {
    console.log(`[Zabbix pfSense] Mise à jour host: ${host.host} (${host.ip})`);

    ensureSnmpInterface(outputRoot, zabbixUrl, auth, existingHostId, host.ip);

    apiCallOnZabbix(
      outputRoot,
      zabbixUrl,
      auth,
      "host.update",
      {
        hostid: existingHostId,
        groups: [{ groupid: groupId }],
        templates,
        macros: [
          {
            macro: "{$SNMP_COMMUNITY}",
            value: "zabbix-monitoring"
          }
        ]
      }
    );

    return;
  }

  console.log(`[Zabbix pfSense] Création host: ${host.host} (${host.ip})`);

  apiCallOnZabbix(
    outputRoot,
    zabbixUrl,
    auth,
    "host.create",
    {
      host: host.host,
      name: host.host,
      groups: [{ groupid: groupId }],
      interfaces,
      templates,
      macros: [
        {
          macro: "{$SNMP_COMMUNITY}",
          value: "zabbix-monitoring"
        }
      ]
    }
  );
}

export function patchLiveZabbixPfSense(outputRoot: string): void {
  console.log("\n[Zabbix pfSense] Découverte des firewalls pfSense...");

  const plan = loadNetworkPlan(outputRoot);
  const zabbix = getZabbixServer(plan);
  const pfsenseHosts = getPfSenseHosts(plan);

  if (pfsenseHosts.length === 0) {
    console.log("[Zabbix pfSense] Aucun pfSense trouvé dans network-plan.json, skip.");
    return;
  }

  const zabbixUrl = `http://${zabbix.ip}:8080/api_jsonrpc.php`;

  console.log(`[Zabbix pfSense] Zabbix API: ${zabbixUrl}`);
  console.log(
    `[Zabbix pfSense] pfSense détectés: ${pfsenseHosts
      .map((host) => `${host.host}=${host.ip}`)
      .join(", ")}`
  );

  const auth = getAuthToken(outputRoot, zabbixUrl);
  const groupId = getOrCreateGroup(outputRoot, zabbixUrl, auth);
  const templateIds = findTemplateIds(outputRoot, zabbixUrl, auth);

  if (templateIds.length === 0) {
    console.warn("[Zabbix pfSense] Aucun template ICMP/SNMP trouvé. Les hosts seront créés sans template.");
  }

  for (const host of pfsenseHosts) {
    createOrUpdatePfSenseHost(outputRoot, zabbixUrl, auth, groupId, templateIds, host);
  }

  console.log("[Zabbix pfSense] Création/mise à jour des hosts pfSense terminée.");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const outputRoot = path.resolve(process.cwd(), "outputs");
  patchLiveZabbixPfSense(outputRoot);
}