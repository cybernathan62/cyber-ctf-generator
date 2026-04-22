import * as fs from "node:fs";
import * as path from "node:path";
import { ROLE_MAP } from "./roleMap.js";
import {
  LabDefinition,
  RequestedRole,
  GeneratedInstance,
  GeneratedNic,
  RoleType,
  ZoneType
} from "./type.js";

type GenerateLabInput = LabDefinition & {
  outputDir: string;
};

type NetworkPlanHost = {
  id: string;
  role: string;
  profile: string;
  interfaces?: Array<{
    network_id: string;
    ip?: string;
  }>;
};

type NetworkPlan = {
  hosts: NetworkPlanHost[];
};

export class LabGeneratorService {
  public generateLab(input: GenerateLabInput) {
    const { outputDir, ...model } = input;

    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const networkPlanPath = path.join(process.cwd(), "outputs", "network-plan.json");
    if (!fs.existsSync(networkPlanPath)) {
      throw new Error(`network-plan.json introuvable: ${networkPlanPath}`);
    }

    const networkPlan = JSON.parse(
      fs.readFileSync(networkPlanPath, "utf-8")
    ) as NetworkPlan;

    let instances = model.instances;

    if (!instances || instances.length === 0) {
      instances = this.buildInstancesFromRoles(model.required_roles);
    }

    instances = this.attachNetworksFromPlan(instances, networkPlan);

    const vagrantfile = this.generateVagrantfile(instances);

    fs.writeFileSync(path.join(outputDir, "Vagrantfile"), vagrantfile, "utf-8");

    return {
      success: true,
      message: "Vagrantfile généré",
      outputDir
    };
  }

  private getTotalNodes(requested: RequestedRole): number {
    return requested.count * requested.node_count;
  }

  private buildInstancesFromRoles(roles: RequestedRole[]): GeneratedInstance[] {
    const instances: GeneratedInstance[] = [];

    for (const requested of roles) {
      const def = ROLE_MAP[requested.role];

      if (!def) {
        throw new Error(`Role inconnu: ${requested.role}`);
      }

      const totalNodes = this.getTotalNodes(requested);
      let globalNodeIndex = 0;

      for (let groupIndex = 1; groupIndex <= requested.count; groupIndex++) {
        for (let nodeIndex = 1; nodeIndex <= requested.node_count; nodeIndex++) {
          globalNodeIndex += 1;

          const id = this.buildInstanceId(
            requested.role,
            requested.zone,
            groupIndex,
            globalNodeIndex,
            totalNodes
          );

          instances.push({
            id,
            hostname: id,
            profile: def.profile,
            role: requested.role,
            variant: requested.variant,
            zone: requested.zone,
            group_index: groupIndex,
            node_index: globalNodeIndex,
            nics: []
          });
        }
      }
    }

    return instances;
  }

  private buildInstanceId(
    role: RoleType,
    zone: ZoneType,
    groupIndex: number,
    nodeIndex: number,
    totalNodes: number
  ): string {
    switch (role) {
      case "edge_firewall":
        return totalNodes > 1 ? `pfsense-edge-${nodeIndex}` : "pfsense-edge-1";

      case "internal_firewall":
        if (zone === "soc") {
          return totalNodes > 1 ? `pfsense-soc-${nodeIndex}` : "pfsense-soc-1";
        }
        if (zone === "data") {
          return totalNodes > 1 ? `pfsense-data-${nodeIndex}` : "pfsense-data-1";
        }
        if (zone === "ad") {
          return totalNodes > 1 ? `pfsense-ad-${nodeIndex}` : "pfsense-ad-1";
        }
        return totalNodes > 1
          ? `pfsense-internal-${nodeIndex}`
          : "pfsense-internal-1";

      case "bastion":
        return totalNodes > 1 ? `bastion-${nodeIndex}` : "bastion-1";

      case "reverse_proxy":
        return totalNodes > 1 ? `reverse-proxy-${nodeIndex}` : "reverse-proxy-1";

      case "wazuh_server":
        return totalNodes > 1 ? `wazuh-${nodeIndex}` : "wazuh-1";

      case "zabbix_server":
        return totalNodes > 1 ? `zabbix-${nodeIndex}` : "zabbix-1";

      case "db_server":
        return totalNodes > 1 ? `db-server-${nodeIndex}` : "db-server-1";

      case "windows_server":
        return totalNodes > 1 ? `windows-server-${nodeIndex}` : "windows-server-1";

      default:
        return `${role}-${groupIndex}-${nodeIndex}`;
    }
  }

  private attachNetworksFromPlan(
    instances: GeneratedInstance[],
    networkPlan: NetworkPlan
  ): GeneratedInstance[] {
    for (const vm of instances) {
      const planHost = networkPlan.hosts.find((h) => h.id === vm.id);

      if (!planHost) {
        throw new Error(`Hôte ${vm.id} introuvable dans network-plan.json`);
      }

      vm.nics = (planHost.interfaces ?? []).map((iface): GeneratedNic => ({
        networkId: iface.network_id,
        ip: iface.ip
      }));
    }

    return instances;
  }

  private isPfSense(vm: GeneratedInstance): boolean {
    return vm.profile === "pfsense";
  }

  private resolveBox(vm: GeneratedInstance): string {
    if (this.isPfSense(vm)) {
      return "cyberctf/firewall";
    }

    if (vm.profile === "windows-server") {
      return "cyberctf/windows-server";
    }

    return "cyberctf/debian_wazuh";
  }

  private resolveCpu(vm: GeneratedInstance): number {
    if (vm.role === "wazuh_server") return 4;
    return 2;
  }

  private resolveMemory(vm: GeneratedInstance): number {
    if (vm.role === "wazuh_server") return 4096;
    return 2048;
  }

  private buildNetworkBlock(ref: string, vm: GeneratedInstance): string {
    return vm.nics
      .filter((nic) => nic.networkId !== "edge-wan")
      .map((nic) => {
        return `    ${ref}.vm.network "private_network", virtualbox__intnet: "${nic.networkId}", auto_config: false`;
      })
      .join("\n");
  }

  private buildSshBlock(ref: string, vm: GeneratedInstance): string {
    if (this.isPfSense(vm)) {
      return `    ${ref}.vm.communicator = "ssh"
    ${ref}.ssh.username = "vagrant"
    ${ref}.ssh.private_key_path = KEY_PFSENSE
    ${ref}.ssh.insert_key = false
    ${ref}.ssh.keys_only = true
    ${ref}.ssh.shell = "/bin/sh"`;
    }

    if (vm.profile === "windows-server") {
      return `    ${ref}.vm.communicator = "winrm"`;
    }

    return `    ${ref}.vm.communicator = "ssh"
    ${ref}.ssh.username = "vagrant"
    ${ref}.ssh.private_key_path = KEY_DEBIAN
    ${ref}.ssh.insert_key = false
    ${ref}.ssh.keys_only = true`;
  }

  private generateVagrantfile(instances: GeneratedInstance[]): string {
    const vmBlocks = instances
      .map((vm) => {
        const ref = vm.id.replace(/-/g, "_");
        const networks = this.buildNetworkBlock(ref, vm);
        const ssh = this.buildSshBlock(ref, vm);
        const box = this.resolveBox(vm);
        const cpu = this.resolveCpu(vm);
        const memory = this.resolveMemory(vm);

        return `
  config.vm.define "${vm.id}" do |${ref}|
    ${ref}.vm.box = "${box}"
${ssh}

${networks}

    ${ref}.vm.provider "virtualbox" do |vb|
      vb.name = "${vm.id}"
      vb.cpus = ${cpu}
      vb.memory = ${memory}
      vb.gui = false
    end
  end
`;
      })
      .join("\n");

    return `Vagrant.configure("2") do |config|
  config.vm.box_check_update = false
  config.vm.boot_timeout = 2800

  KEY_PFSENSE = File.expand_path("../../keys/ssh/vagrant/vagrant.key.rsa", __dir__)
  KEY_DEBIAN  = File.expand_path("~/.vagrant.d/insecure_private_key")

  config.ssh.insert_key = false
  config.ssh.keys_only  = true

  config.vm.synced_folder ".", "/vagrant", disabled: true

${vmBlocks}
end
`;
  }
}