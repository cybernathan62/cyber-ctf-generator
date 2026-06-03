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
    name?: string;
    network_id: string;
    ip?: string;
    mode?: string;
    gateway?: string | null;
  }>;
};

type NetworkPlan = {
  hosts: NetworkPlanHost[];
};

type PortAllocation = {
  ssh?: number;
  gui?: number;
};

export class LabGeneratorService {
  public generateLab(input: GenerateLabInput) {
    const { outputDir, ...model } = input;

    fs.mkdirSync(outputDir, { recursive: true });

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

    const portAllocations = this.allocatePorts(instances);
    const vagrantfile = this.generateVagrantfile(instances, portAllocations);

    this.writeTextAtomic(path.join(outputDir, "Vagrantfile"), vagrantfile, 0o644);

    this.generateSshAccessLocalFile(outputDir, instances, portAllocations);

    return {
      success: true,
      message: "Vagrantfile + ssh-access.local.json générés",
      outputDir
    };
  }

  private writeTextAtomic(filePath: string, content: string, mode = 0o600): void {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });

    const tmpPath = `${filePath}.tmp`;

    fs.writeFileSync(tmpPath, content, {
      encoding: "utf-8",
      mode
    });

    fs.renameSync(tmpPath, filePath);
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

      case "soc_ai_agent":
        return totalNodes > 1 ? `soc-ai-${nodeIndex}` : "soc-ai-1";
      
      case "ids_sensor":
        return totalNodes > 1 ? `ids-sensor-${nodeIndex}` : "ids-sensor-1-1";

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

  private isEdgePfSense(vm: GeneratedInstance): boolean {
    return this.isPfSense(vm) && vm.role === "edge_firewall";
  }

  private isInternalPfSense(vm: GeneratedInstance): boolean {
    return this.isPfSense(vm) && vm.role === "internal_firewall";
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
      .filter(
        (nic) =>
          !(vm.id === "pfsense-edge-1" && nic.networkId === "transit-edge-data-net")
      )
      .map((nic) => {
        return `    ${ref}.vm.network "private_network", virtualbox__intnet: "${nic.networkId}", auto_config: false`;
      })
      .join("\n");
  }

  private buildProviderExtra(vm: GeneratedInstance): string {
    if (vm.id !== "pfsense-edge-1") {
      return "";
    }

    const hasTransitData = vm.nics.some(
      (nic) => nic.networkId === "transit-edge-data-net"
    );

    if (!hasTransitData) {
      return "";
    }

    return `
      # NIC5 VirtualBox : non visible dans la GUI classique, mais actif via VBoxManage
      vb.customize ["modifyvm", :id, "--nic5", "intnet"]
      vb.customize ["modifyvm", :id, "--intnet5", "transit-edge-data-net"]
      vb.customize ["modifyvm", :id, "--nictype5", "82540EM"]
      vb.customize ["modifyvm", :id, "--cableconnected5", "on"]`;
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

  private buildHostnameLine(ref: string, vm: GeneratedInstance): string {
    if (this.isPfSense(vm)) {
      return "";
    }

    return `    ${ref}.vm.hostname = "${vm.hostname ?? vm.id}"`;
  }

  private buildForwardedPortsBlock(
    ref: string,
    vm: GeneratedInstance,
    ports: PortAllocation
  ): string {
    const lines: string[] = [];

    if (ports.ssh) {
      lines.push(
        `    ${ref}.vm.network "forwarded_port", guest: 22, host: ${ports.ssh}, host_ip: "127.0.0.1", auto_correct: true, id: "ssh"`
      );
    }

    if (this.isPfSense(vm) && ports.gui) {
      lines.push(
        `    ${ref}.vm.network "forwarded_port", guest: 443, host: ${ports.gui}, host_ip: "127.0.0.1", auto_correct: true, id: "${vm.id}_gui"`
      );
    }

    if (vm.role === "wazuh_server" && ports.gui) {
      lines.push(
        `    ${ref}.vm.network "forwarded_port", guest: 443, host: ${ports.gui}, host_ip: "127.0.0.1", auto_correct: true, id: "${vm.id}_dashboard"`
      );
    }

    return lines.join("\n");
  }

  private allocatePorts(instances: GeneratedInstance[]): Map<string, PortAllocation> {
    const allocations = new Map<string, PortAllocation>();

    let edgePfSenseIndex = 0;
    let internalPfSenseIndex = 0;
    let debianIndex = 0;
    let wazuhDashboardIndex = 0;

    for (const vm of instances) {
      if (this.isEdgePfSense(vm)) {
        allocations.set(vm.id, {
          ssh: 2301 + edgePfSenseIndex,
          gui: 8443 + edgePfSenseIndex
        });
        edgePfSenseIndex += 1;
        continue;
      }

      if (this.isInternalPfSense(vm)) {
        allocations.set(vm.id, {
          ssh: 2311 + internalPfSenseIndex,
          gui: 8543 + internalPfSenseIndex
        });
        internalPfSenseIndex += 1;
        continue;
      }

      if (!this.isPfSense(vm)) {
        allocations.set(vm.id, {
          ssh: 2401 + debianIndex,
          gui: vm.role === "wazuh_server" ? 9443 + wazuhDashboardIndex : undefined
        });

        if (vm.role === "wazuh_server") {
          wazuhDashboardIndex += 1;
        }

        debianIndex += 1;
      }
    }

    return allocations;
  }

  private generateSshAccessLocalFile(
    outputDir: string,
    instances: GeneratedInstance[],
    portAllocations: Map<string, PortAllocation>
  ): void {
    const sshAccess: Record<string, unknown> = {};

    for (const vm of instances) {
      if (this.isPfSense(vm)) continue;
      if (vm.profile === "windows-server") continue;

      const ports = portAllocations.get(vm.id);

      if (!ports?.ssh) {
        console.warn(`[ssh-access] Pas de port SSH pour ${vm.id}, ignoré.`);
        continue;
      }

      sshAccess[vm.id] = {
        ssh_host: "127.0.0.1",
        ssh_port: ports.ssh,
        ssh_user: "vagrant",
        identity_file: "~/.vagrant.d/insecure_private_key",
        access_method: "edge_port_forward"
      };
    }

    const sshAccessPath = path.join(outputDir, "..", "ssh-access.local.json");

    this.writeTextAtomic(
      sshAccessPath,
      JSON.stringify(sshAccess, null, 2),
      0o600
    );

    console.log(`[ssh-access] Fichier généré : ${sshAccessPath}`);
  }

  private generateVagrantfile(
    instances: GeneratedInstance[],
    portAllocations: Map<string, PortAllocation>
  ): string {
    const vmBlocks = instances
      .map((vm) => {
        const ref = vm.id.replace(/-/g, "_");
        const networks = this.buildNetworkBlock(ref, vm);
        const ssh = this.buildSshBlock(ref, vm);
        const box = this.resolveBox(vm);
        const cpu = this.resolveCpu(vm);
        const memory = this.resolveMemory(vm);
        const providerExtra = this.buildProviderExtra(vm);
        const hostnameLine = this.buildHostnameLine(ref, vm);
        const forwardedPorts = this.buildForwardedPortsBlock(
          ref,
          vm,
          portAllocations.get(vm.id) ?? {}
        );

        return `
  config.vm.define "${vm.id}" do |${ref}|
    ${ref}.vm.box = "${box}"
${hostnameLine}
${ssh}

${forwardedPorts}

${networks}

    ${ref}.vm.provider "virtualbox" do |vb|
      vb.name = "${vm.id}"
      vb.cpus = ${cpu}
      vb.memory = ${memory}
      vb.gui = false${providerExtra}
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