import type { VmProfileName, VmProfile } from "./type.ts";
export const VM_PROFILES: Record<VmProfileName, VmProfile> = {
    pfsense: {
        name: "pfsense",
        box: "cyberctf/pfsense",
        family: "pfsense",
        cpus: 2,
        memory: 2048,
        defaultUser: "vagrant",
        ssh: {
            username: "vagrant",
            privateKeyPath: "./keys/ssh/vagrant/vagrant.key.rsa",
            insertKey: false,
        },
    },

    "debian-wazuh": {
        name: "debian-wazuh",
        box: "cyberctf/debian_wazuh",
        family: "debian",
        cpus: 4,
        memory: 4096,
        defaultUser: "vagrant",
        ssh: {
            username: "vagrant",
            privateKeyPath: "./keys/ssh/vagrant/vagrant.key.rsa",
            insertKey: false,
        },
    },
};
