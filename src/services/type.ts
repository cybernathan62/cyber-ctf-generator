export type RoleType =
  | "edge_firewall"
  | "internal_firewall"
  | "bastion"
  | "reverse_proxy"
  | "wazuh_server"
  | "zabbix_server"
  | "db_server"
  | "windows_server";

export type RoleVariant =
  | "simple"
  | "ha"
  | "cluster";

export type ZoneType =
  | "edge"
  | "management"
  | "dmz"
  | "soc"
  | "data"
  | "ad"
  | "transit"
  | "sync";

export type RequestedRole = {
  role: RoleType;
  variant: RoleVariant;
  zone: ZoneType;
  count: number;
  node_count: number;
};

export type LabDefinition = {
  name: string;
  required_roles: RequestedRole[];
  instances?: GeneratedInstance[];
};

export type GeneratedNic = {
  networkId: string;
  ip?: string;
};

export type GeneratedInstance = {
  id: string;
  hostname: string;
  profile: string;
  role: RoleType;
  variant: RoleVariant;
  zone: ZoneType;
  group_index: number;
  node_index: number;
  nics: GeneratedNic[];
};

// Réseaux générés
export type NetworkPurpose = "zone" | "transit" | "sync";

export type GeneratedNetwork = {
  id: string;
  purpose: NetworkPurpose;
  zone: ZoneType;
  link_name?: string;
  cidr?: string;
  gateway?: string | null;
};

export type GeneratedPlan = {
  lab_name: string;
  lab_id: number;
  networks: GeneratedNetwork[];
  hosts: GeneratedInstance[];
};