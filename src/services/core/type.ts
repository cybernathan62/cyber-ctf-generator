export const ROLE_TYPES = [
  "edge_firewall",
  "internal_firewall",
  "bastion",
  "reverse_proxy",
  "wazuh_server",
  "zabbix_server",
  "opencti_server",
  "passbolt_server",
  "soc_ai_agent",
  "ids_sensor",
  "db_server",
  "opensearch_server",
  "rabbitmq_server",
  "redis_server",
  "windows_server"
] as const;

export type RoleType = (typeof ROLE_TYPES)[number];

export const ROLE_VARIANTS = ["simple", "ha", "cluster"] as const;

export type RoleVariant = (typeof ROLE_VARIANTS)[number];

export const ZONE_TYPES = [
  "edge",
  "management",
  "dmz",
  "soc",
  "data",
  "ad",
  "transit",
  "sync"
] as const;

export type ZoneType = (typeof ZONE_TYPES)[number];

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

export type NetworkPlanHostInterface = {
  name: string;
  network_id: string;
  ip?: string;
  gateway?: string | null;
  dns?: string[];
  mode?: "dhcp";
};

export type NetworkPlanStaticRoute = {
  name: string;
  destination: string;
  gateway: string;
};

export type NetworkPlanHost = {
  id: string;
  role: RoleType;
  variant?: RoleVariant;
  zone?: ZoneType;
  profile: string;
  interfaces: NetworkPlanHostInterface[];
  default_gateway?: string;
  static_routes?: NetworkPlanStaticRoute[];
};

export type NetworkPlanZoneDefinition = {
  network_id: string;
  vlan_id: number;
  cidr: string;
  gateway: string;
  zone_type: ZoneType;
};

export type NetworkPlan = {
  lab_name: string;
  lab_id: number;
  generation_mode: "randomized_definition";
  rules: {
    ip_schema: string;
    gateway_strategy: string;
    host_strategy: string;
    vlan_range: [number, number];
    host_range: [number, number];
    reserved_hosts: number[];
  };
  zone_definitions: NetworkPlanZoneDefinition[];
  hosts: NetworkPlanHost[];
};