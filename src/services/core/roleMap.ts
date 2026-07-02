import type { RoleType, RoleVariant, ZoneType } from "./type.js";
import { ROLE_TYPES, ROLE_VARIANTS, ZONE_TYPES } from "./type.js";

export type RoleDefinition = {
  naming: string;
  profile: string;
  default_zone: ZoneType;
  default_variant: RoleVariant;
};

export const ROLE_MAP = {
  edge_firewall: {
    naming: "pfsense-edge",
    profile: "pfsense",
    default_zone: "edge",
    default_variant: "simple"
  },

  internal_firewall: {
    naming: "pfsense-internal",
    profile: "pfsense",
    default_zone: "transit",
    default_variant: "simple"
  },

  bastion: {
    naming: "bastion",
    profile: "debian-wazuh",
    default_zone: "management",
    default_variant: "simple"
  },

  reverse_proxy: {
    naming: "reverse-proxy",
    profile: "debian-wazuh",
    default_zone: "dmz",
    default_variant: "simple"
  },

  wazuh_server: {
    naming: "wazuh",
    profile: "debian-wazuh",
    default_zone: "soc",
    default_variant: "simple"
  },

  zabbix_server: {
    naming: "zabbix",
    profile: "debian-wazuh",
    default_zone: "soc",
    default_variant: "simple"
  },

  opencti_server: {
    naming: "opencti",
    profile: "debian-wazuh",
    default_zone: "soc",
    default_variant: "simple"
  },

  passbolt_server: {
    naming: "passbolt",
    profile: "debian-wazuh",
    default_zone: "management",
    default_variant: "simple"
  },

  soc_ai_agent: {
    naming: "soc-ai",
    profile: "debian-wazuh",
    default_zone: "soc",
    default_variant: "simple"
  },

  ids_sensor: {
    naming: "suricata",
    profile: "debian-wazuh",
    default_zone: "soc",
    default_variant: "simple"
  },

  db_server: {
    naming: "db-server",
    profile: "debian-wazuh",
    default_zone: "data",
    default_variant: "simple"
  },

  opensearch_server: {
    naming: "opensearch",
    profile: "debian-wazuh",
    default_zone: "soc",
    default_variant: "simple"
  },

  rabbitmq_server: {
    naming: "rabbitmq",
    profile: "debian-wazuh",
    default_zone: "soc",
    default_variant: "simple"
  },

  redis_server: {
    naming: "redis",
    profile: "debian-wazuh",
    default_zone: "soc",
    default_variant: "simple"
  },

  windows_server: {
    naming: "windows-server",
    profile: "windows-server",
    default_zone: "ad",
    default_variant: "simple"
  }
} satisfies Record<RoleType, RoleDefinition>;

export function isValidRole(value: string): value is RoleType {
  return (ROLE_TYPES as readonly string[]).includes(value);
}

export function isValidZone(value: string): value is ZoneType {
  return (ZONE_TYPES as readonly string[]).includes(value);
}

export function isValidVariant(value: string): value is RoleVariant {
  return (ROLE_VARIANTS as readonly string[]).includes(value);
}

export function getRoleDefinition(role: RoleType): RoleDefinition {
  return ROLE_MAP[role];
}

export { ROLE_TYPES, ROLE_VARIANTS, ZONE_TYPES };