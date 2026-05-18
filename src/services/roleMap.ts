import { RoleType } from "./type.js";

export const ROLE_MAP: Record<
  RoleType,
  {
    naming: string;
    profile: string;
    default_zone: string;
    default_variant: string;
  }
> = {
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
  soc_ai_agent: {
    naming: "soc-ai",
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
  db_server: {
    naming: "db-server",
    profile: "debian-wazuh",
    default_zone: "data",
    default_variant: "simple"
  },
  windows_server: {
    naming: "windows-server",
    profile: "windows-server",
    default_zone: "ad",
    default_variant: "simple"
  }
};