import type { RoleType } from "./type.js";

export type Protocol = "tcp" | "udp" | "icmp" | "any";

/**
 * Legacy aliases conservés pour compatibilité avec les règles pfSense.
 * Ils ne doivent pas devenir des RoleType officiels tant qu'ils ne génèrent
 * pas de VM dédiées dans le lab.
 */
export type LegacyRoleAlias =
  | "database"
  | "mariadb_server"
  | "mysql_server";

/**
 * Sélecteurs utilisés par le moteur de flux pfSense.
 *
 * Important :
 * - RoleType = rôles officiels qui peuvent générer des VM.
 * - LegacyRoleAlias = anciens alias encore utilisés dans les règles.
 * - "any" = sélecteur pfSense, pas un rôle de VM.
 */
export type RoleSelector = RoleType | LegacyRoleAlias | "any";

export type RoleFlow = {
  fromRoles: RoleSelector[];
  toRoles: RoleSelector[];
  protocol: Protocol;
  ports?: string[];
  description: string;
};

export const DB_ROLES: RoleSelector[] = [
  "db_server",
  "database",
  "mariadb_server",
  "mysql_server"
];

export const FIREWALL_ROLES: RoleType[] = [
  "edge_firewall",
  "internal_firewall"
];

export const OPENCTI_ROLES: RoleType[] = [
  "opencti_server"
];

export const PASSBOLT_ROLES: RoleType[] = [
  "passbolt_server"
];

export const OPENSEARCH_ROLES: RoleType[] = [
  "opensearch_server"
];

export const RABBITMQ_ROLES: RoleType[] = [
  "rabbitmq_server"
];

export const REDIS_ROLES: RoleType[] = [
  "redis_server"
];

export const WAZUH_AGENT_ROLES: RoleSelector[] = [
  "bastion",
  "reverse_proxy",
  "db_server",
  "database",
  "mariadb_server",
  "mysql_server",
  "ids_sensor",
  "soc_ai_agent",
  "zabbix_server",
  "opencti_server",
  "passbolt_server"
];

export const ZABBIX_AGENT_ROLES: RoleSelector[] = [
  "bastion",
  "opencti_server",
  "reverse_proxy",
  "db_server",
  "database",
  "mariadb_server",
  "mysql_server",
  "ids_sensor",
  "soc_ai_agent",
  "wazuh_server",
  "zabbix_server",
  "passbolt_server"
];