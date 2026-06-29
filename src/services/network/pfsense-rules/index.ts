import type { RoleFlow } from "../../core/roles.js";

import { OPENCTI_FLOWS } from "./opencti.rules.js";
import { WAZUH_FLOWS } from "./wazuh.rules.js";
import { ZABBIX_FLOWS } from "./zabbix.rules.js";
import { BASTION_FLOWS } from "./bastion.rules.js";
import { PASSBOLT_RULES } from "./passbolt.rules.js";
import { DB_SERVER_FLOWS } from "./db-server-rules.js";

export const ALL_ROLE_FLOWS: RoleFlow[] = [
  ...OPENCTI_FLOWS,
  ...WAZUH_FLOWS,
  ...ZABBIX_FLOWS,
  ...BASTION_FLOWS,
  ...PASSBOLT_RULES,
  ...DB_SERVER_FLOWS
];

export {
  OPENCTI_FLOWS,
  WAZUH_FLOWS,
  ZABBIX_FLOWS,
  BASTION_FLOWS,
  PASSBOLT_RULES,
  DB_SERVER_FLOWS
};