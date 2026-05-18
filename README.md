CTF Lab Generator — Wazuh / SOC-AI Infrastructure
Overview

This project generates fully automated cybersecurity lab environments using:

pfSense
Wazuh
Zabbix
SOC-AI agents
Vagrant
VirtualBox
TypeScript automation

The objective is to transform a natural-language request into:

a complete network plan,
infrastructure definitions,
VM provisioning,
security configuration,
monitoring integration,
Wazuh agent onboarding,
SOC-AI deployment.

Example:

npm run infra -- "je veux une infra avec un pfsense edge, un wazuh, un zabbix et un soc-ai"
Features
Infrastructure generation

The generator automatically creates:

Vagrantfile
Network topology
VLAN/IP plan
Security policies
Firewall structure
Monitoring integration
Wazuh enrollment
Runtime secrets
Supported services
Edge security
pfSense edge firewall
NAT
segmentation
DMZ support
internal routing
Monitoring
Wazuh Manager
Wazuh Indexer
Wazuh Dashboard
Wazuh Agents
Zabbix
SOC-AI

SOC-AI nodes can:

authenticate against Wazuh API
retrieve agents
retrieve alerts
monitor infrastructure state
operate in read-only mode
Project structure
src/services/
├── infra.ts
├── labGenerator.ts
├── wazuhLiveConfigPatcher.ts
├── wazuhAgentLivePatcher.ts
├── socAiLivePatcher.ts
├── pfsenseLiveConfigPatcher.ts
├── policyEngine.ts
└── generateNetworkPlan.ts

Generated outputs:

outputs/
├── generated-lab/
├── secrets/
├── wazuh-runtime/
├── network-plan.json
├── lab-definition.json
└── policy-validation.json
Deployment modes
LAB mode

Default mode.

Uses:

wazuh:wazuh

for API authentication.

Recommended for:

local labs
PoC
testing
development
PRODUCTION mode

Production mode enables external API credentials.

Environment variables:

$env:WAZUH_DEPLOYMENT_MODE="production"
$env:WAZUH_API_USER="soc-ai-reader"
$env:WAZUH_API_PASSWORD="StrongPassword"

Launch:

npm run infra -- "je veux une infra avec un pfsense edge, un wazuh, un zabbix et un soc-ai"
Wazuh API validation

Generate a JWT token:

TOKEN=$(curl -sk -u wazuh:wazuh -X POST "https://WAZUH_IP:55000/security/user/authenticate?raw=true")

Validate access:

curl -k -H "Authorization: Bearer $TOKEN" "https://WAZUH_IP:55000/agents"

Expected result:

"status": "active"
Security model
Current protections
runtime-generated secrets
.gitignore protection
hidden password logs
chmod 600 on generated secrets
API read-only logic
policy validation engine
Production recommendations
Strongly recommended
replace wazuh:wazuh
use dedicated RBAC users
rotate credentials
use Vault/Passbolt/Bitwarden
isolate SOC-AI nodes
enable mTLS
harden systemd services
separate bootstrap from provisioning
Known limitations
Current limitations
Wazuh API RBAC provisioning not fully automated
single-node Wazuh deployment focus
secrets stored locally in JSON
repeated deployments are not fully idempotent
Troubleshooting
Invalid credentials

Cause:

API user does not exist
wrong Wazuh API password
confusion between Indexer credentials and Wazuh API credentials

Validation:

curl -sk -u wazuh:wazuh -X POST "https://WAZUH_IP:55000/security/user/authenticate?raw=true"
Invalid token

Cause:

corrupted JWT token
token copied manually

Fix:

Always use:

TOKEN=$(curl ...)

Never paste JWT manually.

EDGE_REQUIRED policy error

Cause:

Infrastructure missing edge firewall.

Fix:

Add:

pfsense edge

inside the prompt.

Example deployment
npm run infra -- "je veux une infra avec un pfsense edge, un wazuh, un zabbix et un soc-ai"

Example generated nodes:

pfsense-edge-1
wazuh-1
zabbix-1
soc-ai-1
Goals

Long-term objectives:

full autonomous infrastructure generation
reproducible cyber ranges
NIS2-ready architecture
SOC automation
AI-assisted monitoring
attack simulation
detection engineering
automated evidence generation
License

Internal project / educational cyber lab environment.