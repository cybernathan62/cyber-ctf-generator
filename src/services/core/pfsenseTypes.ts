export type PfSenseAction = "pass" | "block";
export type PfSenseProtocol = "any" | "tcp" | "udp" | "icmp";
export type PfSenseAliasType = "host" | "network" | "port";

export type PfSenseAlias = {
  name: string;
  type: PfSenseAliasType;
  values: string[];
  description?: string;
};

export type PfSenseFirewallRule = {
  interface: string;
  action: PfSenseAction;
  protocol: PfSenseProtocol;
  source: string;
  destination: string;
  destinationPort?: string;
  destinationPorts?: string;
  description: string;
};

export type PfSenseNatRule = {
  interface: string;
  protocol: "tcp" | "udp";
  externalPort: string;
  internalIp: string;
  internalPort: string;
  description: string;
};

export type PfSensePlan = {
  firewall: string;
  aliases: PfSenseAlias[];
  rules: PfSenseFirewallRule[];
  nat: PfSenseNatRule[];
};