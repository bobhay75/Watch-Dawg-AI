// Offline gateway planning only. Never executes router commands.
import { evaluateConnection } from "./network-guardian.mjs";
import { isIP } from "node:net";
export function planGateway({devices=[],leases=[],connections=[],gateway={}}={}) {
  if (!Array.isArray(devices)||!Array.isArray(leases)||!Array.isArray(connections)) throw new TypeError("Arrays required");
  const warnings=[];
  const seen=new Map();
  for(const lease of leases){
    if(!lease || !isIP(lease.ip) || !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(lease.mac??"")) throw new TypeError("Invalid lease");
    const ip=lease.ip.toLowerCase(),mac=lease.mac.toLowerCase();
    if(seen.has(ip)&&seen.get(ip)!==mac) warnings.push("IP conflict: "+ip);
    seen.set(ip,mac);
  }
  if(gateway.ipv6Enabled!==false) warnings.push("IPv6 requires independent firewall verification");
  if(gateway.dnsInterceptVerified!==true) warnings.push("DNS bypass possible: direct IP, DoH, DoT, VPN");
  if(gateway.reconnected) warnings.push("Reconnection: refresh leases and revalidate before enforcement");
  const decisions=connections.map(c=>{
    const family=isIP(c.destination??"");
    const observedMac=seen.get(String(c.sourceIp??"").toLowerCase());
    const claimedMac=String(c.mac??"").toLowerCase();
    const identityVerified=!!observedMac && observedMac===claimedMac && !warnings.some(w=>w.startsWith("IP conflict:"));
    const policy=identityVerified?evaluateConnection(devices,c):{decision:"deny",reason:"unverified-device-binding"};
    return {sourceIp:c.sourceIp??null,ipFamily:family||"domain",decision:policy.decision,reason:policy.reason,classification:"simulated",enforced:false};
  });
  return {mode:"dry-run",commandsExecuted:0,firewallModified:false,decisions,warnings,rollback:{requiredBeforeApply:true,managementAccessMustRemain:true,automaticRevertRequired:true}};
}
