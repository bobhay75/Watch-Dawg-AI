// Sentinel Network Guardian v1: pure, offline, fail-closed policy evaluation.
// This module does NOT intercept traffic. A privileged gateway adapter must enforce decisions.
export const MODES = Object.freeze(["lockdown", "approved", "isolated"]);
const MAC = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const IP4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
export function normalizeDevice(device) {
  if (!device || typeof device !== "object") throw new TypeError("Device required");
  const mac = String(device.mac ?? "").toLowerCase();
  if (!MAC.test(mac)) throw new TypeError("Invalid MAC address");
  const mode = device.mode ?? "lockdown";
  if (!MODES.includes(mode)) throw new TypeError("Invalid policy mode");
  const destinations = device.destinations ?? [];
  if (!Array.isArray(destinations) || destinations.length > 64 ||
      destinations.some(x => typeof x !== "string" || !x.trim() || x.length > 253))
    throw new TypeError("Invalid destination allowlist");
  return { mac, label: String(device.label ?? "").slice(0, 80),
    mode, destinations: [...new Set(destinations.map(x => x.toLowerCase()))] };
}
export function evaluateConnection(devices, connection) {
  if (!Array.isArray(devices)) throw new TypeError("Device inventory required");
  const mac = String(connection?.mac ?? "").toLowerCase();
  const destination = String(connection?.destination ?? "").toLowerCase();
  const device = devices.map(normalizeDevice).find(x => x.mac === mac);
  if (!device) return { decision: "deny", reason: "unknown-device" };
  if (device.mode === "lockdown") return { decision: "deny", reason: "privacy-lockdown" };
  if (device.mode === "isolated") return { decision: "deny", reason: "internet-isolated" };
  if (!destination || !device.destinations.includes(destination))
    return { decision: "deny", reason: "destination-not-approved" };
  return { decision: "allow", reason: "explicit-approval" };
}
export function classifyObservation(event) {
  if (!event || typeof event !== "object") throw new TypeError("Observation required");
  if (event.type === "firewall" && event.enforced === true &&
      (event.action === "allow" || event.action === "deny"))
    return { status: "verified", finding: "gateway-decision", action: event.action };
  if (event.type === "radio")
    return { status: "unattributed", finding: "wireless-signal-observed" };
  return { status: "unverified", finding: "requires-review" };
}
export function redactConnection(event) {
  const result = evaluateConnection(event.devices ?? [], event);
  return { timestamp: new Date().toISOString(), device: String(event.mac ?? "").toLowerCase(),
    destination: String(event.destination ?? "").slice(0, 253), ...result };
}
