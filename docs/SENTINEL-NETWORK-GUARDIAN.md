# Sentinel Network Guardian v1 — policy core

Status: **offline policy prototype only**. No router integration, packet capture, RF monitoring, firewall changes, or real traffic blocking is implemented. This module is intentionally independent of the existing financial-audit and field-security code.

## Security model

- Unknown MAC addresses: deny by default.
- Known devices default to `lockdown` (deny all outbound traffic).
- `isolated`: deny internet access.
- `approved`: allow only explicitly listed exact destination strings.
- An observed RF signal is **unattributed**, never evidence of recording or surveillance.
- A firewall event is marked verified only if a trusted gateway adapter confirms enforcement.

The evaluator is a *policy decision point*, not a *policy enforcement point*. A future gateway adapter must translate rules to real firewall/DNS enforcement, handle DHCP/IP-to-MAC binding, IPv6, DNS changes, encrypted DNS, VPNs, client isolation, and fail-closed behavior. MAC addresses can be spoofed. Domain allowlisting alone cannot ensure that approved encrypted connections contain no telemetry or audio.

## Run tests

```bash
node --test sentinel/network-guardian.test.mjs
```

## Portable hotspot architecture

Phone hotspot or T-Mobile hotspot → user-owned OpenWrt travel router → protected devices. Only traffic routed through that gateway can be controlled. Wi-Fi monitor mode and SDR receivers are separate optional passive sensors; they cannot identify all radio signals or the contents of encrypted transmissions. An offline microphone or camera may still record locally. Hardware disconnection or physically removing power is required for stronger assurance.

## Next integration milestones

1. Local-only inventory and consent/ownership controls.
2. Read-only OpenWrt ubus/SSH adapter with explicit credential handling.
3. Dry-run ruleset preview and tests for IPv4, IPv6, and reconnect.
4. Human-approved apply/revert with rollback timer and emergency access.
5. Gateway enforcement receipts and locally stored redacted logs.
6. Passive RF observations, with no attribution absent corroborating evidence.

Do not deploy these prototype decisions as production firewall rules.
