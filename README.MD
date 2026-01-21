# SmartDPI Router RS

SmartDPI Router RS is a Windows traffic router focused on one thing: **split tunneling enforcement**.

It provides **policy based routing by process and by domain**, sending traffic into one of multiple egress paths:

- VPN path: a local VPN core proxy (sing-box VLESS, etc)
- DPI bypass path: a local SOCKS5/HTTP proxy (CIADPI) for targets like YouTube
- DIRECT: no proxy
- BLOCK: deny traffic

The goal is to keep DPI bypass tools stable (CIADPI must not break), while still having a working “VPN for selected apps and domains”.

## What we are building

We are building a router with two layers:

1) Policy Engine (pure logic)
- Reads config (rules)
- Decides where a flow must go: `vpn | proxy | direct | block`
- Explains why a decision was made (matched rule)

2) Split Tunneling Enforcement (Windows)
- Enforces policy for real traffic
- Per app routing based on process identity
- Optional domain routing via DNS correlation (domain -> IP cache)

This is the core of the project: **TUN with real per app bypass**, so some processes never enter the VPN tunnel.

## Egress paths

### VPN egress
A local proxy endpoint (provided by sing-box or compatible core):
- inbound on `127.0.0.1:1488`
- outbound goes to provider (VLESS, Reality, etc)

### DPI bypass egress
A dedicated local proxy endpoint (CIADPI or compatible):
- SOCKS5 on `127.0.0.1:1080`
- used for YouTube domains
- must stay outside VPN and outside our packet mangling

### DIRECT
No proxy, system networking as is.

### BLOCK
Drop traffic intentionally.

## Hard requirements

1) App routing must work
- Selected apps go to VPN
- Selected apps go to CIADPI
- Selected apps go DIRECT
- Selected apps are BLOCKED

2) Domain routing must work (for the apps we route)
- YouTube domain list -> CIADPI
- VPN whitelist domains -> VPN
- Optional direct domains -> DIRECT

3) No loop and no self sabotage
- CIADPI process must never be routed into VPN
- VPN core process must never be routed into CIADPI
- defaults must be safe

## Why PAC/system proxy is not enough

PAC/system proxy only works for apps that respect proxy settings.

This project targets the stronger requirement:
- route by process identity
- enforce routing even if the app ignores proxy settings

So enforcement is done at the Windows networking layer (split tunneling).

## MVP scope

### Phase 1: policy engine + skeleton enforcement

Policy:
- TOML config
- app rules + domain rules
- decision output: `vpn | proxy | direct | block`
- logs: matched rule + selected egress

Enforcement (minimal, evolving):
- start/stop supervision for:
  - sing-box core
  - CIADPI
- build the enforcement layer that can route by process
  - first focus: process based “vpn vs direct vs proxy”
  - then: domain based routing via DNS cache

### Explicit non goals for Phase 1
- full featured GUI
- geoip/geosite management
- DPI bypass logic inside this repo
- “works without admin permissions”

## Configuration (concept)

Two rule dimensions:
- app rules: `process_name -> egress`
- domain rules: `domain_suffix -> egress`

Decision priority:
1) block rules (app, domain)
2) app rules
3) domain rules
4) default egress

Example outcomes:
- `zen.exe` + `youtube.com` -> `proxy` (CIADPI)
- `zen.exe` + `chatgpt.com` -> `vpn` (sing-box)
- `ciadpi.exe` -> `direct`
- unknown app/domain -> `direct`

## Roadmap

Phase 2:
- stable split tunneling enforcement implementation
- domain routing via DNS correlation cache
- rule sets and includes

Phase 3:
- GUI (optional)
- profiles, presets, metrics

## License

MIT
