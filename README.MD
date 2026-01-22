# SmartDPI Router RS

SmartDPI Router RS is a Windows traffic router focused on one thing: split tunneling enforcement.

It provides policy based routing by process and by domain, sending traffic into one of multiple egress paths:

- VPN path: a local VPN core proxy (sing-box VLESS, etc)
- DPI bypass path: a local SOCKS5 or HTTP proxy (CIADPI) for targets like YouTube
- DIRECT: no proxy
- BLOCK: deny traffic

The goal is to keep DPI bypass tools stable (CIADPI must not break), while still having a working "VPN for selected apps and domains".

## What we are building

We are building a router with two layers:

1) Policy Engine (pure logic)
- Reads config (rules)
- Decides where a flow must go: vpn | proxy | direct | block
- Explains why a decision was made (matched rule)

2) Split Tunneling Enforcement (Windows)
- Enforces policy for real traffic
- Per app routing based on process identity
- Optional domain routing via DNS correlation (domain -> IP cache)
- Loop prevention to avoid self sabotage

This is the core of the project: TUN with real per app bypass, so some processes never enter the VPN tunnel.

## High level architecture

We split the implementation into three parts:

1) `policy-routerd` (daemon)
- Long running process
- Owns enforcement lifecycle
- Applies and maintains system state (WFP, routes, DNS cache, etc)
- Optionally supervises external egress processes (sing-box, CIADPI)
- Exposes a local control API (IPC)

2) `policy-routerctl` (client)
- CLI tool to manage the daemon
- Sends commands via IPC:
  - status
  - reload
  - stop
  - explain
  - diagnostics

3) `policy-router-rs` (library)
- Shared types
- Config parsing
- Policy engine
- Rule matching and explanation
- Domain suffix matching helpers

This separation is intentional:
- daemon is the only component that touches Windows networking
- ctl is safe to run anytime and never changes global state directly
- GUI (Phase 3) will reuse the same IPC API as `policy-routerctl`

## IPC

Daemon and client communicate via local only IPC.

## Build prerequisites

Building requires clang/libclang because the `netstat2` dependency uses bindgen for Windows APIs.

## CLI

Daemon:
- policy-routerd --config <path>
- policy-routerd --log-level <level> (default: info, overridden by RUST_LOG)

Client:
- policy-routerctl status
- policy-routerctl reload
- policy-routerctl stop
- policy-routerctl explain --process <name> --domain <domain>

Output format:
- default is human readable text
- use --format json for stable machine readable output


Target for Windows:
- Named Pipes (recommended)

Optional later:
- localhost HTTP API (debug only, locked down)

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

## Why PAC or system proxy is not enough

PAC or system proxy only works for apps that respect proxy settings.

This project targets the stronger requirement:
- route by process identity
- enforce routing even if the app ignores proxy settings

So enforcement is done at the Windows networking layer (split tunneling).

## MVP scope

### Phase 1: policy engine + daemon and ctl skeleton

Policy:
- TOML config
- app rules + domain rules
- decision output: vpn | proxy | direct | block
- logs: matched rule + selected egress

Daemon and ctl:
- daemon process exists and stays running
- ctl can connect via IPC and request:
  - `explain` decision for (process, domain)
  - `status`
  - `reload` (re read config)
  - `stop` (clean teardown)

Enforcement (minimal, evolving):
- start/stop supervision for:
  - sing-box core (optional)
  - CIADPI (optional)
- prepare enforcement layer that can route by process
  - first focus: process based vpn vs direct vs proxy
  - then: domain based routing via DNS cache

### Explicit non goals for Phase 1
- full featured GUI
- geoip/geosite management
- DPI bypass logic inside this repo
- "works without admin permissions"

## Configuration (concept)

Two rule dimensions:
- app rules: `process_name -> egress`
- domain rules: `domain_suffix -> egress`

Decision priority:
1) block rules (app, domain)
2) domain rules
3) app rules
4) default egress

For non-block rules, matching is evaluated by egress kind in a fixed order:
Singbox first, then Socks5, then Direct. Block rules always take precedence
and are evaluated before any non-block rules. The ordering does not depend on
egress id names or the order of keys in the TOML file, ensuring deterministic
results even when patterns overlap.

Example outcomes:
- `zen.exe` + `youtube.com` -> `proxy` (CIADPI)
- `zen.exe` + `chatgpt.com` -> `vpn` (sing-box)
- `ciadpi.exe` -> `direct`
- unknown app or domain -> `direct`

## Roadmap

Phase 2:
- stable split tunneling enforcement implementation (WFP)
- domain routing via DNS correlation cache
- rule sets and includes

Phase 3:
- GUI (optional)
- profiles, presets, metrics

## License

MIT
