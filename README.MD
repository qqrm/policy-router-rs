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
  - apply
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
The project is pinned to Rust nightly via `rust-toolchain.toml`; install it with `rustup toolchain install nightly` (rustfmt/clippy included) and use it when building locally.

## CLI

Daemon:
- policy-routerd --config <path>
- policy-routerd --log-level <level> (default: info, overridden by RUST_LOG)
- policy-routerd --watch (dev-only: auto-apply config changes)

Client:
- policy-routerctl status
- policy-routerctl apply
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
  - `apply` (apply config)
  - `reload` (compat; same behavior as apply)
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

Rules are defined as an ordered list of `[[rules]]` entries. Each rule sets an `egress`
and one matcher (`app`, `domain`, or `dst_ip_cidr`), or `app + domain` together for the
most specific tier.

Rule dimensions:
- app rules: `process_name -> egress`
- domain rules: `domain_suffix -> egress`
- dst_ip_cidr rules: `destination_ip/cidr -> egress`

Rules are evaluated in specificity tiers, top-to-bottom within each tier:
1) `app + domain`
2) `domain`
3) `dst_ip_cidr`
4) `app`
5) default egress

Within a tier, rules are evaluated in the exact order they appear in the config; the first
match wins. Rules that overlap in the same tier are rejected at config validation time with
clear diagnostics (ordering is not used to resolve conflicts). If a domain is unknown, only
app rules can match; otherwise default applies.

Example outcomes:
- `zen.exe` + `youtube.com` -> `proxy` (CIADPI)
- `zen.exe` + `chatgpt.com` -> `vpn` (sing-box)
- `ciadpi.exe` -> `direct`
- unknown app or domain -> `direct`

## Roadmap

This repo is intentionally split into incremental phases so each slice is reviewable and can be shipped without blocking the next one.

Current status (implemented and test-covered)
- Policy engine
  - Tiered matching: app+domain > domain > dst_ip_cidr > app > default
  - First-match-wins within each tier, preserving config order
  - Deterministic matching with exact + suffix match kinds for domains
  - Strict conflict validation for overlapping rules in the same tier
- Config
  - TOML config parsing + strict validation (egress ids, endpoint format, rule overlaps)
  - Include lists via "@file:<path>" inside app/domain rule fields
    - Relative to the including file, nested includes supported
    - Cycle detection + max depth limit (MAX_INCLUDE_DEPTH = 16)
    - Include dependencies are discovered and returned (best-effort canonicalized)
- Daemon + IPC + CLI
- policy-routerd IPC server (status/apply/reload/stop/explain/diagnostics)
  - policy-routerctl client with text + JSON output
  - Apply/reload applies new config atomically (ArcSwap) and keeps last-good on failure
- Manual apply (v1)
  - policy-routerctl apply triggers config load + apply
  - policy-routerd --watch enables dev-only auto apply on config/include changes

Queued small follow-ups (safe to bundle into the next task)
- IPC/CLI: expose last_reload_ms in StatusResponse/DiagnosticsResponse and print it in policy-routerctl (serde default for compatibility).
- Cargo metadata: Cargo.toml points to README.md while the repo uses README.MD (either rename file or update Cargo.toml).

What is NOT done yet (this is what blocks “project complete”)
- No traffic interception layer yet (nothing actually routes Windows traffic).
- No process/domain attribution pipeline for real connections yet (beyond “explain”).
- No packaging/installation UX yet (service/task, default config layout, logs).

MVP definition (“project complete”)
On Windows: after installing and starting the daemon, network traffic is routed per config rules:
- app rules and domain rules select an egress: direct / block / socks5 / singbox
- config apply works for both config.toml and include list files (watch is optional)
- basic observability exists (status/diagnostics + logs)

Planned remaining work (estimate: ~8–12 more tasks of similar size)

Phase 2 — Egress supervision (done)
- Implemented EgressSupervisor to start/stop external egress processes (sing-box, etc.) from config.
- Restart policy (backoff, max restarts, “never” vs “always” vs “on-failure”), structured logging.
- Lifecycle wired into policy-routerd (Stop request stops children; apply/reload updates desired set).

Phase 3 — Traffic interception + routing MVP (3–5 tasks)
3.1 Define the routing “plumbing” boundary: internal API that takes (process_path?, domain?, dest_ip?, dest_port?) and returns egress id + reason.
3.2 Interception layer on Windows (WFP callout/WinDivert/etc.) with a minimal integration surface (no policy logic inside).
3.3 Domain attribution path (DNS capture or SNI/HTTP Host extraction) feeding a short-lived cache mapping flows -> domain.
3.4 Policy decision -> route action (direct/block/proxy) implemented end-to-end.
3.5 Hardening: race-free cache eviction, startup/shutdown correctness, failure modes.

Phase 4 — Productization (2–3 tasks)
4.1 Config layout and “first run” UX (config.example, lists folder, documentation).
4.2 Windows install story (service or scheduled task), log file location, graceful updates.
4.3 CI packaging + release artifacts.

Notes
- Task numbering is sequential; if you roll multiple small fixes into a larger task, keep the numbers stable but mention “rolled into X.Y”.
- Additive fields in IPC must remain backward compatible via serde defaulting.
