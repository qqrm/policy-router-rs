# SmartDPI Router RS

SmartDPI Router RS is a Windows user mode traffic router that applies domain and app based policies to send traffic through one of multiple egress paths:
- VPN core (sing-box VLESS, etc)
- DPI bypass proxy (CIADPI or any local SOCKS5/HTTP proxy)
- DIRECT (no proxy)

The main goal is to route selected domains (example: YouTube) through a dedicated DPI bypass proxy while keeping the rest of traffic on VPN or DIRECT, with strict loop prevention.

## What we want

We want a single, configurable router that supports:

1) Domain based routing (primary)
- domain -> DPI bypass proxy (CIADPI)
- domain -> VPN core (sing-box local proxy)
- domain -> DIRECT

2) App based routing (secondary)
- app -> DPI bypass proxy
- app -> VPN core
- app -> DIRECT

3) Proxy routing for selected domains
- Explicitly send YouTube domains to CIADPI even when other traffic goes through VPN
- Keep CIADPI stable by avoiding TUN related loop and reassembly issues

4) Loop prevention (hard requirement)
- CIADPI process must never be routed into VPN core
- VPN core must never be routed into CIADPI
- Safe defaults that do not create feedback loops

## MVP (Phase 1)

Primary goals:
- Route YouTube domains to CIADPI (SOCKS5 on 127.0.0.1:1080)
- Route all other domains to sing-box local proxy (mixed/socks/http)
- Allow DIRECT for local and optional country rules
- Provide clear logs: which rule matched and which egress was selected

Deliverables:
- Single CLI binary
- YAML config for rules and endpoints
- PAC generation + system proxy apply/restore
- Optional process supervision for:
  - sing-box
  - CIADPI
- Clean teardown on exit (restore Windows proxy settings)

## MVP constraints

- No full system TUN routing
- No kernel drivers
- No DPI logic inside this project
- No GUI in Phase 1

## Configuration outline

Egress endpoints (example):
- `ciadpi`: `socks5://127.0.0.1:1080`
- `vpn`: `mixed://127.0.0.1:1488`
- `direct`: `direct://`

Routing rules (example):
- YouTube domains -> `ciadpi`
- ChatGPT and Discord -> `vpn`
- `*.ru`, `*.lan`, private networks -> `direct`

App routing (example):
- `ciadpi.exe` -> `direct`
- `zen.exe` -> `vpn` (unless domain rule sends to `ciadpi`)

## Roadmap

Phase 2:
- Rule sets and include files
- Better app routing options on Windows
- Optional DNS policy layer for target domains

Phase 3:
- GUI (optional)
- Profiles and presets
- Observability and metrics

## License

TBD
