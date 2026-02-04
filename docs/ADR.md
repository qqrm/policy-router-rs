# Router-RS — Questionnaire Answers (Single Source of Truth) — EN

This document captures the decisions and answers agreed during the A–F questionnaire. It is intended to be stable; future changes should be recorded via ADRs.

## A. Interception and Route Enforcement (core)

A1) Target interception mechanism in v1  
Decision: **Windows Filtering Platform (WFP) callout driver** is the primary interception/enforcement mechanism in v1.

A2) Kernel driver allowed in v1?  
Decision: **Yes. Kernel driver is mandatory in v1.** We build “properly from the start” to avoid redesign/rewrite later.

A3) Domain-based routing: domain sources in v1 (must-have)  
Decision: **TLS SNI + HTTP Host + QUIC (SNI/ALPN where applicable)** are must-have in v1.  
Note: DNS may be used as auxiliary correlation/telemetry, but **not** as the only source of truth.

## Driver signing / distribution of the driver

Signing strategy  
Decision:
- **Development builds:** test-signed driver (for speed).
- **Public releases:** **Microsoft attestation signing** via Windows Hardware Dev Portal.

Rationale: avoid “unsigned/self-signed on GitHub for normal users”; production installs require proper signing.

## B. Attribution (process ↔ flow ↔ domain)

B4) Flow-to-process mapping in v1  
Decision: **WFP ALE metadata** is the source of truth (PID + stable identifiers such as AppID/image/path).  
Constraints:
- Must handle PID reuse safely (do not rely on PID alone).
- ETW/netstat are not primary attribution; at most diagnostics/aux tooling.

B5) If domain is unknown (no SNI/Host/QUIC signal, raw TCP, etc.)  
Decision: **App-based fallback → default.**
- If domain is unknown, domain-scoped rules do not match.
- Apply app rule if available; otherwise apply default.
- No “require DNS correlation” gating in v1.

## Policy rules semantics (how rules are evaluated)

Rule shapes allowed  
Decision: a rule may match on:
- `app + domain`
- `domain`
- `app`
- `default` (catch-all)

Final evaluation model (chosen) — Model #2  
Decision: **Two-stage matching: precedence by specificity, top-to-bottom within each specificity tier.**

Tiers (in evaluation order):
1) `app + domain` rules
2) `domain` rules
3) `app` rules
4) `default`

Within each tier: **evaluate rules top-to-bottom; first match wins.**

Conflict handling / validation  
Decision: **Conflicts are not allowed.**  
Behavior:
- Config apply performs strict validation.
- On conflicts, config is rejected with a clear, user-facing diagnostic explaining overlapping rules and what to change.
- Do not “guess” resolution beyond the defined precedence/tier rules.

## C. Egress model

C6) Egress types in v1  
Decision: **SOCKS5-centric egress model.**

Supported egress actions/types in v1:
- `direct`
- `block`
- `socks5_endpoint` (local or remote endpoint)
- `process_provides_socks5` (managed process that exposes local SOCKS5)

HTTP proxy as a separate egress type  
Decision: **Out of scope for v1** (if needed later, handle via an egress process/adapter rather than complicating core).

C7) VPN egress: sing-box TUN vs SOCKS-outbound only  
Decision: **VPN egress uses sing-box in TUN mode** (as a managed egress process).  
Important: regardless of TUN, loop-prevention rules apply (see below).

## Loop prevention (hard requirement)

Loop prevention requirement  
Decision: **Hard requirement for v1: no routing loops.**

Best-practice approach selected  
Decision: **Egress processes are exempt from interception/enforcement** (WFP bypass by AppID/image/path).  
Additionally:
- Exempt loopback traffic to local egress endpoints (e.g., 127.0.0.1:PORT) to prevent self-intercept loops.

Component boundary: no Nekobox in the chain  
Decision: **Nekobox/GUI “sandbox” is not part of the production architecture.**  
Our daemon manages egress agents directly; third-party UI layers must not sit inside the routing chain.

## D. Policy rule dimensions (what’s in MVP v1)

D8) Rule dimensions in v1  
Decision: v1 supports:
- `app`
- `domain`
- `dst_ip_cidr` (simple IP/CIDR destination matching)

Explicitly deferred to v2:
- `port/proto`
- GeoIP-based `geo`

Note: “TLD routing” (e.g., `*.ru`) is treated as **domain suffix matching**, not GeoIP.

D9) Priority for block  
Decision: **`block` is a normal action** of any rule and/or the default action.  
No separate global “block layer”; block follows the same tier + top-to-bottom semantics as route actions.

## E. IPC and UX

E10) GUI vs CLI/TUI in v1  
Decision: **Both GUI and CLI exist in v1.**
- GUI: **egui**.
- CLI: minimal but present (for scripting/automation/diagnostics).

E11) Live reload / profiles / presets / import lists  
Decision: v1 supports **manual apply** (Apply button / `routerctl apply`) with atomic config application where possible.  
Deferred to v2:
- file-watch auto reload
- profiles/presets
- advanced import/list features (beyond minimal includes, if any)

## F. Build, distribution, privileges

F12) Distribution  
Decision: **GitHub Releases + portable ZIP** is the distribution method for v1.  
No MSI/winget in v1.

F13) Admin privileges model  
Decision: **Service-based architecture (option 3):**
- `routerd` runs as a **Windows Service** (admin context).
- `routergui` and `routerctl` are **non-admin clients** communicating over IPC.
- Elevation is only required for install/update/remove of driver/service and similar privileged operations.

Security note: IPC must be protected with appropriate ACLs to prevent unauthorized policy/egress manipulation.

F14) “No Visual Studio” as a goal?  
Decision: **Not a goal.** VS/WDK toolchain is acceptable for driver development/build.  
End users do not need VS to install/run release ZIP.

--- 

## Summary: v1 scope (as agreed)
- WFP callout driver (mandatory).
- Domain routing via TLS SNI + HTTP Host + QUIC (SNI/ALPN).
- Rules: `app+domain`, `domain`, `app`, `default` with tiered matching and top-to-bottom evaluation.
- Actions: direct / block / route-to-egress (SOCKS5-centric).
- Managed egress processes (e.g., sing-box TUN for VPN).
- Loop prevention via WFP bypass for egress processes + loopback exemptions.
- GUI (egui) + minimal CLI; daemon runs as Windows Service; clients non-admin via secured IPC.
- Distribution: GitHub Releases ZIP; dev test-signed, public Microsoft attestation-signed.
