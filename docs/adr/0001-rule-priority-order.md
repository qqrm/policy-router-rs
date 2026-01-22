# Deterministic rule evaluation order by egress kind

Status: Accepted

## Context
- Rules are stored as maps of `EgressId -> patterns` for both app and domain routing.
- The order of keys in a map must not influence routing decisions.
- Previously, the engine iterated `BTreeMap` keys, which are ordered lexicographically, creating a hidden dependency on egress id names and risking regressions.

## Decision
- For non-block rules, evaluation order is determined solely by egress kind:
  1) Singbox
  2) Socks5
  3) Direct
- Block rules have the highest priority and are evaluated separately before any non-block rules.
- When multiple egresses match the same pattern, the higher-priority kind wins.
- Within the same kind, ordering is lexicographic by `EgressId` for determinism only, not as a logical priority.

## Consequences
- Behavior is consistent for any egress id naming scheme.
- New egress entries can be added without changing rule priority semantics.
- Overlapping rules yield predictable results independent of TOML ordering.
