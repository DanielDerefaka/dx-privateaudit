# High: Unauthenticated LOOP-plugin pprof/discovery exposure (process argv, heap/goroutine profiles, DoS) on default 0.0.0.0:6688

**Target:** smartcontractkit/chainlink v2 (Go node) — core/web LOOP-plugin routes  
**Severity:** High  
**Slug:** `chainlink-loop-plugin-unauth-pprof`

## Impact

A remote unauthenticated client enumerates LOOP plugins and pulls their pprof debug surface (argv, memory/goroutine profiles) plus a profile-seconds DoS.

## Proof of Concept

TestLoopPluginPProfUnauthenticatedBypass (report states passing against the real router: UNAUTH /v2/jobs->401 control, /discovery->200 leaks plugin, /plugins/.../pprof/cmdline->200 argv, /pprof/heap->200 profile). Report claims full go build + Postgres test DB.

## Submission notes / caveats

CAVEAT: the chainlink Go-node repo is NOT present in this audit tree (only chainlink-sui), so the PoC file and vulnerable source could not be independently re-run — qualification rests on the report's stated passing run; re-verify against a live checkout before submission. Honestly bounded below Critical (signing keys live in the core process, not LOOP-plugin memory). The node's own pprof is auth-gated; the LOOP proxy is the asymmetric gap.

## Files in this folder

- [`chainlink-node-audit-report.md`](./chainlink-node-audit-report.md) — write-up, from `chainlink-node-audit-report.md`
