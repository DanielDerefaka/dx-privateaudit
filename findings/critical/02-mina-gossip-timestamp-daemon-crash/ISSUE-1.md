# ISSUE-1: Unauthenticated remote DoS — malformed block-gossip timestamp crashes the Mina daemon

## Pipeline Result
**Verdict**: VALID
**Final Severity**: Critical
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 (adversarial check — no invalidation reason held)
**Confidence**: HIGH

## Summary
A peer can crash any Mina node by gossiping a single block/header whose
`blockchain_state.timestamp` has its high bit set (≥ 2^63). The gossipsub block
validator `Block_sink.push` converts that attacker-controlled value with
`Block_time.to_time_exn`, which raises on negative-as-int64 values. No exception
barrier exists on the gossip path, so the raise reaches Async's top-level monitor
and terminates the process — before any proof, signature, or consensus check.
All four core claims were verified against the source at the audited commit, and
the report's own executed PoCs (exit code 1) corroborate the crash end-to-end.

## Location
- `src/lib/transition_handler/block_sink.ml:120-125` — vulnerable `to_time_exn` on the gossiped timestamp
- `src/lib/block_time/block_time.ml:170-173` — `to_time_exn` raises `failwith "converting to negative timestamp"`
- `src/lib/mina_net2/subscription.ml:62-67` — validator (`push`) invoked with no `try_with`
- `src/lib/mina_net2/mina_net2.ml:395-438` — GossipReceived dispatch matches only result variants
- `src/lib/mina_net2/libp2p_helper.ml:229` — `Monitor.protect` (re-raises; not a barrier)
- `src/lib/o1trace/o1trace.ml:103-118` / `87-98` — `sync_thread`/`thread` re-raise via `failwithf`

## Justification

**Mechanism (confirmed).** `block_sink.ml:120-125` computes a Prometheus latency
histogram, calling `Block_time.to_time_exn` on
`Header.protocol_state header |> blockchain_state |> timestamp` — the block's own
timestamp, read straight from the wire. `block_time.ml:170-173` does
`if t_int64 < 0 then failwith "converting to negative timestamp"`, where
`t_int64 = UInt64.to_int64 t`; any value ≥ 2^63 is negative as int64 and raises.
The type is `UInt64.Stable.V1`, so bin_prot accepts the full 64-bit range with no
validation. There is no timestamp range check anywhere before line 124.

**Pre-validation reachability (confirmed).** `Block_sink.push` is the registered
block-topic gossip validator (created at `mina_lib.ml:2131-2156`, exposed via
`mina_networking/sinks.ml`). Lines 120-125 run in the synchronous body of `push`,
*before* the rate limiter (`:141`) and before the block is written to the
processing pipeline (`:156`). The histogram raises regardless of proof/consensus
validity — those checks happen later. So `dev` vs `mainnet` proof level is
irrelevant: the crash fires before any proof verification.

**No exception barrier (confirmed — this is the load-bearing claim).**
`subscription.ml:67` calls `sub.validator` with no `try_with`. The dispatch at
`mina_net2.ml:407-430` runs `handle_and_validate` inside `O1trace.thread` via
`upon`, matching only `Validation_timeout | Decoding_error | Validation_result`
— it cannot catch a raised exception. Both `o1trace` wrappers (`thread`,
`sync_thread`) explicitly **re-raise** via `failwithf` ("exception reported to
parent monitor"). The outermost wrapper on this path is `Monitor.protect`
(`libp2p_helper.ml:229`), which runs `~finally` and re-raises — it suppresses
nothing. The only `Monitor.try_with` in the module (`mina_net2.ml:473`) guards
**direct libp2p stream handlers** (`ph.handler stream`), not gossip. Hence the
`Failure` propagates to `monitor main` and the daemon exits. The report's
executed PoC #2 ("Caught by monitor main", exit 1) and PoC #3 (real two-node
libp2p round-trip, "Caught by monitor Monitor.protect at libp2p_helper.ml:229",
exit 1) confirm this empirically.

**Threat model (confirmed).** Permissionless (any gossip peer), pre-auth,
pre-validation, negligible cost (one connection + one crafted message), no stake
or valid credentials. Re-broadcastable on restart for a sustained outage.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|------------------|
| 1 | Timestamp is validated/bounded before reaching `push` | Generic (input validation) | FAILS | `timestamp : UInt64`, bin_prot accepts full range; no range check before `block_sink.ml:124`; well-formedness check (`:158-186`) runs *after* and only inspects transactions |
| 2 | Exception is caught and downgraded to a rejected message | Generic (graceful handling) | FAILS | No `try_with` on the gossip path; `sync_thread`/`thread` re-raise; `Monitor.protect` re-raises; PoCs exit 1 |
| 3 | Code path requires auth / attacker cannot reach it | Generic (access/reachability) | FAILS | `push` is the gossipsub validator, runs pre-auth/pre-validation on every received block; any peer can publish on the topic |
| 4 | `dev` build differs from mainnet (proof level) | Adversarial (env) | FAILS | Crash fires at `:125` before any proof/consensus logic; proof level is irrelevant |
| 5 | Single message cannot halt the *whole* network | Adversarial (impact scope) | PARTIAL (severity nuance, not invalidation) | gossipsub forwards only on Accept; a node crashing in its validator does not relay, so the message does not self-propagate through crashed nodes. Attacker must directly deliver to each target — still trivial and cheap; block-producer/seed addresses are discoverable. Trims the "one message = network down" framing but not the Critical remote node-crash. |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — location, mechanism, impact all present; cited files/functions/lines exist and match.
- **Step 2 (Privileged Roles)**: SKIPPED — no privileged role in the attack path; attacker is any unauthenticated peer. No trusted-actor downgrade.
- **Step 1.5 (External Research)**: N/A — no external-protocol dependency (internal OCaml/libp2p).
- **Step 3 (Generic Check)**: 3 reasons checked, 0 held → no early exit.
- **Step 4 (Adversarial Check)**: 5 reasons considered; 4 FAIL outright, 1 (propagation scope) is a severity nuance only. Judge: VALID.
- **Final Severity**: Critical (Impact High × Likelihood High). The propagation nuance does not drop it below Critical given the no-prerequisite, pre-auth, cheap, repeatable node-crash.

## Notes on report accuracy (non-substantive)
- The report cites `O1trace.thread` for `block_sink`; the actual wrapper is
  `O1trace.sync_thread`. Both re-raise — conclusion unaffected.
- The "a single gossiped block halts the entire network" framing is slightly
  optimistic: crashed validators do not relay the message, so the attacker must
  directly target each node. This narrows the propagation story but not the
  core impact (cheap, repeatable, remote, unauthenticated node crash).
