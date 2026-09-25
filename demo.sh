#!/usr/bin/env bash
# B2 agent-wallet demo: isolated Knots regtest (no miners), fund, 5 MCP calls.
# Never touches the shared ~/lazarus-regtest node on :18443.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
export B2_ROOT="$ROOT"
export B2_DATADIR="${B2_DATADIR:-$ROOT/.regtest}"
export B2_CONF="${B2_CONF:-$ROOT/bitcoin-b2.conf}"
export B2_RPCPORT="${B2_RPCPORT:-19443}"
export B2_P2PPORT="${B2_P2PPORT:-19444}"
export B2_WALLET="${B2_WALLET:-agent}"
export B2_SIGNER_SOCK="${B2_SIGNER_SOCK:-$ROOT/.run/signer.sock}"
BITCOIND="${BITCOIND:-$HOME/lazarus-regtest/prefix/bin/bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-$HOME/lazarus-regtest/prefix/bin/bitcoin-cli}"
VENV="$ROOT/.venv"
BITCOIND_PID=""
SIGNER_PID=""

cli() {
  "$BITCOIN_CLI" -datadir="$B2_DATADIR" -conf="$B2_CONF" -rpcport="$B2_RPCPORT" "$@"
}

cleanup() {
  if [[ -n "${SIGNER_PID}" ]] && kill -0 "$SIGNER_PID" 2>/dev/null; then
    kill "$SIGNER_PID" 2>/dev/null || true
    wait "$SIGNER_PID" 2>/dev/null || true
  fi
  if [[ -n "${BITCOIND_PID}" ]] && kill -0 "$BITCOIND_PID" 2>/dev/null; then
    cli stop >/dev/null 2>&1 || kill "$BITCOIND_PID" 2>/dev/null || true
    wait "$BITCOIND_PID" 2>/dev/null || true
  else
    cli stop >/dev/null 2>&1 || true
  fi
  for _ in $(seq 20); do
    if ! ss -ltn 2>/dev/null | grep -q ":${B2_RPCPORT}\\|:${B2_P2PPORT}"; then
      break
    fi
    sleep 0.25
  done
  rm -f "$B2_SIGNER_SOCK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

if [[ ! -x "$BITCOIND" ]]; then
  echo "missing Knots binary: $BITCOIND" >&2
  exit 1
fi

# Isolated datadir — do not reuse the shared rig.
mkdir -p "$B2_DATADIR" "$ROOT/.run"
if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
export B2_PYTHON="$VENV/bin/python"
pip install -q -r "$ROOT/requirements.txt"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

echo "== unit tests =="
"$B2_PYTHON" -m unittest discover -s "$ROOT/tests" -v

echo "== isolated Knots on 127.0.0.1:${B2_RPCPORT} =="
if cli getblockcount >/dev/null 2>&1; then
  echo "b2 node already up at height $(cli getblockcount)"
else
  "$BITCOIND" -datadir="$B2_DATADIR" -conf="$B2_CONF" -daemon
  for _ in $(seq 60); do
    if cli getblockcount >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
  cli getblockcount >/dev/null 2>&1 || { echo "b2 node did not start"; exit 1; }
fi
BITCOIND_PID="$(cat "$B2_DATADIR/regtest/bitcoind.pid" 2>/dev/null || cat "$B2_DATADIR/bitcoind.pid" 2>/dev/null || true)"

if ! cli -rpcwallet="$B2_WALLET" getwalletinfo >/dev/null 2>&1; then
  if ! cli loadwallet "$B2_WALLET" >/dev/null 2>&1; then
    cli createwallet "$B2_WALLET" >/dev/null
  fi
fi

FUND_ADDR="$(cli -rpcwallet="$B2_WALLET" getnewaddress "hot" bech32)"
RECOVERY="$(cli -rpcwallet="$B2_WALLET" getnewaddress "recovery" bech32)"
MERCHANT="$(cli -rpcwallet="$B2_WALLET" getnewaddress "merchant" bech32)"
STRANGER="$(cli -rpcwallet="$B2_WALLET" getnewaddress "stranger" bech32)"
export B2_MERCHANT="$MERCHANT"
export B2_STRANGER="$STRANGER"

# Fresh policy + ledger each demo so the five calls are deterministic.
cat > "$ROOT/policy.json" <<EOF
{
  "allowlist": ["$MERCHANT"],
  "max_per_tx_sats": 100000000,
  "daily_budget_sats": 200000000,
  "weekly_budget_sats": 500000000,
  "per_counterparty_cap_sats": 100000000,
  "velocity_max": 20,
  "velocity_window_s": 3600,
  "human_threshold_sats": 10000000,
  "split_window_s": 600,
  "approval_ttl_s": 3600,
  "recovery_address": "$RECOVERY"
}
EOF
rm -f "$ROOT/.run/ledger.json" "$ROOT/.run/audit.jsonl" "$ROOT/.run/vault.json"

# Fund with generatetoaddress — no miners (HL-015).
TRUSTED="$(cli -rpcwallet="$B2_WALLET" getbalances | python3 -c 'import json,sys; print(json.load(sys.stdin)["mine"]["trusted"])')"
if python3 -c "import sys; sys.exit(0 if float('$TRUSTED') >= 40 else 1)"; then
  echo "wallet already funded ($TRUSTED XBT)"
else
  echo "generating 101 blocks to $FUND_ADDR (no miner)"
  cli generatetoaddress 101 "$FUND_ADDR" >/dev/null
fi

echo "== signer =="
"$B2_PYTHON" -m agentwallet.signer &
SIGNER_PID=$!
for _ in $(seq 40); do
  [[ -S "$B2_SIGNER_SOCK" ]] && break
  sleep 0.1
done
[[ -S "$B2_SIGNER_SOCK" ]] || { echo "signer socket missing"; exit 1; }

echo "== five MCP agent calls =="
"$B2_PYTHON" "$ROOT/demo_agent.py"

echo "== miners left running? =="
python3 "$HOME/lazarus-regtest/killminer.py"
echo "DEMO finished (isolated node stopped on exit; shared :18443 untouched)"
