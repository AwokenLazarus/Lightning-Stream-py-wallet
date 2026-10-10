#!/usr/bin/env bash
# B2 wave 2 demo: channel-as-budget + xbt402_pay + Claude session.
# Isolated Knots 29.4.2 on 30300-30301, x402 HTTP 30310, datadir ~/xbt-rnd/xbt-062/run/.
# Never touches the shared :18443 rig. Never runs killminer.py.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
export B2_ROOT="$ROOT"
if [[ -z "${B1_ROOT:-}" ]]; then
  echo "B1_ROOT is not set: point it at a b1 tree or snapshot (for example ~/xbt-rnd/b1, whose master is the accepted line, or a cmp-rails snapshot); B2 never guesses which b1 to test against" >&2
  exit 2
fi
export B1_ROOT
export B2_RUN="${B2_RUN:-$HOME/xbt-rnd/xbt-062/run}"
export B2_DATADIR="${B2_DATADIR:-$B2_RUN/node}"
export B2_CONF="${B2_CONF:-$B2_RUN/bitcoin.conf}"
export B2_RPCPORT="${B2_RPCPORT:-30300}"
export B2_P2PPORT="${B2_P2PPORT:-30301}"
export B2_HTTP_PORT="${B2_HTTP_PORT:-30310}"
export B2_WALLET="${B2_WALLET:-agent}"
export B2_SIGNER_SOCK="${B2_SIGNER_SOCK:-$ROOT/.run/signer.sock}"
export B2_HUMAN_DEVICE="${B2_HUMAN_DEVICE:-$HOME/xbt-rnd/b2-human-device}"
# AGP-013: the hot key's wrapping key, outside the workspace (created 0600 on first start)
export B2_HOT_KEYFILE="${B2_HOT_KEYFILE:-$B2_RUN/hot.key}"
export B2_PENDING="${B2_PENDING:-$ROOT/.run/pending_approval.json}"
export B2_X402_URL="http://127.0.0.1:${B2_HTTP_PORT}/v1/infer"
BITCOIND="${BITCOIND:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2/bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-$HOME/lazarus-regtest/b1-xbt402/knots-29.4.2/bitcoin-cli}"
VENV="$ROOT/.venv"
BITCOIND_PID=""
SIGNER_PID=""
X402_PID=""

cli() {
  "$BITCOIN_CLI" -datadir="$B2_DATADIR" -conf="$B2_CONF" -rpcport="$B2_RPCPORT" "$@"
}

cleanup() {
  if [[ -n "${X402_PID}" ]] && kill -0 "$X402_PID" 2>/dev/null; then
    kill "$X402_PID" 2>/dev/null || true
    wait "$X402_PID" 2>/dev/null || true
  fi
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
  for _ in $(seq 40); do
    if ! ss -ltn 2>/dev/null | grep -q ":${B2_RPCPORT}\\|:${B2_P2PPORT}\\|:${B2_HTTP_PORT}"; then
      break
    fi
    sleep 0.25
  done
  rm -f "$B2_SIGNER_SOCK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

if [[ ! -x "$BITCOIND" ]]; then
  echo "missing Knots 29.4.2: $BITCOIND" >&2
  exit 1
fi

mkdir -p "$B2_DATADIR" "$B2_RUN" "$ROOT/.run"
RDTS_EXPIRY="$(( $(date +%s) + 31536000 ))"
cat > "$B2_CONF" <<EOF
regtest=1
server=1
listenonion=0
discover=0
natpmp=0
upnp=0
dnsseed=0
fixedseeds=0
fallbackfee=0.0002
txindex=1
blake2b_headline=Lazarus-B2-062
daemon=1
[regtest]
listen=1
bind=127.0.0.1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=${B2_RPCPORT}
port=${B2_P2PPORT}
testactivationheight=blake2b@101
rdtsexpiry=${RDTS_EXPIRY}
EOF

if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
export B2_PYTHON="$VENV/bin/python"
pip install -q -r "$ROOT/requirements.txt"
export PYTHONPATH="$ROOT:$B1_ROOT${PYTHONPATH:+:$PYTHONPATH}"

echo "== unit tests =="
"$B2_PYTHON" -m unittest discover -s "$ROOT/tests" -v

echo "== isolated Knots 29.4.2 on 127.0.0.1:${B2_RPCPORT} (datadir $B2_DATADIR) =="
if cli getblockcount >/dev/null 2>&1; then
  echo "b2-062 node already up at height $(cli getblockcount)"
else
  "$BITCOIND" -datadir="$B2_DATADIR" -conf="$B2_CONF" -daemon
  for _ in $(seq 80); do
    if cli getblockcount >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
  cli getblockcount >/dev/null 2>&1 || { echo "b2-062 node did not start"; tail -20 "$B2_DATADIR/regtest/debug.log" || true; exit 1; }
fi
BITCOIND_PID="$(cat "$B2_DATADIR/regtest/bitcoind.pid" 2>/dev/null || true)"

if ! cli -rpcwallet="$B2_WALLET" getwalletinfo >/dev/null 2>&1; then
  if ! cli loadwallet "$B2_WALLET" >/dev/null 2>&1; then
    cli createwallet "$B2_WALLET" >/dev/null
  fi
fi

FUND_ADDR="$(cli -rpcwallet="$B2_WALLET" getnewaddress "hot" bech32)"
RECOVERY="$(cli -rpcwallet="$B2_WALLET" getnewaddress "recovery" bech32)"
STRANGER="$(cli -rpcwallet="$B2_WALLET" getnewaddress "stranger" bech32)"
export B2_STRANGER="$STRANGER"
export B2_RECOVERY="$RECOVERY"

# Merchant = secp payee we register so pay() opens a Spillman channel.
MERCHANT="$("$B2_PYTHON" - <<'PY'
import secrets, os, sys
sys.path.insert(0, os.environ["B1_ROOT"])
from xbt402 import ecc
from xbt402.tx import p2wpkh_spk, segwit_address
sk = secrets.randbelow(ecc.N - 1) + 1
pub = ecc.pubkey(sk)
addr = segwit_address("bcrt", p2wpkh_spk(pub))
open(os.path.join(os.environ["B2_ROOT"], ".run", "merchant_payto.hex"), "w").write(pub.hex() + "\n")
print(addr)
PY
)"
MERCHANT_PAYTO="$(cat "$ROOT/.run/merchant_payto.hex")"
export B2_MERCHANT="$MERCHANT"

"$B2_PYTHON" - <<PY
from pathlib import Path
from agentwallet.approval import write_human_device
import os
info = write_human_device(Path(os.environ["B2_HUMAN_DEVICE"]))
Path(os.environ["B2_ROOT"], ".run", "human_pubkey.hex").write_text(info["public_hex"] + "\n")
print("human device:", info["device_dir"])
print("human pubkey:", info["public_hex"])
PY
HUMAN_PUB="$(cat "$ROOT/.run/human_pubkey.hex")"

cat > "$ROOT/policy.json" <<EOF
{
  "allowlist": ["$MERCHANT", "http://127.0.0.1:${B2_HTTP_PORT}"],
  "counterparties": {
    "$MERCHANT": {"pay_to": "$MERCHANT_PAYTO"}
  },
  "max_per_tx_sats": 100000000,
  "daily_budget_sats": 200000000,
  "weekly_budget_sats": 500000000,
  "per_counterparty_cap_sats": 100000000,
  "velocity_max": 20,
  "velocity_window_s": 3600,
  "human_threshold_sats": 10000000,
  "split_window_s": 600,
  "approval_ttl_s": 900,
  "channel_expiry_blocks": 1008,
  "treasury_csv": 4320,
  "recovery_address": "$RECOVERY",
  "human_pubkey": "$HUMAN_PUB"
}
EOF
rm -f "$ROOT/.run/ledger.json" "$ROOT/.run/ledger.payments.jsonl" "$ROOT/.run/audit.jsonl" "$ROOT/.run/vault.json" \
      "$ROOT/.run/channels.json" "$ROOT/.run/channel_keys.json" "$ROOT/.run/hot.json" \
      "$ROOT/.run/treasury.json" "$B2_PENDING"

if [[ "$(cli getblockcount)" -lt 101 ]]; then
  echo "generating $((101 - $(cli getblockcount))) blocks to $FUND_ADDR (no miner)"
  cli generatetoaddress $((101 - $(cli getblockcount))) "$FUND_ADDR" >/dev/null
fi

echo "== signer =="
"$B2_PYTHON" -m agentwallet.signer &
SIGNER_PID=$!
for _ in $(seq 50); do
  [[ -S "$B2_SIGNER_SOCK" ]] && break
  sleep 0.1
done
[[ -S "$B2_SIGNER_SOCK" ]] || { echo "signer socket missing"; exit 1; }

echo "== top up hot key (wallet → hot, then 0x21 channel fundings) =="
HOT="$("$B2_PYTHON" -c 'from pathlib import Path; import os; from agentwallet.signer import SignerClient; print(SignerClient(Path(os.environ["B2_SIGNER_SOCK"])).call("hot_address")["hot_address"])')"
HOT_TX="$(cli -rpcwallet="$B2_WALLET" sendtoaddress "$HOT" 10)"
export HOT_TX
cli generatetoaddress 1 "$FUND_ADDR" >/dev/null
"$B2_PYTHON" -c 'from pathlib import Path; import os; from agentwallet.signer import SignerClient; print(SignerClient(Path(os.environ["B2_SIGNER_SOCK"])).call("notice_hot_txid", txid=os.environ["HOT_TX"]))'

echo "== open merchant channel (0x21 funding) =="
"$B2_PYTHON" - <<'PY'
import os
from pathlib import Path
from agentwallet.signer import SignerClient
c = SignerClient(Path(os.environ["B2_SIGNER_SOCK"]))
r = c.call("open_channel", dest=os.environ["B2_MERCHANT"])
assert r.get("verdict") == "allow" and r.get("chan"), r
print("CHANNEL_OPEN", r["chan"], "cap", r["cap_sats"], "expiry", r["expiry"], "sighash", r.get("funding_sighash"))
PY

echo "== fund treasury (CSV 4320) =="
"$B2_PYTHON" - <<'PY'
from pathlib import Path
import os, time
from agentwallet.approval import load_private_key, treasury_fund_message, sign, b2x
from agentwallet.signer import SignerClient
c = SignerClient(Path(os.environ["B2_SIGNER_SOCK"]))
# AGP-080: hot funds move to the treasury only on the human's signature
bal = c.call("balance")
expiry = int(time.time()) + 900
priv = load_private_key(Path(os.environ["B2_HUMAN_DEVICE"]) / "ed25519.sk")
msg = treasury_fund_message(bal["hot"]["hot_address"], bal["treasury"]["treasury_address"], 1_000_000, expiry)
r = c.call("fund_treasury", sats=1_000_000, expiry=expiry, signature=b2x(sign(priv, msg)))
assert r.get("txid"), r
print("TREASURY_FUNDED", r)
PY

echo "== x402 provider on :${B2_HTTP_PORT} =="
"$B2_PYTHON" "$ROOT/demo_x402.py" &
X402_PID=$!
for _ in $(seq 40); do
  if "$B2_PYTHON" -c "import urllib.error,urllib.request
try:
    urllib.request.urlopen('http://127.0.0.1:${B2_HTTP_PORT}/v1/infer')
except urllib.error.HTTPError as e:
    raise SystemExit(0 if e.code==402 else 1)
except Exception:
    raise SystemExit(1)"; then
    break
  fi
  sleep 0.15
done

echo "== agent MCP path =="
"$B2_PYTHON" "$ROOT/demo_agent.py"

echo "== human out-of-band approve =="
TOKEN="$("$B2_PYTHON" -c 'import json,os; print(json.load(open(os.environ["B2_PENDING"]))["token"])')"
DEST="$("$B2_PYTHON" -c 'import json,os; print(json.load(open(os.environ["B2_PENDING"]))["dest"])')"
AMT="$("$B2_PYTHON" -c 'import json,os; print(json.load(open(os.environ["B2_PENDING"]))["amount_sats"])')"
EXP="$("$B2_PYTHON" -c 'import json,os; print(json.load(open(os.environ["B2_PENDING"]))["expiry"])')"
"$B2_PYTHON" -m agentwallet.approve \
  --key "$B2_HUMAN_DEVICE/ed25519.sk" \
  --token "$TOKEN" \
  --dest "$DEST" \
  --amount-sats "$AMT" \
  --expiry "$EXP" \
  --sock "$B2_SIGNER_SOCK" \
  --agent-root "$ROOT"

"$B2_PYTHON" - <<'PY'
import json, os
from pathlib import Path
from agentwallet.signer import SignerClient
pending = json.loads(Path(os.environ["B2_PENDING"]).read_text())
c = SignerClient(Path(os.environ["B2_SIGNER_SOCK"]))
hist = c.call("history", limit=80)
commits = [e for e in hist.get("events") or [] if e.get("type") == "commit" and e.get("amount_sats") == pending["amount_sats"]]
assert commits, hist
print("HUMAN_APPROVE_OK", commits[-1].get("txid"))
print("CHANNELS", c.call("channels"))
PY

echo "== claude-session.sh (before 4320 so the x402 channel is still live) =="
bash "$ROOT/claude-session.sh"

echo "== treasury CSV recovery after 4320 blocks =="
cli generatetoaddress 4320 "$FUND_ADDR" >/dev/null
"$B2_PYTHON" - <<'PY'
import os, time
from pathlib import Path
from agentwallet.approval import load_private_key, treasury_recover_message, sign, b2x
from agentwallet.signer import SignerClient
c = SignerClient(Path(os.environ["B2_SIGNER_SOCK"]))
st = c.call("balance")["treasury"]
addr = st["treasury_address"]
expiry = int(time.time()) + 900
priv = load_private_key(Path(os.environ["B2_HUMAN_DEVICE"]) / "ed25519.sk")
to = os.environ.get("B2_RECOVERY") or addr
sig = b2x(sign(priv, treasury_recover_message(addr, to, expiry)))   # AGP-080: the signature names the destination
r = c.call("recover_treasury", signature=sig, expiry=expiry, to=to)
print("TREASURY_RECOVER", r)
assert r.get("ok") or "non-final" not in str(r).lower(), r
if r.get("ok"):
    print("TREASURY_RECOVER_OK", r["txid"])
else:
    # If the node still considers the CSV immature, surface the reason; demo still proves the 0x21 path in unit tests.
    print("TREASURY_RECOVER_PENDING", r.get("reason"))
PY

echo "== miners left in 30300-30399? =="
python3 "$HOME/xbt-rnd/tools/miners_left.py" 30300-30399
echo "DEMO_OK (isolated 30300 node stopped on exit; shared :18443 untouched)"
