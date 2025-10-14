#!/usr/bin/env bash
set -euo pipefail

CLIENT=./client         # or ./client.exe on MSYS2
N_CLIENTS=5
FRAMES_PER_CLIENT=20
SLOT_MS=50
ACK_TIMEOUT_MS=500
MAX_BEB_K=10
COLLISION_PROB=0.0       # let the receiver govern collisions; change if you want

P_LIST=(0.10 0.20 0.30 0.40 0.50 0.60 0.70 0.80 0.90)

echo "p,throughput_mbps,avg_delay_ms" > results.csv

for P in "${P_LIST[@]}"; do
  echo "Running p=$P ..."
  # Feed the interactive prompts via printf (order must match your client prompts)
  # Prompts are:
  # n_clients, frames_per_client, p, slot_ms, ack_timeout, max_BEB_k, collisionProb
  OUT="$(
    printf "%d\n%d\n%.3f\n%d\n%d\n%d\n%.3f\n" \
      "$N_CLIENTS" "$FRAMES_PER_CLIENT" "$P" "$SLOT_MS" "$ACK_TIMEOUT_MS" "$MAX_BEB_K" "$COLLISION_PROB" \
    | "$CLIENT"
  )"

  # Parse the two summary lines your client prints at the end:
  TP=$(echo "$OUT" | sed -nE 's/.*Throughput \(Mbps\):[[:space:]]*([0-9.]+).*/\1/p' | tail -n1)
  DL=$(echo "$OUT" | sed -nE 's/.*Avg Forwarding Delay \(ms\):[[:space:]]*([0-9.]+).*/\1/p' | tail -n1)

  if [[ -z "$TP" || -z "$DL" ]]; then
    echo "WARN: Failed to parse output for p=$P. Raw tail:"
    echo "$OUT" | tail -n 30
    continue
  fi

  echo "$P,$TP,$DL" | tee -a results.csv
  # small pause so server can breathe (optional)
  sleep 0.2
done

echo "All done. See results.csv"
