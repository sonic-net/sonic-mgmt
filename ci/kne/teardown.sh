#!/usr/bin/env bash
# Tear the slot down and release it. Safe to run at any stage (always() step).
# usage: teardown.sh <SLOT>
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
slot_vars "$1"

restore_checkout_owner
docker rm -f "$CI_CONTAINER" >/dev/null 2>&1 && log "removed ${CI_CONTAINER}" || true

if [[ -f "$TOPO_FILE" ]]; then
  log "kne delete ${TOPO_FILE}"
  kne delete "$TOPO_FILE" || warn "kne delete failed; deleting namespace ${NS} directly"
fi

# kind routes to the now-gone pods (best effort)
while read -r route; do
  [[ -n "$route" ]] || continue
  docker exec "$KIND_NODE" ip route del "$route" >/dev/null 2>&1 || true
done < <(docker exec "$KIND_NODE" ip route show 2>/dev/null | awk -v p="172.31.${SLOT}." 'index($1, p)==1 {print $1}')

# Hold the lock until the namespace is gone. pick_slot.sh only skips a number
# it can see; a Terminating namespace released early gets handed out again and
# the next kne create fails.
if kubectl get ns "$NS" >/dev/null 2>&1; then
  log "waiting for namespace ${NS} to finish deleting"
  if ! kubectl delete ns "$NS" --ignore-not-found --wait=true --timeout=180s; then
    warn "namespace ${NS} still present; keeping reservation ${SLOT_DIR}"
    echo "::warning::namespace ${NS} did not finish deleting; slot ${SLOT} stays reserved"
    exit 0
  fi
fi

rm -rf "$SLOT_DIR"
log "slot ${SLOT} released"
