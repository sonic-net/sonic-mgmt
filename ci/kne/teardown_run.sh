#!/usr/bin/env bash
# Tear down every slot this run reserved. Safe to run twice.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
RUN_FILE="${KNE_CI_STATE}/run.${KNE_RUN_ID:-$$}"
[[ -f "$RUN_FILE" ]] || { log "no slot file ${RUN_FILE}"; exit 0; }
while read -r topo slot; do
  [[ -n "${slot:-}" ]] || continue
  log "teardown ${topo} slot ${slot}"
  "${KNE_CI_DIR}/teardown.sh" "$slot" || warn "teardown ${slot} failed"
done < "$RUN_FILE"
rm -f "$RUN_FILE"
