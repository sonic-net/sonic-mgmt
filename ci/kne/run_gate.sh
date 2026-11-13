#!/usr/bin/env bash
# Bring up t0, t1, and t1-lag, run the same tests on each, and tear them down.
# There is no T2 lab. Override with KNE_TOPOS="t0" to bring up fewer labs.
# usage: run_gate.sh [test path ...]
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# A failed or cancelled bring-up must not leave labs behind. The workflow's
# teardown step also runs this, and a second pass is a no-op once the run file
# is gone. SIGKILL of the runner still needs that later step.
on_exit() {
  local rc=$?
  "${KNE_CI_DIR}/teardown_run.sh" || true
  exit "$rc"
}
trap on_exit EXIT

if [[ $# -gt 0 ]]; then
  TESTS=("$@")
else
  LIST="${KNE_TESTS_FILE:-${KNE_CI_DIR}/tests.txt}"
  [[ -f "$LIST" ]] || die "no test list at ${LIST}"
  mapfile -t TESTS < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^[[:space:]]*$/d' "$LIST")
fi
[[ ${#TESTS[@]} -gt 0 ]] || die "no tests to run"
log "tests: ${TESTS[*]}"

RUN_FILE="${KNE_CI_STATE}/run.${KNE_RUN_ID:-$$}"
mkdir -p "$KNE_CI_STATE"
: > "$RUN_FILE"

read -r -a TOPOS <<< "${KNE_TOPOS:-t0 t1 t1-lag}"
[[ ${#TOPOS[@]} -gt 0 ]] || die "KNE_TOPOS is empty"
log "topologies: ${TOPOS[*]}"
for topo in "${TOPOS[@]}"; do
  slot="$("${KNE_CI_DIR}/pick_slot.sh")"
  echo "${topo} ${slot}" >> "$RUN_FILE"
  "${KNE_CI_DIR}/render.sh" "$topo" "$slot"
done
log "slots: $(tr '\n' ' ' < "$RUN_FILE")"

fail=0
pids=()
while read -r topo slot; do
  (
    set -euo pipefail
    "${KNE_CI_DIR}/create.sh" "$slot"
    "${KNE_CI_DIR}/config_neighbors.sh" "$slot"
    "${KNE_CI_DIR}/deploy_dut.sh" "$slot"
    "${KNE_CI_DIR}/run_test.sh" "$slot" "${TESTS[@]}"
  ) > "${KNE_CI_STATE}/${slot}.log" 2>&1 &
  pids+=("$!")
  log "started ${topo} on slot ${slot} (pid $!)"
done < "$RUN_FILE"

for pid in "${pids[@]}"; do
  wait "$pid" || fail=1
done

echo "----------"
for slot in $(awk '{print $2}' "$RUN_FILE"); do
  echo "===== slot ${slot} ====="
  cat "${KNE_CI_STATE}/${slot}.log" || true
done
exit "$fail"
