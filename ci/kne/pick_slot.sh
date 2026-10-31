#!/usr/bin/env bash
# Print the lowest free slot in [KNE_SLOT_MIN, KNE_SLOT_MAX] and lock it.
# A slot is busy if its k8s namespace exists or another job holds the lock dir.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

mkdir -p "$KNE_CI_STATE"
existing_ns="$(kubectl get ns -o name | sed 's#namespace/##')"

for s in $(seq "$KNE_SLOT_MIN" "$KNE_SLOT_MAX"); do
  if grep -qx "$s" <<<"$existing_ns"; then
    continue
  fi
  # mkdir is atomic: whoever creates the lock dir owns the slot.
  if mkdir "${KNE_CI_STATE}/${s}" 2>/dev/null; then
    # The namespace list above is a snapshot. Re-check now so a slot whose
    # namespace is still terminating cannot be taken after its lock was released.
    phase="$(kubectl get ns "$s" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [[ -n "$phase" ]]; then
      warn "slot ${s} namespace is ${phase}; leaving it alone"
      rmdir "${KNE_CI_STATE}/${s}" 2>/dev/null || true
      continue
    fi
    echo "$s"
    exit 0
  fi
done
die "no free slot between ${KNE_SLOT_MIN} and ${KNE_SLOT_MAX}"
