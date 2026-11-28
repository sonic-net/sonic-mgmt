#!/bin/bash
# fast_reboot_refuses_vxlan.sh <fast-reboot script>
#
# Does this fast-reboot / warm-reboot script refuse to run while ASIC_DB holds a VxLAN tunnel, when no control-plane
# assistant (-c) is set up? Scripts before sonic-net/sonic-utilities#4902 do (sonic-net/sonic-buildimage#22560); #4902
# runs the leftover-tunnel check only when the assistant is set up. The script's own setup_control_plane_assistant and the
# helpers it calls are run, without -c, against stub redis-cli / sonic-db-cli that report one VxLAN tunnel. A call of
# the check anywhere else in the script is not covered by that run, so it reads UNKNOWN.
#
# Prints one line: REFUSES (the script exits with EXIT_LEFTOVER_CPA_TUNNEL), PROCEEDS, or UNKNOWN <why>.
set -u
f=${1:?usage: $0 <fast-reboot script>}
[ -r "$f" ] || { echo "UNKNOWN unreadable $f"; exit 0; }
grep -q 'abort_reboot_if_cpa_tunnel_is_leftover' "$f" || { echo "PROCEEDS (no leftover-tunnel check)"; exit 0; }
outside=$(awk '
  /^function (setup_control_plane_assistant|abort_reboot_if_cpa_tunnel_is_leftover)\(\)/ { inside = 1 }
  !inside && /abort_reboot_if_cpa_tunnel_is_leftover/ && !/^[[:space:]]*#/ { n++ }
  inside && /^}/ { inside = 0 }
  END { print n + 0 }' "$f")
[ "$outside" = 0 ] || { echo "UNKNOWN the leftover-tunnel check is called outside setup_control_plane_assistant"; exit 0; }
d=$(mktemp -d) || { echo "UNKNOWN no temp dir"; exit 0; }
trap 'rm -rf "$d"' EXIT

# KEYS <pattern>: one object of that type; HGET <key> <field>: a VxLAN tunnel type. The same stub serves
# `redis-cli -n 1 KEYS ...` and `sonic-db-cli ASIC_DB KEYS ...`.
cat > "$d/redis-cli" <<'EOF'
#!/bin/bash
while [ $# -gt 0 ]; do
  case "$1" in
    KEYS) echo "${2%\*}oid:0x2a000000000001"; exit 0 ;;
    HGET) echo SAI_TUNNEL_TYPE_VXLAN; exit 0 ;;
  esac
  shift
done
EOF
cp "$d/redis-cli" "$d/sonic-db-cli"
cat > "$d/logger" <<'EOF'
#!/bin/bash
EOF
cat > "$d/run.sh" <<'EOF'
#!/bin/bash
set -e
script=$1
# shellcheck disable=SC1090
source <(grep -E '^EXIT_[A-Z_]+=[0-9]+$' "$script")
# shellcheck disable=SC1090
source <(sed -n -e '/^function debug()/,/^}/p' -e '/^function error()/,/^}/p' \
  -e '/^function abort_reboot_if_cpa_tunnel_is_leftover()/,/^}/p' \
  -e '/^function setup_control_plane_assistant()/,/^}/p' "$script")
setup_control_plane_assistant
EOF
chmod +x "$d/redis-cli" "$d/sonic-db-cli" "$d/logger" "$d/run.sh"
PATH="$d:$PATH" ASSISTANT_IP_LIST="" ASSISTANT_SCRIPT=/nonexistent STRICT="" HWSKU=probe \
  bash "$d/run.sh" "$f" >/dev/null 2>&1
rc=$?
leftover=$(sed -n 's/^EXIT_LEFTOVER_CPA_TUNNEL=\([0-9]*\)$/\1/p' "$f" | head -1)
if [ "$rc" = 0 ]; then
  echo PROCEEDS
elif [ -n "$leftover" ] && [ "$rc" = "$leftover" ]; then
  echo REFUSES
else
  echo "UNKNOWN rc=$rc"
fi
