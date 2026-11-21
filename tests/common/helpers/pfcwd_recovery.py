"""
Force software PFC watchdog recovery on a device that boots into hardware
recovery, so the pfcwd suite can run under both mechanisms. Software mode is
staged in the chip config the SAI reads at cold init: sai_pfc_dldr_capability
is set to 0 and sai_stats_support_mask is switched to its software value, then
swss is restarted. Hardware recovery is never forced.
"""

import json
import logging

from tests.common.fixtures.duthost_utils import wait_bgp_sessions
from tests.common.helpers.pfcwd_helper import HARDWARE, SOFTWARE, get_pfcwd_recovery_mode
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# Only Broadcom chip configs carry sai_pfc_dldr_capability; other vendors run the mechanism they boot into.
SWITCHABLE_ASIC_TYPES = ("broadcom",)

# sai_stats_support_mask hardware value -> (software value, global_flexctr_egr_pool_num_reserved or None).
# A mask with a purge-drop bit (0x2000 or 0x8000) that is not listed here fails the switch.
SOFTWARE_MASKS = {
    0x2884: (0x884, None),
    0x8884: (0x884, None),
    0xA884: (0x884, None),
    0x8804: (0x800, 6),
}
PURGE_DROP_BITS = 0x2000 | 0x8000
# recovery_state() of a device running forced software recovery.
SOFTWARE_STATE = {"RECOVERY_MECHANISM": SOFTWARE, "PFC_DLDR_CAPABLE": "false", "PFC_DLR_INIT_CAPABLE": "false"}
BACKUP_SUFFIX = ".pfcwd-orig"
# Real paths of the edited files, one per line, kept in the platform directory so restore also finds
# a symlink target outside that tree.
MANIFEST_NAME = "pfcwd-recovery-staged.txt"
STAGE_SCRIPT_PATH = "/tmp/pfcwd_recovery_stage.py"
SAI_LIB_GLOB = "/usr/lib/libsai*.so*"
PORTS_UP_TIMEOUT = 900
BGP_UP_TIMEOUT = 600

# Manual undo for a run killed before teardown.
RECOVERY_RECIPE = ("pfcwd recovery override recipe: for f in $(sudo cat /usr/share/sonic/device/*/{m} 2>/dev/null) "
                   "$(sudo find -L /usr/share/sonic/device -name '*{b}' | sed 's/{b}$//'); "
                   "do [ -e $f{b} ] && sudo mv -f $f{b} $f; done ; sudo rm -f /usr/share/sonic/device/*/{m} ; "
                   "sudo systemctl stop swss ; sudo systemctl reset-failed swss ; "
                   "sudo systemctl start swss").format(b=BACKUP_SUFFIX, m=MANIFEST_NAME)

# Runs on the DUT. Modes: stage <root> <suffix> <table-json> <purge-bits> | restore <root> <suffix>
# | backups <root> <suffix> | purge <root> <suffix> <purge-bits>. Prints one JSON line.
STAGE_SCRIPT = r'''
import json, os, re, shutil, sys

MASK = re.compile(r"^(\s*)sai_stats_support_mask\s*:\s*(.*?)\s*$")
POOL = re.compile(r"^(\s*global_flexctr_egr_pool_num_reserved\s*:\s*)\S+\s*$")
DLDR_YAML = re.compile(r"^(\s*sai_pfc_dldr_capability\s*:\s*)\S+\s*$")
DLDR_BCM = re.compile(r"^sai_pfc_dldr_capability\s*=")
MANIFEST = "@MANIFEST@"


def manifest_paths(root):
    try:
        with open(os.path.join(root, MANIFEST)) as f:
            return set(l for l in f.read().split("\n") if l)
    except OSError:
        return set()


def write_manifest(root, paths):
    path = os.path.join(root, MANIFEST)
    if paths:
        with open(path, "w") as f:
            f.write("\n".join(sorted(paths)) + "\n")
    elif os.path.exists(path):
        os.remove(path)


def fail(msg):
    print(json.dumps({"error": msg}))
    sys.exit(2)


def configs(root, suffix):
    seen = set()
    for d, _, names in os.walk(root, followlinks=True):
        for name in sorted(names):
            path = os.path.realpath(os.path.join(d, name))
            if path in seen or name.endswith(suffix) or "bcmsim" in name:
                continue
            seen.add(path)
            if name.endswith((".bcm", ".bcm.j2")):
                kind = "bcm"
            elif name.endswith((".yaml", ".yml", ".j2")):
                kind = "yaml"
            else:
                continue
            with open(path) as f:
                lines = f.read().split("\n")
            if kind == "bcm" and any(l.startswith("sai_") for l in lines):
                yield path, kind, lines
            elif kind == "yaml" and any(MASK.match(l) for l in lines):
                yield path, kind, lines


def mask_of(path, line):
    try:
        return int(MASK.match(line).group(2), 0)
    except ValueError:
        fail("cannot parse sai_stats_support_mask in %s: %r" % (path, line))


def stage(root, suffix, table, purge):
    edits, errors = {}, []
    for path, kind, lines in configs(root, suffix):
        new = list(lines)
        if kind == "bcm":
            idx = [i for i, l in enumerate(new) if DLDR_BCM.match(l)]
            for i in idx:
                new[i] = "sai_pfc_dldr_capability=0"
            if not idx:
                new.insert(len(new) - 1 if new and new[-1] == "" else len(new), "sai_pfc_dldr_capability=0")
        else:
            masks = [(i, mask_of(path, l)) for i, l in enumerate(new) if MASK.match(l)]
            for i, mask in masks:
                if not mask & purge:
                    continue
                entry = table.get(hex(mask))
                if entry is None:
                    errors.append("%s: no software value for sai_stats_support_mask %s" % (path, hex(mask)))
                    continue
                new[i] = "%ssai_stats_support_mask: %s" % (MASK.match(new[i]).group(1), entry[0])
                if entry[1] is not None:
                    pools = [j for j, l in enumerate(new) if POOL.match(l)]
                    if not pools:
                        errors.append("%s: no global_flexctr_egr_pool_num_reserved to set" % path)
                    for j in pools:
                        new[j] = POOL.match(new[j]).group(1) + str(entry[1])
            dldr = [i for i, l in enumerate(new) if DLDR_YAML.match(l)]
            for i in dldr:
                new[i] = DLDR_YAML.match(new[i]).group(1) + "0"
            if not dldr:
                i = masks[0][0]
                new.insert(i + 1, MASK.match(lines[i]).group(1) + "sai_pfc_dldr_capability: 0")
        if new != lines:
            edits[path] = new
    if errors:
        fail("; ".join(errors))
    # Recorded before any file changes, so an interrupted stage is still restorable.
    write_manifest(root, manifest_paths(root) | set(edits))
    for path, new in edits.items():
        if not os.path.exists(path + suffix):
            shutil.copy2(path, path + suffix)
        with open(path, "w") as f:
            f.write("\n".join(new))
    print(json.dumps({"edited": sorted(edits)}))


def backups(root, suffix):
    found = set(p + suffix for p in manifest_paths(root) if os.path.exists(p + suffix))
    for d, _, names in os.walk(root, followlinks=True):
        found.update(os.path.realpath(os.path.join(d, n)) for n in names if n.endswith(suffix))
    return sorted(found)


def restore(root, suffix):
    for backup in backups(root, suffix):
        if os.path.exists(backup):
            shutil.move(backup, backup[:-len(suffix)])
    left = backups(root, suffix)
    if not left:
        write_manifest(root, set())
    print(json.dumps({"left": left}))


def purge_masks(root, suffix, purge):
    left = set(path for path, kind, lines in configs(root, suffix) if kind == "yaml"
               for l in lines if MASK.match(l) and mask_of(path, l) & purge)
    print(json.dumps({"purge": sorted(left)}))


mode = sys.argv[1]
if mode == "stage":
    stage(sys.argv[2], sys.argv[3], json.loads(sys.argv[4]), int(sys.argv[5], 0))
elif mode == "restore":
    restore(sys.argv[2], sys.argv[3])
elif mode == "backups":
    print(json.dumps({"backups": backups(sys.argv[2], sys.argv[3])}))
else:
    purge_masks(sys.argv[2], sys.argv[3], int(sys.argv[4], 0))
'''.replace("@MANIFEST@", MANIFEST_NAME)


class RecoveryModeUnsupported(Exception):
    """The device cannot run the requested mechanism; the phase should be skipped, not failed."""


def _device_dir(duthost):
    return "/usr/share/sonic/device/{}".format(duthost.facts["platform"])


def _run_stage_script(duthost, *args):
    duthost.copy(content=STAGE_SCRIPT, dest=STAGE_SCRIPT_PATH)
    result = duthost.shell("sudo python3 {} {}".format(STAGE_SCRIPT_PATH, " ".join("'{}'".format(a) for a in args)),
                           module_ignore_errors=True)
    out = json.loads((result["stdout"].strip().splitlines() or ["{}"])[-1] or "{}")
    if "error" in out or result["rc"] not in (0, 2):
        raise RuntimeError("{}: {}".format(duthost.hostname, out.get("error") or result.get("stderr")))
    return out


def _switch_capability(duthost, field):
    return duthost.asic_instance(0).run_sonic_db_cli_cmd(
        "STATE_DB HGET 'SWITCH_CAPABILITY|switch' {}".format(field))["stdout"].strip().lower()


def recovery_state(duthost):
    """The raw STATE_DB recovery fields, lower-cased; a field the switch has not published reads as ''."""
    return {
        "RECOVERY_MECHANISM": duthost.asic_instance(0).run_sonic_db_cli_cmd(
            "STATE_DB HGET 'PFC_WD_STATE_TABLE|PFC_WD' RECOVERY_MECHANISM")["stdout"].strip().lower(),
        "PFC_DLDR_CAPABLE": _switch_capability(duthost, "PFC_DLDR_CAPABLE"),
        "PFC_DLR_INIT_CAPABLE": _switch_capability(duthost, "PFC_DLR_INIT_CAPABLE"),
    }


def _sai_supports_dldr_property(duthost):
    return duthost.shell("docker exec syncd sh -c 'grep -l -a sai_pfc_dldr_capability {}'".format(SAI_LIB_GLOB),
                         module_ignore_errors=True)["rc"] == 0


def can_force_software(duthost):
    """Return whether duthost's chip config can stage software recovery."""
    return (duthost.facts.get("asic_type") or "").lower() in SWITCHABLE_ASIC_TYPES


def _has_override(duthost):
    return bool(_run_stage_script(duthost, "backups", _device_dir(duthost), BACKUP_SUFFIX)["backups"])


def _clear_override(duthost):
    left = _run_stage_script(duthost, "restore", _device_dir(duthost), BACKUP_SUFFIX)["left"]
    if left:
        raise RuntimeError("{}: chip-config backups could not be restored: {}".format(duthost.hostname, left))


def _apply_override(duthost):
    _clear_override(duthost)
    table = {hex(hw): [hex(sw), pool] for hw, (sw, pool) in SOFTWARE_MASKS.items()}
    edited = _run_stage_script(duthost, "stage", _device_dir(duthost), BACKUP_SUFFIX, json.dumps(table),
                               hex(PURGE_DROP_BITS))["edited"]
    logger.info("%s: staged software recovery in %s", duthost.hostname, edited)


def _restart_swss(duthost):
    """Stop, reset-failed and start swss, then wait for critical processes, ports and BGP."""
    duthost.stop_service("swss")
    duthost.reset_service("swss")
    duthost.start_service("swss")
    wait_critical_processes(duthost)
    if not wait_until(PORTS_UP_TIMEOUT, 20, 0, check_interface_status_of_up_ports, duthost):
        raise RuntimeError("{}: ports did not come up within {}s of restarting swss".format(
            duthost.hostname, PORTS_UP_TIMEOUT))
    wait_bgp_sessions(duthost, timeout=BGP_UP_TIMEOUT)


def native_recovery_mode(duthost):
    """Return the mechanism duthost boots into, restoring a chip config left staged by an earlier run first."""
    if can_force_software(duthost) and _has_override(duthost):
        logger.warning("%s: stale pfcwd recovery staging found; restoring it", duthost.hostname)
        _clear_override(duthost)
        _restart_swss(duthost)
    return get_pfcwd_recovery_mode(duthost)


def available_recovery_modes(duthost, native):
    """Return the mechanisms duthost can run: its native one, plus software when native is hardware."""
    modes = {native}
    if native == HARDWARE and can_force_software(duthost):
        modes.add(SOFTWARE)
    return modes


def set_recovery_mode(duthost, mode):
    """
    Stage software recovery and verify it by read-back; undo and raise on mismatch.
    Raises RecoveryModeUnsupported when the SAI on the image cannot turn hardware DLDR off.
    """
    if mode != SOFTWARE or not can_force_software(duthost):
        raise RuntimeError("{}: cannot force {} recovery on asic type {}".format(
            duthost.hostname, mode, duthost.facts.get("asic_type")))
    # A later module of the same session: already staged and verified, no second restart.
    if _has_override(duthost) and recovery_state(duthost) == SOFTWARE_STATE:
        logger.info("%s: software recovery already staged", duthost.hostname)
        return
    if not _sai_supports_dldr_property(duthost):
        raise RecoveryModeUnsupported("{}: the SAI on this image does not support sai_pfc_dldr_capability".format(
            duthost.hostname))
    logger.warning(RECOVERY_RECIPE)
    _apply_override(duthost)
    _restart_swss(duthost)
    state = recovery_state(duthost)
    state["purge-drop bit set in"] = _run_stage_script(duthost, "purge", _device_dir(duthost), BACKUP_SUFFIX,
                                                       hex(PURGE_DROP_BITS))["purge"]
    if state != dict(SOFTWARE_STATE, **{"purge-drop bit set in": []}):
        logger.error("%s: switch to %s failed (%s); restoring", duthost.hostname, mode, state)
        restore_recovery_mode(duthost)
        raise RuntimeError("{}: asked for {} recovery but read back {}".format(duthost.hostname, mode, state))


def restore_recovery_mode(duthost):
    """Restore the chip config and restart swss; a no-op when nothing is staged."""
    if not _has_override(duthost):
        return
    _clear_override(duthost)
    _restart_swss(duthost)
