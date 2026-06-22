#!/usr/bin/env python3
"""Safe inventory perturbation helper for transceiver negative-path testing.

Fault injection for the "Failure-scenario matrix": flip ONE inventory value to a
known-wrong one, run the target test, confirm it fails with the expected
message, then restore the file byte-for-byte.

The transceiver inventory JSON files are untracked local lab data (git cannot
revert them), so every ``set`` / ``del`` first copies the target file aside to
``<file>.neg.bak``.  ``revert`` restores from that backup byte-for-byte and
removes it.  ``status`` lists any perturbation still in flight.

This script is intentionally dependency-free (stdlib only) so it runs in the
DUT session without importing the test framework.

Examples
--------
  # Flip the merged vdm_supported for all PINEWAVE ports (category defaults):
  python perturb_inventory.py set \
      ansible/files/transceiver/inventory/attributes/eeprom/eeprom.json \
      defaults.vdm_supported false

  # Wrong identifier byte (deployment layer):
  python perturb_inventory.py set \
      ansible/files/transceiver/inventory/attributes/eeprom/eeprom.json \
      transceivers.deployment_configurations.8x100G_DR8.sff8024_identifier 17

  # Remove a required attribute to exercise the "missing -> fail" path:
  python perturb_inventory.py del \
      ansible/files/transceiver/inventory/attributes/eeprom/eeprom.json \
      defaults.cdb_stress_iteration_count

  # Restore after the run:
  python perturb_inventory.py revert \
      ansible/files/transceiver/inventory/attributes/eeprom/eeprom.json

  # See what is still perturbed (and abort a run if anything is):
  python perturb_inventory.py status
"""
import argparse
import glob
import hashlib
import json
import os
import shutil
import sys

BACKUP_SUFFIX = ".neg.bak"

# Where to scan for stray backups in `status`. Anchored on this file's location
# so it works from any cwd: <repo>/tests/transceiver/eeprom/negative_testing/.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), *([os.pardir] * 4)))
_INV_DIR = os.path.join(_REPO_ROOT, "ansible", "files", "transceiver", "inventory")


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()[:12]


def _backup_path(path):
    return path + BACKUP_SUFFIX


def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _dump(path, data):
    # Pretty-print is irrelevant: revert restores the original bytes from the
    # backup, so the perturbed file's formatting never has to match the source.
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _split_key(dotted):
    return dotted.split(".")


def _navigate(data, keys, create=False):
    """Return (parent_dict, last_key). Raise KeyError if a segment is missing."""
    node = data
    for seg in keys[:-1]:
        if seg not in node or not isinstance(node[seg], dict):
            if create:
                node[seg] = {}
            else:
                raise KeyError(f"path segment '{seg}' not found")
        node = node[seg]
    return node, keys[-1]


def _ensure_backup(path):
    bak = _backup_path(path)
    if os.path.exists(bak):
        sys.exit(
            f"ERROR: backup already exists at {bak}\n"
            f"       A perturbation is already in flight for this file.\n"
            f"       Run 'revert {path}' before injecting another fault."
        )
    shutil.copy2(path, bak)
    return bak


def _parse_value(raw):
    """Best-effort: JSON-decode the value, else treat it as a string."""
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


def cmd_set(args):
    path = args.file
    if not os.path.isfile(path):
        sys.exit(f"ERROR: file not found: {path}")
    data = _load(path)
    keys = _split_key(args.key)
    try:
        parent, last = _navigate(data, keys, create=args.create)
    except KeyError as e:
        sys.exit(f"ERROR: {e} in {path} (use --create to add missing parents)")
    if last not in parent and not args.create:
        sys.exit(
            f"ERROR: key '{args.key}' does not currently exist in {path}.\n"
            f"       Refusing to invent a new key (use --create to override).\n"
            f"       This guards against typos that would silently no-op the test."
        )
    new_val = _parse_value(args.value)
    old_val = parent.get(last, "<absent>")
    bak = _ensure_backup(path)
    parent[last] = new_val
    _dump(path, data)
    print(f"SET  {path}")
    print(f"     {args.key}: {old_val!r} -> {new_val!r}")
    print(f"     backup: {bak} (orig sha {_sha(bak)})")
    print(f"     revert with: python {os.path.basename(__file__)} revert {path}")


def cmd_del(args):
    path = args.file
    if not os.path.isfile(path):
        sys.exit(f"ERROR: file not found: {path}")
    data = _load(path)
    keys = _split_key(args.key)
    try:
        parent, last = _navigate(data, keys, create=False)
    except KeyError as e:
        sys.exit(f"ERROR: {e} in {path}")
    if last not in parent:
        sys.exit(f"ERROR: key '{args.key}' not present in {path}; nothing to delete.")
    old_val = parent[last]
    bak = _ensure_backup(path)
    del parent[last]
    _dump(path, data)
    print(f"DEL  {path}")
    print(f"     removed {args.key} (was {old_val!r})")
    print(f"     backup: {bak} (orig sha {_sha(bak)})")
    print(f"     revert with: python {os.path.basename(__file__)} revert {path}")


def cmd_revert(args):
    path = args.file
    bak = _backup_path(path)
    if not os.path.exists(bak):
        sys.exit(f"ERROR: no backup found at {bak}; nothing to revert.")
    shutil.copy2(bak, path)
    restored_sha = _sha(path)
    os.remove(bak)
    print(f"REVERT {path}  (restored, sha {restored_sha}, backup removed)")


def cmd_status(args):
    pattern = os.path.join(_INV_DIR, "**", "*" + BACKUP_SUFFIX)
    backups = sorted(glob.glob(pattern, recursive=True))
    if not backups:
        print("CLEAN: no inventory perturbations in flight.")
        return 0
    print(f"WARNING: {len(backups)} perturbation(s) in flight (backups present):")
    for bak in backups:
        live = bak[: -len(BACKUP_SUFFIX)]
        dirty = "DIFFERS" if (os.path.isfile(live) and _sha(live) != _sha(bak)) else "same"
        print(f"  {live}  [{dirty} from backup]")
    print("Revert each with: python perturb_inventory.py revert <file>")
    return 1


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("set", help="back up file, then set a dotted key to a value")
    ps.add_argument("file")
    ps.add_argument("key", help="dotted path, e.g. defaults.vdm_supported")
    ps.add_argument("value", help="JSON value (true/false/17/\"str\"); bare text -> string")
    ps.add_argument("--create", action="store_true", help="allow creating a missing key/parents")
    ps.set_defaults(func=cmd_set)

    pd = sub.add_parser("del", help="back up file, then delete a dotted key")
    pd.add_argument("file")
    pd.add_argument("key")
    pd.set_defaults(func=cmd_del)

    pr = sub.add_parser("revert", help="restore a file from its backup, byte-for-byte")
    pr.add_argument("file")
    pr.set_defaults(func=cmd_revert)

    pstat = sub.add_parser("status", help="list perturbations still in flight")
    pstat.set_defaults(func=cmd_status)

    args = p.parse_args()
    rc = args.func(args)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
