#!/usr/bin/env python3
"""
Testbed reservation tool.

Prevents multiple engineers from running tests on the same testbed simultaneously.
Reservations are stored on a central server and verified by run_test.sh / spytest_run.py
before allowing test execution.

Usage:
    # Show all testbed status (default, no args):
    ./testbed.py

    # Reserve a testbed for N hours:
    ./testbed.py --testbed 10002 --reserve 4 --note "qos regression"

    # Release a testbed:
    ./testbed.py --testbed 10002 --release
"""
import argparse
import base64
import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timedelta
from testbed_config import TESTBED_IDS, ADMIN_PASSWORD

DEFAULT_LOCK_HOURS = 15  # safety ceiling for programmatic callers

# ── Server config (read from testbed_config or environment) ──
_SERVER_HOST = os.environ.get("TESTBED_LOCK_HOST", "sonic-ucs-m6-51")
_SERVER_USER = os.environ.get("TESTBED_LOCK_USER", "sonic")
_SERVER_PASS = os.environ.get("TESTBED_LOCK_PASS", "")
_SERVER_DIR = os.environ.get("TESTBED_LOCK_DIR", "/home/sonic/.tblk")

# Fallback: read from testbed_config if env not set
if not _SERVER_PASS:
    try:
        from testbed_config import LOCK_SERVER_PASSWORD
        _SERVER_PASS = LOCK_SERVER_PASSWORD
    except ImportError:
        print("Error: TESTBED_LOCK_PASS not set and LOCK_SERVER_PASSWORD not in testbed_config.py",
              file=sys.stderr)
        sys.exit(1)

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "PubkeyAuthentication=no",
    "-o", "PreferredAuthentications=password",
    "-o", "ConnectTimeout=5",
    "-o", "LogLevel=ERROR",
]


def _ssh_cmd(cmd, timeout=15):
    """Run a command on the reservation server. Returns (returncode, stdout, stderr)."""
    full_cmd = [
        "sshpass", "-p", _SERVER_PASS, "ssh"
    ] + SSH_OPTS + [f"{_SERVER_USER}@{_SERVER_HOST}", cmd]
    r = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _encode(data):
    """Obfuscate lock data for storage."""
    return base64.b64encode(data.encode()).decode()


def _decode(data):
    """De-obfuscate lock data from storage."""
    return base64.b64decode(data.encode()).decode()


def _eastern_now():
    """Return current time in US Eastern (auto-detects EDT/EST)."""
    utc = datetime.utcnow()
    # US Eastern: EDT = UTC-4 (Mar second Sun – Nov first Sun), EST = UTC-5
    mar1 = datetime(utc.year, 3, 1)
    dst_start = mar1 + timedelta(days=(6 - mar1.weekday()) % 7 + 7)  # 2nd Sunday
    nov1 = datetime(utc.year, 11, 1)
    dst_end = nov1 + timedelta(days=(6 - nov1.weekday()) % 7)        # 1st Sunday
    # DST transitions at 2:00 AM local (07:00 UTC for EDT start, 06:00 UTC for end)
    is_dst = dst_start.replace(hour=7) <= utc < dst_end.replace(hour=6)
    return utc + timedelta(hours=-4 if is_dst else -5)


def _audit_log(yaml_name, action, result):
    """Append an entry to the audit log on the lock server."""
    ts = _eastern_now().strftime("%b %-d, %Y %H:%M:%S")
    user = os.environ.get("USER", "unknown")
    basename = os.path.splitext(os.path.basename(yaml_name))[0]
    line = f"{ts}  {user}  {basename}  {action}  {result}"
    log = f"{_SERVER_DIR}/audit.log"
    cmd = (f"mkdir -p {_SERVER_DIR} && echo '{line}' >> {log}"
           f" && tail -1000 {log} > {log}.tmp && mv {log}.tmp {log}")
    _ssh_cmd(cmd, timeout=5)


def _lock_path(yaml_name):
    """Remote path for a lock file."""
    basename = os.path.basename(yaml_name)
    return f"{_SERVER_DIR}/.{basename}.dat"


def _schedule_expiry(yaml_name, hours):
    """Schedule an 'at' job on the UCS to auto-remove the lock after N hours.
    Returns the at job ID (str) or None on failure."""
    minutes = max(1, int(hours * 60))
    path = _lock_path(yaml_name)
    basename = os.path.splitext(os.path.basename(yaml_name))[0]
    # The at job: unlock perms, remove lock, log the expiry
    log = f"{_SERVER_DIR}/audit.log"
    at_script = (
        f"chmod 700 {path} 2>/dev/null && rm -f {path} && "
        f"echo \\\"$(TZ=US/Eastern date '+%b %-d, %Y %H:%M:%S')  SYSTEM  {basename}  EXPIRE  auto\\\" >> {log}"
    )
    cmd = f'echo "{at_script}" | at now + {minutes} minutes 2>&1'
    rc, out, _ = _ssh_cmd(cmd, timeout=10)
    if rc != 0:
        return None
    # Parse at job ID from output like "job 42 at Thu May 15 20:00:00 2026"
    m = re.search(r'job\s+(\d+)\s+at', out)
    return m.group(1) if m else None


def _cancel_expiry(at_job_id):
    """Cancel a previously scheduled at job on the UCS."""
    if at_job_id:
        _ssh_cmd(f"atrm {at_job_id} 2>/dev/null", timeout=5)


def get_lock_info(yaml_name):
    """Read lock info from server. Returns dict or None if not locked (or expired)."""
    path = _lock_path(yaml_name)
    # Unlock perms, read, re-lock perms
    _ssh_cmd(f"chmod 700 {path} 2>/dev/null", timeout=5)
    rc, out, _ = _ssh_cmd(f"cat {path} 2>/dev/null")
    _ssh_cmd(f"chmod 000 {path} 2>/dev/null", timeout=5)
    if rc != 0 or not out:
        return None
    try:
        out = _decode(out)
    except Exception:
        pass  # Fallback: try reading as plain JSON (legacy files)
    try:
        info = json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return None

    # Check if lock has expired (all times are UTC)
    expires = info.get("expires", "")
    if expires:
        try:
            exp_time = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
            if datetime.utcnow() > exp_time:
                return None  # Expired — treat as unlocked
        except ValueError:
            pass  # Malformed expires — treat as no expiry

    return info


def _read_raw_lock(yaml_name):
    """Read the raw lock file (ignoring expiry). Returns dict or None."""
    path = _lock_path(yaml_name)
    _ssh_cmd(f"chmod 700 {path} 2>/dev/null", timeout=5)
    rc, out, _ = _ssh_cmd(f"cat {path} 2>/dev/null")
    _ssh_cmd(f"chmod 000 {path} 2>/dev/null", timeout=5)
    if rc != 0 or not out:
        return None
    try:
        out = _decode(out)
    except Exception:
        pass
    try:
        return json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return None


def acquire_lock(yaml_name, note="", force=False, hours=None):
    """Acquire the lock. Returns (success, message)."""
    if hours is None:
        hours = DEFAULT_LOCK_HOURS
    current = get_lock_info(yaml_name)
    me = os.environ.get("USER", "unknown")
    my_host = socket.gethostname()

    if current:
        owner = current.get("user", "unknown")
        since = current.get("since", "?")
        lock_host = current.get("host", "?")

        # Already locked by me — cancel old expiry timer, then renew
        if owner == me:
            _cancel_expiry(current.get("at_job"))
        elif not force:
            _audit_log(yaml_name, "RESERVE", f"REJECTED (held by {owner}@{lock_host})")
            return False, (
                f"LOCKED by {owner}@{lock_host} since {since}\n"
                f"  Ask {owner} to release."
            )
        else:
            # Force-acquire: cancel previous owner's timer
            _cancel_expiry(current.get("at_job"))
    else:
        # Lock is expired or absent — cancel any lingering at job from the
        # previous owner's reservation (the file may still exist on disk even
        # though get_lock_info treats it as expired).
        raw = _read_raw_lock(yaml_name)
        if raw:
            _cancel_expiry(raw.get("at_job"))

    # Schedule auto-expiry on UCS
    at_job = _schedule_expiry(yaml_name, hours)

    now = datetime.utcnow()
    expires = now + timedelta(hours=hours)
    lock_data = json.dumps({
        "user": me,
        "host": my_host,
        "since": now.strftime("%Y-%m-%d %H:%M:%S"),
        "expires": expires.strftime("%Y-%m-%d %H:%M:%S"),
        "hours": hours,
        "note": note,
        "at_job": at_job,
    })

    # Create dir + write lock file (encoded), then lock perms
    encoded = _encode(lock_data)
    path = _lock_path(yaml_name)
    cmd = f"mkdir -p {_SERVER_DIR} && chmod 700 {_SERVER_DIR} && chmod 700 {path} 2>/dev/null; echo '{encoded}' > {path} && chmod 000 {path}"
    rc, _, err = _ssh_cmd(cmd)
    if rc != 0:
        return False, f"Failed to write lock: {err}"
    _audit_log(yaml_name, "RESERVE", "GRANTED")
    exp_eastern = _eastern_now() + timedelta(hours=hours)
    exp_str = exp_eastern.strftime("%b %-d, %Y %-I:%M %p EDT")
    return True, f"Reserved. Expires at {exp_str}."


def release_lock(yaml_name, force=False):
    """Release the lock. Returns (success, message)."""
    current = get_lock_info(yaml_name)
    if not current:
        return True, "Not locked."

    me = os.environ.get("USER", "unknown")
    owner = current.get("user", "unknown")

    if owner != me and not force:
        return False, f"Lock held by {owner} (not you)."

    # Cancel the scheduled auto-expiry
    _cancel_expiry(current.get("at_job"))

    path = _lock_path(yaml_name)
    _ssh_cmd(f"chmod 700 {path} 2>/dev/null", timeout=5)
    rc, _, err = _ssh_cmd(f"rm -f {path}")
    if rc != 0:
        return False, f"Failed to remove lock: {err}"
    _audit_log(yaml_name, "RELEASE", "OK")
    return True, "Released."


def _list_all():
    """List all testbed locks. Returns list of (yaml_name, info_dict)."""
    rc, out, _ = _ssh_cmd(f"ls {_SERVER_DIR}/.*.dat 2>/dev/null")
    if rc != 0 or not out:
        return []
    locks = []
    for path in out.split("\n"):
        # Filename is .gamut_2x2_qos.yaml.dat → strip leading dot and .dat
        fname = os.path.basename(path)
        name = fname[1:].replace(".dat", "")  # remove leading '.' and trailing '.dat'
        info = get_lock_info(name)
        if info:
            locks.append((name, info))
    return locks


# ── Public API for other scripts ──

def check_lock(yaml_name):
    """Check if the current user holds the reservation.

    Returns True if OK to proceed (user holds it), False if not.
    Prints status messages to stderr.
    """
    current = get_lock_info(yaml_name)
    me = os.environ.get("USER", "unknown")

    if not current:
        print(f"  Testbed not reserved. Run: ./testbed.py --testbed <ID> --reserve <HOURS> --note '...'",
              file=sys.stderr)
        return False

    if current.get("user") != me:
        owner = current.get("user", "unknown")
        host = current.get("host", "?")
        expires = current.get("expires", "?")
        note = current.get("note", "")
        print(f"  TESTBED RESERVED by {owner}@{host} (expires {expires}) — {note}",
              file=sys.stderr)
        return False

    return True


def expire_stale_locks():
    """Remove all expired lock files. Called by cron."""
    rc, out, _ = _ssh_cmd(f"ls {_SERVER_DIR}/.*.dat 2>/dev/null")
    if rc != 0 or not out:
        return
    for path in out.split("\n"):
        fname = os.path.basename(path)
        name = fname[1:].replace(".dat", "")
        # chmod to read, then re-lock after
        _ssh_cmd(f"chmod 700 {path} 2>/dev/null", timeout=5)
        rc2, raw, _ = _ssh_cmd(f"cat {path} 2>/dev/null")
        if rc2 != 0 or not raw:
            _ssh_cmd(f"chmod 000 {path} 2>/dev/null", timeout=5)
            continue
        try:
            raw = _decode(raw)
        except Exception:
            pass
        try:
            info = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            _ssh_cmd(f"chmod 000 {path} 2>/dev/null", timeout=5)
            continue
        expires = info.get("expires", "")
        if not expires:
            _ssh_cmd(f"chmod 000 {path} 2>/dev/null", timeout=5)
            continue
        try:
            exp_time = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
            if datetime.utcnow() > exp_time:
                _ssh_cmd(f"rm -f {path}")
                _audit_log(name, "EXPIRE", f"auto-expired (was {info.get('user','?')})")
                print(f"Expired: {name} (was {info.get('user','?')}, expired {expires})")
            else:
                _ssh_cmd(f"chmod 000 {path} 2>/dev/null", timeout=5)
        except ValueError:
            _ssh_cmd(f"chmod 000 {path} 2>/dev/null", timeout=5)


def _resolve_testbed(args):
    """Resolve --testbed <int> or --yaml <name> to a YAML name. Returns str or None."""
    if hasattr(args, 'testbed') and args.testbed is not None:
        entry = TESTBED_IDS.get(args.testbed)
        if not entry:
            print(f"Unknown testbed ID: {args.testbed}", file=sys.stderr)
            print("Valid IDs:", file=sys.stderr)
            for tid, (yname, desc) in sorted(TESTBED_IDS.items()):
                print(f"  {tid} = {desc} ({yname})", file=sys.stderr)
            sys.exit(1)
        return entry[0]
    if hasattr(args, 'yaml') and args.yaml:
        return os.path.basename(args.yaml)
    return None


def _show_all_status():
    """Show status of all known testbeds."""
    locks = _list_all()
    lock_map = {name: info for name, info in locks}

    print(f"{'ID':<7} {'Testbed':<15} {'Status':<10} {'User':<12} {'Remaining':<12} {'Note'}")
    print("-" * 80)
    for tid, (yname, desc) in sorted(TESTBED_IDS.items()):
        stem = os.path.splitext(yname)[0] if "." in yname else yname
        # Try both with and without extension
        info = lock_map.get(yname) or lock_map.get(stem)
        if info:
            user = info.get("user", "?")
            expires = info.get("expires", "")
            remaining = "?"
            if expires:
                try:
                    exp_time = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
                    left = exp_time - datetime.utcnow()
                    hrs = left.total_seconds() / 3600
                    if hrs >= 1:
                        remaining = f"{hrs:.1f}h"
                    elif hrs > 0:
                        remaining = f"{int(left.total_seconds() / 60)}m"
                    else:
                        remaining = "expired"
                except ValueError:
                    pass
            note = info.get("note", "")
            print(f"{tid:<7} {desc:<15} {'RESERVED':<10} {user:<12} {remaining:<12} {note}")
        else:
            print(f"{tid:<7} {desc:<15} {'free':<10}")


def main():
    parser = argparse.ArgumentParser(
        description="Testbed reservation tool",
        epilog="Testbed IDs:\n" + "\n".join(
            f"  {tid} = {desc} ({yname})"
            for tid, (yname, desc) in sorted(TESTBED_IDS.items())
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--testbed", type=int, metavar="ID",
                        help="Testbed ID (see list below)")
    parser.add_argument("--reserve", type=float, metavar="HOURS",
                        help="Reserve testbed for N hours")
    parser.add_argument("--release", action="store_true",
                        help="Release testbed reservation")
    parser.add_argument("--note", metavar="TEXT",
                        help="Purpose of reservation (required with --reserve)")
    parser.add_argument("--force", action="store_true", help=argparse.SUPPRESS)
    # Hidden: used internally by run_test.sh / spytest_run.py
    parser.add_argument("--yaml", help=argparse.SUPPRESS)
    parser.add_argument("--check", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--expire-stale", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--log", nargs="?", const=20, type=int, metavar="N", help=argparse.SUPPRESS)
    args = parser.parse_args()

    # Admin password gate for privileged operations
    if args.force or args.expire_stale:
        import getpass
        pw = getpass.getpass("Admin password: ")
        if pw != base64.b64decode(ADMIN_PASSWORD).decode():
            print("Invalid admin password.", file=sys.stderr)
            sys.exit(1)

    # Hidden: show audit log (--log [N] shows last N entries, default 20)
    if args.log is not None:
        rc, out, _ = _ssh_cmd(f"cat {_SERVER_DIR}/audit.log 2>/dev/null | tail -{args.log}")
        if rc == 0 and out:
            fmt = "%-24s  %-12s  %-35s  %-10s  %s"
            print(fmt % ("Timestamp", "User", "Testbed", "Action", "Result"))
            print("-" * 92)
            for raw in out.splitlines():
                parts = raw.split("  ")
                parts = [p.strip() for p in parts if p.strip()]
                if len(parts) < 5:
                    print(raw)
                    continue
                ts_str = parts[0] + " " + parts[1] + " " + parts[2]
                print(fmt % (ts_str, parts[3], parts[4], parts[5] if len(parts) > 5 else "", parts[6] if len(parts) > 6 else ""))
        else:
            print("(no audit log)")
        return

    # Hidden: cron expiry
    if args.expire_stale:
        expire_stale_locks()
        return

    # Hidden: verify current user holds reservation (exit 0 = yes, exit 1 = no)
    if args.check:
        yaml_name = _resolve_testbed(args)
        if not yaml_name:
            parser.error("--testbed or --yaml required with --check")
        ok = check_lock(yaml_name)
        sys.exit(0 if ok else 1)

    # No action specified → show all testbed status
    if args.reserve is None and not args.release:
        _show_all_status()
        return

    # For reserve/release, need a testbed
    yaml_name = _resolve_testbed(args)
    if not yaml_name:
        parser.error("--testbed is required for --reserve / --release")

    if args.reserve is not None:
        if not args.note and not args.yaml:
            parser.error("--note is required with --reserve (what are you using it for?)")
        ok, msg = acquire_lock(yaml_name, note=args.note or "", force=args.force, hours=args.reserve)
        print(msg)
        sys.exit(0 if ok else 1)

    elif args.release:
        ok, msg = release_lock(yaml_name, force=args.force)
        print(msg)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
