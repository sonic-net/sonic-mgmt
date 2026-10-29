"""Run cpoutil on the DUT without returning identity data or raw EEPROM bytes.

Range comparisons use digests. Scratch-write backup/readback/restoration stays
in this process; only pass/fail flags cross the Ansible boundary.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor


DIAGNOSTICS = (
    "not implemented", "invalid", "no such command", "no such option", "missing option", "missing argument",
    "requires an argument", "invalid value", "offset must be between", "bank must be between",
    "data must contain at least one byte",
    "unexpected extra argument", "root privileges are required", "-1", "hex",
    "size must be greater than zero", "crosses the cmis page boundary", "page must be between",
    "does not use bank selection", "valid range: 80h-ffh", "must be supplied together",
    "not declared", "does not cover offsets", "exactly one", "sfputil", "failed", "traceback",
)
BACKUP_DIRECTORY = "/var/tmp"


def scratch_backup(location, original):
    fd, path = tempfile.mkstemp(prefix="cpoutil-scratch-recovery-", suffix=".json", dir=BACKUP_DIRECTORY)
    # mkstemp creates the file with owner-only access (0600 on the DUT).
    with os.fdopen(fd, "w", encoding="utf-8") as backup:
        json.dump({"address": {key: value for key, value in location.items() if key != "data"},
                   "original_data": original.hex()}, backup)
    return path


def execute(arguments, privileged=True):
    prefix = ["cpoutil"] if privileged else ["sudo", "-u", "nobody", "--", "cpoutil"]
    return subprocess.run(prefix + arguments, capture_output=True, text=True, timeout=300)


def diagnostic(result):
    text = (result.stdout + "\n" + result.stderr).lower()
    labels = [label for label in DIAGNOSTICS if label in text]
    return "; ".join(labels) or ("cpoutil command failed" if result.returncode else "")


def redact_dom(value, in_info=False):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            sensitive = in_info or key == "info" or re.search(
                r"serial|vendor|manufacturer|model|part.?number|oui|date.?code|\bsn\b", str(key), re.I)
            if key == "read_errors":
                result[key] = ["read failed"] * len(item) if isinstance(item, list) else ["read failed"]
            elif sensitive and not isinstance(item, dict):
                result[key] = "<redacted>" if item is not None else None
            else:
                result[key] = redact_dom(item, bool(sensitive))
        return result
    if isinstance(value, list):
        return [redact_dom(item, in_info) for item in value]
    return "<redacted>" if in_info and value is not None else value


def dump_bytes(output):
    data = bytearray()
    for line in output.splitlines():
        match = re.match(r"^\s*[0-9a-fA-F]{8}\s+([^|]+)\|", line)
        if match:
            tokens = match.group(1).split()
            if not tokens or any(not re.fullmatch(r"[0-9a-fA-F]{2}", token) for token in tokens):
                raise ValueError("Malformed EEPROM row")
            data.extend(int(token, 16) for token in tokens)
    if not data:
        raise ValueError("EEPROM output contains no bytes")
    return bytes(data)


def summarize_dump(output, ranged):
    headings = [line for line in output.splitlines() if line.startswith("EEPROM hexdump for ")]
    data = dump_bytes(output)
    result = {"size": len(data), "headings": headings}
    if ranged:
        result["sha256"] = hashlib.sha256(data).hexdigest()
    return result


def run(arguments, privileged=True):
    result = execute(arguments, privileged)
    safe = {"rc": result.returncode, "stdout": "", "stderr": diagnostic(result)}
    if result.returncode == 0 and ("--help" in arguments or "-h" in arguments):
        safe["stdout"] = result.stdout
    elif arguments[:3] == ["show", "interface", "dom"]:
        if "--json" in arguments or "-j" in arguments:
            try:
                safe["stdout"] = json.dumps(redact_dom(json.loads(result.stdout)))
            except (TypeError, ValueError):
                safe["stdout"] = "<invalid DOM JSON>"
        else:
            safe["stdout"] = "\n".join(line for line in result.stdout.splitlines()
                                       if re.fullmatch(r"\S+: CPO EEPROM (?:not )?detected", line))
    elif arguments and arguments[0] == "read-eeprom" and result.returncode == 0:
        try:
            safe["eeprom"] = summarize_dump(result.stdout, "-s" in arguments or "--size" in arguments)
            safe["stdout"] = "\n".join(safe["eeprom"]["headings"])
        except ValueError:
            safe.update(rc=3, stderr="invalid EEPROM output")
    elif arguments[:1] == ["show"]:
        if "--json" in arguments or "-j" in arguments:
            try:
                safe["stdout"] = json.dumps(redact_dom(json.loads(result.stdout)))
            except (TypeError, ValueError):
                safe["stdout"] = "<invalid CLI JSON>"
        else:
            # Table cases check resource rows; values are checked independently
            # through JSON. Do not transport incidental platform diagnostics.
            safe["stdout"] = "\n".join(re.findall(
                r"^\s*((?:Ethernet\S+|OE\d+|ELS\d+))(?=\s|$)", result.stdout, re.M | re.I))
    elif result.returncode == 0 and arguments in (["--help"], ["-h"]):
        safe["stdout"] = result.stdout
    return safe


def scratch_transaction(location, port=None):
    """Keep original scratch bytes on the DUT, including partial-write recovery."""
    address = [location["target"], "-i", str(location["index"]), "-b", str(location["bank"]),
               "-n", str(location["page"]), "-o", str(location["offset"])]
    pattern = bytes.fromhex(location["data"])
    read = ["read-eeprom"] + address + ["-s", str(len(pattern))]
    restore = ["write-eeprom"] + address + ["-d"]
    write = restore if port is None else [
        "write-eeprom", "interface", "-p", port, "--" + location["target"],
        "-n", str(location["page"]), "-o", str(location["offset"]), "-d"]
    summary = {"rc": 0, "readback": False, "restored": False, "stderr": ""}

    def read_bytes():
        result = execute(read)
        if result.returncode:
            raise ValueError("Scratch read failed")
        data = dump_bytes(result.stdout)
        if len(data) != len(pattern):
            raise ValueError("Scratch read length mismatch")
        return data

    original = read_bytes()
    if original == pattern:
        return dict(summary, rc=3, stderr="Scratch pattern must differ from saved bytes")
    # Persist privately before mutation; retain recovery data if restoration fails.
    backup_path = scratch_backup(location, original)
    try:
        result = execute(write + [pattern.hex()])
        if result.returncode:
            summary.update(rc=result.returncode, stderr=diagnostic(result))
        else:
            summary["readback"] = read_bytes() == pattern
    except Exception:
        summary.update(rc=3, stderr="Scratch write/readback failed")
    finally:
        try:
            result = execute(restore + [original.hex()])
            summary["restored"] = result.returncode == 0 and read_bytes() == original
        except Exception:
            summary["restored"] = False
        if summary["restored"]:
            try:
                os.unlink(backup_path)
            except OSError:
                summary.update(rc=3, recovery_file=backup_path, stderr="Private backup cleanup failed")
        else:
            summary["recovery_file"] = backup_path
    if not summary["readback"] or not summary["restored"]:
        summary["rc"] = summary["rc"] or 3
    return summary


def main():
    try:
        request = json.loads(sys.argv[1])
        if "scratch" in request:
            result = scratch_transaction(request["scratch"], request.get("port"))
        elif "concurrent" in request:
            with ThreadPoolExecutor(max_workers=4) as pool:
                result = {"jobs": list(pool.map(run, [request["concurrent"]] * 4))}
        else:
            result = run(request["args"], request.get("privileged", True))
    except Exception:
        result = {"rc": 3, "stdout": "", "stderr": "CPO runner failed; raw output suppressed"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
