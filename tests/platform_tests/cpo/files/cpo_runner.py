"""Execute cpoutil and return only public structure or redacted data.

DOM identities, raw EEPROM bytes and incidental platform diagnostics never
cross the Ansible boundary. This is an output filter, not a test framework.
"""
import json
import re
import subprocess
import sys


TABLE_FIELDS = {
    "Interface", "OE", "OE Lanes", "ELS", "ELS Lasers", "Presence",
    "Module State", "Temperature (C)", "Low-power Mode", "Lane",
    "Tx Disable Status", "Configured Application", "Active Application",
    "Data Path State", "Laser", "ELS Lane State", "Shared",
}
DIAGNOSTICS = ("not implemented", "invalid", "failed", "traceback", "no such command", "no such option",
               "missing option", "missing argument", "requires an argument", "must be supplied together")


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


def table_summary(output):
    lines = output.splitlines()
    headers = []
    tables = []
    for index, line in enumerate(lines):
        if index and re.fullmatch(r"\s*-{2,}[-\s]*", line):
            # Return only known public column names, never arbitrary output.
            fields = [field for field in re.split(r"\s{2,}", lines[index - 1].strip()) if field in TABLE_FIELDS]
            if not fields:
                continue
            headers.extend(fields)
            rows = []
            for row in lines[index + 1:]:
                if not row.strip():
                    break
                match = re.match(r"\s*((?:Ethernet\S+|OE\d+|ELS\d+))(?=\s|$)", row, re.I)
                if match:
                    rows.append(match[1])
            tables.append({"headers": fields, "resources": sorted(set(rows))})
    resources = re.findall(r"^\s*((?:Ethernet\S+|OE\d+|ELS\d+))(?=\s|$)", output, re.M | re.I)
    return {"headers": headers, "resources": sorted(set(resources)), "tables": tables}


def dom_summary(output):
    records = {}
    current = None
    for line in output.splitlines():
        match = re.fullmatch(r"(\S+): CPO EEPROM (not )?detected", line)
        if match:
            current = match[1]
            records[current] = {"present": not bool(match[2]), "sections": []}
        elif current and line.strip() in ("OE:", "ELS:"):
            records[current]["sections"].append(line.strip()[:-1].lower())
    return records


def eeprom_summary(output):
    data_size = 0
    for line in output.splitlines():
        match = re.match(r"^\s*[0-9a-fA-F]{8}\s+([^|]+)\|", line)
        if match:
            tokens = match[1].split()
            if not tokens or any(not re.fullmatch(r"[0-9a-fA-F]{2}", token) for token in tokens):
                raise ValueError("Malformed EEPROM row")
            data_size += len(tokens)
    if not data_size:
        raise ValueError("EEPROM output contains no bytes")
    # The CLI headings contain public port/resource identifiers only.
    headings = [line for line in output.splitlines() if re.fullmatch(
        r"EEPROM hexdump for (?:(?:OE|ELS)\d+|port Ethernet\S+ \((?:OE|ELS)\d+\))", line)]
    return {"size": data_size, "headings": headings}


def run(arguments):
    result = subprocess.run(["cpoutil"] + arguments, capture_output=True, text=True, timeout=300)
    text = (result.stdout + "\n" + result.stderr).lower()
    safe = {"rc": result.returncode, "stdout": "",
            "stderr": "; ".join(label for label in DIAGNOSTICS if label in text)}
    if result.returncode:
        return safe
    if "--help" in arguments or "-h" in arguments:
        safe["stdout"] = result.stdout
    elif "--json" in arguments or "-j" in arguments:
        try:
            safe["stdout"] = json.dumps(redact_dom(json.loads(result.stdout)))
        except (TypeError, ValueError):
            safe.update(rc=3, stderr="invalid CLI JSON")
    elif arguments[:3] == ["show", "interface", "dom"]:
        safe["dom"] = dom_summary(result.stdout)
    elif arguments[:1] == ["show"]:
        safe["table"] = table_summary(result.stdout)
    elif arguments[:1] == ["read-eeprom"]:
        try:
            safe["eeprom"] = eeprom_summary(result.stdout)
        except ValueError:
            safe.update(rc=3, stderr="invalid EEPROM output")
    return safe


def main():
    try:
        result = run(json.loads(sys.argv[1]))
    except Exception:
        result = {"rc": 3, "stdout": "", "stderr": "DUT command failed; raw output suppressed"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
