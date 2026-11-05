"""Parse default cpoutil text on the DUT; return only safe public test data.

The JSON envelope is transport between this filter and Ansible. It is not
cpoutil JSON output. Identity strings and arbitrary cell text stay on the DUT.
"""
import json
import re
import subprocess
import sys


TABLE_FIELDS = {
    "Interface", "OE", "OE Lanes", "ELS", "ELS Lasers", "Presence",
    "Module State", "Status", "Temperature (C)", "Low-power Mode", "Lane",
    "Tx Disable Status", "Configured Application", "Active Application",
    "Data Path State", "Laser", "ELS Lane State", "Shared",
}
DIAGNOSTICS = ("not implemented", "invalid", "failed", "traceback", "no such command", "no such option",
               "missing option", "missing argument", "requires an argument", "must be supplied together")


def table_summary(output):
    """Use simple-table column boundaries, retaining typed values or validity flags."""
    lines = output.splitlines()
    tables, records, ready_resources = [], {}, []
    for index, separator in enumerate(lines):
        if not index or not re.fullmatch(r"\s*-{2,}[-\s]*", separator):
            continue
        columns = [(match.start(), match.end()) for match in re.finditer(r"-{2,}", separator)]
        labels = [lines[index - 1][start:end].strip() for start, end in columns]
        if not any(label in TABLE_FIELDS for label in labels):
            continue
        # Unknown headers remain visible as a neutral marker so their removal
        # cannot accidentally make a malformed table match the expected schema.
        headers = [label if label in TABLE_FIELDS else "<unexpected>" for label in labels]
        resources, lane_rows = [], []
        for line in lines[index + 1:]:
            if not line.strip():
                break
            cells = [line[start:end].strip() for start, end in columns]
            if not cells or not re.fullmatch(r"Ethernet\S+|OE\d+|ELS\d+", cells[0], re.I):
                raise ValueError("Malformed text table row")
            name = cells[0]
            resources.append(name)
            value = None
            if headers == ["Interface", "OE", "OE Lanes", "ELS", "ELS Lasers"]:
                oe = re.fullmatch(r"(OE\d+) bank(\d+)", cells[1])
                els = re.fullmatch(r"(ELS\d+)(?: bank\d+)?", cells[3])
                if not oe or not els or not re.fullmatch(r"\d+(?:,\d+)*", cells[2]):
                    raise ValueError("Malformed map row")
                # Missing precise laser mapping is valid for breakout ports.
                # Use the CLI's actual placeholder, not the old test-only one.
                if cells[4] in ("N/A", "N/A (needs laser_to_asic_lane_mapping)"):
                    lasers = None
                elif not cells[4]:
                    lasers = []  # No lasers were declared for this interface.
                elif re.fullmatch(r"\d+(?:,\d+)*", cells[4]):
                    lasers = [int(item) for item in cells[4].split(",")]
                    if len(lasers) != len(set(lasers)):
                        raise ValueError("Duplicate map laser")
                else:
                    raise ValueError("Malformed laser list")
                lanes = [int(item) for item in cells[2].split(",")]
                if len(lanes) != len(set(lanes)):
                    raise ValueError("Duplicate map lane")
                value = {"oe": {"id": oe[1], "bank": int(oe[2]), "lanes": lanes},
                         "els": {"id": els[1], "lasers": lasers}}
            elif headers == ["Interface", "ELS", "Presence"]:
                if cells[2] not in ("Present", "Not present"):
                    raise ValueError("Malformed presence cell")
                value = {"present": cells[2] == "Present"}
            elif len(headers) == 2 and headers[0] in ("OE", "ELS"):
                name = name.lower()
                if headers[1] == "Low-power Mode":
                    if cells[1] not in ("On", "Off"):
                        raise ValueError("Malformed low-power cell")
                    value = cells[1] == "On"
                elif headers[1] == "Temperature (C)":
                    value = float(cells[1])
                elif headers[1] in ("Module State", "Status"):
                    value = bool(cells[1]) and cells[1] != "N/A"
                    if cells[1] == "ModuleReady":
                        ready_resources.append(name)
            elif headers == ["Interface", "Lane", "Tx Disable Status"]:
                lane = re.fullmatch(r"Lane ([1-9]\d*)", cells[1])
                if not lane or cells[2] not in ("true", "false"):
                    raise ValueError("Malformed TX lane row")
                key = "lane{:02d}".format(int(lane[1]) - 1)
                if key in records.setdefault(name, {}):
                    raise ValueError("Duplicate TX lane row")
                records[name][key] = cells[2] == "true"
            elif headers == ["Interface", "Lane", "Configured Application", "Active Application"]:
                lane = re.fullmatch(r"Lane ([1-9]\d*)", cells[1])
                if not lane:
                    raise ValueError("Malformed Application lane")
                # Public strings are validated here, but never sent to Ansible.
                # N/A and '<AppSel>: N/A' are legitimate display placeholders.
                displays = [bool(re.fullmatch(r"(?:N/A|-?\d+: (?:N/A|\S.* / \S.*))", cell))
                            for cell in cells[2:]]
                lane_rows.append({"port": name, "lane": int(lane[1]) - 1,
                                  "populated": all(bool(cell) for cell in cells[2:]),
                                  "valid_display": all(displays)})
            if value is not None:
                if name in records:
                    raise ValueError("Duplicate resource row")
                records[name] = value
        tables.append({"headers": headers, "resources": sorted(set(resources)), "lane_rows": lane_rows})
    return {"headers": [field for table in tables for field in table["headers"]],
            "resources": sorted({name for table in tables for name in table["resources"]}),
            "tables": tables, "records": records, "ready_resources": sorted(set(ready_resources))}


def dom_summary(output):
    """Keep presence, read-error flags and section/field counts, never DOM values."""
    records = {}
    current, endpoint = None, None
    for line in output.splitlines():
        match = re.fullmatch(r"(Ethernet\S+): CPO EEPROM (not )?detected", line)
        if match:
            current, endpoint = match[1], None
            if current in records:
                raise ValueError("Duplicate DOM interface")
            records[current] = {"present": not bool(match[2]), "sections": [], "read_errors": False,
                                "fields": {"oe": 0, "els": 0}, "monitors": {"oe": False, "els": False},
                                "thresholds": {"oe": False, "els": False}}
        elif current:
            label = line.strip()
            if label.startswith("Read errors:"):
                records[current]["read_errors"] = True
            elif label in ("OE:", "ELS:"):
                endpoint = label[:-1].lower()
                records[current]["sections"].append(endpoint)
            elif endpoint and label in ("ChannelMonitorValues:", "ModuleMonitorValues:", "MonitorValues:"):
                records[current]["monitors"][endpoint] = True
            elif endpoint and label in ("ChannelThresholdValues:", "ModuleThresholdValues:", "ThresholdValues:"):
                records[current]["thresholds"][endpoint] = True
            elif endpoint and re.match(r"\s{8,}\S.*:\s*\S", line):
                records[current]["fields"][endpoint] += 1
    return records


def eeprom_summary(output):
    """Keep a safe target heading and whether any real hexdump row exists."""
    headings = [line.strip() for line in output.splitlines() if re.fullmatch(
        r"EEPROM hexdump for (?:(?:OE|ELS)\d+|port Ethernet\S+ \((?:OE|ELS)\d+\))", line.strip())]
    has_data = any(re.fullmatch(
        r"\s*[0-9a-fA-F]{8}\s+(?:[0-9a-fA-F]{2}\s+){0,15}[0-9a-fA-F]{2}\s+\|.*\|", line)
        for line in output.splitlines())
    return {"headings": headings, "has_data": has_data}


def run(arguments):
    if any(option in arguments for option in ("--json", "-j")):
        raise ValueError("Only default text queries are supported")
    result = subprocess.run(["cpoutil"] + arguments, capture_output=True, text=True, timeout=300)
    diagnostic = (result.stdout + "\n" + result.stderr).lower()
    safe = {"rc": result.returncode, "stderr": "; ".join(label for label in DIAGNOSTICS if label in diagnostic)}
    if result.returncode:
        return safe
    if arguments[:3] == ["show", "interface", "dom"]:
        safe["dom"] = dom_summary(result.stdout)
    elif arguments[:1] == ["show"]:
        safe["table"] = table_summary(result.stdout)
    elif arguments[:1] == ["read-eeprom"]:
        safe["eeprom"] = eeprom_summary(result.stdout)
    return safe


def main():
    try:
        result = run(json.loads(sys.argv[1]))
    except Exception:
        result = {"rc": 3, "stderr": "Invalid text output or DUT command failed; raw output suppressed"}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
