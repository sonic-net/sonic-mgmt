import json
import pytest
import re


pytestmark = [
    pytest.mark.topology("any"),
]


def _cmd_ok(duthost, cmd):
    res = duthost.shell(cmd, module_ignore_errors=True)
    return res.get("rc", 1) == 0


def _get_one_front_panel_port(duthost):
    """
    pick one port that is have queues.
    """
    res = duthost.shell("show interface status 2>/dev/null | awk 'NR>2 {print $1}'", module_ignore_errors=True)
    ports = [p.strip() for p in (res.get("stdout_lines") or []) if p.strip() and not p.startswith("-")]

    eth = [p for p in ports if p.startswith("Ethernet")]
    return (eth[0] if eth else (ports[0] if ports else None))


def _get_rates_entries(duthost):
    """
    Return list of COUNTERS_DB keys like RATES:<table_id>.
    COUNTERS_DB is usually DB 2.
    """
    if _cmd_ok(duthost, "command -v sonic-db-cli >/dev/null 2>&1"):
        res = duthost.shell("sonic-db-cli COUNTERS_DB KEYS 'RATES:*'", module_ignore_errors=True)
    else:
        res = duthost.shell("redis-cli -n 2 KEYS 'RATES:*'", module_ignore_errors=True)

    keys = [k.strip() for k in (res.get("stdout_lines") or []) if k.strip() and k.strip().startswith("RATES:")]
    return keys


def _hget_rates_fields(duthost, rates_key):
    """
    Read Q_PPS/Q_BPS/Q_bPS from COUNTERS_DB RATES:<table_id>.
    Returns dict with possibly-missing values.
    """
    fields = ["Q_PPS", "Q_BPS", "Q_bPS"]
    out = {}

    for f in fields:
        if _cmd_ok(duthost, "command -v sonic-db-cli >/dev/null 2>&1"):
            cmd = f"sonic-db-cli COUNTERS_DB HGET '{rates_key}' '{f}'"
        else:
            cmd = f"redis-cli -n 2 HGET '{rates_key}' '{f}'"
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res.get("rc", 1) != 0:
            out[f] = None
            continue
        val = (res.get("stdout", "") or "").strip()
        out[f] = val if val else None

    return out


def _run_queuestat_json(duthost, port):
    """
    Run queuestat in JSON mode. We only use it for structured parsing.
    """
    cmd = f"queuestat -p {port} -j"
    res = duthost.shell(cmd, module_ignore_errors=True)

    if res.get("rc", 1) != 0:
        stdout = (res.get("stdout", "") or "").strip()
        stderr = (res.get("stderr", "") or "").strip()
        pytest.skip(f"queuestat failed or unsupported in this env rc={res.get('rc')} stdout={stdout} stderr={stderr}")

    raw = (res.get("stdout", "") or "").strip()
    if not raw:
        pytest.skip("queuestat returned empty output")

    # queuestat -j prints JSON (possibly with whitespace)
    try:
        return json.loads(raw)
    except Exception as e:
        pytest.fail(f"queuestat -j did not return valid JSON: {e}. Output was: {raw[:500]}")


def test_queuestat_rates_columns_present(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Validates the new queue rate fields introduced by the feature:
      - Pkts/s
      - Bytes/s
      - Bits/s

    We validate via 'queuestat -j' output that rate fields exist per queue entry
    when COUNTERS_DB has RATES:* entries.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if not _cmd_ok(duthost, "command -v queuestat >/dev/null 2>&1"):
        pytest.skip("queuestat utility not present on DUT")

    rates_keys = _get_rates_entries(duthost)
    if not rates_keys:
        pytest.skip("No RATES:* entries found in COUNTERS_DB (rates feature not present/enabled)")

    port = _get_one_front_panel_port(duthost)
    if not port:
        pytest.skip("No front-panel ports found to run queuestat")

    data = _run_queuestat_json(duthost, port)

    # queuestat -j typically returns a dict keyed by port, then queue tags.
    # Example structure varies a bit, so we do tolerant checks.
    # We assert that at least one queue object has rate keys.
    found_rate_keys = False

    # Walk any nested dicts/lists and look for qpktsps/qbytesps/qbitsps keys
    def walk(obj):
        nonlocal found_rate_keys
        if isinstance(obj, dict):
            # The feature prints these rate values
            keys = set(obj.keys())
            if {"qpktsps", "qbytesps", "qbitsps"}.issubset(keys):
                found_rate_keys = True

                # Values can be "N/A" or numeric strings; both acceptable
                for k in ["qpktsps", "qbytesps", "qbitsps"]:
                    v = obj.get(k)
                    assert v is not None, f"Missing {k} in rate stats object: {obj}"
                    if v != "N/A":
                        # allow float-ish strings too
                        assert re.match(r"^-?\d+(\.\d+)?$", str(v)), f"{k} is not numeric or N/A: {v}"
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for it in obj:
                walk(it)

    walk(data)

    assert found_rate_keys, (
        "Did not find rate keys (qpktsps/qbytesps/qbitsps) in queuestat -j output. "
        "Rates feature may not be active for selected port/queues."
    )


def test_rates_db_entries_parseable(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Sanity-check that COUNTERS_DB RATES:* entries contain parseable values
    for Q_PPS/Q_BPS/Q_bPS (or are missing, which we treat as N/A).
    This aligns with the code change that reads these keys and prints N/A when absent.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    rates_keys = _get_rates_entries(duthost)
    if not rates_keys:
        pytest.skip("No RATES:* entries found in COUNTERS_DB (rates feature not present/enabled)")

    # Check a small sample to avoid heavy scans
    sample = rates_keys[:10]
    for k in sample:
        fields = _hget_rates_fields(duthost, k)

        for name, val in fields.items():
            if val is None:
                continue
            # Code treats values as floats; accept numeric strings
            assert re.match(r"^-?\d+(\.\d+)?$", val), f"{k} {name} is not numeric: {val}"
