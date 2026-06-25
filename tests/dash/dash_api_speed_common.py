# Helpers for test_dash_api_speed_pl: gNMI config push/cleanup + memory reporting (no dataplane pre-config; see the .md).
import json
import logging
import os
import re
import shlex
import time

import pytest
from gnmi_utils import GNMIEnvironment

logger = logging.getLogger(__name__)

# WIP: extracted gNMI client location (git-ignored, copied out-of-band); see the .md.
GNMI_AGENT_EXTRACTED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "gnmi_agent_extracted")

_BATCH_VAL = 3000  # pl_100 sweet spot (see reference_dash_perf_facts)
_VERIFY_SETTLE_SECS = 30  # poll DBSIZE up to this long for async commit to reach the sent count
_VERIFY_POLL_SECS = 2     # gap between DBSIZE polls while settling

# Rendered filename -> (index, kind), e.g. pl_100.dpu0.001eni.json -> (1, "eni").
_FILE_INDEX_RE = re.compile(r"\.(\d{3})(apl|grp|eni|map)\.json$")

# Push order apl->grp->eni->map: dashrouteorch needs the group before its routes, frozen once the ENI binds.
_KIND_ORDER = {"apl": 0, "grp": 1, "eni": 2, "map": 3}

_TRANSIENT_GNMI_MARKERS = ("unavailable", "socket closed", "failed to connect",
                           "error reading server preface", "connection reset")


def parse_file_index(filename):
    # Return (index:int, kind:str) for a rendered config file, or (None, None).
    m = _FILE_INDEX_RE.search(filename)
    return (int(m.group(1)), m.group(2)) if m else (None, None)


# ============================================================================
#  Memory accounting
# ============================================================================
def _parse_mem_str(mem_str):
    # Parse a docker memory string ('512MiB', '1.5GiB', '256kB') into MiB.
    m = re.match(r"([\d.]+)\s*(B|kB|MiB|GiB|TiB)", mem_str.strip())
    if not m:
        return 0.0
    val, unit = float(m.group(1)), m.group(2)
    return val * {"B": 1 / (1024 * 1024), "kB": 1 / 1024, "MiB": 1,
                  "GiB": 1024, "TiB": 1024 * 1024}.get(unit, 1)


def _collect_free_memory(host):
    # `free -m` system memory keys (MiB) for *host*.
    result = {}
    for line in host.shell("free -m", module_ignore_errors=True).get("stdout", "").splitlines():
        if line.startswith("Mem:"):
            parts = line.split()  # total used free shared buff/cache available
            result["_system_total"] = float(parts[1])
            result["_system_used"] = float(parts[2])
            result["_system_free"] = float(parts[3])
            if len(parts) >= 7:
                result["_system_available"] = float(parts[6])
    return result


def _collect_memory(host):
    # Per-container memory (MiB) + '_system_*' keys from `free -m`.
    result = {}
    # awk avoids Jinja2 clash with Go's {{.Name}}; cols: ID NAME CPU% MEM_USED / ...
    out = host.shell("docker stats --no-stream | awk 'NR>1 {print $2\"\\t\"$4}'", module_ignore_errors=True)
    for line in out.get("stdout", "").splitlines():
        line = line.strip()
        if line and "\t" in line:
            name, used_str = line.split("\t", 1)
            result[name.strip()] = _parse_mem_str(used_str.strip())
    result.update(_collect_free_memory(host))
    return result


def _collect_redis_memory(dpuhost):
    # DPU_APPL_DB used_memory totals + 2 sample VNET_MAPPING key sizes.
    result = {}
    info = dpuhost.shell("sonic-db-cli DPU_APPL_DB INFO MEMORY", module_ignore_errors=True)
    for line in info.get("stdout", "").splitlines():
        line = line.strip()
        if line.startswith("used_memory:"):
            try:
                result["_used_memory"] = int(line.split(":")[1])
            except ValueError:
                pass
        elif line.startswith("used_memory_human:"):
            result["_used_memory_human"] = line.split(":", 1)[1].strip()

    # SCAN not KEYS: KEYS blocks single-threaded redis on large keyspaces.
    keys = dpuhost.shell("sonic-db-cli DPU_APPL_DB SCAN 0 MATCH 'DASH_VNET_MAPPING_TABLE:*' COUNT 50 2>/dev/null",
                         module_ignore_errors=True)
    for key in keys.get("stdout", "").splitlines()[1:3]:  # line 0 is the cursor
        key = key.strip()
        if not key:
            continue
        usage = dpuhost.shell(f"sonic-db-cli DPU_APPL_DB MEMORY USAGE '{key}'", module_ignore_errors=True)
        try:
            result[key] = int(usage.get("stdout", "0").strip())
        except ValueError:
            result[key] = 0
    return result


def _print_per_eni_load_times(timings, total_elapsed):
    # Print appliance + per-ENI push times (grp/eni/map in load order) + SUM/WALL/avg.
    apl_total = 0.0
    per_eni = {}  # idx -> {grp, eni, map: secs}
    for filename, elapsed in timings.items():
        idx, kind = parse_file_index(filename)
        if kind == "apl":
            apl_total += elapsed
        elif idx is not None:
            per_eni.setdefault(idx, {})
            per_eni[idx][kind] = per_eni[idx].get(kind, 0.0) + elapsed

    sep = "=" * 72
    print(sep + "\n  DASH API LOAD SPEED — PER-ENI LOAD TIMES\n" + sep)
    print("  %-10s  %8s  %8s  %8s  %10s" % ("ENI", "grp", "eni", "map", "total"))
    print("  " + "-" * 56)
    print("  %-10s  %8s  %8s  %8s  %10.2f" % ("appliance", "", "", "", apl_total))
    grand = apl_total
    for idx in sorted(per_eni):
        k = per_eni[idx]
        row_total = sum(k.values())
        grand += row_total
        print("  %-10s  %8.2f  %8.2f  %8.2f  %10.2f"
              % (f"eni {idx:03d}", k.get("grp", 0.0), k.get("eni", 0.0), k.get("map", 0.0), row_total))
    print("  " + "-" * 56)
    eni_count = len(per_eni)
    print("  %-10s  %40.2f" % ("SUM(push)", grand))
    print("  %-10s  %40.2f" % ("WALL TOTAL", total_elapsed))
    if eni_count:
        # average per-ENI push time = sum of ENI row totals / ENIs (appliance excluded).
        print("  %-10s  %40.2f" % ("avg/ENI", (grand - apl_total) / eni_count))
    print("  ENIs pushed: %d\n%s" % (eni_count, sep))


def _delta_row(label, before, after):
    # Print a 'label before after delta' MiB row.
    print("  %-30s  %8.1f  %8.1f  %+8.1f" % (label, before, after, after - before))


def _print_results(timings, total_elapsed, mem_before, mem_after,
                   redis_before, redis_after, mem_timeline=None):
    # Print per-file times + NPU/DPU container/system/Redis memory before/after.
    sep = "=" * 72
    print(sep + "\n  DASH API LOAD SPEED TEST — RESULTS\n" + sep)

    print("\n  Per-file load times:")
    print("  %-44s  %8s\n  %s" % ("File", "Time (s)", "-" * 56))
    for filename, elapsed in timings.items():
        print("  %-44s  %8.2f" % (filename, elapsed))
    push_sum = sum(timings.values())
    print("  " + "-" * 56)
    print("  %-44s  %8.2f" % ("TOTAL (file pushes)", push_sum))
    print("  %-44s  %8.2f" % ("WALL TOTAL", total_elapsed))
    if timings:
        print("  %-44s  %8.2f" % ("Average per file", push_sum / len(timings)))
    print("  Files loaded: %d" % len(timings))

    for host_label in ("NPU", "DPU"):
        before, after = mem_before[host_label], mem_after[host_label]
        containers = sorted(k for k in set(before) | set(after) if not k.startswith("_"))
        print("\n  Memory usage — %s (MiB):" % host_label)
        print("  %-30s  %8s  %8s  %8s\n  %s" % ("Container", "Before", "After", "Delta", "-" * 58))
        tb = ta = 0.0
        for name in containers:
            b, a = before.get(name, 0.0), after.get(name, 0.0)
            tb += b
            ta += a
            _delta_row(name, b, a)
        print("  " + "-" * 58)
        _delta_row("Containers total", tb, ta)
        _delta_row("System used (free -m)", before.get("_system_used", 0.0), after.get("_system_used", 0.0))
        _delta_row("System free", before.get("_system_free", 0.0), after.get("_system_free", 0.0))
        _delta_row("System available", before.get("_system_available", 0.0), after.get("_system_available", 0.0))
        sys_total = before.get("_system_total", after.get("_system_total", 0.0))
        if sys_total:
            print("  %-30s  %8.1f" % ("System total", sys_total))

    if mem_timeline:
        print("\n  Memory timeline — free memory after each file push (MiB):")
        print("  %-6s  %-40s  %7s  %9s  %9s  %9s  %9s\n  %s"
              % ("#", "File", "Ops", "NPU free", "NPU avail", "DPU free", "DPU avail", "-" * 96))
        for e in mem_timeline:
            print("  %-6s  %-40s  %7d  %9.0f  %9.0f  %9.0f  %9.0f"
                  % (e["idx"], e["file"][:40], e["ops"], e["npu_free"], e["npu_available"],
                     e["dpu_free"], e["dpu_available"]))
        if len(mem_timeline) > 1:
            print("  " + "-" * 96)
            print("  %-6s  %-40s  %7s  %9.0f  %9.0f  %9.0f  %9.0f"
                  % ("", "MINIMUM", "", min(e["npu_free"] for e in mem_timeline),
                     min(e["npu_available"] for e in mem_timeline),
                     min(e["dpu_free"] for e in mem_timeline),
                     min(e["dpu_available"] for e in mem_timeline)))

    print("\n  DPU Redis memory — DPU_APPL_DB (bytes):")
    print("  %-52s  %10s  %10s  %10s\n  %s" % ("Key", "Before", "After", "Delta", "-" * 86))
    rb, ra = redis_before.get("_used_memory", 0), redis_after.get("_used_memory", 0)
    print("  %-52s  %10d  %10d  %+10d" % ("used_memory (total)", rb, ra, ra - rb))
    print("  %-52s  %10s  %10s" % ("used_memory_human", redis_before.get("_used_memory_human", "n/a"),
                                   redis_after.get("_used_memory_human", "n/a")))
    for key in sorted(k for k in set(redis_before) | set(redis_after) if not k.startswith("_")):
        b, a = redis_before.get(key, 0), redis_after.get(key, 0)
        print("  %-52s  %10d  %10d  %+10d" % (key, b, a, a - b))
    print(sep)


# ============================================================================
#  Config inspection
# ============================================================================
def _count_json_operations(filepath):
    # Return (op_count, {table: {SET, DEL}}) for a config JSON file.
    with open(filepath) as f:
        operations = json.load(f)
    tables = {}
    for op in operations:
        op_type = op.get("OP", "?")
        for k in op:
            if k == "OP":
                continue
            t = tables.setdefault(k.split(":")[0], {"SET": 0, "DEL": 0})
            t[op_type] = t.get(op_type, 0) + 1
    return len(operations), tables


def _db_int(shell_result):
    # Parse an integer (e.g. DBSIZE) from a host.shell() result; 0 on anything odd.
    try:
        return int((shell_result.get("stdout", "") or "0").strip() or 0)
    except (ValueError, AttributeError):
        return 0


# ============================================================================
#  gNMI transport detection + readiness
# ============================================================================
def _detect_server_tls(duthost, env):
    # Return 'notls'/'tls'/'mtls' from the running telemetry process flags (CONFIG_DB certs often empty).
    out = duthost.shell(
        "docker exec %s bash -c \"ps -eo args | grep -- '--port %d' | grep -v grep\""  # noqa: E501
        % (env.gnmi_container, env.gnmi_port), module_ignore_errors=True)
    line = (out.get("stdout", "") or "").strip()
    logger.info("NPU gNMI server cmdline: %s", line or "(not found)")
    low = line.lower()
    if not line or "--notls" in low or "-notls" in low:
        return "notls"
    if "allow_no_client_auth" in low:
        return "tls"
    return "mtls" if "ca_crt" in low else "tls"


def _stage_npu_certs(duthost, env, dest_dir):
    # Copy CA+server cert/key off the gnmi container to dest_dir (reused as client cert); returns paths or None.
    files = {"ca": env.gnmi_ca_cert, "cert": env.gnmi_server_cert, "key": env.gnmi_server_key}
    local = {}
    for tag, name in files.items():
        src = env.gnmi_cert_path + name
        cp = duthost.shell("docker cp %s:%s /tmp/%s" % (env.gnmi_container, src, name),  # noqa: E231
                           module_ignore_errors=True)
        if cp.get("rc", 1) != 0:
            logger.warning("  docker cp %s failed: %s", src, (cp.get("stderr", "") or "").strip()[:200])
            return None
        try:
            duthost.fetch(src="/tmp/%s" % name, dest="%s/%s" % (dest_dir, name), flat=True)
        except Exception as e:
            logger.warning("  fetch %s failed: %s", name, e)
            return None
        local[tag] = os.path.join(dest_dir, name)
        logger.info("  Staged NPU cert %s -> %s", name, local[tag])
    return local


def _gnmi_server_ready(localhost, ip, port, tls_paths=None):
    # True iff a gNMI Capabilities RPC succeeds (TLS if tls_paths given).
    if tls_paths:
        probe = (
            "import grpc; from pygnmi.spec.v080 import gnmi_pb2, gnmi_pb2_grpc as g; "  # noqa: E702
            "creds=grpc.ssl_channel_credentials("
            "root_certificates=open({ca!r},'rb').read(),"
            "private_key=open({key!r},'rb').read(),"
            "certificate_chain=open({cert!r},'rb').read()); "
            "ch=grpc.secure_channel('{ip}:{port}',creds); "
            "g.gNMIStub(ch).Capabilities(gnmi_pb2.CapabilityRequest(), timeout=6)"
        ).format(ca=tls_paths["ca"], key=tls_paths["key"], cert=tls_paths["cert"], ip=ip, port=port)
    else:
        probe = (
            "import grpc; from pygnmi.spec.v080 import gnmi_pb2, gnmi_pb2_grpc as g; "  # noqa: E702
            f"g.gNMIStub(grpc.insecure_channel('{ip}:{port}'))."  # noqa: E231
            "Capabilities(gnmi_pb2.CapabilityRequest(), timeout=6)")
    out = localhost.shell("python3 -c %s" % shlex.quote(probe), module_ignore_errors=True)
    return out.get("rc", 1) == 0


def _wait_gnmi_ready(localhost, ip, port, timeout=600, interval=5, tls_paths=None):
    # Block until the gNMI server answers a Capabilities RPC (or timeout).
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _gnmi_server_ready(localhost, ip, port, tls_paths=tls_paths):
            logger.info("gNMI server %s:%s is ready", ip, port)
            return True
        logger.info("gNMI server %s:%s not ready — waiting %ds ...", ip, port, interval)
        time.sleep(interval)
    logger.warning("gNMI server %s:%s not ready after %ds — proceeding anyway", ip, port, timeout)
    return False


# ============================================================================
#  gNMI push / cleanup
# ============================================================================
def _prepare_gnmi(localhost, duthost, dpuhost, config_dir, creds, action="push"):
    # Resolve gNMI target+transport, stage TLS certs, wait for readiness; returns a conn dict.
    env = GNMIEnvironment(duthost)
    ip, port, dpu_index = duthost.mgmt_ip, env.gnmi_port, dpuhost.dpu_index
    extracted_dir = GNMI_AGENT_EXTRACTED_DIR
    assert os.path.isdir(extracted_dir), (
        "gNMI agent client not found at %s — copy gnmi_agent_extracted/ onto the "
        "controller (git-ignored / WIP). See test_dash_api_speed_pl.md." % extracted_dir)

    mode = _detect_server_tls(duthost, env)
    tls_prefix, tls_paths = "", None
    if mode in ("tls", "mtls"):
        cert_dir = os.path.join(os.path.dirname(config_dir.rstrip("/\\")), "gnmi_certs")
        os.makedirs(cert_dir, exist_ok=True)
        tls_paths = _stage_npu_certs(duthost, env, cert_dir)
        if tls_paths:
            tls_prefix = "GNMI_CA=%s " % shlex.quote(tls_paths["ca"])
            if mode == "mtls":
                tls_prefix += "GNMI_CLIENT_CERT=%s GNMI_CLIENT_KEY=%s " % (
                    shlex.quote(tls_paths["cert"]), shlex.quote(tls_paths["key"]))
        else:
            logger.warning("Server is %s but cert staging failed — %s will likely fail", mode.upper(), action)
    logger.info("gNMI %s -> %s:%s (dpu %d, %s)", action, ip, port, dpu_index,
                mode.upper() if tls_paths else "plaintext")

    _wait_gnmi_ready(localhost, ip, port, tls_paths=tls_paths)
    return {"ip": ip, "port": port, "dpu_index": dpu_index, "extracted_dir": extracted_dir,
            "gnmi_user": shlex.quote(creds["sonicadmin_user"]),
            "gnmi_pass": shlex.quote(creds["sonicadmin_password"]),
            "tls_prefix": tls_prefix, "tls_paths": tls_paths}


def _apply_gnmi_file(localhost, conn, cfg_path, attempts=8):
    # Run gnmi_client update -f cfg_path; retry only on transient errors (no per-file pre-probe). File OP drives SET/DEL.
    ip, port, tls_paths = conn["ip"], conn["port"], conn["tls_paths"]
    cmd = (f"cd {conn['extracted_dir']} && {conn['tls_prefix']}PYTHONPATH=. python3 gnmi_client.py"
           f" --batch_val {_BATCH_VAL} -l warning -t {ip}:{port} -i {conn['dpu_index']} -n 8"  # noqa: E231
           f" -u {conn['gnmi_user']} -p {conn['gnmi_pass']} update -f {cfg_path}")
    rc, stderr, stdout = -1, "", ""
    for _ in range(attempts):
        out = localhost.shell(cmd, module_ignore_errors=True)
        rc, stderr, stdout = out.get("rc", -1), out.get("stderr", "") or "", out.get("stdout", "") or ""
        if rc == 0 or not any(m in stderr.lower() for m in _TRANSIENT_GNMI_MARKERS):
            break
        _wait_gnmi_ready(localhost, ip, port, tls_paths=tls_paths)
    return rc, stderr, stdout


def load_config_via_gnmi(localhost, duthost, dpuhost, config_dir, files,
                         creds, timings=None, mem_timeline=None, mem_every=1):
    # [WIP] Push DASH config (apl->grp->eni->map) via gNMI; times each file, samples mem every mem_every files, returns counts {landed (DBSIZE delta), expected_total, per_table (SET ops sent), db_before/after}.
    if timings is None:
        timings = {}
    if mem_timeline is None:
        mem_timeline = []
    mem_every = max(1, int(mem_every))
    conn = _prepare_gnmi(localhost, duthost, dpuhost, config_dir, creds, action="push")

    db_before = dpuhost.shell("sonic-db-cli DPU_APPL_DB DBSIZE", module_ignore_errors=True)
    logger.info("DPU_APPL_DB DBSIZE before push: %s", db_before.get("stdout", "").strip())

    file_info = []
    expected_sets_by_table, expected_total_sets = {}, 0
    for filename in files:
        op_count, tables = _count_json_operations(os.path.join(config_dir, filename))
        file_info.append((filename, op_count, tables))
        for t, c in tables.items():
            expected_sets_by_table[t] = expected_sets_by_table.get(t, 0) + c.get("SET", 0)
            expected_total_sets += c.get("SET", 0)
    file_info.sort(key=lambda fi: (parse_file_index(fi[0])[0] if parse_file_index(fi[0])[0] is not None else -1,
                                   _KIND_ORDER.get(parse_file_index(fi[0])[1], 9)))

    push_errors = []
    for idx, (filename, op_count, tables) in enumerate(file_info, start=1):
        summary = ", ".join("%s:%dS/%dD" % (t, tables[t]["SET"], tables[t]["DEL"]) for t in sorted(tables))
        logger.info("  [%d/%d] pushing %s (%d ops: %s) ...", idx, len(files), filename, op_count, summary)

        t_start = time.time()
        rc, stderr, stdout = _apply_gnmi_file(localhost, conn, os.path.join(config_dir, filename))
        elapsed = time.time() - t_start
        timings[filename] = elapsed

        reason = ("exit code %d" % rc if rc != 0 else
                  "error string in output" if any(s in stderr for s in ("Traceback", "RpcError", "Set failed"))
                  else "")
        if reason:
            logger.error("  [%d/%d] FAILED %s after %.2fs — %s\n  output (tail): %s",
                         idx, len(files), filename, elapsed, reason, (stderr or stdout)[-3000:])
            push_errors.append("%s: %s" % (filename, reason))
        else:
            logger.info("  [%d/%d] done %s %.2fs rc=%d", idx, len(files), filename, elapsed, rc)
        print("  [%d/%d] %-40s  %6.2fs  %s" % (idx, len(files), filename, elapsed, "FAIL" if reason else "ok"))

        # Sample free -m every mem_every files (always on the last); it's pure SSH overhead (~130s at 32-ENI).
        if idx % mem_every == 0 or idx == len(file_info):
            try:
                npu, dpu = _collect_free_memory(duthost), _collect_free_memory(dpuhost)
                mem_timeline.append({"idx": idx, "file": filename, "ops": op_count,
                                     "npu_free": npu.get("_system_free", 0), "npu_available": npu.get("_system_available", 0),
                                     "dpu_free": dpu.get("_system_free", 0), "dpu_available": dpu.get("_system_available", 0)})
            except Exception:
                logger.debug("  [%d/%d] mem snapshot failed (non-fatal)", idx, len(files))

    # Verify via DBSIZE delta (O(1)), not KEYS (blocks redis on large keyspaces).
    # Poll until the delta reaches the sent SET count (async commit may lag the push) or timeout; _assert_programmed requires exact equality.
    before_n = _db_int(db_before)
    deadline = time.time() + _VERIFY_SETTLE_SECS
    after_n = before_n
    while True:
        after_n = _db_int(dpuhost.shell("sonic-db-cli DPU_APPL_DB DBSIZE", module_ignore_errors=True))
        if after_n - before_n >= expected_total_sets or time.time() >= deadline:
            break
        time.sleep(_VERIFY_POLL_SECS)
    landed = after_n - before_n
    logger.info("DPU_APPL_DB DBSIZE after push: %d (was: %d); landed delta=%d, expected=%d",
                after_n, before_n, landed, expected_total_sets)
    counts = {"landed": landed, "expected_total": expected_total_sets,
              "per_table": expected_sets_by_table, "db_before": before_n, "db_after": after_n}

    if push_errors:
        pytest.fail("gNMI push had %d error(s):\n%s" % (len(push_errors), "\n".join("  - " + e for e in push_errors)))
    return counts


def cleanup_config_via_gnmi(localhost, duthost, dpuhost, config_dir, files, creds, mode="precise"):
    # [WIP] Restore DPU state. mode="flushdb": one FLUSHDB (instant, wipes ALL keys, dedicated DPU only). mode="precise": gNMI DELETE each file in reverse via sibling *.del.json (safe on shared DPU, ~as slow as push).
    if mode == "flushdb":
        db_before = dpuhost.shell("sonic-db-cli DPU_APPL_DB DBSIZE", module_ignore_errors=True)
        res = dpuhost.shell("sonic-db-cli DPU_APPL_DB FLUSHDB", module_ignore_errors=True)
        db_after = dpuhost.shell("sonic-db-cli DPU_APPL_DB DBSIZE", module_ignore_errors=True)
        ok = res.get("rc", -1) == 0
        print("Cleanup (FLUSHDB): DPU_APPL_DB DBSIZE: %s -> %s%s"
              % (db_before.get("stdout", "").strip(), db_after.get("stdout", "").strip(),
                 "" if ok else " (FLUSHDB rc!=0)"))
        return
    conn = _prepare_gnmi(localhost, duthost, dpuhost, config_dir, creds, action="cleanup")
    ordered = sorted(files, key=lambda f: (-(parse_file_index(f)[0] if parse_file_index(f)[0] is not None else -1),
                                           -_KIND_ORDER.get(parse_file_index(f)[1], 9)))
    print("Cleanup: deleting %d pushed config file(s) to restore DPU state ..." % len(ordered))
    db_before = dpuhost.shell("sonic-db-cli DPU_APPL_DB DBSIZE", module_ignore_errors=True)
    errors = 0
    for idx, filename in enumerate(ordered, start=1):
        src_path = os.path.join(config_dir, filename)
        del_path = (src_path[:-5] if filename.endswith(".json") else src_path) + ".del.json"
        try:
            with open(src_path) as f:
                ops = json.load(f)
            for op in ops:
                op["OP"] = "DEL"
            with open(del_path, "w") as f:
                json.dump(ops, f)
        except Exception as e:
            errors += 1
            logger.warning("  cleanup [%d/%d] build DEL file failed %s: %s", idx, len(ordered), filename, e)
            print("  cleanup [%d/%d] %-40s  SKIP(build)" % (idx, len(ordered), filename))
            continue
        rc, stderr, stdout = _apply_gnmi_file(localhost, conn, del_path, attempts=5)
        ok = rc == 0 and "Traceback" not in stderr and "RpcError" not in stderr
        if not ok:
            errors += 1
            logger.warning("  cleanup [%d/%d] delete FAILED %s rc=%d: %s",
                           idx, len(ordered), filename, rc, (stderr or stdout)[-500:])
        print("  cleanup [%d/%d] %-40s  %s" % (idx, len(ordered), filename, "ok" if ok else "FAIL"))

    db_after = dpuhost.shell("sonic-db-cli DPU_APPL_DB DBSIZE", module_ignore_errors=True)
    print("Cleanup done (%d error(s)); DPU_APPL_DB DBSIZE: %s -> %s"
          % (errors, db_before.get("stdout", "").strip(), db_after.get("stdout", "").strip()))
