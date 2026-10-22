import json
import logging
from pathlib import Path
import shlex
import tempfile
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


RPC_COMPLETION_PREFIX = "RPC_COMPLETION "
logger = logging.getLogger(__name__)


class DiagnosticReadPending(RuntimeError):
    """An Ansible reader may still fork; do not open a shared gRPC channel."""


def _read_diagnostic_logs(duthost, cursors, timeout):
    """Read a bounded fresh slice, or establish cursors before opening gRPC."""
    script = '''
import json, os, sys
cursors = json.loads(sys.argv[1])
result = {}
for path in ("/var/log/gnmi.log", "/var/log/syslog"):
    try:
        with open(path, "rb") as stream:
            stat = os.fstat(stream.fileno())
            identity = [stat.st_dev, stat.st_ino]
            entry = {"identity": identity, "size": stat.st_size}
            if cursors is not None:
                previous = cursors.get(path, {})
                offset = previous.get("size", 0)
                if previous.get("identity") != identity or stat.st_size < offset:
                    entry["gap"] = "missing baseline, rotated or truncated log"
                else:
                    start = max(offset, stat.st_size - 65536)
                    stream.seek(start)
                    raw = stream.read(min(65536, stat.st_size - start))
                    if start > offset:
                        entry["gap"] = "fresh slice exceeds 65536 bytes; prefix omitted"
                        raw = raw.partition(b"\\n")[2]
                    entry["text"] = raw.decode("utf-8", errors="replace")
                    after = os.stat(path)
                    if [after.st_dev, after.st_ino] != identity or after.st_size < stat.st_size:
                        entry.pop("text", None)
                        entry["gap"] = "log changed identity or truncated during read"
            result[path] = entry
    except OSError as error:
        result[path] = {"gap": str(error)}
print(json.dumps(result))
'''
    command = "sudo timeout -k 1 {0:.3f}s python3 -c {1} {2}".format(
        max(0.1, timeout - 1), shlex.quote(script), shlex.quote(json.dumps(cursors)))
    started = time.monotonic()
    pool, pending = duthost.shell(command, module_async=True, module_ignore_errors=True)
    try:
        # Bound controller/SSH wait too, not just execution on the DUT.
        try:
            result = pending.get(timeout=max(0.001, timeout - (time.monotonic() - started)))
        except Exception as error:
            if not pending.ready():
                raise DiagnosticReadPending("Diagnostic reader has not finished; RPC must not start") from error
            raise
        if result.get("rc") != 0:
            raise RuntimeError("Diagnostic log read failed: rc={}".format(result.get("rc")))
        return json.loads(result["stdout"])
    finally:
        # Neither join nor terminate: ThreadPool termination can wait for a busy
        # worker. Close submits no more work; its read-only command is bounded on
        # the DUT too. A stalled transport may outlive this caller's wait.
        pool.close()


def get_diagnostic_log_cursors(duthost):
    """Best-effort baseline; call before opening a shared gRPC channel."""
    try:
        return _read_diagnostic_logs(duthost, None, timeout=5)
    except DiagnosticReadPending:
        # Returning an empty baseline here could let the late Ansible worker
        # fork after the caller opens its shared gRPC channel.
        raise
    except Exception as error:
        logger.warning("gNMI diagnostic baseline unavailable: %s", error)
        return {}


def collect_rpc_timeout_evidence(duthost, cursors, calls, method, principal, path, timeout=60):
    """Observe after channel closure, before rollback; never decide test success.

    Matching records are candidates, not unique request correlation. No completion
    within this window does not prove the server never received the request.
    The observation target bounds polling and asynchronous result waits, not local
    filesystem latency, synchronous Ansible dispatch or a lingering SSH worker.
    """
    deadline = time.monotonic() + timeout
    directory = Path("logs/gnmi")
    directory.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="rpc-timeout-", dir=str(directory)))
    evidence = {"dut": duthost.hostname, "calls": calls, "baseline": cursors,
                "correlation": "method/principal/path/window only; ambiguous without request ID",
                "observation_target_seconds": timeout,
                "budget_limits": "dispatch/local I/O may exceed target; timed-out SSH reader may still run",
                "snapshots": []}
    try:
        while cursors and time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            snapshot = {"observed_at": time.time()}
            try:
                logs = _read_diagnostic_logs(duthost, cursors, min(10, remaining))
                snapshot["logs"] = logs
                snapshot["completion_candidates"] = parse_audit_records(
                    logs.get("/var/log/gnmi.log", {}).get("text", ""), method, principal, path=path)
            except Exception as error:
                snapshot["collection_error"] = str(error)
            evidence["snapshots"].append(snapshot)
            (directory / "evidence.json").write_text(json.dumps(evidence, indent=2))
            if "collection_error" in snapshot:
                break  # Do not stack SSH workers after a failed/timed-out read.
            time.sleep(min(5, max(0, deadline - time.monotonic())))
    finally:
        evidence["result"] = "observation ended; original client failure remains authoritative"
        (directory / "evidence.json").write_text(json.dumps(evidence, indent=2))
        logger.warning("gNMI timeout evidence saved to %s", directory / "evidence.json")


def get_audit_log_offset(duthost):
    return int(
        duthost.shell(
            "sudo stat -c %s /var/log/gnmi.log"
        )["stdout"].strip()
    )


def parse_audit_records(log_text, method, principal, code=None, path=None):
    records = []
    decoder = json.JSONDecoder()
    for line in log_text.splitlines():
        _, separator, payload = line.partition(RPC_COMPLETION_PREFIX)
        if not separator:
            continue
        try:
            record, _ = decoder.raw_decode(payload)
        except json.JSONDecodeError:
            continue
        if (record.get("method") != method
                or record.get("principal") != principal):
            continue
        if code is not None and record.get("code") != code:
            continue
        if path is not None and path not in (record.get("path") or []):
            continue
        records.append(record)
    return records


def _audit_records_written(duthost, offset, method, principal,
                           expected_count, code, path):
    new_log = duthost.shell(
        "sudo tail -c +{} /var/log/gnmi.log".format(offset + 1),
        module_ignore_errors=True,
    )["stdout"]
    records = parse_audit_records(
        new_log, method, principal, code=code, path=path
    )
    return len(records) >= expected_count


def wait_for_audit_records(duthost, offset, method, principal,
                           expected_count, code=None, path=None, timeout=30):
    pytest_assert(
        wait_until(timeout, 1, 0, _audit_records_written,
                   duthost, offset, method, principal,
                   expected_count, code, path),
        "Expected {} {} completion records in /var/log/gnmi.log".format(
            expected_count, method
        ),
    )
    new_log = duthost.shell(
        "sudo tail -c +{} /var/log/gnmi.log".format(offset + 1)
    )["stdout"]
    records = parse_audit_records(
        new_log, method, principal, code=code, path=path
    )
    pytest_assert(
        len(records) == expected_count,
        "Expected exactly {} {} completion records, got {}".format(
            expected_count, method, len(records)
        ),
    )
    return records


def wait_for_audit_record(duthost, offset, method, principal):
    return wait_for_audit_records(
        duthost, offset, method, principal, expected_count=1
    )
