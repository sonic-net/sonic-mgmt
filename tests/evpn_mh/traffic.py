"""Invoke the native EVPN-MH PTF traffic test."""

import hashlib
from copy import deepcopy
from pathlib import Path
import re
import shlex
import time
import uuid

from tests.ptf_runner import ptf_collect, ptf_runner

from .traffic_profile import load_profiles, resolved_profile


PTF_TEST_ROOT = Path(__file__).resolve().parents[2] / "ansible/roles/test/files/ptftests"
PTF_PROGRAM_SOURCE = PTF_TEST_ROOT / "py3" / "evpn_mh_traffic.py"
PTF_PROGRAM = "/root/ptftests/py3/evpn_mh_traffic.py"
PTF_PLATFORM_SOURCE = PTF_TEST_ROOT / "evpn_mh_remote.py"
PTF_PLATFORM = "/root/ptftests/evpn_mh_remote.py"
PTF_PAYLOADS = (
    (PTF_PROGRAM_SOURCE, PTF_PROGRAM),
    (PTF_PLATFORM_SOURCE, PTF_PLATFORM),
)
PTF_JOB_ROOT = "/root/evpn_mh_jobs"
PTF_TEST_NAME = "evpn_mh_traffic.EvpnMhTraffic"
PTF_PLATFORM_NAME = "evpn_mh_remote"


def ensure_native_ptf_tests(ptfhost):
    """Make the PTF host payload match the checked-out repository."""
    result = ptfhost.shell(
        "mkdir -p /root/ptftests/py3", module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise RuntimeError("cannot create native EVPN-MH PTF directories")
    for source, destination in PTF_PAYLOADS:
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        result = ptfhost.shell(
            "sha256sum {}".format(shlex.quote(destination)),
            module_ignore_errors=True)
        actual = result.get("stdout", "").split()
        if result.get("rc", 1) != 0 or not actual or actual[0] != expected:
            ptfhost.copy(src=str(source), dest=destination)
        result = ptfhost.shell(
            "sha256sum {}".format(shlex.quote(destination)),
            module_ignore_errors=True)
        actual = result.get("stdout", "").split()
        if result.get("rc", 1) != 0 or not actual or actual[0] != expected:
            raise RuntimeError(
                "native EVPN-MH PTF payload checksum mismatch at {}".format(
                    destination))


def _job_files(job_dir, token=None):
    return {
        "token": token,
        "job_dir": job_dir,
        "barrier_file": job_dir + "/ready",
        "stop_file": job_dir + "/stop",
        "event_start_file": job_dir + "/event-start",
        "event_start_ack_file": job_dir + "/event-start-ack",
        "event_end_file": job_dir + "/event-end",
        "event_end_ack_file": job_dir + "/event-end-ack",
        "result_file": job_dir + "/result",
        "error_file": job_dir + "/stderr",
        "stdout_file": job_dir + "/stdout",
        "pid_file": job_dir + "/pid",
        "identity_file": job_dir + "/identity",
        "launch_file": job_dir + "/launch",
        "log_file": job_dir + "/ptf.log",
    }


def _new_job(prefix):
    token = uuid.uuid4().hex
    job_dir = "{}/{}-{}".format(PTF_JOB_ROOT, prefix, token)
    job = _job_files(job_dir, token=token)
    if prefix == "continuous":
        job["require_ownership"] = True
    return job


def _safe_job_dir(job):
    expected = "{}/".format(PTF_JOB_ROOT)
    job_dir = job.get("job_dir", "")
    basename = job_dir[len(expected):] if job_dir.startswith(expected) else ""
    if not re.fullmatch(r"(?:run|continuous)-[0-9a-f]{32}", basename):
        raise ValueError("unsafe EVPN-MH job directory {}".format(job_dir))
    return job_dir


def _stale_continuous_jobs(ptfhost):
    """Discover only suite-owned continuous job directories.

    Names beginning with ``continuous-`` but outside the exact ownership
    pattern are an ambiguous prior-run artifact.  Preserve them and fail the
    preflight instead of silently ignoring or deleting them.
    """
    command = (
        "if [ ! -e {root} ]; then exit 0; fi; "
        "if [ ! -d {root} ] || [ -L {root} ]; then exit 2; fi; "
        "for path in {root}/continuous-*; do "
        "[ -e \"$path\" ] || continue; "
        "if [ ! -d \"$path\" ] || [ -L \"$path\" ]; then exit 3; fi; "
        "basename -- \"$path\"; "
        "done"
    ).format(root=shlex.quote(PTF_JOB_ROOT))
    result = ptfhost.shell(command, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise RuntimeError(
            "cannot safely enumerate stale EVPN-MH traffic jobs: {}".format(
                result.get("stderr", result.get("stdout", ""))))
    jobs = []
    for basename in result.get("stdout", "").splitlines():
        if not re.fullmatch(r"continuous-[0-9a-f]{32}", basename):
            raise RuntimeError(
                "ambiguous stale EVPN-MH job is preserved: {}".format(
                    basename))
        job_dir = "{}/{}".format(PTF_JOB_ROOT, basename)
        job = _job_files(job_dir, token=basename.rsplit("-", 1)[1])
        job.update({
            "ptfhost": ptfhost,
            # Stale PIDs can be reused.  Every liveness and signal operation
            # must re-prove the exact suite worker command line first.
            "require_ownership": True,
        })
        jobs.append(job)
    return jobs


def _prepare_job(ptfhost, job):
    job_dir = _safe_job_dir(job)
    result = ptfhost.shell(
        "mkdir -p {}".format(shlex.quote(job_dir)),
        module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise RuntimeError("cannot create PTF job directory {}".format(job_dir))


def _cleanup_job(job):
    job_dir = _safe_job_dir(job)
    if "/continuous-" in job_dir:
        if not _wait_job_stopped(job, timeout=2):
            raise RuntimeError(
                "refusing to remove live PTF job directory {}".format(
                    job_dir))
    result = job["ptfhost"].shell(
        "rm -rf -- {}".format(shlex.quote(job_dir)),
        module_ignore_errors=True)
    verified = job["ptfhost"].shell(
        "test ! -e {}".format(shlex.quote(job_dir)),
        module_ignore_errors=True)
    if result.get("rc", 1) != 0 or verified.get("rc", 1) != 0:
        raise RuntimeError(
            "failed to remove PTF job directory {}".format(job_dir))


def _cleanup_after_error(job, primary):
    """Preserve the triggering failure while surfacing cleanup leakage."""
    try:
        _cleanup_job(job)
    except Exception as cleanup_error:
        raise RuntimeError(
            "{}; additionally, PTF job cleanup failed: {}".format(
                primary, cleanup_error)) from primary


def _cleanup_failed_start(job, primary):
    """Attempt termination, diagnostics, and safe cleanup after launch error."""
    failures = []
    try:
        _terminate_bounded(job)
    except Exception as error:
        failures.append("worker termination: {}".format(error))
    try:
        _collect_job(job)
    except Exception as error:
        failures.append("diagnostic collection: {}".format(error))
    try:
        # _cleanup_job independently refuses to delete a proven-live worker.
        _cleanup_job(job)
    except Exception as error:
        failures.append("job cleanup: {}".format(error))
    if failures:
        raise RuntimeError(
            "{}; continuous startup cleanup also failed: {}".format(
                primary, "; ".join(failures))) from primary


def _test_file(ptfhost, path):
    return ptfhost.shell(
        "test -f {}".format(shlex.quote(path)),
        module_ignore_errors=True).get("rc", 1) == 0


def _read_file(ptfhost, path):
    result = ptfhost.shell(
        "cat {}".format(shlex.quote(path)), module_ignore_errors=True)
    return result.get("stdout", "") if result.get("rc", 1) == 0 else ""


def _profile_params(profile_name, port_map, topology, runtime=None):
    return {
        "profile": resolved_profile(
            profile_name, topology, runtime=runtime),
        "port_map": port_map,
        "kvm_support": True,
    }


def run_traffic_profile(ptfhost, profile_name, port_map, topology, runtime=None):
    ensure_native_ptf_tests(ptfhost)
    job = _new_job("run")
    job["ptfhost"] = ptfhost
    _prepare_job(ptfhost, job)
    try:
        result = ptf_runner(
            ptfhost,
            "ptftests",
            PTF_TEST_NAME,
            platform_dir="ptftests",
            platform=PTF_PLATFORM_NAME,
            params=_profile_params(
                profile_name, port_map, topology, runtime),
            qlen=10000,
            socket_recv_size=16384,
            log_file=job["log_file"],
            is_python3=True,
        )
    except BaseException as primary:
        _cleanup_after_error(job, primary)
        raise
    else:
        _cleanup_job(job)
        return result


def _ptf_binary(ptfhost):
    result = ptfhost.shell(
        "if [ -x /root/env-python3/bin/ptf ]; then "
        "printf '%s' /root/env-python3/bin/ptf; "
        "elif [ -x /usr/local/bin/ptf ]; then "
        "printf '%s' /usr/local/bin/ptf; else exit 1; fi",
        module_ignore_errors=True)
    binary = result.get("stdout", "").strip()
    if result.get("rc", 1) != 0 or binary not in (
            "/root/env-python3/bin/ptf", "/usr/local/bin/ptf"):
        raise RuntimeError("no supported Python 3 PTF executable was found")
    return binary


def _ptf_command(ptfhost, params, log_file):
    param_text = ";".join(
        "{}={}".format(key, repr(value))
        for key, value in params.items())
    return " ".join((
        shlex.quote(_ptf_binary(ptfhost)),
        "--test-dir", "ptftests/py3", PTF_TEST_NAME,
        "--platform-dir", "ptftests", "--platform", PTF_PLATFORM_NAME,
        "--qlen=10000", "--relax", "--debug", "info",
        "--socket-recv-size", "16384",
        "--log-file", shlex.quote(log_file),
        "-t", shlex.quote(param_text),
    ))


def _continuous_worker_command(job, command):
    """Persist ownership before the worker is allowed to execute PTF."""
    identity_pending = job["identity_file"] + ".pending"
    return (
        "launch_fail() {{ "
        "printf '%s\\n' 'continuous worker identity setup failed' >{error} "
        "2>/dev/null; printf '%s\\n' 125 >{result} 2>/dev/null; exit 125; "
        "}}; "
        "pid=$$; printf '%s\\n' \"$pid\" >{pid_file} || launch_fail; "
        "stat_line=$(cat /proc/\"$pid\"/stat) || launch_fail; "
        "stat_tail=${{stat_line##*) }}; set -- $stat_tail; "
        "[ \"$#\" -ge 20 ] || launch_fail; start_time=${{20}}; "
        "case \"$start_time\" in ''|*[!0-9]*) launch_fail;; esac; "
        "pgid=$(ps -o pgid= -p \"$pid\") || launch_fail; "
        "pgid=$(printf '%s' \"$pgid\" | tr -d ' ') || launch_fail; "
        "case \"$pgid\" in ''|*[!0-9]*) launch_fail;; esac; "
        "[ \"$pgid\" = \"$pid\" ] || launch_fail; "
        "printf '%s %s %s %s\\n' \"$pid\" \"$start_time\" \"$pgid\" "
        "{token} >{identity_pending} || launch_fail; "
        "mv -- {identity_pending} {identity_file} || launch_fail; "
        "attempts=0; while [ \"$attempts\" -lt 100 ]; do "
        "[ -f {launch_file} ] && break; "
        "attempts=$((attempts + 1)); sleep 0.1; done; "
        "[ -f {launch_file} ] || launch_fail; "
        "{command} >{stdout} 2>{error}; rc=$?; "
        "printf '%s\\n' \"$rc\" >{result}; exit \"$rc\""
    ).format(
        error=shlex.quote(job["error_file"]),
        result=shlex.quote(job["result_file"]),
        pid_file=shlex.quote(job["pid_file"]),
        token=shlex.quote(job["token"]),
        identity_pending=shlex.quote(identity_pending),
        identity_file=shlex.quote(job["identity_file"]),
        launch_file=shlex.quote(job["launch_file"]),
        command=command,
        stdout=shlex.quote(job["stdout_file"]),
    )


def _launch_job(job, params):
    ptfhost = job["ptfhost"]
    command = _ptf_command(ptfhost, params, job["log_file"])
    worker = _continuous_worker_command(job, command)
    launcher = (
        "setsid sh -c {} >/dev/null 2>&1 & worker_pid=$!; "
        "attempts=0; while [ \"$attempts\" -lt 50 ]; do "
        "if [ -s {identity} ]; then "
        "read identity_pid identity_start identity_pgid identity_token extra "
        "<{identity} || exit 1; "
        "[ -z \"$extra\" ] || exit 1; "
        "[ \"$identity_pid\" = \"$worker_pid\" ] || exit 1; "
        "[ \"$identity_pgid\" = \"$worker_pid\" ] || exit 1; "
        "[ \"$identity_token\" = {token} ] || exit 1; "
        "touch {launch} || exit 1; exit 0; fi; "
        "if ! kill -0 \"$worker_pid\" 2>/dev/null; then "
        "wait \"$worker_pid\" 2>/dev/null; exit 1; fi; "
        "attempts=$((attempts + 1)); sleep 0.1; done; exit 1"
        .format(
            shlex.quote(worker),
            identity=shlex.quote(job["identity_file"]),
            token=shlex.quote(job["token"]),
            launch=shlex.quote(job["launch_file"]),
        ))
    result = ptfhost.shell(
        launcher, chdir="/root", module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise RuntimeError("failed to launch continuous PTF traffic")


def _process_probe_command(job):
    """Build a fail-closed process-group probe for one exact job."""
    _safe_job_dir(job)
    command = (
        "if [ ! -r {pid_file} ]; then exit 2; fi; "
        "read pid <{pid_file} || exit 3; "
        "case \"$pid\" in ''|*[!0-9]*) exit 3;; esac; "
        "snapshot=$(ps -ww -eo pid=,pgid=,stat=,args=) || exit 4; "
        "group=$(printf '%s\\n' \"$snapshot\" | awk -v id=\"$pid\" '"
        "($1 == id || $2 == id) && $3 !~ /^Z/ {{ print }}') || exit 4; "
        "[ -n \"$group\" ] || exit 1; "
    ).format(pid_file=shlex.quote(job["pid_file"]))
    if job.get("require_ownership"):
        # A numeric PID may now identify an unrelated process.  Match the
        # launch cookie and Linux process start time before inspecting only
        # the original group-leader row.  Never grep the aggregate group: the
        # probe shell itself contains every literal signature and could
        # otherwise self-validate after PID/PGID reuse.
        command += (
            "if [ ! -r {identity_file} ]; then exit 5; fi; "
            "read identity_pid identity_start identity_pgid identity_token "
            "identity_extra "
            "<{identity_file} || exit 5; "
            "[ -z \"$identity_extra\" ] || exit 5; "
            "case \"$identity_pid\" in ''|*[!0-9]*) exit 5;; esac; "
            "case \"$identity_start\" in ''|*[!0-9]*) exit 5;; esac; "
            "case \"$identity_pgid\" in ''|*[!0-9]*) exit 5;; esac; "
            "[ \"$identity_pid\" = \"$pid\" ] || exit 5; "
            "[ \"$identity_pgid\" = \"$pid\" ] || exit 5; "
            "[ \"$identity_token\" = {token} ] || exit 5; "
            "stat_line=$(cat /proc/\"$pid\"/stat) || exit 5; "
            "stat_tail=${{stat_line##*) }}; set -- $stat_tail; "
            "[ \"$#\" -ge 20 ] || exit 5; current_start=${{20}}; "
            "[ \"$current_start\" = \"$identity_start\" ] || exit 5; "
            "leader=$(printf '%s\\n' \"$snapshot\" | "
            "awk -v id=\"$pid\" '$1 == id && $3 !~ /^Z/ {{ print }}') "
            "|| exit 5; "
            "[ -n \"$leader\" ] || exit 5; "
            "current_pgid=$(printf '%s\\n' \"$leader\" | "
            "awk 'NR == 1 {{ print $2 }}') || exit 5; "
            "[ \"$current_pgid\" = \"$pid\" ] || exit 5; "
            "printf '%s\\n' \"$leader\" | grep -F -- {test_name} "
            ">/dev/null || exit 5; "
            "printf '%s\\n' \"$leader\" | grep -F -- {job_dir} "
            ">/dev/null || exit 5; "
            "printf '%s\\n' \"$leader\" | grep -F -- {result_file} "
            ">/dev/null || exit 5; "
            "printf '%s\\n' \"$leader\" | grep -F -- {log_file} "
            ">/dev/null || exit 5; "
            "if ! printf '%s\\n' \"$leader\" | "
            "grep -F -- /root/env-python3/bin/ptf >/dev/null && "
            "! printf '%s\\n' \"$leader\" | "
            "grep -F -- /usr/local/bin/ptf >/dev/null; then exit 5; fi; "
        ).format(
            identity_file=shlex.quote(job["identity_file"]),
            token=shlex.quote(job["token"]),
            test_name=shlex.quote(PTF_TEST_NAME),
            job_dir=shlex.quote(job["job_dir"]),
            result_file=shlex.quote(job["result_file"]),
            log_file=shlex.quote(job["log_file"]),
        )
    return command


def _job_process_alive(job):
    """Return liveness only when the remote probe proves alive or absent.

    Return code 0 means a live leader/process-group member, and 1 is emitted
    only after a successful ``ps`` snapshot proves no live member.  Missing or
    malformed PID state and command/query errors are unknown, not "dead".
    """
    command = _process_probe_command(job) + "exit 0"
    result = job["ptfhost"].shell(command, module_ignore_errors=True)
    rc = result.get("rc", 255)
    if rc == 0:
        return True
    if rc == 1:
        return False
    raise RuntimeError(
        "PTF worker liveness is unknown (rc {}): {}".format(
            rc, result.get("stderr", result.get("stdout", ""))))


def _wait_job_stopped(job, timeout, poll_interval=0.1):
    deadline = time.monotonic() + float(timeout)
    while time.monotonic() < deadline:
        if not _job_process_alive(job):
            return True
        time.sleep(float(poll_interval))
    return not _job_process_alive(job)


def _terminate_job(job, signal):
    if signal not in ("TERM", "KILL"):
        raise ValueError("unsupported process signal {}".format(signal))
    if not _job_process_alive(job):
        return
    command = (
        "{probe}"
        "if [ -x /bin/kill ]; then killer=/bin/kill; "
        "elif [ -x /usr/bin/kill ]; then killer=/usr/bin/kill; "
        "else exit 3; fi; "
        "\"$killer\" -{signal} -- -\"$pid\" 2>/dev/null"
    ).format(probe=_process_probe_command(job), signal=signal)
    result = job["ptfhost"].shell(command, module_ignore_errors=True)
    if result.get("rc", 1) != 0 and _job_process_alive(job):
        raise RuntimeError(
            "failed to signal live PTF process group with {}".format(signal))


def _job_result(job):
    if not _test_file(job["ptfhost"], job["result_file"]):
        return None
    value = _read_file(job["ptfhost"], job["result_file"]).strip()
    try:
        return int(value)
    except ValueError:
        raise RuntimeError("invalid PTF job result {!r}".format(value))


def _collect_job(job):
    if _test_file(job["ptfhost"], job["log_file"]):
        ptf_collect(job["ptfhost"], job["log_file"])
    return {
        "stdout": _read_file(job["ptfhost"], job["stdout_file"]),
        "stderr": _read_file(job["ptfhost"], job["error_file"]),
    }


def _terminate_bounded(job, grace_seconds=5, kill_grace_seconds=2):
    """Stop a process group with a bounded TERM-to-KILL escalation."""
    result = _job_result(job)
    if not _job_process_alive(job):
        return result
    _terminate_job(job, "TERM")
    if _wait_job_stopped(job, grace_seconds):
        return _job_result(job)
    _terminate_job(job, "KILL")
    if not _wait_job_stopped(job, kill_grace_seconds):
        raise RuntimeError(
            "PTF process group is still live after TERM/KILL escalation")
    return _job_result(job)


def _terminate_stale_bounded(job, grace_seconds=5, kill_grace_seconds=2):
    """Reap an ownership-proven prior-run worker without trusting its result."""
    if not _job_process_alive(job):
        return
    _terminate_job(job, "TERM")
    if _wait_job_stopped(job, grace_seconds):
        return
    _terminate_job(job, "KILL")
    if not _wait_job_stopped(job, kill_grace_seconds):
        raise RuntimeError(
            "stale PTF process group is still live after TERM/KILL escalation")


def reap_stale_traffic_jobs(ptfhost):
    """Stop and remove only ownership-proven continuous jobs from prior runs."""
    failures = []
    jobs = _stale_continuous_jobs(ptfhost)
    for job in jobs:
        try:
            _terminate_stale_bounded(job)
            _cleanup_job(job)
        except Exception as error:
            # Unknown ownership/PID state is intentionally preserved so a
            # human can inspect it; never risk signalling a reused PID.
            failures.append("{}: {}".format(job["job_dir"], error))
    if failures:
        raise RuntimeError(
            "stale EVPN-MH traffic cleanup failed; preserved ambiguous jobs: "
            + "; ".join(failures))


def start_traffic_profile(ptfhost, profile_name, port_map, topology, runtime=None):
    """Launch continuous PTF traffic in a suite-owned remote process group."""
    ensure_native_ptf_tests(ptfhost)
    job = _new_job("continuous")
    job["ptfhost"] = ptfhost
    _prepare_job(ptfhost, job)
    effective_runtime = deepcopy(runtime or {})
    profile_overrides = effective_runtime.setdefault("profile_overrides", {})
    profile_overrides.update({
        "barrier_file": job["barrier_file"],
        "stop_file": job["stop_file"],
    })
    profile_definition = load_profiles()["profiles"].get(profile_name, {})
    if float(profile_definition.get("event_window_seconds", 0)) > 0:
        profile_overrides.update({
            "event_start_file": job["event_start_file"],
            "event_start_ack_file": job["event_start_ack_file"],
            "event_end_file": job["event_end_file"],
            "event_end_ack_file": job["event_end_ack_file"],
        })
    try:
        _launch_job(job, _profile_params(
            profile_name, port_map, topology, effective_runtime))
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if _test_file(ptfhost, job["barrier_file"]):
                return job
            result = _job_result(job)
            if result is not None:
                raise AssertionError(
                    "continuous EVPN-MH traffic exited with rc {} before "
                    "its receive barrier: {}".format(
                        result,
                        _read_file(ptfhost, job["error_file"]).strip()))
            time.sleep(1)
        raise AssertionError(
            "continuous EVPN-MH traffic did not reach its receive barrier")
    except BaseException as primary:
        _cleanup_failed_start(job, primary)
        raise


def stop_traffic_profile(job):
    """Request deterministic shutdown of a running PTF traffic worker."""
    result = job["ptfhost"].shell(
        "touch {}".format(shlex.quote(job["stop_file"])),
        module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise RuntimeError(
            "failed to create PTF stop marker {}: {}".format(
                job["stop_file"],
                result.get("stderr", result.get("stdout", ""))))


def hold_traffic_event(job, minimum_seconds, poll_interval=1,
                       clock=time.monotonic, sleeper=time.sleep):
    """Keep a continuous worker alive for a nontrivial graded event window."""
    minimum_seconds = float(minimum_seconds)
    if minimum_seconds <= 0:
        raise ValueError("continuous event window must be positive")
    if _job_result(job) is not None:
        raise AssertionError(
            "continuous worker ended before the graded event window")
    job["ptfhost"].shell(
        "touch {}".format(shlex.quote(job["event_start_file"])))
    started = clock()
    try:
        while clock() - started < minimum_seconds:
            if _job_result(job) is not None:
                raise AssertionError(
                    "continuous worker ended before the graded event window")
            remaining = minimum_seconds - (clock() - started)
            sleeper(min(float(poll_interval), max(0, remaining)))
        elapsed = clock() - started
    finally:
        job["ptfhost"].shell(
            "touch {}".format(shlex.quote(job["event_end_file"])))
    if elapsed < minimum_seconds:
        raise AssertionError(
            "continuous event window lasted {:.3f}s, expected {:.3f}s".format(
                elapsed, minimum_seconds))
    return elapsed


def traffic_event_window(profile_name):
    profile = load_profiles()["profiles"][profile_name]
    value = float(profile.get("event_window_seconds", 0))
    if value <= 0:
        raise ValueError(
            "{} has no positive event_window_seconds".format(profile_name))
    return value


def wait_traffic_profile(job, timeout):
    deadline = time.monotonic() + float(timeout)
    try:
        result = _job_result(job)
        while result is None and time.monotonic() < deadline:
            time.sleep(0.5)
            result = _job_result(job)
        if result is None:
            result = _terminate_bounded(job)
            diagnostics = _collect_job(job)
            raise AssertionError(
                "continuous PTF traffic did not stop within {} seconds: {}"
                .format(timeout, diagnostics["stderr"].strip()))
        diagnostics = _collect_job(job)
        if result != 0:
            raise AssertionError(
                "continuous PTF traffic failed with rc {}: {}".format(
                    result, diagnostics["stderr"].strip()))
    except Exception as primary:
        _cleanup_after_error(job, primary)
        raise
    else:
        _cleanup_job(job)
    return True


def finish_traffic_profile(job, timeout):
    """Request shutdown and always reap/clean the continuous worker.

    A failed stop-marker write must not bypass bounded TERM/KILL or job
    cleanup.  When either phase fails, retain diagnostics from both phases.
    """
    failures = []
    marker_failed = False
    try:
        stop_traffic_profile(job)
    except Exception as error:
        marker_failed = True
        failures.append("stop marker: {}".format(error))

    try:
        # If the marker could not be created, do not wait the normal event
        # timeout: wait_traffic_profile immediately enters its bounded
        # TERM/KILL and diagnostic-collection path.
        wait_traffic_profile(job, 0 if marker_failed else timeout)
    except Exception as error:
        failures.append("worker reap: {}".format(error))
        # wait_traffic_profile normally performs these actions itself.  Its
        # first remote status query can also fail, so make one final bounded
        # termination/cleanup attempt and aggregate every failure.
        try:
            _terminate_bounded(job)
        except Exception as cleanup_error:
            failures.append("fallback termination: {}".format(cleanup_error))
        try:
            _cleanup_job(job)
        except Exception as cleanup_error:
            failures.append("fallback cleanup: {}".format(cleanup_error))

    if failures:
        raise RuntimeError(
            "continuous PTF shutdown failed: {}".format("; ".join(failures)))
    return True
