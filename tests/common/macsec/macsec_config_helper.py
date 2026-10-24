import ast
import json
import logging
import secrets
import shlex
import time
from collections.abc import Mapping
from passlib.hash import cisco_type7

from tests.common.macsec.macsec_helper import get_mka_session, getns_prefix, wait_all_complete, \
     submit_async_task
from tests.common.macsec.macsec_platform_helper import global_cmd, find_portchannel_from_member, get_portchannel
from tests.common.config_reload import config_reload
from tests.common.devices.csonic import CsonicHost
from tests.common.devices.eos import EosHost
from tests.common.utilities import wait_until

__all__ = [
    'enable_macsec_feature',
    'disable_macsec_feature',
    'setup_macsec_configuration',
    'cleanup_macsec_configuration',
    'set_macsec_profile',
    'delete_macsec_profile',
    'enable_macsec_port',
    'disable_macsec_port',
    'get_macsec_enable_status',
    'get_macsec_profile',
    'wait_for_macsec_cleanup',
    'generate_macsec_profile',
    'setup_macsec_multi_profile_configuration',
    'cleanup_macsec_multi_profile_configuration',
]

logger = logging.getLogger(__name__)

CSONIC_MACSEC_SUPERVISOR_CONFIG = "/etc/supervisor/conf.d/sonic-mgmt-macsec.conf"


def _command_succeeded(result):
    return isinstance(result, Mapping) and result.get("rc") == 0


def _command_output_lines(result):
    if not _command_succeeded(result):
        return []

    stdout_lines = result.get("stdout_lines")
    if isinstance(stdout_lines, (list, tuple)):
        return list(stdout_lines)

    stdout = result.get("stdout")
    if isinstance(stdout, str):
        return stdout.splitlines()

    return []


def _host_is_multi_asic(host):
    """Treat lightweight neighbor hosts as single-ASIC by default."""
    return bool(getattr(host, "is_multi_asic", False))


def _host_platform_asic(host):
    """Return platform_asic when the host exposes the standard facts mapping."""
    facts = getattr(host, "facts", {})
    return facts.get("platform_asic") if isinstance(facts, Mapping) else None


def _runtime_port_name(host, port):
    """Translate a logical cSONiC port to its runtime interface name."""
    mapper = getattr(host, "_interface_name", None)
    return mapper(port) if callable(mapper) else port


def _run_required_macsec_command(host, command):
    """Run a setup command and fail closed for CsonicHost's result API."""
    result = host.command(command)
    if isinstance(host, CsonicHost) and not _command_succeeded(result):
        raise AssertionError(
            "MACsec command failed on {}: command={!r}, result={}".format(
                host.hostname, command, _command_diagnostic(result)))
    return result


def _csonic_config_db_hset(host, key, values):
    """Write MACsec configuration without relying on an optional config CLI plugin."""
    command = ["sonic-db-cli", "CONFIG_DB", "HSET", key]
    for field, value in values.items():
        command.extend([field, str(value)])
    return _run_required_macsec_command(
        host, " ".join(shlex.quote(part) for part in command))


def _csonic_config_db_delete(host, key):
    """Delete a cSONiC CONFIG_DB key directly."""
    command = "sonic-db-cli CONFIG_DB DEL {}".format(shlex.quote(key))
    return _run_required_macsec_command(host, command)


def _csonic_config_db_hdel(host, key, field):
    """Delete one field from a cSONiC CONFIG_DB hash directly."""
    command = "sonic-db-cli CONFIG_DB HDEL {} {}".format(
        shlex.quote(key), shlex.quote(field))
    return _run_required_macsec_command(host, command)


def _command_stdout(host, command):
    """Run a required read-only command and return stripped stdout."""
    result = host.command(command)
    if not _command_succeeded(result):
        raise AssertionError(
            "MACsec state query failed on {}: command={!r}, result={}".format(
                getattr(host, "hostname", str(host)), command,
                _command_diagnostic(result)))
    return str(result.get("stdout", "")).strip()


def _macsec_port_profile(host, port):
    """Return the currently bound profile, or None when the port is unbound."""
    if isinstance(host, EosHost):
        result = host.eos_command(commands=[
            "show running-config interfaces {}".format(port)])
        output = result.get("stdout", [""])[0]
        if isinstance(output, list):
            output = "\n".join(output)
        marker = "mac security profile "
        for line in str(output).splitlines():
            line = line.strip()
            if line.startswith(marker):
                return line[len(marker):].strip() or None
        return None

    port = _runtime_port_name(host, port)
    if isinstance(host, CsonicHost):
        command = 'sonic-db-cli CONFIG_DB HGET "PORT|{}" macsec'.format(port)
    else:
        command = 'sonic-db-cli {} CONFIG_DB HGET "PORT|{}" macsec'.format(
            getns_prefix(host, port), port)
    return _command_stdout(host, command) or None


def _eos_macsec_profile_lines(host, profile_name):
    """Return an EOS profile's child configuration lines, or None."""
    result = host.eos_command(commands=[
        "show running-config section mac security"])
    output = result.get("stdout", [""])[0]
    if isinstance(output, list):
        output = "\n".join(output)
    declaration = "profile {}".format(profile_name)
    lines = str(output).splitlines()
    for index, line in enumerate(lines):
        if line.strip() != declaration:
            continue
        profile_lines = []
        for child in lines[index + 1:]:
            stripped = child.strip()
            if stripped.startswith("profile ") or stripped == "!":
                break
            if stripped and stripped != "mac security":
                profile_lines.append(stripped)
        return profile_lines
    return None


def _decode_macsec_profile_fields(host, namespace, output):
    """Decode legacy and JSON ``sonic-db-cli HGETALL`` output."""
    text = str(output).strip()
    if not text:
        return None
    parsed = None
    if text:
        for decoder in (json.loads, ast.literal_eval):
            try:
                parsed = decoder(text)
                break
            except (TypeError, ValueError, SyntaxError):
                continue
    if isinstance(parsed, Mapping):
        return dict(parsed) if parsed else None

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines and len(lines) % 2 == 0:
        return dict(zip(lines[::2], lines[1::2]))
    raise AssertionError(
        "Malformed MACsec profile snapshot on {}: namespace={}, "
        "output={!r}".format(
            getattr(host, "hostname", str(host)), namespace, output))


def _macsec_profile_snapshot(host, profile_name):
    """Capture the exact profile state before a setup transaction mutates it."""
    if isinstance(host, EosHost):
        return {
            "runtime": "eos",
            "lines": _eos_macsec_profile_lines(host, profile_name),
        }

    namespaces = (host.get_asic_namespace_list()
                  if _host_is_multi_asic(host) else [None])
    entries = []
    for namespace in namespaces:
        # Plain HGETALL is supported by old and new sonic-db-cli versions.
        # Depending on the image it returns a dict representation or legacy
        # alternating field/value lines; decode both without requiring ``-j``.
        command = ["sonic-db-cli"]
        if namespace is not None:
            command.extend(["-n", namespace])
        command.extend([
            "CONFIG_DB", "HGETALL",
            "MACSEC_PROFILE|{}".format(profile_name),
        ])
        output = _command_stdout(
            host, " ".join(shlex.quote(part) for part in command))
        fields = _decode_macsec_profile_fields(host, namespace, output)
        entries.append({"namespace": namespace, "fields": fields})
    return {"runtime": "sonic", "entries": entries}


def _macsec_profile_exists(host, profile_name):
    """Return whether a profile existed before this setup transaction."""
    snapshot = _macsec_profile_snapshot(host, profile_name)
    if snapshot["runtime"] == "eos":
        return snapshot["lines"] is not None
    return any(entry["fields"] is not None for entry in snapshot["entries"])


def _macsec_profile_fields(priority, cipher_suite, primary_cak, primary_ckn,
                           policy, send_sci, rekey_period):
    """Return the CONFIG_DB fields for a SONiC MACsec profile."""
    return {
        "priority": str(priority),
        "cipher_suite": cipher_suite,
        "primary_cak": primary_cak,
        "primary_ckn": primary_ckn,
        "policy": policy,
        "send_sci": send_sci,
        "rekey_period": str(rekey_period),
    }


def _macsec_profile_matches(snapshot, priority, cipher_suite, primary_cak,
                            primary_ckn, policy, send_sci, rekey_period):
    """Return whether every SONiC namespace has the requested profile fields."""
    if snapshot["runtime"] != "sonic" or not snapshot["entries"]:
        return False
    expected = _macsec_profile_fields(
        priority, cipher_suite, primary_cak, primary_ckn, policy, send_sci,
        rekey_period)
    # The SONiC CLI omits rekey_period from CONFIG_DB when it is disabled.
    return all(
        entry["fields"] is not None and
        all(entry["fields"].get(
            field, "0" if field == "rekey_period" else None) == value
            for field, value in expected.items())
        for entry in snapshot["entries"])


def _restore_macsec_profile(host, profile_name, snapshot):
    """Restore one profile snapshot, deleting only transaction-created state."""
    if snapshot["runtime"] == "eos":
        host.eos_config(
            lines=["no profile {}".format(profile_name)],
            parents=["mac security"])
        if snapshot["lines"] is not None:
            host.eos_config(
                lines=snapshot["lines"],
                parents=["mac security", "profile {}".format(profile_name)])
        return

    key = "MACSEC_PROFILE|{}".format(profile_name)
    for entry in snapshot["entries"]:
        command = ["sonic-db-cli"]
        if entry["namespace"] is not None:
            command.extend(["-n", entry["namespace"]])
        delete_command = command + ["CONFIG_DB", "DEL", key]
        result = host.command(
            " ".join(shlex.quote(part) for part in delete_command))
        if not _command_succeeded(result):
            raise AssertionError(
                "Failed to delete MACsec profile during rollback on {}: {}"
                .format(getattr(host, "hostname", str(host)),
                        _command_diagnostic(result)))
        if entry["fields"] is None:
            continue
        restore_command = command + ["CONFIG_DB", "HSET", key]
        for field, value in entry["fields"].items():
            restore_command.extend([field, value])
        result = host.command(
            " ".join(shlex.quote(part) for part in restore_command))
        if not _command_succeeded(result):
            raise AssertionError(
                "Failed to restore MACsec profile during rollback on {}: {}"
                .format(getattr(host, "hostname", str(host)),
                        _command_diagnostic(result)))


def _wait_for_macsec_tasks(tasks, timeout):
    """Wait for setup workers and surface child-process failures immediately."""
    wait_all_complete(timeout=timeout)
    failures = [task.exitcode for task in tasks if task.exitcode not in (0, None)]
    assert not failures, "MACsec configuration task failures: {}".format(failures)


def _macsec_host_key(host):
    """Return one identity for a physical MACsec runtime."""
    if isinstance(host, CsonicHost):
        return (host.container_name, host.vm_host_ip, host.vm_host_user)
    return id(host)


def _macsec_endpoint_key(host, port):
    """Return one identity for a physical host/port endpoint."""
    if isinstance(host, CsonicHost) and hasattr(host, "_interface_name"):
        port = host._interface_name(port)
    return (_macsec_host_key(host), port)


def _unique_macsec_neighbor_hosts(macsec_nbrhosts):
    """Collapse logical neighbors backed by the same cSONiC container."""
    unique = {}
    csonic_containers = set()
    for name, neighbor in macsec_nbrhosts.items():
        host = neighbor["host"]
        if isinstance(host, CsonicHost):
            host_key = _macsec_host_key(host)
            if host_key in csonic_containers:
                continue
            csonic_containers.add(host_key)
        unique[name] = neighbor
    return unique


def _macsec_service_ready(host, expected_instances):
    """Check the service shape used by the host's actual runtime."""
    try:
        if isinstance(host, CsonicHost):
            result = host.shell("supervisorctl status macsecmgrd")
            return any("RUNNING" in line for line in _command_output_lines(result))

        if len(_command_output_lines(
                host.shell("docker ps | grep macsec | grep -v grep"))) < expected_instances:
            return False
        return len(_command_output_lines(
            host.shell("ps -ef | grep macsecmgrd | grep -v grep"))) >= expected_instances
    except Exception:
        logger.exception("Failed to check MACsec service readiness on %s", host)
        return False


def _command_diagnostic(result):
    if not isinstance(result, Mapping):
        return {"result": repr(result)}
    return {
        "rc": result.get("rc"),
        "stdout": str(result.get("stdout", ""))[-2000:],
        "stderr": str(result.get("stderr", ""))[-2000:],
    }


def _macsec_service_diagnostics(host):
    if isinstance(host, CsonicHost):
        commands = [
            ("supervisor", "supervisorctl status macsecmgrd"),
            ("process", "pgrep -a -x macsecmgrd"),
            ("post_state", "sonic-db-cli STATE_DB HGET \"FIPS_MACSEC_POST_TABLE|sai\" post_state"),
            ("feature", "sonic-db-cli CONFIG_DB HGET \"FEATURE|macsec\" state"),
            ("database", "sonic-db-cli CONFIG_DB PING"),
            ("supervisor_config", "test -e {0} && sed -n '1,80p' {0}".format(
                CSONIC_MACSEC_SUPERVISOR_CONFIG)),
            ("syslog", "grep -i macsec /var/log/syslog 2>/dev/null | tail -n 40"),
        ]
        runtime = "csonic"
    else:
        commands = [
            ("containers", "docker ps -a --filter name=macsec --format '{{.Names}} {{.Status}}'"),
            ("processes", "ps -ef | grep '[m]acsecmgrd'"),
            ("feature", "sonic-db-cli CONFIG_DB HGET 'FEATURE|macsec' state"),
            ("service", "systemctl status macsec --no-pager -l"),
        ]
        runtime = "sonic"

    checks = {}
    for label, command in commands:
        try:
            checks[label] = _command_diagnostic(
                host.shell(command, module_ignore_errors=True))
        except Exception as error:
            checks[label] = {"exception": repr(error)}
    return {
        "host": getattr(host, "hostname", str(host)),
        "runtime": runtime,
        "checks": checks,
    }


def _macsec_interface_diagnostics(host, interface_name):
    """Capture enough state to distinguish DUT and neighbor readiness failures."""
    if isinstance(host, EosHost):
        return {
            "host": getattr(host, "hostname", str(host)),
            "runtime": "eos",
            "interface": interface_name,
        }

    commands = [
        ("config_profile", "sonic-db-cli CONFIG_DB HGET \"PORT|{}\" macsec".format(interface_name)),
        ("state", "sonic-db-cli STATE_DB HGET \"MACSEC_PORT_TABLE|{}\" state".format(interface_name)),
        ("appl", "sonic-db-cli APPL_DB HGETALL \"MACSEC_PORT_TABLE:{}\"".format(interface_name)),
        ("link", "ip -d link show {}".format(interface_name)),
    ]
    if isinstance(host, CsonicHost):
        runtime = "csonic"
        commands.extend([
            ("service", "supervisorctl status macsecmgrd"),
            ("post_state", "sonic-db-cli STATE_DB HGET \"FIPS_MACSEC_POST_TABLE|sai\" post_state"),
            ("wpa_supplicant", "test -x /sbin/wpa_supplicant && /sbin/wpa_supplicant -v"),
            ("wpa_cli", "test -x /sbin/wpa_cli && /sbin/wpa_cli -v"),
            ("macsec_syslog", "grep -iE 'macsecmgrd|wpa_supplicant|macsec' /var/log/syslog 2>/dev/null | tail -n 80"),
            ("mka", "ip -j macsec show"),
        ])
    else:
        runtime = "sonic"
        commands.extend([
            ("service", "docker ps -a --filter name=macsec --format '{{.Names}} {{.Status}}'"),
            ("mka", "docker exec syncd ip -j macsec show"),
        ])

    checks = {}
    for label, command in commands:
        try:
            checks[label] = _command_diagnostic(
                host.shell(command, module_ignore_errors=True))
        except Exception as error:
            checks[label] = {"exception": repr(error)}
    return {
        "host": getattr(host, "hostname", str(host)),
        "runtime": runtime,
        "interface": interface_name,
        "checks": checks,
    }


def _supervisor_macsec_state(result):
    """Normalize Supervisor status text, including non-zero inactive states."""
    if not isinstance(result, Mapping):
        return "ERROR"
    output = "{}\n{}".format(result.get("stdout", ""), result.get("stderr", ""))
    if "no such process" in output.lower():
        return "MISSING"
    for state in ("RUNNING", "STARTING", "BACKOFF", "STOPPED", "EXITED", "FATAL"):
        if state in output:
            return state
    return "ERROR"


def _csonic_macsec_service_state(host):
    """Capture state that this fixture owns and must restore."""
    status = host.shell(
        "supervisorctl status macsecmgrd", module_ignore_errors=True)
    config = host.shell(
        "test -e {}".format(CSONIC_MACSEC_SUPERVISOR_CONFIG),
        module_ignore_errors=True)
    post_state = host.shell(
        'sonic-db-cli STATE_DB HGET "FIPS_MACSEC_POST_TABLE|sai" post_state',
        module_ignore_errors=True)
    supervisor_state = _supervisor_macsec_state(status)
    if supervisor_state == "ERROR":
        raise AssertionError(
            "Failed to snapshot cSONiC Supervisor state on {}: {}".format(
                host.hostname, _command_diagnostic(status)))
    if not isinstance(config, Mapping) or config.get("rc") not in (0, 1):
        raise AssertionError(
            "Failed to snapshot cSONiC Supervisor config on {}: {}".format(
                host.hostname, _command_diagnostic(config)))
    if not _command_succeeded(post_state):
        raise AssertionError(
            "Failed to snapshot cSONiC POST state on {}: {}".format(
                host.hostname, _command_diagnostic(post_state)))
    post_value = str(post_state.get("stdout", "")).strip() or None
    return {
        "state": supervisor_state,
        "config_exists": config.get("rc") == 0,
        "post_state": post_value,
    }


def _start_csonic_macsec_service(host, initial=None):
    """Provision dependencies and start the daemon with an ownership token."""
    initial = initial or _csonic_macsec_service_state(host)
    provision = """set -e
test -x /sbin/wpa_supplicant
test -x /sbin/wpa_cli
/sbin/wpa_supplicant -h 2>&1 | grep -q \
    'macsec_sonic = MACsec Ethernet driver for SONiC'
printf 'eapol_version=3\\nap_scan=0\\nfast_reauth=1\\n' | \
    cmp -s - /etc/wpa_supplicant.conf
cleanup_macsec_probe() {
    ip link del sm_macsec_test 2>/dev/null || true
    ip link del sm_macsec_base 2>/dev/null || true
}
trap cleanup_macsec_probe EXIT
cleanup_macsec_probe
ip link add sm_macsec_base type dummy
ip link add link sm_macsec_base name sm_macsec_test type macsec
ip -d link show sm_macsec_test | grep -q 'macsec'"""
    result = host.shell(
        provision, module_ignore_errors=True, timeout=300)
    if not _command_succeeded(result):
        logger.error(
            "Failed to provision cSONiC MACsec dependencies on %s: %s",
            host.hostname, _command_diagnostic(result))
        return False

    if initial["post_state"] not in ("pass", "disabled"):
        result = host.shell(
            'sonic-db-cli STATE_DB HSET "FIPS_MACSEC_POST_TABLE|sai" '
            'post_state disabled', module_ignore_errors=True)
        if not _command_succeeded(result):
            return False

    current = _csonic_macsec_service_state(host)
    state = current["state"]
    if state in ("RUNNING", "STARTING", "BACKOFF"):
        if not hasattr(host, "_sonic_mgmt_macsec_initial"):
            host._sonic_mgmt_macsec_initial = initial
        return True
    if state in ("STOPPED", "EXITED", "FATAL"):
        success = _command_succeeded(host.shell(
            "supervisorctl start macsecmgrd", module_ignore_errors=True))
        if success and not hasattr(host, "_sonic_mgmt_macsec_initial"):
            host._sonic_mgmt_macsec_initial = initial
        return success
    if state != "MISSING":
        logger.error("Unexpected macsecmgrd Supervisor state on %s: %s",
                     host.hostname, current)
        return False

    install = """set -e
if [ ! -e {config} ]; then
    cat > {config} <<'EOF'
[program:macsecmgrd]
command=/usr/bin/macsecmgrd
priority=2
autostart=true
autorestart=false
stdout_logfile=NONE
stdout_syslog=true
stderr_logfile=NONE
stderr_syslog=true
EOF
fi
supervisorctl reread
supervisorctl update""".format(config=CSONIC_MACSEC_SUPERVISOR_CONFIG)
    result = host.shell(install, module_ignore_errors=True)
    success = _command_succeeded(result)
    if not success:
        logger.error(
            "Failed to install cSONiC macsecmgrd Supervisor config on %s: %s",
            host.hostname, _command_diagnostic(result))
    if success and not hasattr(host, "_sonic_mgmt_macsec_initial"):
        host._sonic_mgmt_macsec_initial = initial
    return success


def _restore_csonic_post_state(host, initial):
    if initial["post_state"] is None:
        command = (
            'sonic-db-cli STATE_DB HDEL "FIPS_MACSEC_POST_TABLE|sai" '
            'post_state')
    else:
        command = (
            'sonic-db-cli STATE_DB HSET "FIPS_MACSEC_POST_TABLE|sai" '
            'post_state {}').format(shlex.quote(initial["post_state"]))
    return _command_succeeded(host.shell(
        command, module_ignore_errors=True))


def _stop_csonic_macsec_service(host):
    """Restore the service/config/POST state captured by this fixture."""
    initial = getattr(host, "_sonic_mgmt_macsec_initial", None)
    if initial is None:
        logger.error("Missing cSONiC MACsec ownership token on %s", host.hostname)
        return False
    success = _rollback_csonic_macsec_service(host, initial)
    if success:
        delattr(host, "_sonic_mgmt_macsec_initial")
    return success


def _rollback_csonic_macsec_service(host, initial):
    """Undo only service/config/POST changes made by this enable attempt."""
    try:
        current = _csonic_macsec_service_state(host)
    except AssertionError as error:
        logger.error(
            "Cannot safely snapshot cSONiC MACsec state for rollback on %s: %s",
            host.hostname, error)
        return False
    failures = []
    if (initial["state"] not in ("RUNNING", "STARTING", "BACKOFF") and
            current["state"] in ("RUNNING", "STARTING", "BACKOFF")):
        result = host.shell(
            "supervisorctl stop macsecmgrd", module_ignore_errors=True)
        if not _command_succeeded(result):
            failures.append(_command_diagnostic(result))

    if not initial["config_exists"] and current["config_exists"]:
        cleanup = """set -e
rm -f {config}
supervisorctl reread
supervisorctl update""".format(config=CSONIC_MACSEC_SUPERVISOR_CONFIG)
        result = host.shell(cleanup, module_ignore_errors=True)
        if not _command_succeeded(result):
            failures.append(_command_diagnostic(result))
    if current["post_state"] != initial["post_state"]:
        if not _restore_csonic_post_state(host, initial):
            failures.append({"post_state": "restore failed"})
    if failures:
        logger.error("Failed to roll back cSONiC MACsec state on %s: %s",
                     host.hostname, failures)
        return False
    return True


def get_macsec_enable_status(host):
    # Retrieve the enable_macsec flag passed by user for this testrun
    request = host.duthosts.request
    return request.config.getoption("--enable_macsec", default=False)


def get_macsec_profile(host):
    # Retrieve the macsec_profile passed by user for this testrun
    request = host.duthosts.request
    return request.config.getoption("--macsec_profile", default=None)


def set_macsec_profile(host, profile_name, priority, cipher_suite,
                       primary_cak, primary_ckn, policy, send_sci, rekey_period=0):
    if isinstance(host, EosHost):
        eos_cipher_suite = {
            "GCM-AES-128": "aes128-gcm",
            "GCM-AES-256": "aes256-gcm",
            "GCM-AES-XPN-128": "aes128-gcm-xpn",
            "GCM-AES-XPN-256": "aes256-gcm-xpn"
        }
        lines = [
            'cipher {}'.format(eos_cipher_suite[cipher_suite]),
            'key {} 7 {}'.format(primary_ckn, primary_cak),
            'mka key-server priority {}'.format(priority)
            ]
        if rekey_period:
            lines.append('mka session rekey-period {}'.format(rekey_period))
        if send_sci == 'true':
            lines.append('sci')
        host.eos_config(
            lines=lines,
            parents=['mac security', 'profile {}'.format(profile_name)])
        return

    macsec_profile = {
        "priority": priority,
        "cipher_suite": cipher_suite,
        "primary_cak": primary_cak,
        "primary_ckn": primary_ckn,
        "policy": policy,
        "send_sci" if send_sci == "true" else "no_send_sci": "",
        "rekey_period": rekey_period,
    }

    opts = ""
    for k, v in list(macsec_profile.items()):
        opts += " --{} {}".format(k, v)

    if isinstance(host, CsonicHost):
        profile_entry = _macsec_profile_fields(
            priority, cipher_suite, primary_cak, primary_ckn, policy,
            send_sci, rekey_period)
        _csonic_config_db_hset(
            host, "MACSEC_PROFILE|{}".format(profile_name), profile_entry)
    elif _host_is_multi_asic(host):
        for ns in host.get_asic_namespace_list():
            cmd = "config macsec -n {} profile add {} {}".format(ns, profile_name, opts)
            host.command(cmd)
    else:
        cmd = "config macsec profile add {} {}".format(profile_name, opts)
        _run_required_macsec_command(host, cmd)

    _prepare_macsec_lldp(host, send_sci)


def _prepare_macsec_lldp(host, send_sci):
    """Apply the source-MAC workaround independently of profile writes."""
    if isinstance(host, EosHost) or send_sci != "false":
        return
    # The MAC address of SONiC host is locally administrated, so LLDPd would
    # otherwise use an arbitrary source MAC. Linux MACsec cannot handle that
    # mismatch when SCI transmission is disabled.
    _run_required_macsec_command(
        host, "lldpcli configure system bond-slave-src-mac-type real")


def is_macsec_configured(host, mac_profile, ctrl_links):
    is_profile_present = False
    is_port_profile_present = False
    profile_name = mac_profile['name']

    # Check macsec profile is configured in all namespaces
    if _host_is_multi_asic(host):
        for ns in host.get_asic_namespace_list():
            CMD_PREFIX = "-n {}".format(ns) if ns is not None else " "
            cmd = "sonic-db-cli {} CONFIG_DB KEYS 'MACSEC_PROFILE|{}'".format(CMD_PREFIX, profile_name)
            output = host.command(cmd)['stdout'].strip()
            profile = output.split('|')[1] if output else None
            is_profile_present = (profile == profile_name)
    else:
        cmd = "sonic-db-cli CONFIG_DB KEYS 'MACSEC_PROFILE|{}'".format(profile_name)
        output = host.command(cmd)['stdout'].strip()
        profile = output.split('|')[1] if output else None
        is_profile_present = (profile == profile_name)

    # Check if macsec profile is configured on interfaces
    for port, nbr in ctrl_links.items():
        cmd = "sonic-db-cli {} CONFIG_DB HGET 'PORT|{}' 'macsec' ".format(getns_prefix(host, port), port)
        output = host.command(cmd)['stdout'].strip()
        is_port_profile_present = (output == profile_name)

    return is_profile_present and is_port_profile_present


def delete_macsec_profile(host, profile_name):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no profile {}'.format(profile_name)],
            parents=['mac security'])
        return

    if isinstance(host, CsonicHost):
        _csonic_config_db_delete(host, "MACSEC_PROFILE|{}".format(profile_name))
    elif _host_is_multi_asic(host):
        for ns in host.get_asic_namespace_list():
            CMD_PREFIX = "-n {}".format(ns) if ns is not None else " "
            cmd = "config macsec {} profile del {}".format(CMD_PREFIX, profile_name)
            host.command(cmd, module_ignore_errors=True)
    else:
        cmd = ("config macsec profile del {}".format(profile_name))
        host.command(cmd, module_ignore_errors=True)


def enable_macsec_port(host, port, profile_name):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['mac security profile {}'.format(profile_name)],
            parents=['interface {}'.format(port)])
        return

    if isinstance(host, CsonicHost):
        runtime_port = _runtime_port_name(host, port)
        ovs_macsec_member = getattr(host, "set_ovs_macsec_member", None)
        previous_profile = (
            _macsec_port_profile(host, port)
            if callable(ovs_macsec_member) else None)
        _csonic_config_db_hset(
            host, "PORT|{}".format(runtime_port), {"macsec": profile_name})
        if callable(ovs_macsec_member):
            try:
                ovs_macsec_member(port, True)
            except Exception:
                try:
                    ovs_macsec_member(port, previous_profile is not None)
                except Exception:
                    logger.exception(
                        "Failed to restore cSONiC OVS MACsec path on %s",
                        getattr(host, "hostname", str(host)))
                if previous_profile is None:
                    _csonic_config_db_hdel(
                        host, "PORT|{}".format(runtime_port), "macsec")
                else:
                    _csonic_config_db_hset(
                        host, "PORT|{}".format(runtime_port),
                        {"macsec": previous_profile})
                raise
        return

    pc = find_portchannel_from_member(port, get_portchannel(host))

    dnx_platform = _host_platform_asic(host) == 'broadcom-dnx'

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member del {} {}".format(getns_prefix(host, port), pc["name"], port))

    cmd = "config macsec {} port add {} {}".format(getns_prefix(host, port), port, profile_name)
    _run_required_macsec_command(host, cmd)

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member add {} {}".format(getns_prefix(host, port), pc["name"], port))


def disable_macsec_port(host, port):
    if isinstance(host, EosHost):
        host.eos_config(
            lines=['no mac security profile'],
            parents=['interface {}'.format(port)])
        return

    if isinstance(host, CsonicHost):
        runtime_port = _runtime_port_name(host, port)
        ovs_macsec_member = getattr(host, "set_ovs_macsec_member", None)
        if callable(ovs_macsec_member):
            ovs_macsec_member(port, False)
        try:
            _csonic_config_db_hdel(
                host, "PORT|{}".format(runtime_port), "macsec")
        except Exception:
            if callable(ovs_macsec_member):
                try:
                    ovs_macsec_member(port, True)
                except Exception:
                    logger.exception(
                        "Failed to restore cSONiC OVS MACsec path on %s",
                        getattr(host, "hostname", str(host)))
            raise
        return

    pc = find_portchannel_from_member(port, get_portchannel(host))
    dnx_platform = _host_platform_asic(host) == 'broadcom-dnx'

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member del {} {}".format(getns_prefix(host, port), pc["name"], port))

    cmd = "config macsec {} port del {}".format(getns_prefix(host, port), port)
    host.command(cmd)

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member add {} {}".format(getns_prefix(host, port), pc["name"], port))


def replace_macsec_port(host, port, profile_name):
    disable_macsec_port(host, port)
    time.sleep(10)
    enable_macsec_port(host, port, profile_name)


def _macsec_feature_state(host):
    """Return the exact CONFIG_DB feature state before a temporary enable."""
    return _command_stdout(
        host, 'sonic-db-cli CONFIG_DB HGET "FEATURE|macsec" state') or None


def _restore_macsec_feature_state(host, state):
    """Restore a previously captured MACsec feature state or field absence."""
    if state is None:
        return _run_required_macsec_command(
            host, 'sonic-db-cli CONFIG_DB HDEL "FEATURE|macsec" state')
    return _run_required_macsec_command(
        host, "sudo config feature state macsec {}".format(state))


def enable_macsec_feature(duthost, macsec_nbrhosts):
    nbrhosts = _unique_macsec_neighbor_hosts(macsec_nbrhosts)
    num_asics = duthost.num_asics()
    attempted = []
    feature_hosts = [duthost]
    feature_hosts.extend(
        nbr["host"] for nbr in nbrhosts.values()
        if not isinstance(nbr["host"], EosHost))
    feature_snapshots = [
        (host, _macsec_feature_state(host)) for host in feature_hosts]

    try:
        global_cmd(duthost, nbrhosts, "sudo config feature state macsec enabled")
        for nbr in [n["host"] for n in list(nbrhosts.values())]:
            if isinstance(nbr, CsonicHost):
                initial = _csonic_macsec_service_state(nbr)
                ownership = getattr(
                    nbr, "_sonic_mgmt_macsec_initial", None)
                attempted.append((nbr, initial, ownership))
                assert _start_csonic_macsec_service(nbr, initial), \
                    "Failed to start macsecmgrd on {}".format(nbr.hostname)

        def check_macsec_enabled():
            dut_ready = _macsec_service_ready(duthost, num_asics)
            neighbor_ready = []
            for nbr in [n["host"] for n in list(nbrhosts.values())]:
                if isinstance(nbr, EosHost):
                    continue
                neighbor_ready.append(_macsec_service_ready(nbr, 1))
            return dut_ready and all(neighbor_ready)

        if not wait_until(180, 5, 10, check_macsec_enabled):
            diagnostics = [_macsec_service_diagnostics(duthost)]
            diagnostics.extend(
                _macsec_service_diagnostics(nbr)
                for nbr in [n["host"] for n in list(nbrhosts.values())]
                if not isinstance(nbr, EosHost)
            )
            logger.error("MACsec readiness timed out: %s", diagnostics)
            raise AssertionError(
                "MACsec readiness timed out: {}".format(diagnostics))
    except Exception:
        for nbr, initial, ownership in reversed(attempted):
            rollback_succeeded = False
            try:
                rollback_succeeded = _rollback_csonic_macsec_service(
                    nbr, initial)
            except Exception:
                logger.exception(
                    "Failed to roll back MACsec setup on %s", nbr.hostname)
            finally:
                if ownership is not None:
                    nbr._sonic_mgmt_macsec_initial = ownership
                elif rollback_succeeded:
                    if hasattr(nbr, "_sonic_mgmt_macsec_initial"):
                        delattr(nbr, "_sonic_mgmt_macsec_initial")
                else:
                    nbr._sonic_mgmt_macsec_initial = initial
        for host, state in reversed(feature_snapshots):
            try:
                _restore_macsec_feature_state(host, state)
            except Exception:
                logger.exception(
                    "Failed to restore MACsec feature state on %s",
                    getattr(host, "hostname", str(host)))
        raise


def disable_macsec_feature(duthost, macsec_nbrhosts):
    nbrhosts = _unique_macsec_neighbor_hosts(macsec_nbrhosts)
    failures = []
    try:
        global_cmd(duthost, nbrhosts, "sudo config feature state macsec disabled")
    except Exception as error:
        failures.append({"feature_disable": repr(error)})
    for nbr in [n["host"] for n in list(nbrhosts.values())]:
        if isinstance(nbr, CsonicHost):
            try:
                if not _stop_csonic_macsec_service(nbr):
                    failures.append({"host": nbr.hostname,
                                     "service_restore": "failed"})
            except Exception as error:
                failures.append({"host": nbr.hostname,
                                 "service_restore": repr(error)})
    assert not failures, "Failed to disable MACsec cleanly: {}".format(failures)


def _wait_for_macsec_cleanup_with_vs_recovery(host, interfaces, is_dut):
    if wait_for_macsec_cleanup(host, interfaces):
        return False

    if isinstance(host, CsonicHost):
        diagnostics = [
            _macsec_interface_diagnostics(host, interface)
            for interface in interfaces
        ]
        raise AssertionError(
            "MACsec cleanup timed out on cSONiC host {}: {}".format(
                host.hostname, diagnostics))

    if getattr(host, "facts", {}).get("asic_type") != "vs":
        return False

    logger.warning(
        "MACsec cleanup timed out on %s; reloading config to clear "
        "stale VS state",
        host.hostname,
    )
    if is_dut:
        config_reload(
            host,
            config_source="config_db",
            safe_reload=True,
            yang_validate=False,
        )
    else:
        host.shell("sudo config reload -y -f", executable="/bin/bash")
        assert wait_until(
            200, 10, 0, host.is_service_fully_started, "database"), \
            "Database did not recover on {}".format(host.hostname)
        assert wait_until(
            420, 10, 0, host.critical_processes_running, "swss"), \
            "Swss did not recover on {}".format(host.hostname)

    assert wait_for_macsec_cleanup(host, interfaces), \
        "MACsec entries remain on {} after config reload".format(host.hostname)
    return True


def _restore_macsec_feature_after_cleanup_recovery(
        duthost, ctrl_links):
    nbrhosts = {nbr["name"]: nbr for nbr in ctrl_links.values()}
    enable_macsec_feature(duthost, nbrhosts)


def _macsec_configuration_targets(duthost, ctrl_links):
    """Return unique physical profile hosts and host/port endpoints."""
    profile_hosts = []
    endpoints = []
    seen_hosts = set()
    seen_endpoints = set()

    for host, port in [(duthost, dut_port) for dut_port in ctrl_links]:
        endpoint_key = _macsec_endpoint_key(host, port)
        if endpoint_key not in seen_endpoints:
            seen_endpoints.add(endpoint_key)
            endpoints.append((host, port))

    for nbr in ctrl_links.values():
        host = nbr["host"]
        host_key = _macsec_host_key(host)
        if host_key not in seen_hosts:
            seen_hosts.add(host_key)
            profile_hosts.append(host)
        endpoint_key = _macsec_endpoint_key(host, nbr["port"])
        if endpoint_key not in seen_endpoints:
            seen_endpoints.add(endpoint_key)
            endpoints.append((host, nbr["port"]))
    return profile_hosts, endpoints


def _rollback_macsec_configuration(
        profile_snapshots, attempted_endpoints, profile_name):
    """Best-effort reverse-order rollback for changes this setup attempted."""
    failures = []
    for host, port, previous_profile in reversed(attempted_endpoints):
        try:
            if previous_profile is None:
                disable_macsec_port(host, port)
            else:
                enable_macsec_port(host, port, previous_profile)
        except Exception as error:
            failures.append({"host": str(host), "port": port,
                             "previous_profile": previous_profile,
                             "exception": repr(error)})
    for host, snapshot in reversed(profile_snapshots):
        try:
            _restore_macsec_profile(host, profile_name, snapshot)
        except Exception as error:
            failures.append({"host": str(host), "profile": profile_name,
                             "exception": repr(error)})
    if failures:
        logger.error("MACsec configuration rollback failures: %s", failures)


def _macsec_session_cleanup_hosts(duthost, neighbor_profile_hosts):
    """Return hosts where the legacy syncd MKA check is valid."""
    hosts = list(neighbor_profile_hosts)
    if getattr(duthost, "facts", {}).get("asic_type") == "vs":
        hosts.insert(0, duthost)
    return hosts


def cleanup_macsec_configuration(duthost, ctrl_links, profile_name):
    neighbor_profile_hosts, endpoints = _macsec_configuration_targets(
        duthost, ctrl_links)
    profile_hosts = [duthost] + neighbor_profile_hosts

    logger.info("Cleanup macsec configuration step1: disable macsec port")
    tasks = [submit_async_task(disable_macsec_port, endpoint)
             for endpoint in endpoints]
    _wait_for_macsec_tasks(tasks, timeout=300)

    logger.info("Cleanup macsec configuration step2: delete macsec profile")
    tasks = [submit_async_task(delete_macsec_profile, (host, profile_name))
             for host in profile_hosts]
    _wait_for_macsec_tasks(tasks, timeout=300)

    logger.info("Cleanup macsec configuration step3: wait for automatic cleanup")
    interfaces = list(ctrl_links.keys())
    recovered = _wait_for_macsec_cleanup_with_vs_recovery(
        duthost, interfaces, is_dut=True)

    seen_endpoints = set()
    for nbr in ctrl_links.values():
        endpoint_key = _macsec_endpoint_key(nbr["host"], nbr["port"])
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)
        neighbor_recovered = _wait_for_macsec_cleanup_with_vs_recovery(
            nbr["host"], [nbr["port"]], is_dut=False)
        recovered = neighbor_recovered or recovered

    if recovered:
        _restore_macsec_feature_after_cleanup_recovery(duthost, ctrl_links)

    logger.info("Cleanup macsec configuration finished")
    for host in _macsec_session_cleanup_hosts(
            duthost, neighbor_profile_hosts):
        if isinstance(host, EosHost):
            continue
        assert wait_until(30, 1, 0, lambda host=host: not get_mka_session(host))


def setup_macsec_configuration(duthost, ctrl_links, profile_name, default_priority,
                               cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period, tbinfo):
    neighbor_profile_hosts, endpoints = _macsec_configuration_targets(
        duthost, ctrl_links)
    profile_hosts = [duthost] + neighbor_profile_hosts
    profile_snapshots = [
        (host, _macsec_profile_snapshot(host, profile_name))
        for host in profile_hosts
    ]
    endpoint_snapshots = [
        (host, port, _macsec_port_profile(host, port))
        for host, port in endpoints
    ]
    attempted_profiles = []
    attempted_endpoints = []

    try:
        logger.info("Setup macsec configuration step1: set macsec profile")
        profile_settings = [(duthost, default_priority)]
        for index, host in enumerate(neighbor_profile_hosts):
            priority = default_priority - 1 if index % 2 == 0 else default_priority + 1
            profile_settings.append((host, priority))

        tasks = []
        for (host, priority), (_, snapshot) in zip(
                profile_settings, profile_snapshots):
            if _macsec_profile_matches(
                    snapshot, priority, cipher_suite, primary_cak, primary_ckn,
                    policy, send_sci, rekey_period):
                logger.info(
                    "MACsec profile %s already matches requested state on %s",
                    profile_name, getattr(host, "hostname", str(host)))
                if send_sci == "false":
                    tasks.append(submit_async_task(
                        _prepare_macsec_lldp, (host, send_sci)))
                continue
            attempted_profiles.append((host, snapshot))
            tasks.append(submit_async_task(
                set_macsec_profile,
                (host, profile_name, priority, cipher_suite, primary_cak,
                 primary_ckn, policy, send_sci, rekey_period)))
        _wait_for_macsec_tasks(tasks, timeout=180)

        logger.info("Setup macsec configuration step2: enable macsec profile")
        tasks = []
        for host, port, previous_profile in endpoint_snapshots:
            time.sleep(3)
            attempted_endpoints.append((host, port, previous_profile))
            tasks.append(submit_async_task(
                enable_macsec_port, (host, port, profile_name)))
        _wait_for_macsec_tasks(tasks, timeout=180)

        for dut_port, nbr in list(ctrl_links.items()):
            if not wait_until(
                    300, 3, 0,
                    lambda dut_port=dut_port, nbr=nbr:
                    duthost.iface_macsec_ok(dut_port) and
                    nbr["host"].iface_macsec_ok(nbr["port"])):
                diagnostics = {
                    "dut": _macsec_interface_diagnostics(duthost, dut_port),
                    "neighbor": _macsec_interface_diagnostics(
                        nbr["host"], nbr["port"]),
                }
                logger.error(
                    "MACsec interface readiness timed out: %s", diagnostics)
                raise AssertionError(
                    "MACsec interface readiness timed out: {}".format(
                        diagnostics))

        time.sleep(60)
        logger.info("Setup macsec configuration finished")
    except Exception:
        _rollback_macsec_configuration(
            attempted_profiles, attempted_endpoints, profile_name)
        raise


def generate_macsec_profile(port_name, cipher_suite="GCM-AES-128", priority=64,
                            policy="security", send_sci="true", rekey_period=0):
    """Generate a MACsec profile with random CAK/CKN for a specific port.

    The profile is named ``MACSEC_PROFILE_<port_name>`` and the pre-shared keys
    are generated using ``secrets.token_hex`` so that every port receives a
    unique key pair.

    Args:
        port_name: Interface name (e.g. "Ethernet0"). Used in the profile name.
        cipher_suite: Cipher suite string. Determines key lengths.
        priority: MKA key-server priority (0-255).
        policy: "security" (encrypt) or "integrity" (auth only).
        send_sci: "true" or "false".
        rekey_period: Seconds between rekeying (0 = disabled).

    Returns:
        dict: A profile dict compatible with set_macsec_profile().
    """

    # CAK length: AES-128 variants use 32 bytes (66 hex chars),
    #             AES-256 variants use 64 bytes (130 hex chars).
    # CKN length: AES-128 variants use 16 bytes (32 hex chars),
    #             AES-256 variants use 32 bytes (64 hex chars).
    if "128" in cipher_suite:
        cak = secrets.token_hex(16)
        # token_hex produces a string of n*2 chars (as each hex num is 2 chars)
        # For CKN, this is interpreted as the literal password, so when passed to
        # the type7 encoder each hex char is treated as its own byte.
        # This is why the number passed to token hex is half the expected number of bytes,
        # because the length of the string generated is double
        ckn = secrets.token_hex(16)
    else:
        cak = secrets.token_hex(32)
        ckn = secrets.token_hex(32)

    # CAK is expected to be in "type7" encoding format
    # This adds the extra byte to the cak / ckn length
    cak = cisco_type7.hash(cak)

    profile_name = "MACSEC_PROFILE_{}".format(port_name)
    return {
        "name": profile_name,
        "priority": priority,
        "cipher_suite": cipher_suite,
        "primary_cak": cak,
        "primary_ckn": ckn,
        "policy": policy,
        "send_sci": send_sci,
        "rekey_period": rekey_period,
    }


def setup_macsec_multi_profile_configuration(duthost, ctrl_links, port_profiles, tbinfo):
    """Set up MACsec with a different profile per port.

    Each port in *ctrl_links* is configured with its own profile from
    *port_profiles*.  The DUT uses ``default_priority`` from the profile while
    neighbors alternate between ``priority - 1`` and ``priority + 1`` so the
    DUT is elected MKA key-server on most links.

    Args:
        duthost: DUT host object.
        ctrl_links: dict ``{dut_port: {name, host, port, ...}}``.
        port_profiles: dict ``{dut_port: profile_dict}`` where each
            ``profile_dict`` has keys matching ``generate_macsec_profile``
            output.
        tbinfo: Testbed info dict.
    """
    logger.info("Multi-profile setup step 1: set per-port macsec profiles")

    for dut_port, profile in port_profiles.items():
        set_macsec_profile(
            duthost, profile["name"], profile["priority"],
            profile["cipher_suite"], profile["primary_cak"],
            profile["primary_ckn"], profile["policy"],
            profile["send_sci"], profile["rekey_period"])
    i = 0
    for dut_port, nbr in ctrl_links.items():
        profile = port_profiles[dut_port]

        if i % 2 == 0:
            nbr_priority = profile["priority"] - 1
        else:
            nbr_priority = profile["priority"] + 1
        set_macsec_profile(
            nbr["host"], profile["name"], nbr_priority,
            profile["cipher_suite"], profile["primary_cak"],
            profile["primary_ckn"], profile["policy"],
            profile["send_sci"], profile["rekey_period"])
        i += 1
        time.sleep(3)

    logger.info("Multi-profile setup step 2: enable per-port macsec")

    for dut_port, nbr in list(ctrl_links.items()):
        profile = port_profiles[dut_port]
        time.sleep(3)
        enable_macsec_port(duthost, dut_port, profile["name"])
        enable_macsec_port(nbr["host"], nbr["port"], profile["name"])

    logger.info("Multi-profile setup step 3: wait for macsec ready on each port")

    for dut_port, nbr in list(ctrl_links.items()):
        assert wait_until(300, 3, 0,
                          lambda dp=dut_port, n=nbr: duthost.iface_macsec_ok(dp) and
                          n["host"].iface_macsec_ok(n["port"]))

    # Hold time for protocol recovery after link flaps.
    time.sleep(60)
    logger.info("Multi-profile setup finished")


def cleanup_macsec_multi_profile_configuration(duthost, ctrl_links, port_profiles):
    """Clean up per-port MACsec profiles.

    Disables MACsec on every controlled port, then deletes each unique profile
    from CONFIG_DB on both the DUT and neighbor devices.

    Args:
        duthost: DUT host object.
        ctrl_links: dict ``{dut_port: {name, host, port, ...}}``.
        port_profiles: dict ``{dut_port: profile_dict}``.
    """
    devices = set([nbr["host"] for nbr in ctrl_links.values()])
    if duthost.facts["asic_type"] == "vs":
        devices.add(duthost)

    logger.info("Multi-profile cleanup step 1: disable macsec on all ports")
    for dut_port, nbr in list(ctrl_links.items()):
        time.sleep(3)
        disable_macsec_port(duthost, dut_port)
        disable_macsec_port(nbr["host"], nbr["port"])

    logger.info("Multi-profile cleanup step 2: delete per-port profiles")
    for dut_port, nbr in list(ctrl_links.items()):
        profile_name = port_profiles[dut_port]["name"]
        delete_macsec_profile(duthost, profile_name)
        delete_macsec_profile(nbr["host"], profile_name)

    logger.info("Multi-profile cleanup step 3: wait for automatic cleanup")

    interfaces = list(ctrl_links.keys())
    recovered = _wait_for_macsec_cleanup_with_vs_recovery(
        duthost, interfaces, is_dut=True)

    for dut_port, nbr in list(ctrl_links.items()):
        neighbor_recovered = _wait_for_macsec_cleanup_with_vs_recovery(
            nbr["host"], [nbr["port"]], is_dut=False)
        recovered = neighbor_recovered or recovered

    if recovered:
        _restore_macsec_feature_after_cleanup_recovery(
            duthost, ctrl_links)

    logger.info("Multi-profile cleanup finished")

    for d in devices:
        if isinstance(d, EosHost):
            continue
        assert wait_until(30, 1, 0, lambda d=d: not get_mka_session(d))


def wait_for_macsec_cleanup(host, interfaces, timeout=90):
    """Wait for MACsec daemon to automatically clean up all MACsec entries.

    This function implements proper synchronization to wait for the automatic
    cleanup process to complete, preserving the intended MACsec cleanup behavior.

    Args:
        host: SONiC DUT or neighbor host object
        interfaces: List of interface names to check
        timeout: Maximum time to wait in seconds for MACsec cleanup to finish (default: 90).

    Returns:
        bool: True if cleanup completed, False if timeout
    """
    if isinstance(host, EosHost):
        # EOS hosts don't use Redis databases
        logger.info("EOS host detected, skipping Redis cleanup verification")
        return True

    logger.info(f"Waiting for automatic MACsec cleanup (timeout: {timeout}s)")

    start_time = time.time()
    # Poll at most ~10 times over the full timeout, capped at 10 seconds between checks.
    poll_interval = min(10, max(1, timeout / 10.0))

    # We only care about APPL_DB and STATE_DB for MACsec tables. Instead of
    # trying to reverse-engineer numeric DB IDs from CONFIG_DB, rely on
    # sonic-db-cli with logical DB names and the same namespace logic used
    # elsewhere in MACsec helpers.

    while time.time() - start_time < timeout:
        all_clean = True
        remaining_entries = {}

        for interface in interfaces:
            ns_prefix = getns_prefix(host, interface)

            for db_name, sep in (("APPL_DB", ":"), ("STATE_DB", "|")):
                pattern = f"MACSEC_*{sep}{interface}*"
                cmd = f"sonic-db-cli {ns_prefix} {db_name} KEYS '{pattern}'"

                try:
                    result = host.command(cmd, verbose=False)
                    out_lines = result.get("stdout_lines", [])
                except Exception as e:
                    logger.warning(
                        "Failed to query MACsec keys on host %s, DB %s, interface %s: %r",
                        getattr(host, 'hostname', host),
                        db_name,
                        interface,
                        e,
                    )
                    # If we cannot query Redis for this DB/interface, be
                    # conservative and assume cleanup is not complete yet.
                    all_clean = False
                    continue

                keys = [k.strip() for k in out_lines if k.strip()]
                if keys:
                    all_clean = False
                    remaining_entries.setdefault((db_name, interface), []).extend(keys)

        elapsed = time.time() - start_time

        if all_clean:
            logger.info(
                f"Automatic MACsec cleanup completed successfully in {elapsed:.1f}s"
            )
            return True

        # Log progress every 30 seconds to reduce verbosity
        if int(elapsed) % 30 == 0 and elapsed > 0:
            logger.info(f"Still waiting for cleanup... ({elapsed:.0f}s elapsed)")

        time.sleep(poll_interval)

    # Timeout reached
    elapsed = time.time() - start_time
    logger.warning(f"Automatic MACsec cleanup timeout after {elapsed:.1f}s")

    # Log summary of remaining entries
    total_remaining = sum(len(entries) for entries in remaining_entries.values())
    if total_remaining > 0:
        logger.warning(
            f"  {total_remaining} MACsec entries still remain after timeout"
        )

    return False
