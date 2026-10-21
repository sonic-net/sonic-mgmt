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


def _wait_for_macsec_tasks(tasks, timeout):
    """Wait for setup workers and surface child-process failures immediately."""
    wait_all_complete(timeout=timeout)
    failures = [task.exitcode for task in tasks if task.exitcode not in (0, None)]
    assert not failures, "MACsec configuration task failures: {}".format(failures)


def _unique_macsec_neighbor_hosts(macsec_nbrhosts):
    """Collapse logical neighbors backed by the same cSONiC container."""
    unique = {}
    csonic_containers = set()
    for name, neighbor in macsec_nbrhosts.items():
        host = neighbor["host"]
        if isinstance(host, CsonicHost):
            identity = (host.container_name, host.vm_host_ip, host.vm_host_user)
            if identity in csonic_containers:
                continue
            csonic_containers.add(identity)
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
            ("post_state", "sonic-db-cli STATE_DB HGET 'FIPS_MACSEC_POST_TABLE|sai' post_state"),
            ("feature", "sonic-db-cli CONFIG_DB HGET 'FEATURE|macsec' state"),
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
        ("config_profile", "sonic-db-cli CONFIG_DB HGET 'PORT|{}' macsec".format(interface_name)),
        ("state", "sonic-db-cli STATE_DB HGET 'MACSEC_PORT_TABLE|{}' state".format(interface_name)),
        ("appl", "sonic-db-cli APPL_DB HGETALL 'MACSEC_PORT_TABLE:{}'".format(interface_name)),
        ("link", "ip -d link show {}".format(interface_name)),
    ]
    if isinstance(host, CsonicHost):
        runtime = "csonic"
        commands.extend([
            ("service", "supervisorctl status macsecmgrd"),
            ("post_state", "sonic-db-cli STATE_DB HGET 'FIPS_MACSEC_POST_TABLE|sai' post_state"),
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


def _start_csonic_macsec_service(host):
    """Ensure monolithic docker-sonic-vs supervises its bundled daemon.

    Some docker-sonic-vs images contain the macsecmgrd binary without its
    wpa_supplicant runtime or a supervisor program. Install the missing Debian
    runtime on demand and register only the daemon at the MACsec call site;
    images that already provide either dependency skip that work.

    macsecmgrd does not consume CONFIG_DB until the SAI MACsec POST state is
    ``pass`` or ``disabled``. The standalone macsec container gets this state
    from orchagent, but the monolithic VS neighbor does not consistently
    publish it. VS has no hardware MACsec POST, so seed the same ``disabled``
    state that orchagent uses when POST is unsupported before starting the
    daemon.
    """
    command = """set -e
if [ ! -x /sbin/wpa_supplicant ] || [ ! -x /sbin/wpa_cli ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends wpasupplicant
    rm -rf /var/lib/apt/lists/*
fi
test -x /sbin/wpa_supplicant
test -x /sbin/wpa_cli
sonic-db-cli STATE_DB HSET 'FIPS_MACSEC_POST_TABLE|sai' post_state disabled >/dev/null
status=$(supervisorctl status macsecmgrd 2>&1 || true)
case "$status" in
    *RUNNING*) exit 0 ;;
    *"no such process"*)
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
        supervisorctl reread
        supervisorctl update
        ;;
    *) supervisorctl start macsecmgrd ;;
esac""".format(config=CSONIC_MACSEC_SUPERVISOR_CONFIG)
    return _command_succeeded(host.shell(command, module_ignore_errors=True))


def _stop_csonic_macsec_service(host):
    """Stop macsecmgrd and remove only the config installed above."""
    command = """set -e
status=$(supervisorctl status macsecmgrd 2>&1 || true)
case "$status" in
    *RUNNING*) supervisorctl stop macsecmgrd ;;
esac
if [ -e {config} ]; then
    rm -f {config}
    supervisorctl reread
    supervisorctl update
fi""".format(config=CSONIC_MACSEC_SUPERVISOR_CONFIG)
    return _command_succeeded(host.shell(command, module_ignore_errors=True))


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
        profile_entry = {
            "priority": priority,
            "cipher_suite": cipher_suite,
            "primary_cak": primary_cak,
            "primary_ckn": primary_ckn,
            "policy": policy,
            "send_sci": send_sci,
        }
        if rekey_period > 0:
            profile_entry["rekey_period"] = rekey_period
        _csonic_config_db_hset(
            host, "MACSEC_PROFILE|{}".format(profile_name), profile_entry)
    elif _host_is_multi_asic(host):
        for ns in host.get_asic_namespace_list():
            cmd = "config macsec -n {} profile add {} {}".format(ns, profile_name, opts)
            host.command(cmd)
    else:
        cmd = "config macsec profile add {} {}".format(profile_name, opts)
        _run_required_macsec_command(host, cmd)

    if send_sci == "false":
        # The MAC address of SONiC host is locally administrated
        # So, LLDPd will use an arbitrary fixed value (00:60:08:69:97:ef)
        # as the source MAC address of LLDP packet (https://lldpd.github.io/usage.html)
        # But the MACsec driver in Linux used by SONiC VM has a bug that
        # cannot handle the packet with different source MAC address to SCI if the send_sci = false
        # So, if send_sci = false and the neighbor device is SONiC VM,
        # LLDPd need to use the real MAC address as the source MAC address
        host.command("lldpcli configure system bond-slave-src-mac-type real")


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
        _csonic_config_db_hset(
            host, "PORT|{}".format(port), {"macsec": profile_name})
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
        _csonic_config_db_hdel(host, "PORT|{}".format(port), "macsec")
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


def enable_macsec_feature(duthost, macsec_nbrhosts):
    nbrhosts = _unique_macsec_neighbor_hosts(macsec_nbrhosts)
    num_asics = duthost.num_asics()
    global_cmd(duthost, nbrhosts, "sudo config feature state macsec enabled")

    for nbr in [n["host"] for n in list(nbrhosts.values())]:
        if isinstance(nbr, CsonicHost):
            assert _start_csonic_macsec_service(nbr), \
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
        assert False, "MACsec readiness timed out: {}".format(diagnostics)


def disable_macsec_feature(duthost, macsec_nbrhosts):
    nbrhosts = _unique_macsec_neighbor_hosts(macsec_nbrhosts)
    global_cmd(duthost, nbrhosts, "sudo config feature state macsec disabled")
    for nbr in [n["host"] for n in list(nbrhosts.values())]:
        if isinstance(nbr, CsonicHost):
            assert _stop_csonic_macsec_service(nbr), \
                "Failed to stop macsecmgrd on {}".format(nbr.hostname)


def _wait_for_macsec_cleanup_with_vs_recovery(host, interfaces, is_dut):
    if wait_for_macsec_cleanup(host, interfaces):
        return False

    if host.facts["asic_type"] != "vs":
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


def cleanup_macsec_configuration(duthost, ctrl_links, profile_name):
    devices = set()
    if duthost.facts["asic_type"] == "vs":
        devices.add(duthost)

    logger.info("Cleanup macsec configuration step1: disable macsec port")
    for dut_port, nbr in list(ctrl_links.items()):
        time.sleep(3)
        submit_async_task(disable_macsec_port, (duthost, dut_port))
        submit_async_task(disable_macsec_port, (nbr["host"], nbr["port"]))
        devices.add(nbr["host"])
    wait_all_complete(timeout=300)

    logger.info("Cleanup macsec configuration step2: delete macsec profile")
    # Delete the macsec profile once after it is removed from all interfaces.
    # On multi-asic the profile is removed from the DB in all namespaces.
    submit_async_task(delete_macsec_profile, (duthost, profile_name))

    # Delete the macsec profile in neighbors
    for d in devices:
        submit_async_task(delete_macsec_profile, (d, profile_name))
    wait_all_complete(timeout=300)

    logger.info("Cleanup macsec configuration step3: wait for automatic cleanup")

    # Extract DUT interface names from ctrl_links and wait for automatic
    # MACsec cleanup on the DUT side.
    interfaces = list(ctrl_links.keys())
    recovered = _wait_for_macsec_cleanup_with_vs_recovery(
        duthost, interfaces, is_dut=True)

    # Also wait for neighbor devices to complete automatic cleanup for their
    # corresponding ports.
    for dut_port, nbr in list(ctrl_links.items()):
        neighbor_recovered = _wait_for_macsec_cleanup_with_vs_recovery(
            nbr["host"], [nbr["port"]], is_dut=False)
        recovered = neighbor_recovered or recovered

    if recovered:
        _restore_macsec_feature_after_cleanup_recovery(
            duthost, ctrl_links)

    logger.info("Cleanup macsec configuration finished")

    # Waiting for all MKA sessions to be cleared on neighbor devices.
    for d in devices:
        if isinstance(d, EosHost):
            continue
        assert wait_until(30, 1, 0, lambda d=d: not get_mka_session(d))


def setup_macsec_configuration(duthost, ctrl_links, profile_name, default_priority,
                               cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period, tbinfo):
    logger.info("Setup macsec configuration step1: set macsec profile")
    # 1. Set macsec profile. The profile is host-wide (no port arg), so the
    # DUT-side set runs once outside the per-link loop.
    tasks = [submit_async_task(set_macsec_profile, (duthost, profile_name, default_priority,
                               cipher_suite, primary_cak, primary_ckn, policy,
                               send_sci, rekey_period))]
    i = 0
    for dut_port, nbr in ctrl_links.items():
        if i % 2 == 0:
            priority = default_priority - 1
        else:
            priority = default_priority + 1
        tasks.append(submit_async_task(
            set_macsec_profile,
            (nbr["host"], profile_name, priority, cipher_suite, primary_cak,
             primary_ckn, policy, send_sci, rekey_period)))
        i += 1
    _wait_for_macsec_tasks(tasks, timeout=180)

    logger.info("Setup macsec configuration step2: enable macsec profile")
    # 2. Enable macsec profile
    tasks = []
    for dut_port, nbr in list(ctrl_links.items()):
        time.sleep(3)
        tasks.append(submit_async_task(enable_macsec_port, (duthost, dut_port, profile_name)))
        tasks.append(submit_async_task(enable_macsec_port, (nbr["host"], nbr["port"], profile_name)))
    _wait_for_macsec_tasks(tasks, timeout=180)

    # 3. Wait for interface's macsec ready
    for dut_port, nbr in list(ctrl_links.items()):
        if not wait_until(300, 3, 0,
                          lambda: duthost.iface_macsec_ok(dut_port) and
                          nbr["host"].iface_macsec_ok(nbr["port"])):
            diagnostics = {
                "dut": _macsec_interface_diagnostics(duthost, dut_port),
                "neighbor": _macsec_interface_diagnostics(nbr["host"], nbr["port"]),
            }
            logger.error("MACsec interface readiness timed out: %s", diagnostics)
            assert False, "MACsec interface readiness timed out: {}".format(diagnostics)

    # Enabling macsec may cause link flap, which impacts LACP, BGP, etc
    # protocols. To hold some time for protocol recovery.
    time.sleep(60)
    logger.info("Setup macsec configuration finished")


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
