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


def _command_diagnostic(result):
    if not isinstance(result, Mapping):
        return {"result": repr(result)}
    return {
        "rc": result.get("rc"),
        "stdout": str(result.get("stdout", ""))[-2000:],
        "stderr": str(result.get("stderr", ""))[-2000:],
    }


def _runtime_port_name(host, port):
    """Translate only cSONiC logical ports that expose a runtime mapper."""
    if not isinstance(host, CsonicHost):
        return port
    mapper = getattr(host, "_interface_name", None)
    return mapper(port) if callable(mapper) else port


def _run_required_csonic_command(host, command):
    """Fail closed for CsonicHost's non-raising command API."""
    result = host.command(command)
    if not _command_succeeded(result):
        raise AssertionError(
            "MACsec command failed on {}: command={!r}, result={}".format(
                host.hostname, command, _command_diagnostic(result)))
    return result


def _csonic_config_db_hset(host, key, values):
    command = ["sonic-db-cli", "CONFIG_DB", "HSET", key]
    for field, value in values.items():
        command.extend([field, str(value)])
    return _run_required_csonic_command(
        host, " ".join(shlex.quote(part) for part in command))


def _csonic_config_db_delete(host, key):
    return _run_required_csonic_command(
        host, "sonic-db-cli CONFIG_DB DEL {}".format(shlex.quote(key)))


def _csonic_config_db_hdel(host, key, field):
    return _run_required_csonic_command(
        host, "sonic-db-cli CONFIG_DB HDEL {} {}".format(
            shlex.quote(key), shlex.quote(field)))


def _csonic_macsec_profile_fields(
        priority, cipher_suite, primary_cak, primary_ckn, policy, send_sci,
        rekey_period):
    return {
        "priority": str(priority),
        "cipher_suite": cipher_suite,
        "primary_cak": primary_cak,
        "primary_ckn": primary_ckn,
        "policy": policy,
        "send_sci": send_sci,
        "rekey_period": str(rekey_period),
    }


def _supervisor_macsec_state(result):
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
    """Snapshot only cSONiC state temporarily owned by the MACsec fixture."""
    status = host.shell(
        "supervisorctl status macsecmgrd", module_ignore_errors=True)
    config = host.shell(
        "test -e {}".format(CSONIC_MACSEC_SUPERVISOR_CONFIG),
        module_ignore_errors=True)
    post_state = host.shell(
        'sonic-db-cli STATE_DB HGET "FIPS_MACSEC_POST_TABLE|sai" post_state',
        module_ignore_errors=True)
    feature_state = host.shell(
        'sonic-db-cli CONFIG_DB HGET "FEATURE|macsec" state',
        module_ignore_errors=True)
    state = _supervisor_macsec_state(status)
    if state == "ERROR":
        raise AssertionError(
            "Failed to snapshot cSONiC Supervisor state on {}: {}".format(
                host.hostname, _command_diagnostic(status)))
    if not isinstance(config, Mapping) or config.get("rc") not in (0, 1):
        raise AssertionError(
            "Failed to snapshot cSONiC Supervisor config on {}: {}".format(
                host.hostname, _command_diagnostic(config)))
    for label, result in (("POST", post_state), ("feature", feature_state)):
        if not _command_succeeded(result):
            raise AssertionError(
                "Failed to snapshot cSONiC {} state on {}: {}".format(
                    label, host.hostname, _command_diagnostic(result)))
    return {
        "state": state,
        "config_exists": config.get("rc") == 0,
        "post_state": str(post_state.get("stdout", "")).strip() or None,
        "feature_state": str(feature_state.get("stdout", "")).strip() or None,
    }


def _restore_csonic_hash_field(host, database, key, field, value):
    if value is None:
        command = "sonic-db-cli {} HDEL {} {}".format(
            database, shlex.quote(key), shlex.quote(field))
    else:
        command = "sonic-db-cli {} HSET {} {} {}".format(
            database, shlex.quote(key), shlex.quote(field), shlex.quote(value))
    return _command_succeeded(host.shell(
        command, module_ignore_errors=True))


def _start_csonic_macsec_service(host, initial):
    """Start the image-provided cSONiC service without altering other hosts."""
    if not initial["config_exists"] or initial["state"] == "MISSING":
        logger.error("cSONiC image lacks the macsecmgrd Supervisor entry on %s",
                     host.hostname)
        return False
    provision = """set -e
test -x /sbin/wpa_supplicant
test -x /sbin/wpa_cli
/sbin/wpa_supplicant -h 2>&1 | grep -q \\
    'macsec_sonic = MACsec Ethernet driver for SONiC'
printf 'eapol_version=3\\nap_scan=0\\nfast_reauth=1\\n' | \\
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
    result = host.shell(provision, module_ignore_errors=True, timeout=300)
    if not _command_succeeded(result):
        logger.error("Failed cSONiC MACsec dependency check on %s: %s",
                     host.hostname, _command_diagnostic(result))
        return False
    if initial["post_state"] not in ("pass", "disabled"):
        result = host.shell(
            'sonic-db-cli STATE_DB HSET "FIPS_MACSEC_POST_TABLE|sai" '
            'post_state disabled', module_ignore_errors=True)
        if not _command_succeeded(result):
            return False
    if initial["state"] in ("RUNNING", "STARTING", "BACKOFF"):
        success = True
    else:
        success = _command_succeeded(host.shell(
            "supervisorctl start macsecmgrd", module_ignore_errors=True))
    if success and not hasattr(host, "_sonic_mgmt_macsec_initial"):
        host._sonic_mgmt_macsec_initial = initial
    return success


def _rollback_csonic_macsec_service(host, initial):
    """Restore only cSONiC state changed by this MACsec fixture."""
    failures = []
    current = _csonic_macsec_service_state(host)
    if (initial["state"] not in ("RUNNING", "STARTING", "BACKOFF") and
            current["state"] in ("RUNNING", "STARTING", "BACKOFF")):
        result = host.shell(
            "supervisorctl stop macsecmgrd", module_ignore_errors=True)
        if not _command_succeeded(result):
            failures.append({"service": _command_diagnostic(result)})
    if current["post_state"] != initial["post_state"]:
        if not _restore_csonic_hash_field(
                host, "STATE_DB", "FIPS_MACSEC_POST_TABLE|sai",
                "post_state", initial["post_state"]):
            failures.append({"post_state": "restore failed"})
    if current["feature_state"] != initial["feature_state"]:
        if not _restore_csonic_hash_field(
                host, "CONFIG_DB", "FEATURE|macsec", "state",
                initial["feature_state"]):
            failures.append({"feature_state": "restore failed"})
    if failures:
        logger.error("Failed to restore cSONiC MACsec state on %s: %s",
                     host.hostname, failures)
    return not failures


def _stop_csonic_macsec_service(host):
    initial = getattr(host, "_sonic_mgmt_macsec_initial", None)
    if initial is None:
        logger.error("Missing cSONiC MACsec ownership token on %s", host.hostname)
        return False
    success = _rollback_csonic_macsec_service(host, initial)
    if success:
        delattr(host, "_sonic_mgmt_macsec_initial")
    return success


def _unique_csonic_hosts(nbrhosts):
    hosts = []
    seen = set()
    for neighbor in nbrhosts.values():
        host = neighbor["host"]
        if not isinstance(host, CsonicHost):
            continue
        key = (host.container_name, host.vm_host_ip, host.vm_host_user)
        if key not in seen:
            seen.add(key)
            hosts.append(host)
    return hosts


def _csonic_service_ready(host):
    result = host.shell(
        "supervisorctl status macsecmgrd", module_ignore_errors=True)
    return _supervisor_macsec_state(result) == "RUNNING"


def _csonic_interface_diagnostics(host, interface_name):
    checks = {}
    for label, command in (
        ("profile", 'sonic-db-cli CONFIG_DB HGET "PORT|{}" macsec'.format(interface_name)),
        ("state", 'sonic-db-cli STATE_DB HGET "MACSEC_PORT_TABLE|{}" state'.format(interface_name)),
        ("service", "supervisorctl status macsecmgrd"),
        ("mka", "ip -j macsec show"),
    ):
        try:
            checks[label] = _command_diagnostic(
                host.shell(command, module_ignore_errors=True))
        except Exception as error:
            checks[label] = {"exception": repr(error)}
    return checks


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

    if isinstance(host, CsonicHost):
        _csonic_config_db_hset(
            host,
            "MACSEC_PROFILE|{}".format(profile_name),
            _csonic_macsec_profile_fields(
                priority, cipher_suite, primary_cak, primary_ckn, policy,
                send_sci, rekey_period))
        if send_sci == "false":
            _run_required_csonic_command(
                host,
                "lldpcli configure system bond-slave-src-mac-type real")
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

    if host.is_multi_asic:
        for ns in host.get_asic_namespace_list():
            cmd = "config macsec -n {} profile add {} {}".format(ns, profile_name, opts)
            host.command(cmd)
    else:
        cmd = "config macsec profile add {} {}".format(profile_name, opts)
        host.command(cmd)

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

    if isinstance(host, CsonicHost):
        output = host.command(
            "sonic-db-cli CONFIG_DB KEYS 'MACSEC_PROFILE|{}'".format(
                profile_name))['stdout'].strip()
        profile = output.split('|')[1] if output else None
        is_profile_present = (profile == profile_name)
        for port in ctrl_links:
            port = _runtime_port_name(host, port)
            output = host.command(
                "sonic-db-cli CONFIG_DB HGET 'PORT|{}' 'macsec' ".format(
                    port))['stdout'].strip()
            is_port_profile_present = (output == profile_name)
        return is_profile_present and is_port_profile_present

    # Check macsec profile is configured in all namespaces
    if host.is_multi_asic:
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
        _csonic_config_db_delete(
            host, "MACSEC_PROFILE|{}".format(profile_name))
        return

    if host.is_multi_asic:
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
        ovs_switch = getattr(host, "set_ovs_macsec_member", None)
        _csonic_config_db_hset(
            host, "PORT|{}".format(runtime_port), {"macsec": profile_name})
        if callable(ovs_switch):
            try:
                ovs_switch(port, True)
            except Exception:
                _csonic_config_db_hdel(
                    host, "PORT|{}".format(runtime_port), "macsec")
                raise
        return

    pc = find_portchannel_from_member(port, get_portchannel(host))

    dnx_platform = host.facts.get("platform_asic") == 'broadcom-dnx'

    if dnx_platform and pc:
        host.command("sudo config portchannel {} member del {} {}".format(getns_prefix(host, port), pc["name"], port))

    cmd = "config macsec {} port add {} {}".format(getns_prefix(host, port), port, profile_name)
    host.command(cmd)

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
        ovs_switch = getattr(host, "set_ovs_macsec_member", None)
        if callable(ovs_switch):
            ovs_switch(port, False)
        try:
            _csonic_config_db_hdel(
                host, "PORT|{}".format(runtime_port), "macsec")
        except Exception:
            if callable(ovs_switch):
                ovs_switch(port, True)
            raise
        return

    pc = find_portchannel_from_member(port, get_portchannel(host))
    dnx_platform = host.facts.get("platform_asic") == 'broadcom-dnx'

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
    nbrhosts = macsec_nbrhosts
    num_asics = duthost.num_asics()
    csonic_hosts = _unique_csonic_hosts(nbrhosts)

    if not csonic_hosts:
        # This is the pre-change SonicHost/EosHost implementation. Keep this
        # branch isolated from all cSONiC lifecycle and rollback behavior.
        global_cmd(duthost, nbrhosts, "sudo config feature state macsec enabled")

        def check_macsec_enabled():
            if len(duthost.shell("docker ps | grep macsec | grep -v grep")["stdout_lines"]) < num_asics:
                return False
            if len(duthost.shell("ps -ef | grep macsecmgrd | grep -v grep")["stdout_lines"]) < num_asics:
                return False
            for nbr in [n["host"] for n in list(nbrhosts.values())]:
                if isinstance(nbr, EosHost):
                    continue
                if len(nbr.shell("docker ps | grep macsec | grep -v grep")["stdout_lines"]) < 1:
                    return False
                if len(nbr.shell("ps -ef | grep macsecmgrd | grep -v grep")["stdout_lines"]) < 1:
                    return False
            return True
        assert wait_until(180, 5, 10, check_macsec_enabled)
        return

    initial_states = []
    try:
        # Keep the legacy DUT, SonicHost, and EosHost command path unchanged.
        # cSONiC needs only an additional local Supervisor start.
        initial_states = [
            (host, _csonic_macsec_service_state(host))
            for host in csonic_hosts
        ]
        global_cmd(duthost, nbrhosts, "sudo config feature state macsec enabled")
        for host, initial in initial_states:
            assert _start_csonic_macsec_service(host, initial), \
                "Failed to start macsecmgrd on {}".format(host.hostname)

        def check_macsec_enabled():
            if len(duthost.shell("docker ps | grep macsec | grep -v grep")["stdout_lines"]) < num_asics:
                return False
            if len(duthost.shell("ps -ef | grep macsecmgrd | grep -v grep")["stdout_lines"]) < num_asics:
                return False
            for nbr in [n["host"] for n in list(nbrhosts.values())]:
                if isinstance(nbr, EosHost):
                    continue
                if isinstance(nbr, CsonicHost):
                    if not _csonic_service_ready(nbr):
                        return False
                    continue
                if len(nbr.shell("docker ps | grep macsec | grep -v grep")["stdout_lines"]) < 1:
                    return False
                if len(nbr.shell("ps -ef | grep macsecmgrd | grep -v grep")["stdout_lines"]) < 1:
                    return False
            return True
        assert wait_until(180, 5, 10, check_macsec_enabled)
    except Exception:
        for host, initial in reversed(initial_states):
            try:
                _rollback_csonic_macsec_service(host, initial)
            except Exception:
                logger.exception(
                    "Failed to roll back cSONiC MACsec state on %s",
                    host.hostname)
        raise


def disable_macsec_feature(duthost, macsec_nbrhosts):
    # Preserve the legacy command path, then restore only cSONiC-local state.
    global_cmd(duthost, macsec_nbrhosts, "sudo config feature state macsec disabled")
    csonic_hosts = _unique_csonic_hosts(macsec_nbrhosts)
    if not csonic_hosts:
        return
    failures = [
        host.hostname for host in csonic_hosts
        if not _stop_csonic_macsec_service(host)
    ]
    assert not failures, "Failed to restore cSONiC MACsec state: {}".format(
        failures)


def _wait_for_macsec_cleanup_with_vs_recovery(host, interfaces, is_dut):
    if wait_for_macsec_cleanup(host, interfaces):
        return False

    if isinstance(host, CsonicHost):
        diagnostics = {
            interface: _csonic_interface_diagnostics(host, interface)
            for interface in interfaces
        }
        raise AssertionError(
            "MACsec cleanup timed out on cSONiC host {}: {}".format(
                host.hostname, diagnostics))

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
    submit_async_task(set_macsec_profile, (duthost, profile_name, default_priority,
                      cipher_suite, primary_cak, primary_ckn, policy,
                      send_sci, rekey_period))
    i = 0
    for dut_port, nbr in ctrl_links.items():
        if i % 2 == 0:
            priority = default_priority - 1
        else:
            priority = default_priority + 1
        submit_async_task(set_macsec_profile,
                          (nbr["host"], profile_name, priority,
                           cipher_suite, primary_cak, primary_ckn, policy, send_sci, rekey_period))
        i += 1
    wait_all_complete(timeout=180)

    logger.info("Setup macsec configuration step2: enable macsec profile")
    # 2. Enable macsec profile
    for dut_port, nbr in list(ctrl_links.items()):
        time.sleep(3)
        submit_async_task(enable_macsec_port, (duthost, dut_port, profile_name))
        submit_async_task(enable_macsec_port, (nbr["host"], nbr["port"], profile_name))
    wait_all_complete(timeout=180)

    # 3. Wait for interface's macsec ready
    for dut_port, nbr in list(ctrl_links.items()):
        assert wait_until(300, 3, 0,
                          lambda: duthost.iface_macsec_ok(dut_port) and
                          nbr["host"].iface_macsec_ok(nbr["port"]))

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
