"""Management VRF connectivity, configuration, isolation and RADIUS tests.

Run on an isolated testbed with working local inventory credentials. Fixtures
snapshot live and saved configuration before mutation and verify restoration.
RADIUS login tests require FreeRADIUS 3.x and Paramiko on the PTF host.
"""
import pytest
import time
import re
import shlex
import logging
import json
import ipaddress
import secrets
from pathlib import Path

from pytest_ansible.errors import AnsibleConnectionFailure

from tests.common import reboot
from tests.common.utilities import wait_until
from tests.common.config_reload import config_force_option_supported
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import creds_on_dut
from tests.common.helpers.ntp_helper import NtpDaemon, get_ntp_daemon_in_use, setup_ntp_context
from tests.common.devices.ptf import PTFHost
from tests.common.fixtures.duthost_utils import duthosts_ipv4_mgmt_only  # noqa: F401
from tests.mvrf import radius_test_helper
from tests.mvrf.temp_http_server import MAGIC_STRING

pytestmark = [
    # These checks do not require one specific data-plane topology.
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)

SONIC_SSH_REGEX = "OpenSSH"
SONIC_SSH_PORT = 22
MGMT_VRF_READY_TIMEOUT = 120
SNMP_READY_TIMEOUT = 180
SNMP_CHECK_INTERVAL = 10
SNMP_QUERY_TIMEOUT = 5
RESTORE_TIMEOUT = 420

# Read the switch's real SNMP restart limit and recent start requests.
# This only reads Linux settings/logs; it never resets or changes the limit.
SNMP_RESTART_POLICY_SCRIPT = r'''import json
import re
import subprocess
import time

def snmp_duration_seconds(value):
    units = {'us': 0.000001, 'ms': 0.001, 's': 1, 'min': 60,
             'h': 3600, 'd': 86400, 'w': 604800}
    if value == '0':
        return 0.0
    parts = re.findall(r'(\d+(?:\.\d+)?)\s*(us|ms|min|s|h|d|w)', value)
    remainder = re.sub(r'\d+(?:\.\d+)?\s*(us|ms|min|s|h|d|w)', '', value)
    if not parts or remainder.strip():
        raise RuntimeError('Cannot safely interpret SNMP restart interval: ' + value)
    return sum(float(number) * units[unit] for number, unit in parts)

def snmp_restart_policy():
    command = ['systemctl', 'show', 'snmp.service', '-p', 'LoadState',
               '-p', 'Result', '-p', 'StartLimitIntervalUSec', '-p', 'StartLimitBurst',
               '-p', 'ExecMainStartTimestampMonotonic']
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError('Cannot read the SNMP restart policy')
    fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if fields.get('LoadState') != 'loaded':
        raise RuntimeError('Required snmp.service is not loaded')
    interval = snmp_duration_seconds(fields['StartLimitIntervalUSec'])
    burst = int(fields['StartLimitBurst'])
    policy = {'interval': interval, 'burst': burst, 'delay': 0.0,
              'recent_starts': 0, 'result': fields.get('Result', '')}
    if interval == 0 or burst == 0:
        return policy
    # Journal monotonic timestamps use the same boot clock as time.monotonic.
    # Count start requests, not snmpd's startup or both Starting/Started lines.
    journal = subprocess.run(['journalctl', '-b', '-u', 'snmp.service',
                              '-o', 'json', '--no-pager'],
                             capture_output=True, text=True, timeout=30)
    if journal.returncode:
        raise RuntimeError('Cannot inspect SNMP restart history; refusing to guess')
    now = time.monotonic()
    starts = []
    history = []
    for line in journal.stdout.splitlines():
        row = json.loads(line)
        stamp = int(row['__MONOTONIC_TIMESTAMP']) / 1000000.0
        history.append(stamp)
        message = row.get('MESSAGE', '')
        start_job = (row.get('MESSAGE_ID') == '7d4958e842da4a758f6c1cdc7b36dcc5'
                     and row.get('UNIT') == 'snmp.service')
        if start_job or (isinstance(message, str) and message.startswith('Starting snmp.service')):
            if now - interval <= stamp <= now:
                starts.append(stamp)
    starts = sorted(set(starts))
    last_start = int(fields.get('ExecMainStartTimestampMonotonic', '0')) / 1000000.0
    history_incomplete = not history or (now > interval and min(history) > now - interval)
    if history_incomplete and (starts or (last_start > 0 and now - interval <= last_start <= now)):
        # With missing journal entries, assume the allowance is used rather
        # than inventing free starts. An old start outside the window is safe.
        latest = max(starts + [last_start])
        policy['delay'] = max(0.0, latest + interval + 1 - now)
    elif not starts and now - interval <= last_start <= now and last_start > 0:
        policy['delay'] = max(0.0, last_start + interval + 1 - now)
    elif len(starts) >= burst:
        policy['delay'] = max(0.0, starts[-burst] + interval + 1 - now)
    policy['recent_starts'] = len(starts)
    return policy
'''


def _snmp_restart_policy(duthost):
    # Get a small, non-secret restart-budget summary from the switch.
    script = SNMP_RESTART_POLICY_SCRIPT + '\nprint(json.dumps(snmp_restart_policy()))\n'
    result = duthost.shell('sudo python3 -c ' + shlex.quote(script),
                           module_ignore_errors=True, verbose=False)
    pytest_assert(result.get('rc') == 0,
                  'Unable to read SNMP restart policy/history; no DUT setting was changed')
    return json.loads(result['stdout'])


def _wait_for_snmp_restart_slot(duthost, allow_failed=False):
    # Wait only when the switch has used its SNMP start allowance.
    # Never clear a real service failure or disable the switch's protection.
    policy = _snmp_restart_policy(duthost)
    deadline = time.monotonic() + policy['interval'] + 60
    while True:
        pytest_assert(allow_failed or policy['result'] in ('', 'success'),
                      'SNMP service is already failed (Result={}); not a clean prerequisite'.format(
                          policy['result']))
        if policy['delay'] <= 0:
            return
        pytest_assert(time.monotonic() < deadline,
                      'SNMP restart allowance did not become available; competing restarts may be occurring')
        logger.info('Respecting SNMP start limit: %s starts in %ss; next check in at most 30s '
                    '(remaining policy wait %.0fs)', policy['burst'], policy['interval'], policy['delay'])
        time.sleep(min(30, policy['delay']))
        policy = _snmp_restart_policy(duthost)


def _snmp_config_command(duthost, command):
    # Use the ordinary CLI, but check restart errors as well as its exit code.
    # Some images return rc=0 even when systemctl could not restart SNMP.
    _wait_for_snmp_restart_slot(duthost)
    result = duthost.shell(command, module_ignore_errors=True, verbose=False)
    error = result.get('stderr', '')
    pytest_assert(result.get('rc') == 0 and not re.search(
        r'Job for snmp(?:\.service)? failed|start.*(?:too often|too quickly)|'
        r'Failed to (?:start|restart).*snmp|Error:', error, re.I),
        'SNMP configuration/restart failed; a saved row or rc=0 is not proof of success')
    policy = _snmp_restart_policy(duthost)
    pytest_assert(policy['result'] in ('', 'success'),
                  'SNMP restart failed (Result={}); do not continue waiting for a reply'.format(
                      policy['result']))
    return result


# The reload runs on the DUT instead of inside an SSH-dependent Ansible task.
# A reconnect alone cannot establish success: the controller must read rc=0,
# verify the original live settings, and wait for services and interfaces.
# Preserve the original on-disk file separately from the live Redis snapshot;
# reboot tests call `config save`, but must not make their settings permanent.
RESTORE_SCRIPT = """#!/bin/bash
set -eu
backup=$1
finish() {
    rc=$?
    trap - EXIT
    if ! cp -p "$backup/saved.json" /etc/sonic/config_db.json; then
        rc=1
    fi
    printf '%s\\n' "$rc" > "$backup/restore.rc.tmp"
    mv "$backup/restore.rc.tmp" "$backup/restore.rc"
    exit "$rc"
}
trap finish EXIT
sleep 2
cp -p "$backup/running.json" /etc/sonic/config_db.json
if [ "$2" = force ]; then
    config reload -y -f
else
    config reload -y
fi
"""

# Only table names (never credentials or table contents) leave this verifier.
RESTORE_VERIFY_SCRIPT = """import hashlib
import json
import subprocess
import sys
from pathlib import Path
backup = Path(sys.argv[1])
expected = json.loads((backup / 'running.json').read_text())
current = json.loads(subprocess.check_output(
    ['sonic-cfggen', '-d', '--print-data'], text=True))
tables = ('MGMT_VRF_CONFIG', 'MGMT_INTERFACE', 'MGMT_PORT',
          'SNMP_COMMUNITY', 'SNMP_AGENT_ADDRESS_CONFIG',
          'TACPLUS_SERVER', 'TACPLUS', 'AAA', 'RADIUS_SERVER', 'NTP', 'NTP_SERVER',
          'ACL_TABLE', 'ACL_RULE', 'INTERFACE', 'PORTCHANNEL_INTERFACE', 'VLAN_INTERFACE')
different = [name for name in tables
             if expected.get(name, {}) != current.get(name, {})]
saved_ok = (hashlib.sha256((backup / 'saved.json').read_bytes()).digest() ==
            hashlib.sha256(Path('/etc/sonic/config_db.json').read_bytes()).digest())
print(json.dumps({'different_tables': different, 'saved_file_restored': saved_ok}))
"""

# Shared by the ordinary NTP finalizer and the per-case/emergency gap cleanup.
# Restoring Redis rows alone does not remove a test peer from the running daemon.
NTP_APPLY_SCRIPT = """
import os
from pathlib import Path
import stat
import subprocess
import tempfile

def apply_ntp_config():
    # Prefer the image's generator; older images need an explicit render.
    for service in ('ntp-config', 'chrony', 'ntpsec', 'ntp'):
        found = subprocess.run(['systemctl', 'show', service, '-p', 'LoadState', '--value'],
                               capture_output=True, text=True, timeout=15)
        if found.stdout.strip() == 'not-found':
            continue
        found.check_returncode()
        if found.stdout.strip() != 'loaded':
            continue
        if service != 'ntp-config':
            if service == 'chrony':
                target, template = '/etc/chrony/chrony.conf', 'chrony.conf.j2'
            else:
                target = '/etc/ntpsec/ntp.conf' if Path('/etc/ntpsec/ntp.conf').is_file() else '/etc/ntp.conf'
                template = 'ntp.conf.j2'
            rendered = subprocess.run(['sonic-cfggen', '-d', '-t', '/usr/share/sonic/templates/' + template],
                                      capture_output=True, text=True, check=True, timeout=30).stdout
            if not rendered.strip():
                raise RuntimeError('NTP configuration generator returned an empty file')
            target = str(Path(target).resolve(strict=True))
            original_stat = Path(target).stat()
            # Do not truncate the live file if generation or writing fails.
            with tempfile.NamedTemporaryFile(mode='w', dir=str(Path(target).parent), delete=False) as output:
                temporary = output.name
                try:
                    output.write(rendered)
                    output.flush()
                    os.fchmod(output.fileno(), stat.S_IMODE(original_stat.st_mode))
                    os.fchown(output.fileno(), original_stat.st_uid, original_stat.st_gid)
                    os.replace(temporary, target)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
        subprocess.run(['systemctl', 'restart', service], capture_output=True, text=True, check=True, timeout=120)
        return
    raise RuntimeError('No supported NTP configuration/service unit for restore')
"""

# Restore complete rows, including their per-peer options, before applying.
NTP_RESTORE_SCRIPT = NTP_APPLY_SCRIPT + """
import json
import sys
from swsscommon.swsscommon import ConfigDBConnector
db = ConfigDBConnector()
db.connect()
with open(sys.argv[1]) as stream:
    original = json.load(stream)
for table in ('NTP_SERVER', 'NTP'):
    for key in db.get_table(table):
        db.set_entry(table, key, None)
    for key, fields in original.get(table, {}).items():
        db.set_entry(table, key, fields)
apply_ntp_config()
"""

# This job must keep running after it blocks NEW controller SSH connections.
# Keep the community acl-loader workflow, scoped to ONE SSH service table.
# A testbed need not already have that table. Snapshot it before any changes,
# create it if necessary, and restore it locally even while SSH is blocked.
SERVICE_ACL_SCRIPT = """import ipaddress
import json
import signal
import subprocess
import sys
import time
from pathlib import Path
from sonic_py_common import multi_asic
from swsscommon.swsscommon import ConfigDBConnector
source = ipaddress.ip_address(sys.argv[1])
prefix = Path(sys.argv[2])
hold_seconds = int(sys.argv[3])
db = ConfigDBConnector()
db.connect()
table = None
original_table = None
snapshots = []
changed = False
def interrupted(signum, frame):
    raise SystemExit(1)
signal.signal(signal.SIGTERM, interrupted)
rc = 1
try:
    time.sleep(2)  # Let the launch acknowledgement return before blocking SSH.
    tables = db.get_table('ACL_TABLE')
    ssh_tables = []
    for name, fields in tables.items():
        services = fields.get('services', [])
        if isinstance(services, str):
            services = services.split(',')
        if fields.get('type') == 'CTRLPLANE' and 'SSH' in services:
            ssh_tables.append(name)
    if not ssh_tables:
        table = 'MVRF_SSH_' + prefix.parent.name.rsplit('.', 1)[-1].upper()
        if table in tables:
            raise RuntimeError('Temporary SSH ACL table name already exists')
    else:
        table = sorted(ssh_tables)[0]
        original_table = tables[table]
    # Unlike the original unscoped full update/delete, never erase rules in
    # other tables. Fail before mutation if this loader lacks scoped updates.
    help_text = subprocess.check_output(
        ['acl-loader', 'update', 'full', '--help'], text=True)
    if '--table_name' not in help_text:
        raise RuntimeError('acl-loader lacks safe table-scoped full update')
    connectors = [db]
    for namespace in multi_asic.get_all_namespaces()['front_ns']:
        connector = ConfigDBConnector(namespace=namespace)
        connector.connect()
        connectors.append(connector)
    for connector in connectors:
        rules = {key: fields for key, fields in connector.get_table('ACL_RULE').items()
                 if key[0] == table}
        snapshots.append((connector, rules))
    entry = {
        'config': {'sequence-id': 1},
        'actions': {'config': {'forwarding-action': 'DROP'}},
        'ip': {'config': {'protocol': 'IP_TCP',
                          'source-ip-address': str(source) + '/' + str(source.max_prefixlen)}},
        'transport': {'config': {'destination-port': 22}}}
    config = {'acl': {'acl-sets': {'acl-set': {
        table: {'config': {'name': table},
                'acl-entries': {'acl-entry': {'1': entry}}}}}}}
    config_path = Path(str(prefix) + '.json')
    config_path.write_text(json.dumps(config))
    changed = True  # Also restore after a partially successful command.
    if original_table is None:
        db.set_entry('ACL_TABLE', table, {'type': 'CTRLPLANE', 'services': ['SSH'],
                                        'stage': 'ingress', 'policy_desc': table})
    subprocess.run(['acl-loader', 'update', 'full', str(config_path),
                    '--table_name', table], check=True)
    expected = str(source) + '/' + str(source.max_prefixlen)
    programmed = db.get_table('ACL_RULE')
    if not any(key[0] == table and fields.get('PACKET_ACTION') == 'DROP' and
               fields.get('SRC_IP' if source.version == 4 else 'SRC_IPV6') == expected
               for key, fields in programmed.items()):
        raise RuntimeError('acl-loader returned success without the requested SSH DROP rule')
    time.sleep(hold_seconds)  # Bounded observation window, not a readiness guess.
    rc = 0
finally:
    try:
        if changed:
            for connector, original_rules in snapshots:
                for key in connector.get_table('ACL_RULE'):
                    if key[0] == table:
                        connector.set_entry('ACL_RULE', key, None)
                for key, fields in original_rules.items():
                    connector.set_entry('ACL_RULE', key, fields)
                current = {key: fields for key, fields in connector.get_table('ACL_RULE').items()
                           if key[0] == table}
                if current != original_rules:
                    raise RuntimeError('Original SSH ACL rules were not restored')
            db.set_entry('ACL_TABLE', table, original_table)
            if db.get_table('ACL_TABLE').get(table) != original_table:
                raise RuntimeError('Original SSH ACL table was not restored')
    except BaseException:
        rc = 1
        raise
    finally:
        temporary = Path(str(prefix) + '.rc.tmp')
        temporary.write_text(str(rc))
        temporary.replace(Path(str(prefix) + '.rc'))
"""


@pytest.fixture(autouse=True)
def _ignore_mux_errlogs(rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    # `autouse` means pytest applies this fixture to every test automatically.
    # This known mux log is unrelated to management VRF, so it should not
    # make a successful management test look like a failure.
    if loganalyzer:
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(
            [
                ".*ERR pmon#CCmisApi.*y_cable_port.*GET http.*"
            ])
    return


def restore_config_db(duthost, localhost, backup):
    """Restore once, survive eth0's SSH interruption, and verify recovery."""
    directory = backup['directory']
    wait_for_ssh_and_reset_connection(duthost, localhost)
    # Cleanup must run even after a failed test, but must not force/reset a
    # restart counter. The same policy also applies to config reload's start.
    _wait_for_snmp_restart_slot(duthost, allow_failed=True)
    reload_mode = 'force' if config_force_option_supported(duthost) else 'normal'
    launch = "nohup bash {}/restore.sh {} {} > {}/restore.log 2>&1 < /dev/null &".format(
        shlex.quote(directory), shlex.quote(directory), reload_mode, shlex.quote(directory))
    try:
        duthost.shell("sudo sh -c {}".format(shlex.quote(launch)), verbose=False)
    except AnsibleConnectionFailure:
        # Do not issue a second reload when the launch acknowledgement is lost.
        # The status file below proves whether the first launch completed.
        logger.info("SSH interrupted during restore launch; checking its completion marker")

    def completed():
        try:
            result = duthost.command(
                "sudo cat {}/restore.rc".format(shlex.quote(directory)),
                module_ignore_errors=True, verbose=False)
            return result.get('rc') == 0
        except AnsibleConnectionFailure:
            _reset_ssh_connection(duthost)
            return False

    pytest_assert(wait_until(RESTORE_TIMEOUT, 5, 5, completed),
                  "Configuration restore did not finish; root-only evidence retained at {}".format(directory))
    result = duthost.command("sudo cat {}/restore.rc".format(shlex.quote(directory)), verbose=False)
    pytest_assert(result['stdout'].strip() == '0',
                  "Configuration restore failed (rc={}); see {}/restore.log".format(
                      result['stdout'].strip(), directory))
    wait_for_ssh_and_reset_connection(duthost, localhost, delay=0)

    pytest_assert(wait_until(RESTORE_TIMEOUT, 10, 0, duthost.critical_services_fully_started),
                  "Critical services did not recover after restoring original configuration")
    # The shared helper retains its own bounded polling.
    wait_critical_processes(duthost)

    def original_links_recovered():
        # A physically unplugged admin-up hardware port is not a regression.
        # Require only the data-plane links that were UP before this module.
        ports = backup['up_ports']
        if not ports:
            return True
        facts = duthost.interface_facts(up_ports=ports, verbose=False)['ansible_facts']
        return not facts['ansible_interface_link_down_ports']

    pytest_assert(wait_until(RESTORE_TIMEOUT, 10, 0, original_links_recovered),
                  "Previously UP interfaces did not recover after restore")
    pytest_assert(wait_until(MGMT_VRF_READY_TIMEOUT, 5, 0,
                             _mgmt_vrf_state_matches, duthost, backup['enabled']),
                  "Original Management VRF state did not return after restore")

    def original_settings_restored():
        output = duthost.command(
            "sudo python3 {}/verify.py {}".format(shlex.quote(directory), shlex.quote(directory)),
            verbose=False)['stdout']
        result = json.loads(output)
        backup['restore_check'] = result
        return not result['different_tables'] and result['saved_file_restored']

    restored = wait_until(60, 5, 0, original_settings_restored)
    pytest_assert(restored, "Original configuration was not restored: {}; evidence at {}".format(
        backup.get('restore_check', {}), directory))
    # The global core collector can attach a warning without failing pytest.
    # A clean suite requires no new/changed core, including during cleanup.
    verify_no_new_core_dumps(duthost, backup['core_files'])
    # Delete snapshots containing secrets only after every restore check passed.
    duthost.file(path=directory, state="absent")


def core_dump_snapshot(duthost):
    """Record existing cores without deleting them or reading crash contents."""
    result = duthost.find(paths="/var/core", file_type="file",
                          patterns=["*.core", "*.core.gz"], verbose=False)
    pytest_assert(not result.get('failed', False) and isinstance(result.get('files'), list),
                  "Unable to inspect DUT core dumps")
    return {entry['path']: (entry.get('size'), entry.get('mtime')) for entry in result['files']}


def verify_no_new_core_dumps(duthost, original):
    """A passing traffic check must not hide an unrelated process crash."""
    current = core_dump_snapshot(duthost)
    new_or_changed = sorted(path for path, state in current.items()
                            if original.get(path) != state)
    pytest_assert(not new_or_changed,
                  "New or changed DUT core dumps (not a clean pass): {}".format(new_or_changed))


def _snmp_community_exists(duthost, community):
    """Return whether the inventory community is present in running CONFIG_DB."""
    facts = duthost.config_facts(
        host=duthost.hostname, source="running", verbose=False)['ansible_facts']
    return community in facts.get("SNMP_COMMUNITY", {})


def ensure_snmp_community(duthost, community):
    """Install the test inventory's RO community when provisioning omitted it.

    The module-level config_db backup is taken before this helper runs, so the
    original state (including an absent community) is restored in teardown.
    Do not include the community value in log or assertion messages.
    """
    pytest_assert(isinstance(community, str) and bool(community),
                  "Inventory must provide a nonempty snmp_rocommunity")
    if _snmp_community_exists(duthost, community):
        logger.info("Required read-only SNMP community is already configured")
        return

    logger.info("Required read-only SNMP community is absent; configuring it for this module")
    result = _snmp_config_command(duthost,
                                  "sudo config snmp community add {} ro".format(shlex.quote(community)))
    pytest_assert(result.get("rc") == 0,
                  "Failed to configure the inventory SNMP community prerequisite")
    pytest_assert(wait_until(60, 5, 0, _snmp_community_exists, duthost, community),
                  "SNMP community command succeeded but CONFIG_DB was not updated")


def clear_snmp_listeners(duthost):
    # Give this isolated suite one listener owned by the test.
    # The module backup restores every original listener after testing.
    script = ("from swsscommon.swsscommon import ConfigDBConnector; "
              "db=ConfigDBConnector(); db.connect(); "
              "[db.set_entry('SNMP_AGENT_ADDRESS_CONFIG', key, None) "
              "for key in db.get_table('SNMP_AGENT_ADDRESS_CONFIG')]")
    duthost.command('sudo python3 -c ' + shlex.quote(script), verbose=False)


def ensure_snmp_listener(duthost, mvrf=True):
    """Bind the inventory management IP to mgmt using the supported CLI.

    Leave an existing correct listener alone. Move a conflicting listener for
    this IP/port; the module backup restores its original row.
    Check CONFIG_DB because older CLIs can report an error but return rc=0.
    Never change sysctls, bypass validation, or edit snmpd.conf to force a pass.
    """
    address = str(ipaddress.ip_address(duthost.mgmt_ip))
    wanted, other = ('mgmt', '') if mvrf else ('', 'mgmt')

    def exists(vrf):
        key = 'SNMP_AGENT_ADDRESS_CONFIG|{}|161|{}'.format(address, vrf)
        result = duthost.command(
            'sonic-db-cli CONFIG_DB EXISTS {}'.format(shlex.quote(key)), verbose=False)
        return result['stdout'].strip() == '1'

    if exists(wanted):
        return
    if exists(other):
        suffix = ' -v ' + other if other else ''
        _snmp_config_command(duthost, 'sudo config snmpagentaddress del {} -p 161{}'.format(
            shlex.quote(address), suffix))
        pytest_assert(wait_until(60, 5, 0, lambda: not exists(other)),
                      'Conflicting SNMP listener was not removed from CONFIG_DB')
    suffix = ' -v ' + wanted if wanted else ''
    _snmp_config_command(duthost, 'sudo config snmpagentaddress add {} -p 161{}'.format(
        shlex.quote(address), suffix))
    pytest_assert(wait_until(60, 5, 0, exists, wanted),
                  'SNMP CLI did not save the management listener; check image CLI support and validation')


def _snmp_responds(duthost, localhost, community):
    # Use the same Ansible SNMP-facts module as the original test, while keeping
    # the inventory community out of DEBUG command/result logs.
    result = localhost.snmp_facts(
        host=duthost.mgmt_ip,
        version="v2c",
        community=community,
        module_ignore_errors=True,
        timeout=SNMP_QUERY_TIMEOUT,
        verbose=False)
    return (not result.get("failed", False) and
            bool(result.get("ansible_facts", {}).get("ansible_sysdescr")))


def _snmp_diagnostics(duthost):
    """Collect non-secret diagnostics for a failed SNMP readiness check."""
    commands = {
        "community_count": "sudo sonic-db-cli CONFIG_DB KEYS 'SNMP_COMMUNITY*' | wc -l",
        "agent_addresses": "docker exec snmp grep '^agentAddress' /etc/snmp/snmpd.conf",
        "snmpd_status": "docker exec snmp supervisorctl status snmpd",
        "udp_161_sockets": "docker exec snmp ss -H -lunp | grep ':161'",
        "systemd_state": "systemctl show snmp.service -p ActiveState -p SubState -p Result",
    }
    diagnostics = {}
    for name, command in commands.items():
        try:
            result = duthost.shell(command, module_ignore_errors=True, verbose=False)
        except AnsibleConnectionFailure:
            diagnostics[name] = {"error": "DUT SSH unreachable while collecting SNMP diagnostics"}
            break
        diagnostics[name] = {
            "rc": result.get("rc"),
            "stdout": result.get("stdout", "").strip(),
            "stderr": result.get("stderr", "").strip(),
        }
    return diagnostics


def verify_snmp_response(duthost, localhost, community):
    """Wait for a real SNMP response and report the failed layer on timeout."""
    result = duthost.shell('systemctl show snmp.service -p Result --value',
                           module_ignore_errors=True, verbose=False)
    pytest_assert(result.get('rc') == 0 and result.get('stdout', '').strip() == 'success',
                  'SNMP systemd service is failed or unreadable before the reply check '
                  '(Result={}); inspect its journal'.format(result.get('stdout', '').strip()))
    ready = wait_until(
        SNMP_READY_TIMEOUT,
        SNMP_CHECK_INTERVAL,
        0,
        _snmp_responds,
        duthost,
        localhost,
        community)
    if not ready:
        pytest.fail("SNMP did not answer after {} seconds. Non-secret diagnostics: {}".format(
            SNMP_READY_TIMEOUT, _snmp_diagnostics(duthost)))


def _mgmt_vrf_state_matches(duthost, enabled):
    try:
        verify_show_command(duthost, mvrf=enabled)
        return True
    except Exception as error:
        logger.debug("Management VRF not ready: %s", error)
        return False


def _reset_ssh_connection(duthost):
    # Bypass SonicHost._run: Ansible's meta action has no host result to index.
    # A successful meta invocation with no payload is expected, not an error.
    duthost.host.meta("reset_connection")


def wait_for_ssh_and_reset_connection(duthost, localhost, delay=0, timeout=180):
    """Wait for SSH and discard Ansible's possibly stale control socket.

    A reboot or an eth0 VRF transition can leave the TCP port reachable while
    pytest-ansible still holds a dead pre-transition SSH connection.  Resetting
    it forces the next DUT command to establish a new session.
    """
    localhost.wait_for(host=duthost.mgmt_ip,
                       port=SONIC_SSH_PORT,
                       state="started",
                       search_regex=SONIC_SSH_REGEX,
                       delay=delay,
                       timeout=timeout)
    _reset_ssh_connection(duthost)

    def authenticated():
        try:
            result = duthost.command("true", module_ignore_errors=True, verbose=False)
            return result.get('rc') == 0 and not result.get('failed', False)
        except AnsibleConnectionFailure:
            _reset_ssh_connection(duthost)
            return False

    pytest_assert(wait_until(timeout, 5, 0, authenticated),
                  "SSH banner returned but inventory-authenticated commands still failed")


def verify_fast_reboot_compatibility(duthost):
    """Reject a mixed image before fast reboot destroys the SSH session.

    Older fast-reboot scripts call ``counterpoll config-db delay``. Newer
    counterpoll versions removed that command. Combining the two revisions
    makes fast-reboot abort after it has started disruptive preparation.
    """
    script_check = duthost.shell(
        "grep -qF 'counterpoll config-db delay' /usr/local/bin/fast-reboot",
        module_ignore_errors=True)
    pytest_assert(script_check.get('rc') in (0, 1),
                  "Unable to inspect fast-reboot compatibility")
    if script_check.get("rc") == 1:
        return

    help_result = duthost.shell("counterpoll --help", module_ignore_errors=True)
    pytest_assert(help_result.get('rc') == 0, "Unable to inspect counterpoll commands")
    has_config_db = bool(re.search(
        r"^\s*config-db(?:\s|$)", help_result.get("stdout", ""), re.MULTILINE))
    pytest_assert(
        has_config_db,
        "Incompatible SONiC image components: /usr/local/bin/fast-reboot calls "
        "'counterpoll config-db delay', but this counterpoll build has no "
        "'config-db' command. Fix the image integration before running the "
        "disruptive fast-reboot test.")


@pytest.fixture(scope="module")
def mvrf_duthost(duthosts, rand_one_dut_hostname, duthosts_ipv4_mgmt_only):  # noqa: F811
    # Use the same selected DUT in setup AND every test on multi-DUT beds.
    # The global session duthost fixture otherwise selects DUT index zero.
    return duthosts[rand_one_dut_hostname]


@pytest.fixture(scope="module")
def mvrf_ntp_daemon(mvrf_duthost):
    return get_ntp_daemon_in_use(mvrf_duthost)


@pytest.fixture(scope="module")
def check_ntp_sync(mvrf_duthost, mvrf_ntp_daemon, backup_config_db):
    # Preserve the community test's decision: use PTF only if the DUT was
    # not synchronized before enabling mgmt. Probe its original context.
    return 0 if check_ntp_status(mvrf_duthost, mvrf_ntp_daemon,
                                 mvrf=backup_config_db['enabled']) else 1


@pytest.fixture(scope="module")
def backup_config_db(duthosts, rand_one_dut_hostname, localhost,
                     duthosts_ipv4_mgmt_only):  # noqa: F811
    """Snapshot both live and saved configuration; always restore after setup.

    This finalizer runs even if setup_mvrf fails before its own yield. Store
    backups in a unique root-only directory, without an existing .bak overwrite.
    """
    duthost = duthosts[rand_one_dut_hostname]
    directory = duthost.command("sudo mktemp -d /var/tmp/mvrf-restore.XXXXXXXX")['stdout'].strip()
    pytest_assert(re.fullmatch(r'/var/tmp/mvrf-restore\.[A-Za-z0-9]+', directory),
                  "Unexpected configuration backup directory")
    snapshot = ("set -eu; umask 077; sonic-cfggen -d --print-data > {0}/running.json; "
                "python3 -m json.tool {0}/running.json > /dev/null; "
                "cp -p /etc/sonic/config_db.json {0}/saved.json").format(shlex.quote(directory))
    duthost.shell("sudo sh -c {}".format(shlex.quote(snapshot)), verbose=False)
    duthost.copy(content=RESTORE_SCRIPT, dest=directory + '/restore.sh', mode=0o700, verbose=False)
    duthost.copy(content=RESTORE_VERIFY_SCRIPT, dest=directory + '/verify.py', mode=0o600, verbose=False)
    enabled_query = ("import json,sys; c=json.load(open(sys.argv[1])); "
                     "print(c.get('MGMT_VRF_CONFIG', {}).get('vrf_global', {})"
                     ".get('mgmtVrfEnabled') == 'true')")
    enabled = duthost.command("sudo python3 -c {} {}/running.json".format(
        shlex.quote(enabled_query), shlex.quote(directory)), verbose=False)['stdout'].strip() == 'True'
    interfaces = duthost.interface_facts(verbose=False)['ansible_facts']['ansible_interface_facts']
    up_ports = [name for name, facts in interfaces.items()
                if name.startswith(('Ethernet', 'PortChannel')) and facts.get('link')]
    backup = {'directory': directory, 'enabled': enabled, 'up_ports': up_ports,
              'core_files': core_dump_snapshot(duthost)}
    yield backup
    restore_config_db(duthost, localhost, backup)


def configure_tacacs_for_mgmt_vrf(duthost):
    """Re-add existing TACACS+ servers with mgmt VRF binding.
    """
    # TACACS+ is a remote login/authentication service. Once eth0 moves into
    # mgmt, its server must be contacted through the mgmt routing table.
    # This helper makes the suite work, but it also manually repairs existing
    # rows; therefore this suite does not test automatic AAA re-plumbing.

    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running", verbose=False)['ansible_facts']
    tacacs_servers = config_facts.get('TACPLUS_SERVER', {})
    if not tacacs_servers:
        logger.info("No TACACS+ servers configured, skipping mgmt VRF update")
        return

    for server_ip, server_cfg in tacacs_servers.items():
        if server_cfg.get('vrf') == 'mgmt':
            logger.info("TACACS+ server %s already has vrf=mgmt, skipping", server_ip)
            continue

        logger.info("Updating TACACS+ server %s to use mgmt VRF", server_ip)
        # Delete and re-add each old server with `-m` to bind it to mgmt.
        # Reuse its saved options so the test does not change its behavior.
        duthost.shell("sudo config tacacs delete %s" % shlex.quote(server_ip), verbose=False)

        add_cmd = "sudo config tacacs add %s -m" % shlex.quote(server_ip)
        if server_cfg.get('tcp_port'):
            add_cmd += " --port %s" % shlex.quote(str(server_cfg['tcp_port']))
        if server_cfg.get('timeout'):
            add_cmd += " --timeout %s" % shlex.quote(str(server_cfg['timeout']))
        if server_cfg.get('passkey'):
            add_cmd += " --key %s" % shlex.quote(str(server_cfg['passkey']))
        if server_cfg.get('auth_type'):
            add_cmd += " --auth_type %s" % shlex.quote(str(server_cfg['auth_type']))
        if server_cfg.get('priority'):
            add_cmd += " --pri %s" % shlex.quote(str(server_cfg['priority']))

        result = duthost.shell(add_cmd, module_ignore_errors=True, verbose=False)
        pytest_assert(result.get('rc') == 0,
                      "Failed to configure an existing TACACS+ server in Management VRF")

    logger.info("TACACS+ servers updated for mgmt VRF: %s", list(tacacs_servers.keys()))


@pytest.fixture(scope="module", autouse=True)
def setup_mvrf(duthosts, rand_one_dut_hostname, localhost,
               backup_config_db, creds, check_ntp_sync):
    """Prepare management tests; the backup fixture owns ALL DUT cleanup.

    Its finalizer runs even if this fixture fails before yielding. Do not
    delete individual listeners/VRFs over a disappearing SSH connection.
    """
    duthost = duthosts[rand_one_dut_hostname]
    # Old listeners may name addresses/VRFs no longer present on this testbed.
    # Backup already exists; cleanup restores all removed listener rows.
    clear_snmp_listeners(duthost)
    # Some provisioning paths populate inventory but omit the community
    # in CONFIG_DB. Use the inventory value, never a hardcoded credential.
    ensure_snmp_community(duthost, creds['snmp_rocommunity'])
    logger.info("Configure mgmt vrf")
    try:
        # Do not leave an uncollected async task racing with restoration.
        if not backup_config_db['enabled']:
            duthost.command("sudo config vrf add mgmt")
    except AnsibleConnectionFailure:
        logger.info("SSH interrupted while eth0 moved into mgmt; checking actual Linux state")
    wait_for_ssh_and_reset_connection(duthost, localhost)
    pytest_assert(wait_until(MGMT_VRF_READY_TIMEOUT, 5, 0,
                             _mgmt_vrf_state_matches, duthost, True),
                  "Management VRF did not converge in Linux after enable")
    ensure_snmp_listener(duthost)
    configure_tacacs_for_mgmt_vrf(duthost)
    # A saved row is not proof that snmpd started. Fail setup with diagnostics
    # rather than running every case on a baseline that already cannot reply.
    verify_snmp_response(duthost, localhost, creds['snmp_rocommunity'])
    # Tests execute here. backup_config_db restores the exact original state
    # afterward, whether setup/test bodies passed, failed, or raised errors.
    yield


@pytest.fixture()
def ntp_teardown(ptfhost, mvrf_duthost, backup_config_db, check_ntp_sync):
    """Keep original NTP setup; restore complete state even on test failure."""
    duthost = mvrf_duthost
    # An already-synchronized DUT uses its existing servers for a fresh sync.
    # Do not require or mutate a PTF daemon when that branch does not use it.
    ptf_backup = None
    if check_ntp_sync:
        daemon = get_ntp_daemon_in_use(ptfhost)
        settings = {NtpDaemon.NTP: ('ntp', '/etc/ntp.conf'),
                    NtpDaemon.NTPSEC: ('ntpsec', '/etc/ntpsec/ntp.conf'),
                    NtpDaemon.CHRONY: ('chrony', '/etc/chrony/chrony.conf')}
        service, path = settings[daemon]
        state = ptfhost.command('service {} status'.format(service), module_ignore_errors=True)
        pytest_assert(state.get('rc') in (0, 1, 3), 'Cannot determine original PTF NTP service state')
        shared_backup = path + '.sonicmgmt.bak'
        backup_existed = ptfhost.stat(path=shared_backup)['stat']['exists']
        pytest_assert(not backup_existed,
                      'PTF has an existing NTP helper backup; recover it before this test')
        directory = ptfhost.command('mktemp -d /tmp/mvrf-ntp.XXXXXXXX')['stdout'].strip()
        pytest_assert(re.fullmatch(r'/tmp/mvrf-ntp\.[A-Za-z0-9]+', directory),
                      'Unexpected PTF NTP backup directory')
        ptfhost.command('cp -p {} {}/original.conf'.format(shlex.quote(path), shlex.quote(directory)))
        ptf_backup = (service, path, directory, state['rc'] == 0, shared_backup)
    original = duthost.config_facts(host=duthost.hostname, source='running',
                                    verbose=False)['ansible_facts']
    saved = backup_config_db['directory'] + '/ntp-before.json'
    restore_script = backup_config_db['directory'] + '/restore-ntp.py'
    duthost.copy(content=json.dumps({name: original.get(name, {}) for name in ('NTP', 'NTP_SERVER')}),
                 dest=saved, mode=0o600, verbose=False)
    duthost.copy(content=NTP_RESTORE_SCRIPT, dest=restore_script, mode=0o600, verbose=False)
    try:
        yield
    finally:
        # Nested finally ensures a DUT disconnect cannot prevent PTF cleanup.
        try:
            duthost.command('sudo python3 {} {}'.format(shlex.quote(restore_script),
                                                        shlex.quote(saved)), verbose=False)
        finally:
            if ptf_backup is not None:
                service, path, directory, was_running, shared_backup = ptf_backup
                ptfhost.command('cp -p {}/original.conf {}'.format(shlex.quote(directory), shlex.quote(path)))
                ptfhost.service(name=service, state='restarted' if was_running else 'stopped')
                # The helper may leave this file if an exception interrupted
                # its context. It was absent before our test, so it is ours.
                ptfhost.file(path=shared_backup, state='absent')
                ptfhost.file(path=directory, state='absent')


@pytest.fixture()
def change_critical_services(duthosts, rand_one_dut_hostname):
    # Warm reboot temporarily needs a different list of services to watch.
    # Restore the original list after that test.
    duthost = duthosts[rand_one_dut_hostname]
    backup = duthost.critical_services
    services = duthost.DEFAULT_ASIC_SERVICES
    duthost.reset_critical_services_tracking_list(services + ['pmon'])
    yield
    duthost.reset_critical_services_tracking_list(backup)


def check_ntp_status(host, ntp_daemon_in_use, mvrf=True):  # noqa: F811
    # SONiC images may use chrony or ntpd. Ask the installed one whether
    # clock synchronization has completed; return True only on success.
    if ntp_daemon_in_use == NtpDaemon.CHRONY:
        ntpstat_cmd = "chronyc -n tracking"
    else:
        ntpstat_cmd = "ntpstat"
    if isinstance(host, PTFHost):
        res = host.command(ntpstat_cmd, module_ignore_errors=True)
    else:
        # On the switch, run the check in mgmt VRF so it sees the same
        # routing context requested by the original status check. This does
        # not, by itself, prove the running daemon's packet path.
        res = execute_dut_command(host, ntpstat_cmd, mvrf=mvrf, ignore_errors=True)
    if res.get('rc') != 0:
        return False
    if ntp_daemon_in_use == NtpDaemon.CHRONY:
        # chronyc exits successfully even when it reports Not synchronised.
        # Check synchronization fields, not just whether the command ran.
        output = res.get('stdout', '')
        leap = re.search(r'^Leap status\s*:\s*Normal\s*$', output, re.MULTILINE)
        stratum = re.search(r'^Stratum\s*:\s*(\d+)\s*$', output, re.MULTILINE)
        return bool(leap and stratum and 0 < int(stratum.group(1)) < 16)
    return True


def verify_fresh_ntp_sync(host, daemon):
    # Status alone can still describe synchronization from before the VRF
    # transition. A new one-shot client must exchange packets inside mgmt.
    service = {NtpDaemon.CHRONY: 'chrony', NtpDaemon.NTPSEC: 'ntpsec', NtpDaemon.NTP: 'ntp'}[daemon]
    command = ('timeout 60 chronyd -q -F 1' if daemon == NtpDaemon.CHRONY
               else 'timeout 60 ntpd -gq')
    try:
        host.service(name=service, state='stopped')
        result = execute_dut_command(host, command, mvrf=True, ignore_errors=True)
        pytest_assert(result.get('rc') == 0, 'Fresh NTP synchronization through mgmt VRF failed')
    finally:
        host.service(name=service, state='started')
    pytest_assert(wait_until(400, 10, 0, check_ntp_status, host, daemon), 'Ntp not started')


def verify_show_command(duthost, mvrf=True):
    """Check the CLI AND Linux interfaces, address, and connected route.

    JSON checks avoid dependence on interface numbers, flag ordering, and
    a hardcoded routing-table ID. 'Enabled' alone is not convergence.
    """
    show_mgmt_vrf = duthost.shell("show mgmt-vrf")["stdout"]
    expected = "ManagementVRF : {}".format("Enabled" if mvrf else "Disabled")
    if expected not in show_mgmt_vrf:
        raise AssertionError("show mgmt-vrf does not report the expected state: " + expected)
    links = json.loads(duthost.command("ip -j -d link show", verbose=False)['stdout'])
    by_name = {link['ifname']: link for link in links}
    eth0 = by_name.get('eth0', {})
    if not eth0 or 'UP' not in eth0.get('flags', []):
        raise AssertionError("Linux eth0 is missing or administratively down")
    if mvrf:
        mgmt = by_name.get('mgmt', {})
        info = mgmt.get('linkinfo', {})
        table = info.get('info_data', {}).get('table')
        if info.get('info_kind') != 'vrf' or not isinstance(table, int) or table <= 0:
            raise AssertionError("Linux mgmt VRF or its routing table is missing")
        if 'UP' not in mgmt.get('flags', []):
            raise AssertionError("Linux mgmt VRF is administratively down")
        for name in ('eth0', 'lo-m'):
            link = by_name.get(name, {})
            if link.get('master') not in ('mgmt', mgmt.get('ifindex')) or 'UP' not in link.get('flags', []):
                raise AssertionError("Linux {} is not UP and attached to mgmt".format(name))
    else:
        if 'mgmt' in by_name or eth0.get('master') == 'mgmt':
            raise AssertionError("Linux still has mgmt VRF although the CLI reports Disabled")
        table = 'all'

    address = ipaddress.ip_address(duthost.mgmt_ip)
    addresses = json.loads(duthost.command("ip -j address show dev eth0", verbose=False)['stdout'])
    matching = [item for link in addresses for item in link.get('addr_info', [])
                if item.get('local') == str(address)]
    if not matching:
        raise AssertionError("Inventory management address is not configured on Linux eth0")
    network = ipaddress.ip_network('{}/{}'.format(address, matching[0]['prefixlen']), strict=False)
    routes = json.loads(duthost.command(
        "ip -j -{} route show table {}".format(address.version, table), verbose=False)['stdout'])
    if not any(route.get('dev') == 'eth0' and route.get('dst') == str(network) for route in routes):
        raise AssertionError("Management connected route is missing from the expected Linux routing table")


def execute_dut_command(duthost, command, mvrf=True, ignore_errors=False):
    # Outgoing processes need the right route table. `ip vrf exec mgmt`
    # starts this one command inside the mgmt VRF context.
    result = {}
    prefix = ""
    if mvrf:
        prefix = "sudo ip vrf exec mgmt "
    result = duthost.command(prefix + command, module_ignore_errors=ignore_errors)
    return result


# ===========================================================================
# SECTION 1 — THE EXISTING NINE FUNCTIONAL TESTS
# Keep their investigated SNMP prerequisites, NTP/ACL behavior, and cleanup.
# ===========================================================================
class TestMvrfInbound():
    # Inbound means another machine starts traffic toward the switch.
    def test_ping(self, mvrf_duthost):
        # Basic question: can the switch's management IP be reached?
        mvrf_duthost.ping()

    def test_snmp_fact(self, localhost, mvrf_duthost, creds):
        # SNMP is a monitoring service. Reading facts proves it is listening
        # and answering at the switch's management IP.
        verify_snmp_response(mvrf_duthost, localhost, creds['snmp_rocommunity'])


class TestMvrfOutbound():
    # Outbound means the switch starts traffic toward another machine.

    @pytest.fixture
    def setup_http_server(self, localhost, ptfhost):
        # Give the switch a simple web endpoint to contact. `yield` passes
        # its URL and expected reply to test_curl, then removes the script.
        directory = ptfhost.command('mktemp -d /tmp/mvrf-http.XXXXXXXX')['stdout'].strip()
        pytest_assert(re.fullmatch(r'/tmp/mvrf-http\.[A-Za-z0-9]+', directory),
                      'Unexpected PTF HTTP directory')
        script = directory + '/temp_http_server.py'
        ready = directory + '/ready.json'
        server = {}

        def published():
            result = ptfhost.command('cat {}'.format(shlex.quote(ready)), module_ignore_errors=True)
            if result.get('rc') != 0:
                return False
            server.update(json.loads(result['stdout']))
            return isinstance(server.get('port'), int) and 0 < server['port'] < 65536

        try:
            ptfhost.copy(src='mvrf/temp_http_server.py', dest=script)
            launch = 'nohup python3 {} 0 {} {} > {}/server.log 2>&1 < /dev/null &'.format(
                shlex.quote(script), shlex.quote(ready), shlex.quote(ptfhost.mgmt_ip), shlex.quote(directory))
            ptfhost.shell(launch)
            pytest_assert(wait_until(30, 1, 0, published),
                          'PTF HTTP server did not publish a bound port; see ' + directory + '/server.log')
            localhost.wait_for(host=ptfhost.mgmt_ip, port=server['port'], state='started', timeout=30)
            host = '[{}]'.format(ptfhost.mgmt_ip) if ':' in ptfhost.mgmt_ip else ptfhost.mgmt_ip
            yield 'http://{}:{}'.format(host, server['port']), MAGIC_STRING
        finally:
            if ptfhost.stat(path=ready)['stat']['exists']:
                ptfhost.command('python3 {} --stop {}'.format(shlex.quote(script), shlex.quote(ready)))
            ptfhost.file(path=directory, state='absent')

    def test_ping(self, mvrf_duthost, ptfhost):
        # Check that the switch can reach PTF through the mgmt route table.
        logger.info("Test OutBound Ping")
        command = "ping  -c 3 " + ptfhost.mgmt_ip
        execute_dut_command(mvrf_duthost, command, mvrf=True)

    def test_curl(self, duthosts, rand_one_dut_hostname, setup_http_server):
        # A successful TCP connection is stronger proof than ping alone.
        # Check the exact reply to make sure the expected server answered.
        duthost = duthosts[rand_one_dut_hostname]
        logger.info("Test Curl")

        url, MAGIC_STRING = setup_http_server

        curl_cmd = "curl --fail --silent --show-error --noproxy '*' --connect-timeout 10 --max-time 30 {}".format(
            shlex.quote(url))
        result = execute_dut_command(duthost, curl_cmd, mvrf=True)
        pytest_assert(result["stdout"].strip() == MAGIC_STRING)


class TestServices():
    # A VRF can look healthy while an application still uses the wrong route.
    # These tests check real management services, not just the interface.
    @pytest.mark.usefixtures("ntp_teardown")
    def test_ntp(self, mvrf_duthost, ptfhost, check_ntp_sync, mvrf_ntp_daemon):
        # Keep the community test's existing-server / temporary-PTF branches.
        # Do not require the optional/newer `config ntp vrf` CLI on older images.
        if check_ntp_sync:
            with setup_ntp_context(ptfhost, mvrf_duthost, False):
                verify_fresh_ntp_sync(mvrf_duthost, mvrf_ntp_daemon)
        else:
            verify_fresh_ntp_sync(mvrf_duthost, mvrf_ntp_daemon)

    def test_service_acl(self, duthosts, rand_one_dut_hostname, localhost, backup_config_db):
        duthost = duthosts[rand_one_dut_hostname]
        # An ACL is a traffic filter. This helper briefly blocks SSH to prove
        # the management ACL works, then removes the rule so access returns.
        logger.info("test Service acl")

        address = ipaddress.ip_address(duthost.mgmt_ip)
        route = localhost.command('ip -j -{} route get {}'.format(
            address.version, shlex.quote(str(address))))
        routes = json.loads(route['stdout'])
        pytest_assert(bool(routes), 'Controller has no route to the inventory DUT address')
        source = routes[0].get('prefsrc') or routes[0].get('src')
        pytest_assert(bool(source), 'Cannot determine controller source address for SSH ACL test')
        source = str(ipaddress.ip_address(source))
        # Reject a NAT/mismatched controller rather than silently testing a
        # rule against an IP that never appears at the DUT.
        sessions = duthost.command("ss -Htn state established '( sport = :22 )'")['stdout']
        pytest_assert(any(field.startswith(source + ':') or field.startswith('[' + source + ']:')
                          for field in sessions.split()),
                      'Controller route source is not an established DUT SSH peer; check testbed NAT')
        prefix = backup_config_db['directory'] + '/acl-job'
        script = prefix + '.py'
        duthost.copy(content=SERVICE_ACL_SCRIPT, dest=script, mode=0o700)
        launch = 'nohup python3 {} {} {} 90 > {}.log 2>&1 < /dev/null &'.format(
            shlex.quote(script), shlex.quote(source), shlex.quote(prefix), shlex.quote(prefix))
        try:
            duthost.shell('sudo sh -c {}'.format(shlex.quote(launch)))
        except AnsibleConnectionFailure:
            logger.info('SSH interrupted during ACL launch; waiting for DUT-local rollback')
        try:
            # Test a fresh TCP connection, not an already-established session.
            localhost.wait_for(host=duthost.mgmt_ip, port=SONIC_SSH_PORT,
                               state='stopped', timeout=45)
        finally:
            wait_for_ssh_and_reset_connection(duthost, localhost, timeout=180)

            def completed():
                result = duthost.command('sudo cat {}.rc'.format(shlex.quote(prefix)),
                                         module_ignore_errors=True)
                return result.get('rc') == 0

            pytest_assert(wait_until(120, 5, 0, completed),
                          'SSH ACL rollback did not finish; see ' + prefix + '.log')
            result = duthost.command('sudo cat {}.rc'.format(shlex.quote(prefix)))
            pytest_assert(result['stdout'].strip() == '0',
                          'SSH ACL job failed; see ' + prefix + '.log')


class TestReboot():
    # All three reboot types repeat the same basic management checks.
    def basic_check_after_reboot(self, duthost, localhost, ptfhost, creds):
        # Confirm the VRF exists and that outbound ping, inbound ping, and
        # inbound SNMP still work after the switch starts again.
        wait_for_ssh_and_reset_connection(duthost, localhost)
        pytest_assert(wait_until(MGMT_VRF_READY_TIMEOUT, 5, 0,
                                 _mgmt_vrf_state_matches, duthost, True),
                      "Management VRF did not recover in Linux after reboot")
        inbound_test = TestMvrfInbound()
        outbound_test = TestMvrfOutbound()
        outbound_test.test_ping(mvrf_duthost=duthost, ptfhost=ptfhost)
        inbound_test.test_ping(mvrf_duthost=duthost)
        inbound_test.test_snmp_fact(localhost=localhost, mvrf_duthost=duthost, creds=creds)

    @pytest.mark.disable_loganalyzer
    def test_warmboot(self, duthosts, rand_one_dut_hostname, localhost, ptfhost, creds, change_critical_services):
        # Warm reboot aims to preserve forwarding while restarting software.
        # Save the VRF configuration so it survives the reboot, wait for key
        # services, then repeat the basic connectivity checks.
        duthost = duthosts[rand_one_dut_hostname]
        # A disabled feature may retain a stopped container. Snapshot enabled
        # optional services before reboot; do not infer intent from docker ps.
        feature_status, status_ok = duthost.get_feature_status()
        pytest_assert(status_ok, 'Cannot determine enabled features before warm reboot')
        critical_services = ['snmp'] + [name for name in ('mgmt-framework', 'gnmi', 'telemetry')
                                        if feature_status.get(name) in ('enabled', 'always_enabled')]
        duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config
        reboot(duthost, localhost, reboot_type="warm")
        pytest_assert(wait_until(120, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started")

        duthost.reset_critical_services_tracking_list(critical_services)

        pytest_assert(wait_until(180, 20, 0, duthost.critical_services_fully_started),
                      "Not all services which start with bootOn timer are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)

    @pytest.mark.disable_loganalyzer
    def test_reboot(self, duthosts, rand_one_dut_hostname, localhost, ptfhost, creds):
        # Normal reboot: prove saved management settings and basic services
        # return after a full restart.
        duthost = duthosts[rand_one_dut_hostname]
        duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config
        reboot(duthost, localhost)
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)

    @pytest.mark.disable_loganalyzer
    def test_fastboot(self, duthosts, rand_one_dut_hostname, localhost, ptfhost, creds):
        # Fast reboot follows a different startup path. Repeat the same
        # checks because a different service order can expose new failures.
        duthost = duthosts[rand_one_dut_hostname]
        verify_fast_reboot_compatibility(duthost)
        duthost.command("sudo config save -y")  # This will override config_db.json with mgmt vrf config
        reboot(duthost, localhost, reboot_type="fast")
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started")
        self.basic_check_after_reboot(duthost, localhost, ptfhost, creds)


# ===========================================================================
# SECTION 2 — THIRTEEN NEW GAP / REGRESSION CASES
#
# Why these exist:
#   * A successful reply alone does not check saved/rendered configuration.
#   * A rejected command must not damage settings that were already working.
#   * Existing setup manually fixes TACACS+ rows, masking automatic migration.
#
# No new reboot, eth0 flap, remote AAA login, image repair, skip, or xfail is
# added here. CLI-only checks are distinguished from runtime/traffic checks.
# These run after Section 1 in normal pytest file order. Each case snapshots
# the state it receives and restores it BEFORE the next case; the module's
# original backup remains the final safety net. Do not run these concurrently.
# ===========================================================================
GAP_TABLES = ('MGMT_VRF_CONFIG', 'NTP', 'NTP_SERVER', 'AAA', 'TACPLUS_SERVER',
              'RADIUS_SERVER', 'SNMP_AGENT_ADDRESS_CONFIG')
GAP_TIMEOUT = 180

# This small helper executes on the DUT. Raw AAA keys stay in a root-only
# snapshot there. Read operations return salted hashes for secret fields, so
# we can prove an unchanged key without returning it to assertion frames.
# DB writes below are test setup/rollback only, NEVER a repair of the behavior
# under test. In particular, the AAA test expects the VRF CLI to migrate rows.
GAP_DB_SCRIPT = SNMP_RESTART_POLICY_SCRIPT + NTP_APPLY_SCRIPT + r'''
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
import traceback
from swsscommon.swsscommon import ConfigDBConnector

root = os.path.dirname(os.path.abspath(__file__))
snapshot = os.path.join(root, 'snapshot.json')
db = ConfigDBConnector()
db.connect()

def flat(table):
    connector, name = table_source(table)
    return {'|'.join(k) if isinstance(k, tuple) else k: v
            for k, v in connector.get_table(name).items()}

def table_source(table):
    # Front-panel rows may live in an ASIC namespace, not the host database.
    namespace, separator, name = table.partition('::')
    if not separator:
        return db, table
    connector = ConfigDBConnector(namespace=namespace)
    connector.connect()
    return connector, name

def native(key):
    return tuple(key.split('|')) if '|' in key else key

def save(state):
    with open(snapshot + '.tmp', 'w') as out:
        json.dump(state, out, sort_keys=True)
    os.chmod(snapshot + '.tmp', 0o600)
    os.replace(snapshot + '.tmp', snapshot)

def checked(argv):
    # Keep commands/output that may contain AAA secrets on the DUT.
    with open(os.path.join(root, 'operations.log'), 'a') as out:
        out.write(json.dumps(argv) + '\n')
        out.flush()
        result = subprocess.run(argv, stdout=out, stderr=subprocess.STDOUT, timeout=240)
    if result.returncode:
        raise RuntimeError('DUT-local operation failed (rc={}); see operations.log'.format(result.returncode))

def linux_ready(enabled):
    # Wait for the real network before restoring VRF-bound service sockets.
    end = time.monotonic() + 180
    while time.monotonic() < end:
        result = subprocess.run(['ip', '-j', '-d', 'link', 'show'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            links = {row['ifname']: row for row in json.loads(result.stdout)}
            eth0, mgmt = links.get('eth0', {}), links.get('mgmt', {})
            master = eth0.get('master')
            if enabled:
                if mgmt.get('linkinfo', {}).get('info_kind') == 'vrf' and (
                        master == 'mgmt' or master == mgmt.get('ifindex')) and 'UP' in eth0.get('flags', []):
                    return
            elif eth0 and not mgmt and master is None and 'UP' in eth0.get('flags', []):
                return
        time.sleep(2)
    raise RuntimeError('Linux Management VRF did not recover before service restoration')

def redact(value, salt):
    if isinstance(value, dict):
        return {k: ('<redacted:' + hmac.new(salt.encode(), str(v).encode(),
                         hashlib.sha256).hexdigest() + '>')
                if any(s in k.lower() for s in ('key', 'secret', 'password'))
                else redact(v, salt) for k, v in value.items()}
    return value

def main():
    action, args = sys.argv[1], sys.argv[2:]
    if action == 'snapshot':
        save({'salt': secrets.token_hex(32), 'tables': {t: flat(t) for t in args}})
        print('{}')
        return
    with open(snapshot) as inp:
        state = json.load(inp)
    if action == 'extend':
        for table in args:
            if table not in state['tables']:
                state['tables'][table] = flat(table)
        save(state)
        print('{}')
    elif action in ('read', 'baseline'):
        rows = flat(args[0]) if action == 'read' else state['tables'][args[0]]
        print(json.dumps(redact(rows, state['salt']), sort_keys=True))
    elif action == 'ntp-vrf':
        # Set the input to show ntp, without assuming the optional CLI exists.
        state['ntp_touched'] = True
        save(state)
        row = db.get_entry('NTP', 'global') or {}
        row['vrf'] = args[0]
        db.set_entry('NTP', 'global', row)
        print('{}')
    elif action in ('ntp-touched', 'snmp-touched'):
        # Record possible runtime/file side effects even if a rejected CLI
        # command leaves the saved database rows unchanged.
        state[action.replace('-', '_')] = True
        save(state)
        print('{}')
    elif action == 'aaa-seed':
        table, address = args
        if address in flat(table):
            raise RuntimeError('Test peer already exists')
        row = {'passkey': secrets.token_hex(16), 'timeout': '7',
               'priority': '64', 'auth_type': 'pap'}
        if table == 'TACPLUS_SERVER':
            row['tcp_port'] = '49'
        elif table == 'RADIUS_SERVER':
            row.update({'auth_port': '1812', 'retransmit': '4'})
        else:
            raise RuntimeError('Unsupported AAA table')
        db.set_entry(table, address, row)
        print('{}')
    elif action == 'probe-ip':
        # Record ownership BEFORE config interface ip add could partially fail.
        state['probe_ip'] = args
        save(state)
        print('{}')
    elif action == 'network-touched':
        # Removing/recreating a VRF can invalidate sockets even when their
        # saved listener row is identical afterward. Regenerate on rollback.
        state['network_touched'] = True
        save(state)
        print('{}')
    elif action == 'snmp-default-listener':
        # Service-test setup, not a test or repair of the SNMP CLI.
        # An empty VRF field is the existing template's default-context format.
        state['snmp_touched'] = True
        save(state)
        db.set_entry('SNMP_AGENT_ADDRESS_CONFIG', (args[0], '161', ''), {})
        checked(['systemctl', 'restart', 'snmp'])
        print('{}')
    elif action == 'snmp-clear':
        # This is fixture preparation, not a repair inside an SNMP assertion.
        state['snmp_touched'] = True
        save(state)
        for key in db.get_table('SNMP_AGENT_ADDRESS_CONFIG'):
            db.set_entry('SNMP_AGENT_ADDRESS_CONFIG', key, None)
        print('{}')
    elif action == 'restore':
        # Main cleanup and the emergency timer share a lock; never race writes.
        with open(os.path.join(root, 'restore.lock'), 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            wanted = state['tables']['MGMT_VRF_CONFIG'].get('vrf_global', {}).get(
                'mgmtVrfEnabled') == 'true'
            now = (db.get_entry('MGMT_VRF_CONFIG', 'vrf_global') or {}).get(
                'mgmtVrfEnabled') == 'true'
            network_changed = now != wanted or state.get('network_touched', False)
            # Do not retain a listener bound to a VRF being removed. Save the
            # fact that rows differed BEFORE clearing them for safe rollback.
            listeners_changed = flat('SNMP_AGENT_ADDRESS_CONFIG') != state['tables'].get(
                'SNMP_AGENT_ADDRESS_CONFIG', {})
            if listeners_changed or network_changed:
                state['snmp_touched'] = True
                save(state)
            if network_changed:
                for key in db.get_table('SNMP_AGENT_ADDRESS_CONFIG'):
                    db.set_entry('SNMP_AGENT_ADDRESS_CONFIG', key, None)
            if now != wanted:
                checked(['config', 'vrf', 'add' if wanted else 'del', 'mgmt'])
            if 'probe_ip' in state:
                port, address, namespace, table = state['probe_ip']
                if port + '|' + address in flat(table):
                    command = ['config', 'interface'] + (['-n', namespace] if namespace else [])
                    checked(command + ['ip', 'remove', port, address])
            changed = []
            for table, before in state['tables'].items():
                # Restore listeners only AFTER their Linux VRF is ready.
                if table == 'SNMP_AGENT_ADDRESS_CONFIG':
                    continue
                current = flat(table)
                if current != before:
                    changed.append(table)
                    if table in ('NTP', 'NTP_SERVER'):
                        state['ntp_touched'] = True
                        save(state)
                connector, name = table_source(table)
                for key in set(current) | set(before):
                    if current.get(key) != before.get(key):
                        # Delete first: an HSET alone cannot remove extra fields.
                        connector.set_entry(name, native(key), None)
                        if key in before:
                            connector.set_entry(name, native(key), before[key])
            if network_changed or 'MGMT_VRF_CONFIG' in changed:
                checked(['systemctl', 'restart', 'interfaces-config'])
                linux_ready(wanted)
            if network_changed or state.get('ntp_touched') or any(t in changed for t in ('NTP', 'NTP_SERVER')):
                # Persist before rendering: a failed attempt has already restored
                # Redis, so a retry must not skip applying equal database rows.
                state['ntp_touched'] = True
                save(state)
                apply_ntp_config()
                state['ntp_touched'] = False
                save(state)
            if listeners_changed or state.get('snmp_touched') or network_changed:
                before = state['tables'].get('SNMP_AGENT_ADDRESS_CONFIG', {})
                current = flat('SNMP_AGENT_ADDRESS_CONFIG')
                for key in set(current) | set(before):
                    if current.get(key) != before.get(key):
                        db.set_entry('SNMP_AGENT_ADDRESS_CONFIG', native(key), None)
                        if key in before:
                            db.set_entry('SNMP_AGENT_ADDRESS_CONFIG', native(key), before[key])
                # Respect the real rate limit during rollback too. Restarting
                # successfully here never changes a failed test into a pass.
                policy = snmp_restart_policy()
                deadline = time.monotonic() + policy['interval'] + 60
                while policy['delay'] > 0:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('SNMP rollback restart allowance did not recover')
                    time.sleep(min(30, policy['delay']))
                    policy = snmp_restart_policy()
                checked(['systemctl', 'restart', 'snmp'])
            if state.get('radius_users'):
                # The private helper registered these absent-before-test names
                # before any login. Cleanup also runs from the local watchdog.
                checked(['python3', os.path.join(root, 'radius-dut.py'), 'cleanup'])
        print('{}')
    else:
        raise RuntimeError('Unknown snapshot action')

if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except Exception as error:
        # No traceback/local values containing secrets go to controller logs.
        with open(os.path.join(root, 'helper-errors.log'), 'a') as out:
            traceback.print_exc(file=out)
        print('Gap snapshot helper failed: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
'''


def _gap_run(host, command, accepted=(0,)):
    """Require success, or an explicitly allowed status code; never hide errors."""
    result = host.shell(command, module_ignore_errors=True, verbose=False)
    pytest_assert(not result.get('unreachable') and 'exception' not in result
                  and result.get('rc') in accepted,
                  'Gap-test command failed (rc={}): {}'.format(result.get('rc'), command))
    return result


def _gap_json(host, command):
    return json.loads(_gap_run(host, command)['stdout'])


def _gap_wait(description, predicate):
    # wait_until returns as soon as the condition succeeds. Unlike sleep(5),
    # it checks completion. Remote commands may add to the polling budget.
    pytest_assert(wait_until(GAP_TIMEOUT, 5, 0, predicate), description)


def _gap_network(host):
    """Compare eth0 addresses/routes without hardcoding table 5000 or lab IPs."""
    addresses = _gap_json(host, 'ip -j address show dev eth0')[0]['addr_info']
    state = {'addresses': sorted((a['family'], a['local'], a['prefixlen'])
                                 for a in addresses if a.get('scope') == 'global')}
    for family in (4, 6):
        routes = _gap_json(host, 'ip -j -{} route show table all dev eth0'.format(family))
        # Routes may move between main/default/mgmt or appear in two tables.
        # Ignore table IDs and transient expiry/cache metadata, not gateways.
        state[str(family)] = sorted(set((r.get('dst', 'default'), r.get('gateway', ''),
                                        r.get('metric', 0)) for r in routes
                                        if r.get('type', 'unicast') == 'unicast'))
    return state


class MvrfGapState:
    """Per-case private backup, emergency recovery, and verified restoration."""

    def __init__(self, host, localhost, community=None):
        self.host, self.localhost = host, localhost
        self.community = community
        self.directory = None
        self.ready = False
        self.timer = None
        self.timer_armed = False
        self.tables = set(GAP_TABLES)
        self.original_network = None
        self.interface_checks = {}
        self.restart_interval = 0

    def db(self, action, *args):
        command = 'sudo python3 {} {}'.format(shlex.quote(self.directory + '/db.py'),
                                              ' '.join(shlex.quote(str(a)) for a in (action,) + args))
        value = json.loads(_gap_run(self.host, command)['stdout'])
        if action == 'extend':
            self.tables.update(args)
        return value

    def table(self, name):
        return self.db('read', name)

    def start(self):
        # Do not interpret an already broken SNMP service as a new regression.
        _gap_wait('SNMP baseline is not running/listening before this case',
                  lambda: _gap_snmp_ready(self.host))
        if self.community is not None:
            verify_snmp_response(self.host, self.localhost, self.community)
        self.restart_interval = _snmp_restart_policy(self.host)['interval']
        self.directory = _gap_run(self.host, 'sudo mktemp -d /var/tmp/mvrf-gap.XXXXXXXX')['stdout'].strip()
        pytest_assert(re.fullmatch(r'/var/tmp/mvrf-gap\.[A-Za-z0-9]+', self.directory),
                      'Unexpected gap-test backup path')
        self.host.copy(content=GAP_DB_SCRIPT, dest=self.directory + '/db.py', mode=0o600, verbose=False)
        self.db('snapshot', *GAP_TABLES)
        self.ready = True  # A finalizer is already registered, before mutation.
        self.original_network = _gap_network(self.host)
        self.timer = 'mvrf-gap-' + self.directory.rsplit('.', 1)[-1]
        self.host.copy(content='#!/bin/sh\nset -eu\ntouch {0}/watchdog-fired\n'
                       'python3 {0}/db.py restore\n'.format(self.directory),
                       dest=self.directory + '/recover.sh', mode=0o700)
        # Allow the six listener edits plus transition/rollback waits. A short
        # watchdog must not interrupt a legitimate long restart-policy wait.
        watchdog_seconds = int(900 + 8 * self.restart_interval)
        _gap_run(self.host, 'sudo systemd-run --unit={} --on-active={}s {}'.format(
            self.timer, watchdog_seconds, shlex.quote(self.directory + '/recover.sh')))
        self.timer_armed = True

    def transition(self, enabled):
        current = self.table('MGMT_VRF_CONFIG').get('vrf_global', {}).get('mgmtVrfEnabled') == 'true'
        if current != enabled:
            self.db('network-touched')
            # The SNMP listener is a test prerequisite, not the migration
            # feature being tested. Never leave it bound to a deleted VRF.
            self.db('snmp-clear')
            try:
                _gap_run(self.host, 'sudo timeout 240 config vrf {} mgmt'.format(
                    'add' if enabled else 'del'))
            except AnsibleConnectionFailure:
                # Expected possibility when eth0 moves. Not evidence of success.
                logger.info('SSH interrupted during VRF transition; verifying recovery')
        wait_for_ssh_and_reset_connection(self.host, self.localhost)
        _gap_wait('CONFIG_DB and Linux must agree after the VRF transition',
                  lambda: self.table('MGMT_VRF_CONFIG').get('vrf_global', {}).get(
                      'mgmtVrfEnabled') == str(enabled).lower()
                  and _mgmt_vrf_state_matches(self.host, enabled))
        if current != enabled:
            ensure_snmp_listener(self.host, mvrf=enabled)
            if self.community is not None:
                verify_snmp_response(self.host, self.localhost, self.community)

    def local_login(self):
        # A synthetic AAA peer must never become the controller's login server.
        # Use the ordinary CLI, verify a fresh login, and restore AAA in cleanup.
        login = self.table('AAA').get('authentication', {}).get('login', 'local')
        if login != 'local':
            _gap_run(self.host, 'sudo config aaa authentication login local')
            _gap_wait('Could not prepare local authentication for the AAA configuration test',
                      lambda: self.table('AAA').get('authentication', {}).get('login') == 'local')
            wait_for_ssh_and_reset_connection(self.host, self.localhost)

    def cleanup(self):
        if not self.ready:
            return  # No test mutation occurred; module backup remains available.
        # Stop future timer activation, not a recovery service already running.
        # The helper lock serializes any timer job already in progress.
        timer_error = False
        if self.timer_armed:
            try:
                _gap_run(self.host, 'sudo systemctl stop {}.timer'.format(self.timer))
            except (Exception, pytest.fail.Exception):
                # Still attempt restoration; a timer error must not abandon it.
                timer_error = True
        launch = ('nohup sh -c {0} > {1}/restore.log 2>&1 < /dev/null &').format(
            shlex.quote('python3 {0}/db.py restore; rc=$?; '
                        'printf "%s\\n" "$rc" > {0}/restore.rc.tmp; '
                        'mv {0}/restore.rc.tmp {0}/restore.rc'.format(self.directory)),
            shlex.quote(self.directory))
        try:
            _gap_run(self.host, 'sudo sh -c ' + shlex.quote(launch))
        except AnsibleConnectionFailure:
            logger.info('SSH interrupted during gap restoration; checking DUT-local completion')
        wait_for_ssh_and_reset_connection(self.host, self.localhost, timeout=RESTORE_TIMEOUT)

        def finished():
            result = self.host.command('sudo cat ' + shlex.quote(self.directory + '/restore.rc'),
                                       module_ignore_errors=True, verbose=False)
            return result.get('rc') == 0

        pytest_assert(wait_until(RESTORE_TIMEOUT + self.restart_interval, 5, 0, finished),
                      'Gap restore job did not finish; private backup: ' + self.directory)
        result = _gap_run(self.host, 'sudo cat ' + shlex.quote(self.directory + '/restore.rc'))
        pytest_assert(result['stdout'].strip() == '0',
                      'Gap restore job failed; private backup: ' + self.directory)
        for table in sorted(self.tables):
            _gap_wait('Gap cleanup did not restore ' + table,
                      lambda name=table: self.table(name) == self.db('baseline', name))
        enabled = self.db('baseline', 'MGMT_VRF_CONFIG').get('vrf_global', {}).get(
            'mgmtVrfEnabled') == 'true'
        _gap_wait('Gap cleanup did not restore Linux VRF state',
                  lambda: _mgmt_vrf_state_matches(self.host, enabled))
        if self.original_network is not None:
            _gap_wait('Gap cleanup changed original eth0 addresses or routes',
                      lambda: _gap_network(self.host) == self.original_network)
        _gap_wait('SNMP did not recover after gap cleanup', lambda: _gap_snmp_ready(self.host))
        if self.community is not None:
            verify_snmp_response(self.host, self.localhost, self.community)
        for (namespace, port), before in self.interface_checks.items():
            _gap_wait('Gap cleanup did not restore front-panel Linux addresses',
                      lambda name=port, ns=namespace, expected=before:
                      _gap_interface(self.host, name, ns) == expected)
        fired = self.host.command('sudo test -e ' + shlex.quote(self.directory + '/watchdog-fired'),
                                  module_ignore_errors=True, verbose=False)
        pytest_assert(fired.get('rc') == 1,
                      'Emergency gap recovery ran; not a clean pass. Backup: ' + self.directory)
        pytest_assert(not timer_error, 'Could not disarm recovery timer; private backup: ' + self.directory)
        # Remove only the validated private directory, after verified recovery.
        self.host.file(path=self.directory, state='absent')


@pytest.fixture
def mvrf_gap_state(mvrf_duthost, localhost, setup_mvrf, creds):
    """Snapshot the investigated module setup, then undo each new case's work."""
    state = MvrfGapState(mvrf_duthost, localhost, creds['snmp_rocommunity'])
    try:
        state.start()
        yield state
    finally:
        state.cleanup()


def _gap_interfaces_file(host, enabled):
    """Check the real generated file AND Linux, not a separately rendered copy."""
    text = _gap_run(host, 'sudo cat /etc/network/interfaces')['stdout']
    lines = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
    pytest_assert(bool(re.search(r'^iface eth0\b', lines, re.M)), 'Generated eth0 stanza is missing')
    pytest_assert(bool(re.search(r'^iface mgmt\b', lines, re.M)) == enabled,
                  '/etc/network/interfaces has the wrong mgmt stanza')
    pytest_assert(bool(re.search(r'^\s+vrf mgmt\s*$', lines, re.M)) == enabled,
                  '/etc/network/interfaces has the wrong management VRF membership')
    if enabled:
        links = _gap_json(host, 'ip -j -d link show dev mgmt')
        table = links[0]['linkinfo']['info_data']['table']
        pytest_assert(re.search(r'^\s+vrf-table {}\s*$'.format(table), lines, re.M),
                      'Generated VRF table does not match the actual Linux VRF')


def _gap_snmp_lines(host):
    # A CLI-triggered restart can briefly make docker exec unavailable.
    # Return not-ready to the bounded wait; do not fail on its first attempt.
    result = host.shell("docker exec snmp grep -E '^[[:space:]]*agentAddress' /etc/snmp/snmpd.conf",
                        module_ignore_errors=True, verbose=False)
    return result.get('stdout', '').splitlines() if result.get('rc') == 0 else []


def _gap_snmp_ready(host):
    daemon = host.shell('docker exec snmp supervisorctl status snmpd',
                        module_ignore_errors=True, verbose=False)
    sockets = host.shell('docker exec snmp ss -H -lun', module_ignore_errors=True, verbose=False)
    address = str(ipaddress.ip_address(host.mgmt_ip))
    # ss may print an explicit address, a %VRF suffix, or a wildcard socket.
    # Socket presence alone is not success: the caller also checks a real reply.
    family_wildcards = ('[::]', '::', '*') if ':' in address else ('0.0.0.0', '*')
    endpoints = [line.split()[3] for line in sockets.get('stdout', '').splitlines()
                 if len(line.split()) >= 5]
    listening = any(endpoint.rsplit(':', 1)[-1] == '161' and (
        endpoint.rsplit(':', 1)[0].strip('[]').split('%', 1)[0] == address
        or endpoint.rsplit(':', 1)[0] in family_wildcards) for endpoint in endpoints)
    return (daemon.get('rc') == 0 and bool(re.search(r'^snmpd\s+RUNNING\b',
            daemon.get('stdout', ''), re.M)) and sockets.get('rc') == 0 and listening)


def _gap_assert_snmp(state, localhost, creds):
    pytest_assert(_snmp_community_exists(state.host, creds['snmp_rocommunity']),
                  'Inventory SNMP community is missing from CONFIG_DB')
    address = str(ipaddress.ip_address(state.host.mgmt_ip))
    key = address + '|161|mgmt'
    pytest_assert(key in state.table('SNMP_AGENT_ADDRESS_CONFIG'), 'SNMP listener row is missing')
    transport = 'udp6' if ':' in address else 'udp'
    expected = '{}:{}@mgmt:161'.format(transport, address)

    def rendered():
        for line in _gap_snmp_lines(state.host):
            fields = line.strip().split(None, 1)
            if len(fields) == 2 and fields[0] == 'agentAddress':
                endpoints = fields[1].replace('[', '').replace(']', '').replace(' ', '').split(',')
                if expected in endpoints:
                    return True
        return False
    _gap_wait('Saved SNMP listener was not rendered with its mgmt binding',
              rendered)
    _gap_wait('Rendered SNMP listener has no running daemon/socket',
              lambda: _gap_snmp_ready(state.host))
    # The real response is necessary: ss and RUNNING alone missed our earlier
    # missing-community failure. Reuse the investigated inventory-based probe.
    verify_snmp_response(state.host, localhost, creds['snmp_rocommunity'])


def _gap_free_peer(state, table):
    # Documentation addresses are synthetic configuration inputs, not lab
    # endpoints or a claim that an NTP/AAA server is reachable at that address.
    used = state.table(table)
    for index in range(1, 255):
        candidate = '192.0.2.{}'.format(index)
        if candidate not in used:
            return candidate
    pytest.fail('No unused documentation address for the configuration test')


def _gap_ntp_path(daemon):
    return {NtpDaemon.NTP: '/etc/ntp.conf', NtpDaemon.NTPSEC: '/etc/ntpsec/ntp.conf',
            NtpDaemon.CHRONY: '/etc/chrony/chrony.conf'}[daemon]


def _gap_interface(host, name, namespace=''):
    prefix = 'sudo ip netns exec ' + shlex.quote(namespace) + ' ' if namespace else ''
    link = _gap_json(host, prefix + 'ip -j address show dev ' + shlex.quote(name))[0]
    return {'master': link.get('master'), 'flags': sorted(link.get('flags', [])),
            'addresses': sorted((a['family'], a['local'], a['prefixlen'])
                                for a in link.get('addr_info', []) if a.get('scope') == 'global')}


class TestMvrfRegressionGaps:
    """NEW: thirteen parameter-expanded cases, after the original nine tests."""

    # NEW 1: both directions must change CONFIG_DB, the generated interfaces
    # file, and Linux together. Disabling must not lose the eth0 IP or route.
    def test_vrf_transition_and_rollback(self, mvrf_gap_state):
        state = mvrf_gap_state
        original = _gap_network(state.host)
        # One off/on cycle covers both directions; a second cycle only adds
        # duplicate listener restarts and consumes the DUT's start allowance.
        for enabled in (False, True):
            state.transition(enabled)
            _gap_wait('Generated interfaces file did not follow the VRF transition',
                      lambda wanted=enabled: _gap_interfaces_file(state.host, wanted) is None)
            _gap_wait('VRF transition lost an original eth0 address or route',
                      lambda: _gap_network(state.host) == original)
            # NTP migration is checked by its own test below. A time-service
            # defect should not hide whether the Linux VRF transition worked.

    # NEW 2: prove the full listener chain, including the real answer. Do not
    # repair configuration here: Section 1 already prepared the prerequisite.
    def test_snmp_saved_rendered_running_and_reply(self, mvrf_gap_state, localhost, creds):
        _gap_assert_snmp(mvrf_gap_state, localhost, creds)

    # NEW 3: an absent VRF must be rejected for that reason, without changing
    # listener rows or the generated file. Use a fresh port to avoid a duplicate
    # listener error falsely satisfying the rejection test.
    def test_snmp_invalid_vrf_preserves_configuration(self, mvrf_gap_state):
        state = mvrf_gap_state
        before = state.table('SNMP_AGENT_ADDRESS_CONFIG')
        digest = _gap_run(state.host, 'docker exec snmp sha256sum /etc/snmp/snmpd.conf')['stdout']
        invalid = 'VrfGap' + state.directory.rsplit('.', 1)[-1]
        pytest_assert(invalid not in state.table('VRF'), 'Test VRF unexpectedly exists')
        port_script = "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); " \
                      "s.bind(('',0)); print(s.getsockname()[1]); s.close()"
        port = int(_gap_run(state.host, 'python3 -c ' + shlex.quote(port_script))['stdout'])
        pytest_assert(not any(k.split('|')[1] == str(port) for k in before),
                      'Allocated port conflicts with a saved SNMP listener')
        state.db('snmp-touched')
        result = state.host.shell('sudo config snmpagentaddress add {} -p {} -v {}'.format(
            shlex.quote(state.host.mgmt_ip), port, shlex.quote(invalid)),
            module_ignore_errors=True, verbose=False)
        message = result.get('stdout', '') + result.get('stderr', '')
        pytest_assert(result.get('rc', 0) != 0 and re.search(
            r'vrf.*(does not exist|not exist|not configured|not found|invalid|unknown)|'
            r'(invalid|unknown|nonexistent|non-existent)\s+vrf', message, re.I),
            'Absent SNMP VRF must be rejected explicitly, not accepted or rejected for another reason')
        pytest_assert(state.table('SNMP_AGENT_ADDRESS_CONFIG') == before,
                      'Rejected SNMP command changed CONFIG_DB')
        pytest_assert(_gap_run(state.host, 'docker exec snmp sha256sum /etc/snmp/snmpd.conf')['stdout'] == digest,
                      'Rejected SNMP command changed snmpd.conf')

    # NEW 4: repeat listener changes while respecting the DUT's restart policy.
    # This checks recovery, not unlimited-rate stress. No failed service is reset.
    def test_snmp_listener_churn_recovers(self, mvrf_gap_state, localhost, creds):
        state = mvrf_gap_state
        address = str(ipaddress.ip_address(state.host.mgmt_ip))
        key = address + '|161|mgmt'
        state.db('snmp-touched')
        for _ in range(3):
            _snmp_config_command(state.host, 'sudo config snmpagentaddress del {} -p 161 -v mgmt'.format(
                shlex.quote(address)))
            pytest_assert(key not in state.table('SNMP_AGENT_ADDRESS_CONFIG'),
                          'Listener deletion did not update CONFIG_DB')
            _snmp_config_command(state.host, 'sudo config snmpagentaddress add {} -p 161 -v mgmt'.format(
                shlex.quote(address)))
        _gap_assert_snmp(state, localhost, creds)

    # NEW 5: Request iburst explicitly and check the saved and generated settings.
    # Do not assume a daemon-specific default. This does not test clock synchronization.
    def test_ntp_saved_show_and_explicit_iburst(self, mvrf_gap_state, mvrf_ntp_daemon):
        state = mvrf_gap_state
        help_text = _gap_run(state.host, 'sudo config ntp add --help')['stdout']
        pytest_assert(re.search(r'(?<![\w-])--iburst\b', help_text),
                      'NTP CLI must support explicit --iburst for this configuration test')
        # Force a real transition; do not write the expected migration ourselves.
        state.transition(False)
        state.transition(True)
        pytest_assert(state.table('NTP').get('global', {}).get('vrf') == 'mgmt',
                      'VRF enable did not set NTP saved routing context')
        shown = _gap_run(state.host, 'show runningconfiguration ntp')['stdout']
        pytest_assert(re.search(r'^\s*VRF\s*:?\s+mgmt\s*$', shown, re.M | re.I),
                      'NTP configuration display disagrees with the saved VRF')
        address = _gap_free_peer(state, 'NTP_SERVER')
        _gap_run(state.host, 'sudo config ntp add {} --iburst'.format(shlex.quote(address)))
        servers = state.table('NTP_SERVER')
        pytest_assert(address in servers, 'NTP CLI did not save the new peer')
        # Branches may represent an enabled option as "on", "true", or a boolean.
        pytest_assert(str(servers[address].get('iburst', '')).lower() in ('on', 'true', '1'),
                      'NTP CLI --iburst did not save an enabled option for ' + address)
        path = _gap_ntp_path(mvrf_ntp_daemon)
        peer_lines = []

        def rendered():
            text = _gap_run(state.host, 'sudo cat ' + shlex.quote(path))['stdout']
            # Keep the actual peer line for diagnosis; a comment is not an option.
            lines = [line.split('#', 1)[0].strip() for line in text.splitlines()]
            peer_lines[:] = [line for line in lines if line.split()[:2] == ['server', address]]
            return any('iburst' in line.split()[2:] for line in peer_lines)

        ready = wait_until(GAP_TIMEOUT, 5, 0, rendered)
        pytest_assert(ready,
                      'Explicit NTP iburst was not rendered for {} in {}. Matching server lines: {}'.format(
                          address, path, peer_lines or 'none'))

    # Test SHOW behavior independently of optional `config ntp vrf` support.
    # Set its input directly in CONFIG_DB, then inspect verbose command
    # traces. This does not prove the time daemon's real packet/egress path.
    def test_show_ntp_uses_saved_vrf(self, mvrf_gap_state):
        state = mvrf_gap_state
        for vrf in ('default', 'mgmt'):
            state.db('ntp-vrf', vrf)
            pytest_assert(state.table('NTP').get('global', {}).get('vrf') == vrf,
                          'Could not prepare saved NTP context for the display test')
            result = _gap_run(state.host, 'show ntp --verbose', accepted=(0, 1, 2))
            text = re.sub(r'\x1b\[[0-9;]*m', '', result['stdout'] + result.get('stderr', ''))
            traces = [line for line in text.splitlines() if 'Command:' in line]
            pytest_assert(bool(traces) and any(re.search(r'\b(ntpstat|ntpq|chronyc)\b', t) for t in traces),
                          'NTP show has no usable command trace; not proof of correct routing context')
            for trace in traces:
                if re.search(r'\b(ntpstat|ntpq|chronyc)\b', trace):
                    wrapped = bool(re.search(r'ip vrf exec mgmt|cgexec -g l3mdev:mgmt', trace))
                    pytest_assert(wrapped == (vrf == 'mgmt'),
                                  'NTP status command ignored its saved VRF')

    # NEW 7–10: four inputs, four collected cases. Rejection must keep ALL
    # saved peers/global settings and the rendered file unchanged.
    @pytest.mark.parametrize('address', ('0.0.0.0', '::', '224.0.0.1', 'ff02::1'),
                             ids=('ipv4-unspecified', 'ipv6-unspecified', 'ipv4-multicast', 'ipv6-multicast'))
    def test_ntp_rejects_invalid_server_without_changes(self, mvrf_gap_state, mvrf_ntp_daemon, address):
        state = mvrf_gap_state
        before = {table: state.table(table) for table in ('NTP', 'NTP_SERVER')}
        path = _gap_ntp_path(mvrf_ntp_daemon)
        digest = _gap_run(state.host, 'sudo sha256sum ' + shlex.quote(path))['stdout']
        state.db('ntp-touched')
        result = state.host.shell('sudo config ntp add ' + shlex.quote(address),
                                  module_ignore_errors=True, verbose=False)
        message = result.get('stdout', '') + result.get('stderr', '')
        pytest_assert(result.get('rc', 0) != 0 and re.search(
            r'invalid.*(ip|address|ConfigDB)|'
            r'(address|peer|server).*(unicast|unspecified|multicast|not allowed|not permitted)|'
            r'(unspecified|multicast).*(address|peer|server)', message, re.I),
                      'NTP must reject an unusable unicast peer for a validation reason')
        pytest_assert(all(state.table(table) == value for table, value in before.items()),
                      'Rejected NTP command damaged an existing setting')
        pytest_assert(_gap_run(state.host, 'sudo sha256sum ' + shlex.quote(path))['stdout'] == digest,
                      'Rejected NTP command changed the generated configuration')

    # NEW 11–12: one TACACS+ and one RADIUS case. Seed a realistic server BEFORE
    # enable, then let ONLY the VRF CLI migrate it. No login server is required;
    # this checks saved attributes, not external authentication success.
    @pytest.mark.parametrize('table', ('TACPLUS_SERVER', 'RADIUS_SERVER'), ids=('tacacs', 'radius'))
    def test_aaa_migration_preserves_attributes(self, mvrf_gap_state, table):
        state = mvrf_gap_state
        state.local_login()
        if table == 'RADIUS_SERVER':
            pytest_assert(len(state.table(table)) < 8, 'AAA test needs one free RADIUS server slot')
        state.transition(False)
        address = _gap_free_peer(state, table)
        state.db('aaa-seed', table, address)
        before = state.table(table)
        pytest_assert('passkey' in before[address] and 'vrf' not in before[address],
                      'AAA test peer was not prepared in the original routing context')
        for enabled in (True, False):
            state.transition(enabled)
            _gap_wait('AAA server did not migrate automatically with Management VRF',
                      lambda wanted=enabled: state.table(table).get(address, {}).get('vrf')
                      == ('mgmt' if wanted else None))
            after = state.table(table)
            pytest_assert(set(after) == set(before), 'AAA transition added or removed a server')
            for peer, fields in before.items():
                pytest_assert({k: v for k, v in fields.items() if k != 'vrf'}
                              == {k: v for k, v in after[peer].items() if k != 'vrf'},
                              'AAA migration changed port, timeout, key, or another non-VRF field')

    # NEW 13: a forbidden bind must fail BEFORE removing an existing IP.
    # Prefer an existing Ethernet, PortChannel or VLAN routed interface. Otherwise
    # use an unconfigured, down, unconnected spare port and a documentation IP.
    # Never change eth0, a VLAN member, a LAG member, or an existing VRF binding.
    def test_forbidden_front_panel_binding_preserves_ip(self, mvrf_gap_state):
        state = mvrf_gap_state
        host = state.host
        chosen = None
        namespaces = host.get_frontend_asic_namespace_list() if host.is_multi_asic else ['']
        for namespace in namespaces:
            for name, pattern in (('INTERFACE', r'Ethernet\d+'),
                                  ('PORTCHANNEL_INTERFACE', r'PortChannel\d+'),
                                  ('VLAN_INTERFACE', r'Vlan\d+')):
                table = namespace + '::' + name if namespace else name
                rows = state.table(table)
                ports = sorted({key.split('|')[0] for key in rows})
                for port in ports:
                    if not re.fullmatch(pattern, port) or rows.get(port, {}).get('vrf_name'):
                        continue
                    live = _gap_interface(host, port, namespace)
                    if any(k.startswith(port + '|') for k in rows) and live['addresses']:
                        chosen = port
                        break
                if chosen is not None:
                    break
            if chosen is not None:
                break
        if chosen is None:
            # Only use a spare in the host namespace; do not guess ASIC-local
            # cable status or move a configured VLAN/LAG member for this test.
            namespace, table = '', 'INTERFACE'
            rows = state.table(table)
            members = {k.split('|')[-1] for t in ('VLAN_MEMBER', 'PORTCHANNEL_MEMBER') for k in state.table(t)}
            ports = state.table('PORT')
            facts = host.interface_facts(verbose=False)['ansible_facts']['ansible_interface_facts']
            for port, fields in sorted(ports.items()):
                if re.fullmatch(r'Ethernet\d+', port) and port not in members and fields.get('admin_status') == 'down' \
                        and not facts.get(port, {}).get('link') and not any(
                            k == port or k.startswith(port + '|') for k in rows) \
                        and not _gap_interface(host, port)['addresses']:
                    chosen = port
                    break
        pytest_assert(chosen is not None,
                      'IP-preservation test needs an existing routed port or an unused down spare; none is safe')
        state.db('extend', table)
        original = _gap_interface(host, chosen, namespace)
        state.interface_checks[(namespace, chosen)] = original
        if not original['addresses']:
            used = [ipaddress.ip_network(k.split('|', 1)[1], strict=False) for k in rows if '|' in k]
            subnet = next((ipaddress.ip_network('198.51.100.{}/30'.format(i)) for i in range(0, 256, 4)
                           if all(n.version != 4 or not n.overlaps(ipaddress.ip_network(
                               '198.51.100.{}/30'.format(i))) for n in used)), None)
            pytest_assert(subnet is not None, 'No unused documentation subnet for the temporary port IP')
            address = str(next(subnet.hosts())) + '/30'
            state.db('probe-ip', chosen, address, namespace, table)
            _gap_run(host, 'sudo config interface ip add {} {}'.format(chosen, address))
            _gap_wait('Temporary front-panel IP did not reach Linux',
                      lambda: address.split('/')[0] in [a[1] for a in _gap_interface(host, chosen)['addresses']])
        before = state.table(table)
        linux = _gap_interface(host, chosen, namespace)
        option = ' -n ' + shlex.quote(namespace) if namespace else ''
        result = host.shell('sudo config interface{} vrf bind {} mgmt'.format(option, chosen),
                            module_ignore_errors=True, verbose=False)
        message = result.get('stdout', '') + result.get('stderr', '')
        pytest_assert(result.get('rc', 0) != 0 and re.search(
            r'front.panel.*(cannot|not).*bound|management.*reserved|'
            r'(mgmt|management).*only.*eth0|only.*eth0.*(mgmt|management)', message, re.I),
            'Front-panel bind must be rejected by the management-VRF validation')
        pytest_assert(state.table(table) == before, 'Rejected bind removed an IP or changed saved rows')
        pytest_assert(_gap_interface(host, chosen, namespace) == linux,
                      'Rejected bind changed Linux addresses or membership')


# ===========================================================================
# SECTION 3 — TWO HLD TRAFFIC CHECKS, AFTER THE EXISTING 22 CASES
#
# These need two working IPv4 PTF endpoints: management and front-panel.
# Use addresses already assigned by the testbed; never guess an unused IP,
# move eth0, change an ACL/sysctl, or install a route to force a passing test.
# If no suitable PTF endpoint exists, report a prerequisite skip, not a pass.
# Existing module and per-case backups still own DUT configuration rollback.
# ===========================================================================
DUAL_PATH_PROBE_SCRIPT = r'''
import json
import os
import secrets
import socket
import sys
import time
from pathlib import Path

from scapy.all import ARP, ICMP, IP, UDP, AsyncSniffer, Ether, Raw, get_if_hwaddr, sendp, srp1
from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse, SNMPvarbind


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def packet_kind(packet, endpoints, token, port):
    # Ignore unrelated traffic and the probe sent OUT of the source interface.
    if not (IP in packet and UDP in packet and Raw in packet and Ether in packet):
        return None
    if packet[UDP].dport != port:
        return None
    payload = bytes(packet[Raw].load).decode('ascii', errors='ignore')
    for side, endpoint in endpoints.items():
        if (packet.sniffed_on != endpoint['interface'] or packet[IP].dst != endpoint['source']
                or packet[Ether].dst.lower() != endpoint['client_mac'].lower()):
            continue
        other = 'default' if side == 'mgmt' else 'mgmt'
        if payload == token + ':control:' + side and packet[IP].src == endpoint['dut']:
            return 'control', side
        if payload == token + ':cross:' + other and packet[IP].src == endpoints[other]['source']:
            return 'cross', other
    return None


def prepare(endpoints):
    for side, endpoint in endpoints.items():
        interface, source, target = endpoint['interface'], endpoint['source'], endpoint['dut']
        endpoint['client_mac'] = get_if_hwaddr(interface)
        answer = srp1(Ether(src=endpoint['client_mac'], dst='ff:ff:ff:ff:ff:ff') /
                      ARP(hwsrc=endpoint['client_mac'], psrc=source, pdst=target),
                      iface=interface, timeout=3, retry=2, verbose=False)
        require(answer is not None and ARP in answer and answer[ARP].op == 2
                and answer[ARP].psrc == target, side + ': DUT did not answer ARP on the selected path')
        endpoint['dut_mac'] = answer[ARP].hwsrc
        marker = secrets.token_hex(8).encode()
        answer = srp1(Ether(src=endpoint['client_mac'], dst=endpoint['dut_mac']) /
                      IP(src=source, dst=target) /
                      ICMP(id=secrets.randbelow(65536)) / Raw(marker),
                      iface=interface, timeout=3, retry=2, verbose=False)
        require(answer is not None and IP in answer and ICMP in answer
                and answer[IP].src == target and answer[IP].dst == source
                and answer[ICMP].type == 0 and Raw in answer and bytes(answer[Raw].load) == marker,
                side + ': same-VRF ping prerequisite failed; isolation cannot be judged')
    return endpoints


def snmp_query(endpoint, community):
    request_id = secrets.randbelow(2147483647)
    port = 20000 + secrets.randbelow(40000)
    request = (Ether(src=endpoint['client_mac'], dst=endpoint['dut_mac']) /
               IP(src=endpoint['source'], dst=endpoint['dut']) / UDP(sport=port, dport=161) /
               SNMP(version=1, community=community, PDU=SNMPget(id=request_id,
                    varbindlist=[SNMPvarbind(oid='1.3.6.1.2.1.1.1.0')])))
    answer = srp1(request, iface=endpoint['interface'], timeout=3, retry=4, verbose=False)
    require(answer is not None and IP in answer and UDP in answer and SNMP in answer
            and answer[IP].src == endpoint['dut'] and answer[IP].dst == endpoint['source']
            and answer[UDP].sport == 161 and answer[UDP].dport == port,
            'SNMP did not reply on the selected path')
    pdu = answer[SNMP].PDU
    require(isinstance(pdu, SNMPresponse) and int(pdu.id.val) == request_id
            and int(pdu.error.val) == 0 and len(pdu.varbindlist) == 1,
            'SNMP reply was not a successful response to this request')
    value = pdu.varbindlist[0].value.val
    require(isinstance(value, bytes) and bool(value), 'SNMP sysDescr reply was empty or invalid')
    return value


def ssh_login(endpoint, credentials, boot_id):
    import paramiko

    class DutHostKeyPolicy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            require([key.get_name(), key.get_base64()] in credentials['host_keys'],
                    'SSH server key does not match this DUT')

    # Bind the real client socket to this path; an SSH banner is not a login.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                        endpoint['interface'].encode() + bytes([0]))
        sock.bind((endpoint['source'], 0))
        sock.settimeout(10)
        sock.connect((endpoint['dut'], 22))
        with paramiko.SSHClient() as client:
            client.set_missing_host_key_policy(DutHostKeyPolicy())
            client.connect(endpoint['dut'], sock=sock, username=credentials['username'],
                           password=credentials['password'], allow_agent=False, look_for_keys=False,
                           timeout=10, banner_timeout=10, auth_timeout=10)
            _, stdout, _ = client.exec_command('cat /proc/sys/kernel/random/boot_id', timeout=10)
            require(stdout.read().decode().strip() == boot_id and stdout.channel.recv_exit_status() == 0,
                    'SSH login did not return this DUT boot ID')


def services(config):
    descriptions = []
    for side, endpoint in config['endpoints'].items():
        try:
            descriptions.append(snmp_query(endpoint, config['community']))
            ssh_login(endpoint, config['credentials'], config['boot_id'])
        except Exception as error:
            reason = str(error) if isinstance(error, RuntimeError) else type(error).__name__
            raise RuntimeError(side + ' path: ' + reason) from None
    require(descriptions[0] == descriptions[1], 'The two SNMP paths returned different DUT descriptions')
    return {'mgmt': {'snmp': True, 'ssh': True}, 'default': {'snmp': True, 'ssh': True}}


def isolation(config, directory):
    endpoints, token, port = config['endpoints'], config['token'], config['port']
    controls, crossed = set(), set()

    def received(packet):
        kind = packet_kind(packet, endpoints, token, port)
        if kind is not None:
            (controls if kind[0] == 'control' else crossed).add(kind[1])

    # Publish readiness only after packet capture is actually running.
    sniffer = AsyncSniffer(iface=[e['interface'] for e in endpoints.values()], store=False,
                          filter='udp and dst port ' + str(port), prn=received,
                          started_callback=lambda: (directory / 'capture-ready').touch())
    sniffer.start()
    try:
        deadline = time.monotonic() + 35
        while controls != {'mgmt', 'default'} and time.monotonic() < deadline:
            time.sleep(0.1)
        require(controls == {'mgmt', 'default'},
                'DUT-to-client capture controls failed; missing packets are not proof of isolation')
        for side, endpoint in endpoints.items():
            other = 'default' if side == 'mgmt' else 'mgmt'
            # Raw Ethernet injection forces the packet THROUGH the DUT, even
            # though both destination IPs belong to this same PTF host.
            packet = (Ether(src=endpoint['client_mac'], dst=endpoint['dut_mac']) /
                      IP(src=endpoint['source'], dst=endpoints[other]['source'], ttl=64) /
                      UDP(sport=port, dport=port) / Raw((token + ':cross:' + side).encode()))
            sendp(packet, iface=endpoint['interface'], count=3, inter=0.1, verbose=False)
        time.sleep(5)
    finally:
        sniffer.stop()
    require(not crossed, 'Cross-VRF forwarding detected from: ' + ', '.join(sorted(crossed)))
    return {'controls': sorted(controls), 'crossed': sorted(crossed), 'probes_per_direction': 3}


if __name__ == '__main__':
    directory = Path(__file__).parent
    stage = sys.argv[1]
    try:
        config = json.loads((directory / 'input.json').read_text())
        result = (prepare(config['endpoints']) if stage == 'prepare' else
                  services(config) if stage == 'services' else isolation(config, directory))
        output = {'ok': True, 'result': result}
    except Exception as error:
        # Do not put credentials, SNMP community or exception locals in logs.
        output = {'ok': False, 'stage': stage, 'error_type': type(error).__name__}
        if isinstance(error, RuntimeError):
            output['reason'] = str(error)
    temporary = directory / (stage + '.json.tmp')
    temporary.write_text(json.dumps(output))
    os.replace(str(temporary), str(directory / (stage + '.json')))
    sys.exit(0 if output['ok'] else 1)
'''


def _dual_path_endpoints(dut_links, ptf_links, management_ip, management_interface, ptf_ports):
    """Find two existing, directly connected IPv4 clients; allocate no addresses."""
    management = ipaddress.ip_address(management_ip)
    if management.version != 4:
        return None
    endpoints = {}
    for dut in dut_links:
        name = dut['ifname']
        if name == 'eth0':
            side = 'mgmt'
        elif name.startswith(('Ethernet', 'PortChannel', 'Vlan')) and not dut.get('master'):
            side = 'default'
        else:
            continue
        if 'UP' not in dut.get('flags', []):
            continue
        for address in dut.get('addr_info', []):
            if address.get('family') != 'inet' or address.get('scope') != 'global':
                continue
            target = ipaddress.ip_interface('{}/{}'.format(address['local'], address['prefixlen']))
            if side == 'mgmt' and target.ip != management:
                continue
            for client in ptf_links:
                interface = client['ifname']
                if 'UP' not in client.get('flags', []):
                    continue
                if ((side == 'mgmt' and interface != management_interface) or
                        (side == 'default' and (interface == management_interface or
                         interface.split('.')[0] not in ptf_ports or client.get('master')))):
                    continue
                for peer in client.get('addr_info', []):
                    if peer.get('family') != 'inet' or peer.get('scope') != 'global':
                        continue
                    source = ipaddress.ip_interface('{}/{}'.format(peer['local'], peer['prefixlen']))
                    if source.ip != target.ip and source.ip in target.network and target.ip in source.network:
                        endpoints.setdefault(side, {'interface': interface, 'source': str(source.ip),
                                                    'dut': str(target.ip), 'dut_interface': name})
    if set(endpoints) != {'mgmt', 'default'}:
        return None
    if (endpoints['mgmt']['interface'] == endpoints['default']['interface'] or
            endpoints['mgmt']['source'] == endpoints['default']['source']):
        return None
    return endpoints


def _dual_path_probe(ptfhost, directory, action):
    command = 'sudo timeout 100 python3 {} {}'.format(shlex.quote(directory + '/probe.py'), action)
    result = ptfhost.shell(command, module_ignore_errors=True, verbose=False)
    output = _gap_json(ptfhost, 'sudo cat ' + shlex.quote(directory + '/' + action + '.json'))
    pytest_assert(result.get('rc') == 0 and output.get('ok'),
                  'Dual-path {} check failed: {}'.format(action, output))
    return output['result']


def _dual_path_service_input(host, ptfhost, directory, config, request):
    # Keep credentials out of test locals when pytest uses --showlocals.
    __tracebackhide__ = True
    # Resolve this DUT's working password, including alternate passwords.
    # Inventory may still contain an unsuccessful primary one.
    creds = creds_on_dut(host)
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')
    pytest_assert(bool(username) and bool(password), 'Selected DUT needs resolved password-login credentials')
    keys = ("import glob,json,pathlib; print(json.dumps([pathlib.Path(p).read_text().split()[:2] "
            "for p in glob.glob('/etc/ssh/ssh_host_*_key.pub')]))")
    private = dict(config, community=creds['snmp_rocommunity'],
                   credentials={'username': username, 'password': password,
                                'host_keys': _gap_json(host, 'sudo python3 -c ' + shlex.quote(keys))},
                   boot_id=_gap_run(host, 'cat /proc/sys/kernel/random/boot_id')['stdout'].strip())
    try:
        ptfhost.copy(content=json.dumps(private), dest=directory + '/input.json', mode=0o600, verbose=False)
    except Exception:
        pytest.fail('Could not write the private PTF service-probe input', pytrace=False)


@pytest.fixture
def mvrf_dual_path(mvrf_gap_state, ptfhost, tbinfo):
    """Use real assigned PTF addresses; leave interfaces, routes and ACLs alone."""
    state = mvrf_gap_state
    host = state.host
    verify_show_command(host, mvrf=True)
    if ipaddress.ip_address(host.mgmt_ip).version != 4:
        pytest.skip('These two HLD cases currently need IPv4 management and front-panel endpoints')
    route = _gap_json(ptfhost, 'ip -j -4 route get ' + shlex.quote(host.mgmt_ip))[0]
    graph = host.get_extended_minigraph_facts(tbinfo)
    ports = {'eth{}'.format(index) for index in graph['minigraph_ptf_indices'].values()}
    endpoints = _dual_path_endpoints(_gap_json(host, 'ip -j -4 address show'),
                                     _gap_json(ptfhost, 'ip -j -4 address show'),
                                     host.mgmt_ip, route.get('dev'), ports)
    if endpoints is None:
        pytest.skip('Needs an existing PTF IPv4 address in a directly connected DUT front-panel subnet '
                    'and a separate on-link management endpoint; no IP was guessed or changed')
    dependency = ptfhost.command('python3 -c "import paramiko; import scapy.layers.snmp"',
                                 module_ignore_errors=True, verbose=False)
    pytest_assert(dependency.get('rc') == 0, 'PTF needs Python 3 Scapy SNMP and Paramiko for these tests')
    directory = _gap_run(ptfhost, 'sudo mktemp -d /tmp/mvrf-dual.XXXXXXXX')['stdout'].strip()
    pytest_assert(re.fullmatch(r'/tmp/mvrf-dual\.[A-Za-z0-9]+', directory), 'Unexpected PTF backup path')
    config = {'endpoints': endpoints, 'token': directory.rsplit('.', 1)[-1], 'port': 49161}
    try:
        ptfhost.copy(content=DUAL_PATH_PROBE_SCRIPT, dest=directory + '/probe.py', mode=0o600)
        ptfhost.copy(content=json.dumps(config), dest=directory + '/input.json', mode=0o600, verbose=False)
        config['endpoints'] = _dual_path_probe(ptfhost, directory, 'prepare')
        yield state, ptfhost, directory, config
    finally:
        # Any background capture is bounded to 100 seconds. Stop only this
        # private script, and check its command line before signalling its PID.
        stop = ("import os,signal,time\nfrom pathlib import Path\nroot=Path({!r})\np=root/'capture.pid'\n"
                "try:\n pid=int(p.read_text()) if p.exists() else 0\n"
                " cmd=Path('/proc/'+str(pid)+'/cmdline')\n"
                " if pid>1 and str(root/'probe.py').encode() in cmd.read_bytes().split(bytes([0])):\n"
                "  os.kill(pid,signal.SIGTERM)\n"
                "  for attempt in range(50):\n"
                "   if str(root/'probe.py').encode() not in cmd.read_bytes().split(bytes([0])): break\n"
                "   time.sleep(0.1)\n"
                "  else: raise RuntimeError('Owned capture did not stop; keeping private files')\n"
                "except (FileNotFoundError,ProcessLookupError):\n pass\n").format(directory)
        _gap_run(ptfhost, 'sudo python3 -c ' + shlex.quote(stop))
        ptfhost.file(path=directory, state='absent')


class TestMvrfDualPath:
    """NEW: check simultaneous service access and real cross-VRF traffic isolation."""

    def test_snmp_and_ssh_in_both_vrfs(self, mvrf_dual_path, request):
        state, ptfhost, directory, config = mvrf_dual_path
        host = state.host
        # Configure the saved default listener, not an image/template repair.
        # Keep the existing mgmt listener. CLI spelling differs across images,
        # so this service test deliberately does not claim CLI validation.
        _wait_for_snmp_restart_slot(host)
        state.db('snmp-default-listener', config['endpoints']['default']['dut'])
        _gap_wait('SNMP did not recover with both listeners', lambda: _gap_snmp_ready(host))
        # Secrets stay in this root-only PTF directory and are never printed.
        _dual_path_service_input(host, ptfhost, directory, config, request)
        logger.info('Checking real SNMP replies and authenticated SSH through management and front-panel paths')
        _dual_path_probe(ptfhost, directory, 'services')
        verify_show_command(host, mvrf=True)

    def test_no_forwarding_between_mgmt_and_default(self, mvrf_dual_path):
        state, ptfhost, directory, config = mvrf_dual_path
        ptfhost.copy(content=json.dumps(config), dest=directory + '/input.json', mode=0o600, verbose=False)
        launch = ('nohup timeout 100 python3 {0}/probe.py isolation > {0}/capture.log 2>&1 '
                  '< /dev/null & echo $! > {0}/capture.pid').format(shlex.quote(directory))
        _gap_run(ptfhost, 'sudo sh -c ' + shlex.quote(launch))
        _gap_wait('PTF packet capture did not become ready', lambda: ptfhost.command(
            'sudo test -e ' + shlex.quote(directory + '/capture-ready'),
            module_ignore_errors=True, verbose=False).get('rc') == 0)
        # Prove both receivers can see packets sent by the DUT in their own
        # VRF before interpreting missing cross-VRF packets as successful isolation.
        sender = ('import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); '
                  's.bind((sys.argv[1],0)); s.sendto(sys.argv[3].encode(),(sys.argv[2],int(sys.argv[4])))')
        for side, endpoint in config['endpoints'].items():
            command = 'sudo ip vrf exec {} python3 -c {} {} {} {} {}'.format(
                side, shlex.quote(sender), shlex.quote(endpoint['dut']), shlex.quote(endpoint['source']),
                shlex.quote(config['token'] + ':control:' + side), config['port'])
            _gap_run(state.host, command)
        _gap_wait('PTF isolation capture did not finish', lambda: ptfhost.command(
            'sudo test -e ' + shlex.quote(directory + '/isolation.json'),
            module_ignore_errors=True, verbose=False).get('rc') == 0)
        result = _gap_json(ptfhost, 'sudo cat ' + shlex.quote(directory + '/isolation.json'))
        pytest_assert(result.get('ok'), 'Isolation check failed: {}'.format(result))
        pytest_assert(result['result']['controls'] == ['default', 'mgmt'] and not result['result']['crossed'],
                      'Both positive controls and zero cross-VRF packets are required')
        verify_show_command(state.host, mvrf=True)


# ===========================================================================
# SECTION 4 — FIVE RADIUS CHECKS
#
# The first four check service behaviour/state, not invalid CLI arguments.
# The fifth checks package contents, not resistance to a BlastRADIUS attack.
# Nothing installs packages or changes the system PTF RADIUS service.
# ===========================================================================
def _radius_dut(state, action, *args):
    return _gap_json(state.host, 'sudo python3 {} {} {}'.format(
        shlex.quote(state.directory + '/radius-dut.py'), shlex.quote(action),
        ' '.join(shlex.quote(str(arg)) for arg in args)))


@pytest.fixture
def mvrf_radius_state(mvrf_gap_state):
    state = mvrf_gap_state
    # This also backs up global NAS/source settings before the login fixture
    # temporarily supplies a controlled input with no explicit NAS override.
    state.db('extend', 'RADIUS')
    state.host.copy(content=radius_test_helper.DUT_RADIUS_SCRIPT,
                    dest=state.directory + '/radius-dut.py', mode=0o600, verbose=False)
    return state


class MvrfRadiusServer:
    """One private server per case. Never put its secret payload in assertions."""

    def __init__(self, state, ptfhost, directory):
        self.state, self.ptfhost, self.directory = state, ptfhost, directory
        self.private = None
        self.server = None
        self.port = None
        self.failed = False

    def call(self, action):
        result = self.ptfhost.shell('sudo python3 {} {}'.format(
            shlex.quote(self.directory + '/probe.py'), shlex.quote(action)),
            module_ignore_errors=True, verbose=False)
        try:
            reply = json.loads(result.get('stdout', ''))
        except ValueError:
            self.failed = True
            pytest.fail('Private RADIUS helper returned no valid result; inspect its private logs', pytrace=False)
        if result.get('rc') != 0 or not reply.get('ok'):
            self.failed = True
        pytest_assert(result.get('rc') == 0 and reply.get('ok'),
                      'Private RADIUS {} failed ({}); inspect {}'.format(
                          action, reply.get('error', 'unknown'), self.directory))
        return reply['result']

    def prepare(self):
        __tracebackhide__ = True
        host = self.state.host
        self.server = str(ipaddress.IPv4Address(self.ptfhost.mgmt_ip))
        dut = ipaddress.IPv4Address(host.mgmt_ip)
        links = _gap_json(host, 'ip -j -4 address show dev eth0')[0]['addr_info']
        on_link = any(a.get('family') == 'inet' and a.get('local') == str(dut)
                      and ipaddress.ip_address(self.server) in ipaddress.ip_network(
                          '{}/{}'.format(a['local'], a['prefixlen']), strict=False) for a in links)
        if not on_link:
            pytest.skip('RADIUS login cases need an existing on-link IPv4 PTF management endpoint; no NAT/IP changes')
        nss = _gap_run(host, 'sudo cat /etc/radius_nss.conf')['stdout']
        if re.search(r'^\s*many_to_one\s*=\s*y', nss, re.M | re.I):
            pytest.skip('Owned-user RADIUS fixture needs one-to-one NSS mapping, not many_to_one')
        available = self.call('available')
        if 'prerequisite' in available:
            pytest.skip(available['prerequisite'])
        token = secrets.token_hex(6)
        keys = ("import glob,json,pathlib; print(json.dumps([pathlib.Path(p).read_text().split()[:2] "
                "for p in glob.glob('/etc/ssh/ssh_host_*_key.pub')]))")
        self.private = {'server': self.server, 'dut': str(dut), 'secret': secrets.token_hex(24),
                        'lifetime': int(900 + 6 * self.state.restart_interval),
                        'host_keys': _gap_json(host, 'sudo python3 -c ' + shlex.quote(keys)),
                        'users': {profile: {'name': 'mvrfr_' + token + '_' + profile,
                                            'password': secrets.token_hex(24), 'level': level}
                                  for profile, level in (('mpl15', 15), ('mpl1', 1),
                                                         ('cisco15', 15), ('cisco1', 1))}}
        try:
            self.ptfhost.copy(content=json.dumps(self.private), dest=self.directory + '/input.json',
                              mode=0o600, verbose=False)
            started = self.call('start')
            self.port = started['port']
            self.private['port'] = self.port
            host.copy(content=json.dumps(self.private), dest=self.state.directory + '/radius-input.json',
                      mode=0o600, verbose=False)
        except Exception:
            self.failed = True
            pytest.fail('Could not prepare private RADIUS input/server; inspect private logs', pytrace=False)
        _radius_dut(self.state, 'register')

    def configure(self, vrf):
        # Used once, before a migration test starts. Never repair its result.
        _radius_dut(self.state, 'configure', vrf)
        _gap_wait('Controlled RADIUS PAM/NSS configuration did not appear',
                  lambda: _radius_dut(self.state, 'ready')['ready'])
        # Prove the inventory's separate local login still works before probing.
        wait_for_ssh_and_reset_connection(self.state.host, self.state.localhost)

    def login(self, profile='mpl15'):
        _gap_wait('RADIUS PAM configuration did not follow its saved VRF',
                  lambda: _radius_dut(self.state, 'ready')['ready'])
        result = self.call(profile)
        identity = _radius_dut(self.state, 'identity', self.private['users'][profile]['name'])
        pytest_assert(identity['exists'] and identity['local_password_locked']
                      and identity['level'] == self.private['users'][profile]['level'],
                      'Authenticated RADIUS user did not receive the server-returned privilege')
        return result


@pytest.fixture
def mvrf_radius_server(mvrf_radius_state, ptfhost):
    state = mvrf_radius_state
    if ipaddress.ip_address(state.host.mgmt_ip).version != 4 or ipaddress.ip_address(ptfhost.mgmt_ip).version != 4:
        pytest.skip('Private RADIUS login fixture currently supports IPv4 management endpoints')
    state.local_login()
    directory = _gap_run(ptfhost, 'sudo mktemp -d /tmp/mvrf-radius.XXXXXXXX')['stdout'].strip()
    pytest_assert(re.fullmatch(r'/tmp/mvrf-radius\.[A-Za-z0-9]+', directory), 'Unexpected PTF RADIUS directory')
    server = MvrfRadiusServer(state, ptfhost, directory)
    copied = False
    try:
        ptfhost.copy(content=Path(radius_test_helper.__file__).read_text(),
                     dest=directory + '/probe.py', mode=0o600, verbose=False)
        copied = True
        server.prepare()
        yield server
    finally:
        try:
            # Do not leave the controller relying on a server about to stop.
            state.local_login()
        finally:
            if copied:
                server.call('stop')
            if not server.failed:
                ptfhost.file(path=directory, state='absent')
        # mvrf_gap_state then restores original tables and removes registered
        # test users/homes/cache. A failed restore retains the private DUT backup.


class TestMvrfRadius:
    """Service behaviour and package evidence; no invalid-input CLI cases."""

    def test_radius_login_across_vrf_transitions(self, mvrf_radius_server):
        """A real existing server follows off/on/off without reseeding."""
        server = mvrf_radius_server
        state = server.state
        state.transition(False)
        server.configure('default')
        before = state.table('RADIUS_SERVER')[server.server]
        server.login()
        for enabled in (True, False):
            state.transition(enabled)
            after = state.table('RADIUS_SERVER')[server.server]
            pytest_assert(after.get('vrf') == ('mgmt' if enabled else None),
                          'Existing RADIUS server did not migrate with Management VRF')
            pytest_assert({k: v for k, v in after.items() if k != 'vrf'}
                          == {k: v for k, v in before.items() if k != 'vrf'},
                          'RADIUS migration changed a non-VRF server field')
            server.login()  # Fresh SSH + fresh server Access-Accept each time.

    def test_radius_request_uses_management_nas_ip(self, mvrf_radius_server):
        """Check the actual Access-Request, not only the generated PAM line."""
        server = mvrf_radius_server
        addresses = [str(ipaddress.ip_interface(key.split('|', 1)[1]).ip)
                     for key in server.state.table('MGMT_INTERFACE')
                     if key.startswith('eth0|') and ipaddress.ip_interface(key.split('|', 1)[1]).version == 4]
        if len(addresses) != 1:
            pytest.skip('Default NAS-IP oracle needs exactly one configured MGMT_INTERFACE eth0 IPv4 address')
        server.configure('mgmt')
        result = server.login()
        pytest_assert(all(row['nas_ip'] == addresses[0] for row in result['accepts']),
                      'RADIUS Access-Request did not carry the configured management NAS-IP')

    def test_radius_cisco_avpair_privilege(self, mvrf_radius_server):
        """Cisco-AVPair-only replies match standard MPL replies at levels 1/15."""
        server = mvrf_radius_server
        server.configure('mgmt')
        for level in (1, 15):
            control = server.login('mpl' + str(level))
            cisco = server.login('cisco' + str(level))
            # Do not hardcode platform-specific admin group names or numeric GIDs.
            pytest_assert(control['groups'] == cisco['groups'],
                          'Cisco-AVPair privilege did not produce the standard MPL group membership')

    def test_radius_delete_removes_only_its_pam_file(self, mvrf_radius_state):
        """Delete one owned peer; keep the other active peer file intact."""
        state = mvrf_radius_state
        state.local_login()
        pytest_assert(len(state.table('RADIUS_SERVER')) <= 6, 'RADIUS cleanup case needs two free server slots')
        first = _gap_free_peer(state, 'RADIUS_SERVER')
        state.db('aaa-seed', 'RADIUS_SERVER', first)
        second = _gap_free_peer(state, 'RADIUS_SERVER')
        state.db('aaa-seed', 'RADIUS_SERVER', second)
        _gap_wait('Owned RADIUS PAM files were not generated', lambda: all(
            _radius_dut(state, 'pam-file', address)['exists'] for address in (first, second)))
        survivor = _radius_dut(state, 'pam-file', second)['digest']
        _gap_run(state.host, 'sudo config radius delete ' + shlex.quote(first))
        _gap_wait('Deleted RADIUS server left its PAM secret file',
                  lambda: not _radius_dut(state, 'pam-file', first)['exists'])
        pytest_assert(first not in state.table('RADIUS_SERVER') and second in state.table('RADIUS_SERVER'),
                      'RADIUS delete removed the wrong saved server')
        pytest_assert(_radius_dut(state, 'pam-file', second)['digest'] == survivor,
                      'Deleting one RADIUS peer damaged the active peer file')

    def test_radius_client_message_authenticator_support(self, mvrf_radius_state):
        """Check that the installed PAM binary exposes the hardening option."""
        info = _radius_dut(mvrf_radius_state, 'package')
        pytest_assert(info.get('installed') and info.get('modules'), 'RADIUS PAM package/module is not installed')
        pytest_assert(all(module['requires_message_authenticator'] for module in info['modules']),
                      'Installed RADIUS PAM binary lacks require_message_authenticator support')
        logger.info('RADIUS client package=%s; PAM module checksums=%s (binary evidence, not an attack test)',
                    info['version'], [module['sha256'] for module in info['modules']])
