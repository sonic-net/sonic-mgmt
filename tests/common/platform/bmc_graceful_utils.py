import logging
import os
import re
import shlex
import subprocess
import uuid

from contextlib import contextmanager
from pytest_ansible.errors import AnsibleConnectionFailure
from tests.common.cert_utils import create_gnmi_cert_generator
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import (
    CONFIG_DB,
    STATE_DB,
    redis_del,
    redis_hget,
    redis_hgetall,
    redis_hset,
)
from tests.common.platform.bmc_utils import (
    BMC_EVENT_LOG,
    get_host_uptime,
    get_switch_host_or_skip_test,
    get_system_leak_status,
    pause_pmon_daemon,
    recover_switch_host_after_power_off,
    set_system_leak_status,
    wait_host_off,
    wait_host_on,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


# bmcctld operation results
OP_RESULT_SUCCESS_GRACEFUL = 'SUCCESS_GRACEFUL'
OP_RESULT_SUCCESS_FORCED = 'SUCCESS_FORCED'
OP_RESULT_SUCCESS = 'SUCCESS'
OP_RESULT_PREEMPTED = 'PREEMPTED'
OP_RESULT_OFF_LEAK_BLOCKED = 'OFF_LEAK_BLOCKED'
# What bmcctld writes into op_result when it admits an operation, and rewrites when the
# operation ends. Reading it back means the operation is still in flight, not that it finished
# without a result.
OP_RESULT_IN_FLIGHT = '-'

# op_reason
OP_REASON_NONE = '-'
OP_REASON_NOT_QUALIFIED = 'not_qualified'
OP_REASON_TIMEOUT_ZERO = 'timeout_zero'
OP_REASON_ALREADY_OFF = 'already_off'
OP_REASON_PREEMPTED = 'preempted'
OP_REASON_RPC_FAILURE = 'rpc_failure'
OP_REASON_CHECK_FAILED = 'check_failed'
OP_REASON_DEADLINE = 'deadline'
OP_REASON_UNCLASSIFIED = 'unclassified'

# device_power_state
POWER_STATE_GRACEFUL_SHUTTING_DOWN = 'GRACEFUL_SHUTTING_DOWN'
POWER_STATE_POWERED_OFF = 'POWERED_OFF'
POWER_STATE_POWERED_ON = 'POWERED_ON'

# RACK_MANAGER_COMMAND
RACK_MANAGER_COMMAND_TABLE = 'RACK_MANAGER_COMMAND'
CMD_GRACEFUL_SHUT = 'GRACEFUL_SHUT'
CMD_GRACEFUL_RESTART = 'GRACEFUL_RESTART'
CMD_POWER_ON = 'POWER_ON'
CMD_POWER_OFF = 'POWER_OFF'
CMD_POWER_CYCLE = 'POWER_CYCLE'
CMD_STATUS_DONE = 'DONE'
CMD_STATUS_FAILED = 'FAILED'
CMD_TERMINAL_STATES = (CMD_STATUS_DONE, CMD_STATUS_FAILED)
CMD_RESULT_SUCCESS = 'SUCCESS'
CMD_RESULT_BUSY = 'BUSY'
CMD_RESULT_PREEMPTED = 'PREEMPTED'
CMD_RESULT_CRITICAL_LEAK_PRESENT = 'CRITICAL_LEAK_PRESENT'

HOST_STATE_KEY = 'HOST_STATE|switch-host'
SYSTEM_LEAK_STATUS_KEY = 'SYSTEM_LEAK_STATUS|system'
CHASSIS_MODULE_KEY = 'CHASSIS_MODULE|SWITCH-HOST'
CHASSIS_MODULE_TABLE_KEY = 'CHASSIS_MODULE_TABLE|SWITCH-HOST'

# op_trigger values written by bmcctld
TRIGGER_CLI_SHUTDOWN = 'CHASSIS_MODULE:ADMIN_DOWN'
TRIGGER_CLI_STARTUP = 'CHASSIS_MODULE:ADMIN_UP'

# 'show chassis modules status' columns. The first group predates this feature and has to keep
# its order; Result and Request-Id are the two columns the feature adds.
CHASSIS_STATUS_BASE_COLUMNS = ('Name', 'Description', 'Oper-Status', 'Admin-Status', 'Serial')
CHASSIS_STATUS_RESULT_COLUMN = 'Result'
CHASSIS_STATUS_REQUEST_ID_COLUMN = 'Request-Id'


def rack_manager_trigger(command):
    """Return the op_trigger bmcctld writes for one Rack-Manager command."""
    return 'RACK_MGR_CMD:{}'.format(command)


# --- BMC-link provisioning ---
BMC_LINK_DIR = '/etc/sonic/bmc-link'
# A deployment installs the BMC-link material itself and can point bmcctld at where it put it,
# through this CONFIG_DB entry on the BMC. The three paths are independent: they need share
# neither a directory nor the default file names. With the entry absent bmcctld falls back to
# the defaults below, which is what every image ships with today.
BMC_GNOI_CERTS_KEY = 'BMC_GNOI|certs'
# CONFIG_DB field -> the file this suite generates, which is also the default base name, and
# the mode to install it with.
BMC_CERT_FIELDS = (
    ('client_crt', 'client.crt', '0644'),
    ('client_key', 'client.key', '0600'),
    ('ca_crt', 'ca.crt', '0644'),
)
# The host side is not configurable: the GNMI rows this suite writes name these paths itself.
HOST_CERT_LAYOUT = (
    ('server.cer', 'server.cer', '0644'),
    ('server.key', 'server.key', '0600'),
    ('ca.crt', 'ca.cer', '0644'),
)
# Must match bmcctld's GNOI_SERVER_NAME, otherwise the TLS host name check fails.
GNOI_SERVER_CN = 'switch-host.bmc-link.sonic'
BMC_CLIENT_CN = 'bmc.bmc-link.sonic'
TEST_CA_CN = 'test.ca.bmc-link.sonic'
GNOI_CLIENT_ROLE = 'gnoi_readwrite'
DEFAULT_GNMI_PORT = 8080

# --- pre-shutdown test hook ---
HOOK_DIR = '/host/bmc-graceful-test'
HOOK_COUNT_FILE = HOOK_DIR + '/hook.count'
HOOK_ORIGINAL = HOOK_DIR + '/pre_reboot_hook.original'
# Flags live on tmpfs so a power cycle always clears them.
HOOK_HOLD_FLAG = '/run/bmc-graceful.hold'
HOOK_FAIL_FLAG = '/run/bmc-graceful.fail'
# scripts/reboot bounds the hook by platform.json pre_shutdown_hook_timeout_secs (default 60s)
# and treats a non-zero exit as a failed pre-shutdown. Release the hold before that fires so a
# held hook reports the outcome the test is after instead of 'check_failed'.
HOOK_HOLD_MAX_SECS = 50

# Bound on closing one ControlMaster socket, so a wedged master cannot hang the run.
SSH_CONTROL_EXIT_TIMEOUT_SECS = 10

# Keep the graceful timeout below HOOK_HOLD_MAX_SECS so a held hook can outlast the deadline.
DEFAULT_GRACEFUL_TIMEOUT = 30

# The value the CLI documents as its own default. Used as a valid setting well away from the
# lower boundary. This release declares the argument click.IntRange(min=0), so 0 is the only
# boundary there is to test.
CLI_DEFAULT_GRACEFUL_TIMEOUT = 120

# --- critical system leak ---
# thermalctld's LeakSeverity values, as they reach STATE_DB. bmcctld acts on CRITICAL only.
SYSTEM_LEAK_CRITICAL = 'CRITICAL'
SYSTEM_LEAK_CLEARED = 'None'
# bmcctld's own pause between the two legs of a restart, and the window a leak has to land in
# to preempt the restart rather than the shutdown. Not configurable.
RESTART_PAUSE_SECS = 10

HOOK_SCRIPT = """#!/bin/bash
# Lab-only pre-shutdown hook installed by the BMC graceful-restart test suite.
# The original hook, if any, is kept at {original} and restored on teardown.
if [ "${{SONIC_PRE_SHUTDOWN:-0}}" != "1" ]; then
    [ -x {original} ] && exec {original} "$@"
    exit 0
fi
date -Is >> {count}
sync
[ -e {fail} ] && exit 1
timeout {hold_max} sh -c 'while test -e "$1"; do sleep 0.5; done' sh {hold}
exit 0
"""

OP_DONE_RE = re.compile(
    r'OP_DONE action=(?P<action>\S+) result=(?P<result>\S+) reason=(?P<reason>\S+) '
    r'request_id=(?P<request_id>\S+) trigger=(?P<trigger>\S+) detail=(?P<detail>.*)$'
)


def reset_ansible_ssh_control_masters():
    """Drop persistent SSH masters so the next command reconnects.

    ansible.cfg sets ControlPersist=7200s. When the switch-host power cycles the socket stays
    behind and every later command against it fails until it is closed.

    Every socket in the directory is closed, not just the switch-host's: the control path
    template is an ansible.cfg setting this module should not have to parse, and the sockets
    belong to this session, which is serial and disruptive by design -- the only cost of
    closing a live one is that the next command reconnects.
    """
    control_path_dir = os.path.join(
        os.environ.get('ANSIBLE_HOME', os.path.expanduser('~/.ansible')), 'cp')
    try:
        sockets = os.listdir(control_path_dir)
    except OSError:
        return

    for name in sockets:
        path = os.path.join(control_path_dir, name)
        try:
            # A wedged master would otherwise block the run here for as long as it stays wedged.
            subprocess.run(['ssh', '-O', 'exit', '-o', 'ControlPath={}'.format(path), 'none'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=SSH_CONTROL_EXIT_TIMEOUT_SECS, check=False)
        except (OSError, subprocess.TimeoutExpired):
            # Closing the master politely is an optimisation, not a requirement: unlinking the
            # socket below is what actually stops the next command from reusing it.
            pass
        try:
            os.unlink(path)
        except OSError:
            # Already gone -- a successful 'ssh -O exit' removes the socket itself. Nothing is
            # left to clean up, which is the outcome this loop wanted.
            pass
    logger.info("Reset %d Ansible SSH ControlMaster socket(s)", len(sockets))


def parse_op_done(line):
    """Parse one bmcctld OP_DONE event-log line into a dict; return None if it is not one."""
    match = OP_DONE_RE.search(line)
    return match.groupdict() if match else None


class BmcGracefulEnv(object):
    """Own the reversible BMC-link fixture and the per-case switch-host recovery."""

    def __init__(self, bmc, host, local_pki_dir):
        self.bmc = bmc
        self.host = host
        self.local_pki_dir = str(local_pki_dir)
        self.host_addr = None
        self.bmc_addr = None
        self.gnmi_port = DEFAULT_GNMI_PORT
        # CONFIG_DB field -> absolute path bmcctld reads it from, filled in by _discover().
        self.bmc_cert_paths = {}
        self.hook_path = None
        self.graceful_timeout = DEFAULT_GRACEFUL_TIMEOUT
        self._original_timeout = None
        self._original_hook_present = False
        self._command_keys = set()
        # Certificate rollback is tracked per file rather than per directory: with the paths
        # configurable the material can sit among a deployment's own files, so this suite puts
        # back exactly what it displaced and removes exactly what it created.
        self._installed_certs = []          # (target, absolute path) written by this run
        self._saved_certs = {}              # (hostname, path) -> where the displaced file went
        self._created_cert_dirs = []        # (target, directory) this run had to create
        # Each flag gates exactly one rollback step, so a setup that fails half way removes what
        # it created and nothing else. In particular the platform ships a real pre_reboot_hook
        # (a firmware upgrade script); deleting it because a flag was never set would be silent
        # and only show up on the next reboot.
        self._installed = False
        self._certs_installed = False
        self._hook_installed = False
        self._timeout_recorded = False

    @classmethod
    def create(cls, bmc, local_pki_dir):
        pytest_assert(bmc.is_bmc(), "selected DUT must be the BMC of a paired setup")
        host = get_switch_host_or_skip_test(bmc)
        return cls(bmc, host, local_pki_dir)

    # ----------------------------------------------------------------- shell helpers

    @staticmethod
    def _shell(target, command, description):
        result = target.shell(command, module_ignore_errors=True)
        pytest_assert(
            result.get('rc') == 0,
            "{} failed on {}: rc={} stderr={!r}".format(
                description, target.hostname, result.get('rc'), result.get('stderr', '')))
        return result

    @staticmethod
    def _stdout(target, command):
        return (target.shell(command, module_ignore_errors=True).get('stdout', '') or '').strip()

    def _install_file(self, target, local_path, remote_path, mode):
        staged = '/tmp/bmc-graceful-{}'.format(os.path.basename(remote_path))
        target.copy(src=local_path, dest=staged, mode='0644')
        self._shell(target, "sudo install -o root -g root -m {} {} {}".format(
            mode, shlex.quote(staged), shlex.quote(remote_path)),
            "install {}".format(remote_path))
        target.file(path=staged, state='absent')

    # ----------------------------------------------------------------- discovery

    def _discover(self):
        """Read the BMC-link addresses, the gNMI port and the host platform directory."""
        self.host_addr = self._stdout(
            self.host,
            "python3 -c 'from sonic_py_common import device_info; "
            "print(device_info.get_switch_host_address())'")
        self.bmc_addr = self._stdout(
            self.host,
            "python3 -c 'from sonic_py_common import device_info; "
            "print(device_info.get_bmc_address())'")
        pytest_assert(self.host_addr and self.bmc_addr,
                      "could not read the BMC-link addresses from the switch-host")

        port = self._stdout(
            self.bmc,
            "python3 -c \"import json;print(json.load(open('/usr/share/sonic/platform/bmc.json'))"
            ".get('switch_host_gnmi_port',''))\"")
        self.gnmi_port = int(port) if port.isdigit() else DEFAULT_GNMI_PORT

        self.bmc_cert_paths = self._discover_bmc_cert_paths()

        platform = self._stdout(self.host, "sonic-cfggen -H -v DEVICE_METADATA.localhost.platform")
        pytest_assert(platform, "could not read the switch-host platform identifier")
        # scripts/reboot resolves the hook as <device dir>/<platform>/pre_reboot_hook.
        self.hook_path = '/usr/share/sonic/device/{}/pre_reboot_hook'.format(platform)

        logger.info("BMC-link: bmc=%s host=%s gnmi_port=%s hook=%s certs=%s",
                    self.bmc_addr, self.host_addr, self.gnmi_port, self.hook_path,
                    self.bmc_cert_paths)

    def _discover_bmc_cert_paths(self):
        """Return {CONFIG_DB field: absolute path} for the material bmcctld reads.

        The suite has to write the material where bmcctld will look for it. Installing it
        under the default directory while the BMC is configured to read elsewhere would leave
        bmcctld unqualified, and every case would degrade to a forced shutdown without naming
        the mismatch as the cause.
        """
        configured = redis_hgetall(self.bmc, CONFIG_DB, BMC_GNOI_CERTS_KEY) or {}
        paths = {}
        for field, name, _mode in BMC_CERT_FIELDS:
            # Resolved the way bmcctld resolves it: each field falls back on its own, and a
            # field that is set is taken as written.
            paths[field] = configured.get(field, '{}/{}'.format(BMC_LINK_DIR, name))
        # A value bmcctld would refuse is reported here rather than quietly replaced by the
        # default, which would put the material somewhere bmcctld is not going to read and turn
        # a misconfigured BMC into a suite-wide degradation with no stated cause.
        invalid = {field: path for field, path in paths.items() if not os.path.isabs(path)}
        pytest_assert(not invalid,
                      "{} carries a path bmcctld will refuse: {}. It requires an absolute path "
                      "in every field and leaves itself unqualified otherwise.".format(
                          BMC_GNOI_CERTS_KEY, invalid))
        if configured:
            logger.info("%s points bmcctld at its own material: %s", BMC_GNOI_CERTS_KEY, configured)
        return paths

    def _preflight(self):
        status, _ = self.bmc.get_pmon_daemon_status('bmcctld')
        pytest_assert(status == 'RUNNING', "bmcctld must be running, got {!r}".format(status))
        pytest_assert(
            self.bmc.shell(
                "docker exec pmon python3 -c 'import grpc; from sonic_grpc.gnoi.client import GnoiClient'",
                module_ignore_errors=True).get('rc') == 0,
            "the BMC pmon container has no gNOI client library; the graceful leg can never run")
        pytest_assert(
            self._stdout(self.bmc,
                         "docker exec pmon python3 -c 'from sonic_py_common import device_info; "
                         "print(device_info.is_switch_bmc())'") == 'True',
            "bmcctld does not recognise this device as a switch BMC")
        pytest_assert(
            self._stdout(self.host,
                         "python3 -c 'from sonic_py_common import device_info; "
                         "print(device_info.is_switch_host())'") == 'True',
            "the paired host does not recognise itself as a switch-host; 'reboot -p' would be rejected")

    # ----------------------------------------------------------------- setup / teardown

    def setup(self):
        self._preflight()
        self._discover()
        # From here on anything may fail part way, so teardown has to run.
        self._installed = True
        self._install_certificates()
        self._install_hook()
        self._original_timeout = redis_hget(
            self.bmc, CONFIG_DB, CHASSIS_MODULE_KEY, 'graceful_shutdown_timeout')
        self._timeout_recorded = True
        self.set_timeout(self.graceful_timeout)
        self.ensure_host_provisioned()
        self._verify_provisioning_effective()

    def _verify_provisioning_effective(self):
        """Fail here, rather than in every case, when the BMC-link provisioning did not take.

        Every graceful case rests on two things this fixture installs: bmcctld finding itself
        qualified, and the BMC reaching the switch-host's gNOI server. When either is untrue
        bmcctld does not report an error -- it silently skips the graceful leg and forces the
        power off. The cases would then all fail on the recorded result and read as a product
        regression rather than as a lab that was never provisioned.

        Only what the install steps cannot already prove is checked here: set_timeout(),
        _install_hook() and ensure_host_provisioned() each assert their own effect.
        """
        missing = self.missing_certificates(self.bmc, sorted(self.bmc_cert_paths.values()))
        pytest_assert(not missing,
                      "BMC-link material is missing or empty on {}: {}. bmcctld reads exactly "
                      "these paths to decide it is qualified for the graceful leg.".format(
                          self.bmc.hostname, missing))

        pytest_assert(self.bmc_can_reach_host_gnmi(),
                      "BMC cannot open {}:{}, the switch-host gNOI endpoint. "
                      "ensure_host_provisioned() only proves the host is listening; this is the "
                      "other end of that link.".format(self.host_addr, self.gnmi_port))

        pytest_assert(self.hook_count() == 0,
                      "the pre-shutdown hook has a non-zero count before any case ran; a count "
                      "left behind by an earlier run would break the cases that prove no "
                      "shutdown request reached the host")

        pytest_assert(self.host_is_online(),
                      "BMC reports the switch-host as {!r}, expected ONLINE".format(
                          self.host_state().get('device_status')))
        pytest_assert(self.host.critical_services_fully_started(),
                      "switch-host critical services are not fully started")

    def teardown(self):
        if not self._installed:
            return
        errors = []
        for step, action in (
                ('rack-manager commands', self._clear_commands),
                ('host gNMI rows', self._remove_host_gnmi_rows),
                ('pre-shutdown hook', self._remove_hook),
                ('certificates', self._remove_certificates),
                ('graceful timeout', self._restore_timeout)):
            try:
                action()
            except Exception as exc:  # cleanup is best effort: keep going and report at the end
                errors.append('{}: {}'.format(step, exc))
                logger.warning("Cleanup of %s failed: %s", step, exc)
        self._installed = False
        pytest_assert(not errors, "BMC graceful fixture cleanup failed: {}".format('; '.join(errors)))

    # ----------------------------------------------------------------- certificates

    def _generate_pki(self):
        generator = create_gnmi_cert_generator(
            server_ip=self.host_addr,
            backdate_days=7,
            dns_names=[GNOI_SERVER_CN],
            ca_cn=TEST_CA_CN,
            server_cn=GNOI_SERVER_CN,
            client_cn=BMC_CLIENT_CN,
            ca_cert_name='ca.crt', ca_key_name='ca.key',
            server_cert_name='server.cer', server_key_name='server.key',
            client_cert_name='client.crt', client_key_name='client.key',
        )
        generator.write_all(self.local_pki_dir)

    def _cert_layout(self):
        """Return (target, generated file, absolute remote path, mode) for every file to install."""
        layout = [(self.host, local_name, '{}/{}'.format(BMC_LINK_DIR, remote_name), mode)
                  for local_name, remote_name, mode in HOST_CERT_LAYOUT]
        layout += [(self.bmc, name, self.bmc_cert_paths[field], mode)
                   for field, name, mode in BMC_CERT_FIELDS]
        return layout

    def _set_aside_existing(self, target, remote_path):
        """Move a file this suite is about to write out of the way, to be put back on teardown.

        A deployed device carries its own BMC-link material at these paths and this suite must
        not be the reason it is lost.
        """
        if target.shell("sudo test -e {}".format(shlex.quote(remote_path)),
                        module_ignore_errors=True).get('rc') != 0:
            return
        saved = '{}.pretest.{}'.format(remote_path, uuid.uuid4().hex[:8])
        self._shell(target, "sudo mv {} {}".format(shlex.quote(remote_path), shlex.quote(saved)),
                    "set aside the existing {}".format(remote_path))
        self._saved_certs[(target.hostname, remote_path)] = saved

    def _ensure_parent_dir(self, target, remote_path):
        """Create the directory a file is to be installed in, remembering only what was created."""
        parent = os.path.dirname(remote_path)
        if target.shell("sudo test -d {}".format(shlex.quote(parent)),
                        module_ignore_errors=True).get('rc') == 0:
            return
        self._shell(target, "sudo install -d -m 0755 {}".format(shlex.quote(parent)),
                    "create {}".format(parent))
        self._created_cert_dirs.append((target, parent))

    def _install_certificates(self):
        self._generate_pki()
        # Set before the first write, not after the last one: a failure half way through still
        # has to be rolled back, and the flag is what teardown keys off.
        self._certs_installed = True
        for target, local_name, remote_path, mode in self._cert_layout():
            self._set_aside_existing(target, remote_path)
            self._ensure_parent_dir(target, remote_path)
            self._install_file(target, os.path.join(self.local_pki_dir, local_name),
                               remote_path, mode)
            self._installed_certs.append((target, remote_path))

    def _remove_certificates(self):
        if not self._certs_installed:
            return
        for target, remote_path in self._installed_certs:
            self._shell(target, "sudo rm -f {}".format(shlex.quote(remote_path)),
                        "remove {}".format(remote_path))
            saved = self._saved_certs.pop((target.hostname, remote_path), None)
            if saved:
                self._shell(target, "sudo mv {} {}".format(shlex.quote(saved),
                                                           shlex.quote(remote_path)),
                            "restore the pre-existing {}".format(remote_path))
        self._installed_certs = []
        # rmdir, not rm -rf: a directory that this run created but that now holds restored or
        # unrelated material is left where it is.
        for target, parent in self._created_cert_dirs:
            target.shell("sudo rmdir {}".format(shlex.quote(parent)), module_ignore_errors=True)
        self._created_cert_dirs = []

    def missing_certificates(self, target, paths):
        """Return the paths that are absent or empty on the given device."""
        return [path for path in paths
                if target.shell("sudo test -s {}".format(shlex.quote(path)),
                                module_ignore_errors=True).get('rc') != 0]

    @contextmanager
    def no_client_cert(self):
        """Move the BMC client certificate aside so the BMC is not qualified for the graceful leg."""
        active = self.bmc_cert_paths['client_crt']
        retained = '{}.retained'.format(active)
        self._shell(self.bmc, "sudo mv {} {}".format(active, retained), "hide BMC client certificate")
        try:
            yield
        finally:
            self.bmc.shell("sudo mv {} {}".format(retained, active), module_ignore_errors=True)

    # ----------------------------------------------------------------- host gNMI rows

    def _host_gnmi_ready(self):
        certs = redis_hgetall(self.host, CONFIG_DB, 'GNMI|certs')
        if certs.get('server_crt') != '{}/server.cer'.format(BMC_LINK_DIR):
            return False
        listening = self._stdout(
            self.host, "ss -lnt | awk '$4 ~ /:{}$/ {{print $4}}'".format(self.gnmi_port))
        # An unprovisioned gNMI binds 127.0.0.1 only, which the BMC cannot reach.
        return any(not addr.startswith('127.0.0.1') for addr in listening.split())

    def ensure_host_provisioned(self):
        """(Re)apply the host gNMI rows and restart gnmi when needed. Idempotent.

        The rows are written to the runtime CONFIG_DB only -- never persisted -- so every
        switch-host power cycle drops them and the BMC falls back to 'not_qualified'. Any case
        that powers the host off has to call this again before the next graceful attempt.
        """
        if self._host_gnmi_ready():
            return
        logger.info("Re-applying the BMC-link gNMI configuration on %s", self.host.hostname)
        redis_hset(self.host, CONFIG_DB, 'GNMI|certs',
                   server_crt='{}/server.cer'.format(BMC_LINK_DIR),
                   server_key='{}/server.key'.format(BMC_LINK_DIR),
                   ca_crt='{}/ca.cer'.format(BMC_LINK_DIR))
        redis_hset(self.host, CONFIG_DB, 'GNMI|gnmi',
                   port=self.gnmi_port, client_auth='true', user_auth='cert')
        # 'role@' is not a valid keyword argument, so this one row goes through the shell.
        self._shell(self.host, "sonic-db-cli CONFIG_DB -- HSET 'GNMI_CLIENT_CERT|{}' 'role@' {}".format(
            BMC_CLIENT_CN, GNOI_CLIENT_ROLE), "set the BMC client certificate role")
        self._restart_gnmi()
        pytest_assert(wait_until(120, 5, 5, self._host_gnmi_ready),
                      "host gNMI did not come back listening off loopback on port {}".format(self.gnmi_port))

    def _restart_gnmi(self):
        """Restart the host gNMI container, clearing a previous failure first.

        The suite restarts gnmi twice per case. Enough of those in one window trips systemd's
        start rate limit, which leaves the unit in 'failed (start-limit-hit)' -- and from then on
        every restart is a no-op, so the host is left degraded long after the run.
        """
        self.host.shell("sudo systemctl reset-failed gnmi.service", module_ignore_errors=True)
        self._shell(self.host, "sudo systemctl restart gnmi.service", "restart host gNMI")

    def _gnmi_service_active(self):
        return self.host.shell("systemctl is-active --quiet gnmi.service",
                               module_ignore_errors=True).get('rc') == 0

    def _remove_host_gnmi_rows(self):
        redis_del(self.host, CONFIG_DB, 'GNMI|certs', 'GNMI|gnmi',
                  'GNMI_CLIENT_CERT|{}'.format(BMC_CLIENT_CN))
        self._restart_gnmi()
        # Leaving gnmi down is how this fixture would silently degrade the host for whoever
        # runs next, so the rollback verifies it rather than assuming the restart took.
        pytest_assert(wait_until(120, 5, 5, self._gnmi_service_active),
                      "host gNMI did not come back up after the fixture was removed")

    def stop_host_gnmi(self):
        """Stop the host gNMI service, without waiting for the job to settle.

        Called while the host is held inside its pre-shutdown, where a blocking systemctl can
        queue behind the teardown; --no-block returns as soon as the job is accepted.

        The unit is not awaited on purpose. Stopping the container can take seconds to report
        inactive, while the gNOI channel dies with its endpoint well before that, and every
        second spent waiting is a second off the graceful deadline the case has to beat. A stop
        that never lands shows up as a 'deadline' result instead of 'rpc_failure'.
        """
        self._shell(self.host, "sudo systemctl --no-block stop gnmi.service",
                    "stop host gNMI mid-operation")

    def bmc_can_reach_host_gnmi(self):
        return self.bmc.shell(
            "timeout 5 bash -c '</dev/tcp/{}/{}'".format(self.host_addr, self.gnmi_port),
            module_ignore_errors=True).get('rc') == 0

    # ----------------------------------------------------------------- pre-shutdown hook

    def _install_hook(self):
        # Record whether the platform ships a hook before anything else can fail, so the rollback
        # never has to guess: on this platform the original is a real firmware upgrade script.
        self._original_hook_present = self.host.shell(
            "sudo test -e {}".format(self.hook_path), module_ignore_errors=True).get('rc') == 0
        self._shell(self.host, "sudo install -d -m 0755 {}".format(HOOK_DIR),
                    "create the hook evidence directory")
        if self._original_hook_present:
            self._shell(self.host, "sudo cp -a {} {}".format(self.hook_path, HOOK_ORIGINAL),
                        "back up the original pre-reboot hook")

        script = HOOK_SCRIPT.format(original=HOOK_ORIGINAL, count=HOOK_COUNT_FILE,
                                    fail=HOOK_FAIL_FLAG, hold=HOOK_HOLD_FLAG,
                                    hold_max=HOOK_HOLD_MAX_SECS)
        self.host.copy(content=script, dest='/tmp/bmc-graceful-hook', mode='0644')
        self._shell(self.host, "sudo install -o root -g root -m 0755 /tmp/bmc-graceful-hook {}".format(
            self.hook_path), "install the test pre-shutdown hook")
        self._hook_installed = True
        self.host.file(path='/tmp/bmc-graceful-hook', state='absent')
        self.clear_hook_flags()
        self.reset_hook_count()

    def _remove_hook(self):
        if not self._hook_installed:
            return
        if self._original_hook_present:
            self._shell(self.host, "sudo cp -a {} {}".format(HOOK_ORIGINAL, self.hook_path),
                        "restore the original pre-reboot hook")
        else:
            self._shell(self.host, "sudo rm -f {}".format(self.hook_path),
                        "remove the test pre-shutdown hook")
        self.host.shell("sudo rm -rf {}".format(HOOK_DIR), module_ignore_errors=True)
        self.clear_hook_flags()

    def hook_count(self):
        """Return how many times the hook has run since the last reset."""
        out = self._stdout(self.host, "sudo sh -c 'test -e {f} && wc -l < {f} || echo 0'".format(
            f=HOOK_COUNT_FILE))
        return int(out) if out.isdigit() else 0

    def reset_hook_count(self):
        self._shell(self.host, "sudo sh -c ': > {}'".format(HOOK_COUNT_FILE),
                    "reset the hook invocation count")

    def _clear_flags(self, *flags):
        """Remove hook flags, tolerating a switch-host that has already lost power.

        Every case that holds or fails the hook ends with the host powered off, so the removal
        in those context managers runs against an unreachable host. The flags live on tmpfs and
        are gone with the power anyway, and recover() clears them again once the host is back.
        """
        names = ' '.join(flags)
        try:
            self.host.shell("sudo rm -f {}".format(names), module_ignore_errors=True)
        except AnsibleConnectionFailure:
            logger.info("switch-host unreachable while clearing %s; the tmpfs flags went with "
                        "the power", names)

    def clear_hook_flags(self):
        self._clear_flags(HOOK_HOLD_FLAG, HOOK_FAIL_FLAG)

    def hook_is_running(self):
        """Return whether the pre-shutdown hook has started.

        Addressed to a host that is already tearing itself down, so an unreachable host is
        reported as 'not yet' rather than raised: the caller is polling for a transition.
        """
        try:
            return self.hook_count() >= 1
        except AnsibleConnectionFailure:
            return False

    def wait_hook_running(self, timeout=60):
        """Wait until the switch-host has entered its pre-shutdown hook."""
        return wait_until(timeout, 2, 0, self.hook_is_running)

    @contextmanager
    def hold_hook(self):
        """Block the switch-host inside its pre-shutdown for the duration of the block."""
        self._shell(self.host, "sudo touch {}".format(HOOK_HOLD_FLAG), "hold the pre-shutdown hook")
        try:
            yield
        finally:
            self._clear_flags(HOOK_HOLD_FLAG)

    @contextmanager
    def fail_hook(self):
        """Make the pre-shutdown hook exit non-zero, which fails the whole pre-shutdown."""
        self._shell(self.host, "sudo touch {}".format(HOOK_FAIL_FLAG), "fail the pre-shutdown hook")
        try:
            yield
        finally:
            self._clear_flags(HOOK_FAIL_FLAG)

    # ----------------------------------------------------------------- graceful timeout

    def configured_timeout(self):
        """Return graceful_shutdown_timeout as CONFIG_DB holds it, unparsed."""
        return redis_hget(self.bmc, CONFIG_DB, CHASSIS_MODULE_KEY, 'graceful_shutdown_timeout')

    def set_timeout_cli(self, value):
        """Run the shutdown-timeout CLI with a raw value and return the ansible result.

        set_timeout() is for the cases that need the timeout to take; this one is for the case
        that tests the CLI's own validation, so it asserts nothing and passes the value through
        as written rather than as an int.

        '--' ends option parsing, so a negative value is offered to the argument's own range
        check instead of being read as a short option and refused by the parser before the
        check this suite is testing ever runs.
        """
        return self.bmc.shell(
            "sudo config chassis modules shutdown-timeout SWITCH-HOST -- {}".format(value),
            module_ignore_errors=True)

    def set_timeout(self, seconds):
        result = self.set_timeout_cli(int(seconds))
        pytest_assert(result.get('rc') == 0,
                      "setting the graceful shutdown timeout to {} failed on {}: rc={} stderr={!r}".format(
                          int(seconds), self.bmc.hostname, result.get('rc'), result.get('stderr', '')))
        actual = self.configured_timeout()
        pytest_assert(actual == str(int(seconds)),
                      "graceful timeout readback is {!r}, expected {!r}".format(actual, str(int(seconds))))

    @contextmanager
    def timeout(self, seconds):
        previous = redis_hget(self.bmc, CONFIG_DB, CHASSIS_MODULE_KEY, 'graceful_shutdown_timeout')
        self.set_timeout(seconds)
        try:
            yield
        finally:
            self.set_timeout(previous if previous.isdigit() else self.graceful_timeout)

    def _restore_timeout(self):
        if not self._timeout_recorded:
            return
        if self._original_timeout:
            self.set_timeout(self._original_timeout)
        else:
            # The field was absent before the test; bmcctld treats that as 0.
            self._shell(self.bmc, "sonic-db-cli CONFIG_DB HDEL '{}' graceful_shutdown_timeout".format(
                CHASSIS_MODULE_KEY), "remove the test graceful timeout")

    # ----------------------------------------------------------------- triggers

    def shutdown_cli(self):
        return self.bmc.shell("sudo config chassis modules shutdown SWITCH-HOST",
                              module_ignore_errors=True)

    def startup_cli(self):
        return self.bmc.shell("sudo config chassis modules startup SWITCH-HOST",
                              module_ignore_errors=True)

    def submit(self, command):
        """Submit one Rack-Manager command and return its RACK_MANAGER_COMMAND key."""
        key = 'CMD_GRACEFUL_TEST_{}'.format(uuid.uuid4().hex[:12])
        redis_hset(self.bmc, STATE_DB, '{}|{}'.format(RACK_MANAGER_COMMAND_TABLE, key),
                   command=command, status='PENDING')
        self._command_keys.add(key)
        logger.info("Submitted Rack-Manager command %s=%s", key, command)
        return key

    def command_row(self, key):
        return redis_hgetall(self.bmc, STATE_DB, '{}|{}'.format(RACK_MANAGER_COMMAND_TABLE, key))

    def wait_command(self, key, timeout=300):
        pytest_assert(
            wait_until(timeout, 5, 0,
                       lambda: self.command_row(key).get('status') in CMD_TERMINAL_STATES),
            "Rack-Manager command {} did not reach a terminal state".format(key))
        row = self.command_row(key)
        logger.info("Terminal Rack-Manager command %s: %s", key, row)
        return row

    def _clear_commands(self):
        if self._command_keys:
            redis_del(self.bmc, STATE_DB,
                      *['{}|{}'.format(RACK_MANAGER_COMMAND_TABLE, k) for k in self._command_keys])
            self._command_keys.clear()

    def power_off_host(self):
        """Remove switch-host power outright, outside any graceful flow.

        bmcctld decides 'already off' from the live oper status, so the host has to really be
        down before the graceful shutdown under test is triggered.
        """
        key = self.submit(CMD_POWER_OFF)
        row = self.wait_command(key)
        pytest_assert(row.get('status') == CMD_STATUS_DONE and row.get('result') == CMD_RESULT_SUCCESS,
                      "Rack-Manager POWER_OFF did not complete: {}".format(row))
        pytest_assert(self.wait_host_powered_off(),
                      "switch-host is still reachable after a plain POWER_OFF")

    # ----------------------------------------------------------------- critical system leak

    @contextmanager
    def leak_window(self):
        """Hold thermalctld still for the block and guarantee the leak is cleared after it.

        thermalctld owns SYSTEM_LEAK_STATUS and would overwrite an injected value within a
        poll, so it is stopped for the duration. A leak left standing would refuse every
        later power raise, including the one that recovers the switch-host, so clearing it is
        the one step that must happen whatever the case did.
        """
        with pause_pmon_daemon(self.bmc, 'thermalctld'):
            try:
                yield
            finally:
                self.clear_critical_leak()

    def publish_critical_leak(self):
        """Publish a CRITICAL system leak. Only valid inside leak_window()."""
        logger.info("Publishing a CRITICAL system leak on %s", self.bmc.hostname)
        set_system_leak_status(self.bmc, SYSTEM_LEAK_CRITICAL)

    def clear_critical_leak(self):
        set_system_leak_status(self.bmc, SYSTEM_LEAK_CLEARED)
        pytest_assert(wait_until(60, 2, 0,
                                 lambda: get_system_leak_status(self.bmc) != SYSTEM_LEAK_CRITICAL),
                      "the injected critical leak is still standing; every later power raise "
                      "would be refused")

    def submit_with_leak_at(self, command, power_state, budget_secs=180):
        """Submit a Rack-Manager command, publish the CRITICAL leak once the operation reaches
        the given power state, and return the command key.

        The restart's powered-off pause is RESTART_PAUSE_SECS long, and it is the only window
        in which a leak preempts the restart rather than the shutdown that preceded it. A
        round trip to this BMC costs around two seconds, so polling for the state from the
        test runner and then writing would spend most of that window on its own overhead, and
        arming a watch after submitting races the state it is waiting for. Submitting and
        watching in one BMC-side command removes both problems.
        """
        key = 'CMD_GRACEFUL_TEST_{}'.format(uuid.uuid4().hex[:12])
        script = (
            "sonic-db-cli STATE_DB HSET '{table}|{key}' command {command} status PENDING\n"
            "while [ \"$(sonic-db-cli STATE_DB HGET '{host}' device_power_state)\" != '{state}' ]\n"
            "do sleep 0.2\n"
            "done\n"
            "sonic-db-cli STATE_DB HSET '{leak}' device_leak_status {critical}\n"
        ).format(table=RACK_MANAGER_COMMAND_TABLE, key=key, command=command,
                 host=HOST_STATE_KEY, state=power_state,
                 leak=SYSTEM_LEAK_STATUS_KEY, critical=SYSTEM_LEAK_CRITICAL)
        self._command_keys.add(key)
        logger.info("Submitting %s and arming the critical leak for %s", command, power_state)
        self._shell(self.bmc, "sudo timeout {} bash -c {}".format(budget_secs, shlex.quote(script)),
                    "submit {} and publish the leak at {}".format(command, power_state))
        return key

    # ----------------------------------------------------------------- BMC event log

    def event_log_mark(self):
        """Return the current event-log length, so a later search can be scoped to what follows.

        The log is on /host and outlives the run, so an unscoped search would happily match a
        line from a previous case or a previous session.
        """
        out = self._stdout(self.bmc, "sudo wc -l < {}".format(BMC_EVENT_LOG))
        return int(out) if out.isdigit() else 0

    def event_log_since(self, mark, pattern):
        """Return the last event-log line after `mark` containing `pattern`, or ''."""
        return self._stdout(self.bmc, "sudo tail -n +{} {} | grep -F {} | tail -1".format(
            mark + 1, BMC_EVENT_LOG, shlex.quote(pattern)))

    def wait_event_log_since(self, mark, pattern, timeout=60):
        """Wait for an event-log line after `mark` containing `pattern` and return it, or ''."""
        found = []

        def _logged():
            line = self.event_log_since(mark, pattern)
            if line:
                found[:] = [line]
                return True
            return False

        wait_until(timeout, 2, 0, _logged)
        return found[0] if found else ''

    # ----------------------------------------------------------------- operation records

    def host_state(self):
        return redis_hgetall(self.bmc, STATE_DB, HOST_STATE_KEY)

    def wait_new_request_id(self, previous_id, timeout=120):
        """Wait until bmcctld admits a new operation and return its request id."""
        admitted = []

        def _admitted():
            request_id = self.host_state().get('op_request_id', '')
            if request_id and request_id != previous_id:
                admitted[:] = [request_id]
                return True
            return False

        pytest_assert(wait_until(timeout, 2, 0, _admitted),
                      "bmcctld did not admit a new operation request id")
        return admitted[0]

    def wait_op_done(self, request_id, timeout=300):
        """Wait until the given operation reaches a terminal op_result and return HOST_STATE."""
        def _done():
            state = self.host_state()
            return (state.get('op_request_id') == request_id
                    and state.get('op_result') not in ('', OP_RESULT_IN_FLIGHT))

        pytest_assert(wait_until(timeout, 5, 0, _done),
                      "operation {} did not reach a terminal result".format(request_id))
        state = self.host_state()
        logger.info("Terminal HOST_STATE for %s: %s", request_id, state)
        return state

    def wait_power_state(self, request_id, power_state, timeout=300):
        """Wait until the given operation reports the given power state."""
        def _reached():
            # One read: two reads could take op_request_id from before a transition and
            # device_power_state from after it, and report a state that never existed.
            state = self.host_state()
            return (state.get('op_request_id') == request_id
                    and state.get('device_power_state') == power_state)

        return wait_until(timeout, 2, 0, _reached)

    def wait_op_done_log(self, request_id, timeout=300):
        """Wait for the BMC event log's OP_DONE record for one request id and return it.

        HOST_STATE only ever holds the latest operation. A preempted operation is followed by
        the action that preempted it within about a second, so its terminal fields are gone
        before any poll of HOST_STATE can see them. The event log keeps one line per
        operation, which makes it the only race-free record for those cases.
        """
        found = []

        def _logged():
            record = self.op_done_log(request_id)
            if record:
                found[:] = [record]
                return True
            return False

        pytest_assert(wait_until(timeout, 5, 0, _logged),
                      "no OP_DONE record appeared in the BMC event log for request {}".format(
                          request_id))
        logger.info("OP_DONE record for %s: %s", request_id, found[0])
        return found[0]

    def op_done_log(self, request_id):
        """Return the parsed OP_DONE event-log record for one request id, or None."""
        out = self._stdout(self.bmc, "sudo grep -F 'request_id={}' {} | grep -F OP_DONE | tail -1".format(
            request_id, BMC_EVENT_LOG))
        return parse_op_done(out) if out else None

    # ----------------------------------------------------------------- recovery

    def host_is_online(self):
        return self.host_state().get('device_status') == 'ONLINE'

    def wait_host_powered_off(self, timeout=300):
        """Wait until the BMC reports the switch-host OFFLINE and can no longer ping it."""
        return wait_host_off(self.bmc, self.host, timeout=timeout, interval=10, delay=0)

    def host_boot_time(self):
        """Return the switch-host boot timestamp; it advances across a real power cycle."""
        return get_host_uptime(self.host)

    def host_reboot_cause(self):
        return self.host.shell(
            "show reboot-cause", module_ignore_errors=True).get('stdout', '').strip().lower()

    def host_reboot_cause_history_latest(self):
        """Return the newest 'show reboot-cause history' row, lowercased ('' if there is none).

        The graceful cause lands in the Cause column while the BMC's power-down -- the hardware
        cause behind it -- is recorded in the comment, so the whole row is returned rather than
        one field.
        """
        out = self.host.shell(
            "show reboot-cause history", module_ignore_errors=True).get('stdout', '')
        # Drop blank lines and tabulate's rule of dashes; the header is then the first line and
        # the newest entry the second.
        rows = [line for line in out.splitlines()
                if line.strip() and set(line.strip()) - set('- ')]
        return rows[1].strip().lower() if len(rows) > 1 else ''

    def chassis_status_text(self):
        return self.bmc.shell(
            "show chassis modules status", module_ignore_errors=True).get('stdout', '')

    def chassis_status_columns(self):
        """Return the column names of 'show chassis modules status', in order.

        Split on runs of two or more spaces: a single space is part of a name ('Power-On-Delay
        (sec)'), only the padding between columns is wider than that.
        """
        lines = [line for line in self.chassis_status_text().splitlines() if line.strip()]
        return re.split(r'\s{2,}', lines[0].strip()) if lines else []

    def admin_status_config(self):
        """admin_status as persisted in CONFIG_DB."""
        return redis_hget(self.bmc, CONFIG_DB, CHASSIS_MODULE_KEY, 'admin_status')

    def admin_status_runtime(self):
        """admin_status as mirrored into STATE_DB by bmcctld."""
        return redis_hget(self.bmc, STATE_DB, CHASSIS_MODULE_TABLE_KEY, 'admin_status')

    def recover(self):
        """Bring the switch-host back to a serving, provisioned state."""
        reset_ansible_ssh_control_masters()
        if self.host_is_online():
            # recover_switch_host_after_power_off() first waits out its full wait_host_off()
            # timeout, which costs three minutes on every case that left the host running.
            pytest_assert(wait_host_on(self.host, delay=0),
                          "switch-host critical services did not come up")
        else:
            recover_switch_host_after_power_off(self.bmc, self.host, context="after graceful test case")
        self.clear_hook_flags()
        # The counter is deliberately left alone: the degraded-path cases can only read it once
        # the host is back, and graceful_case resets it before the next case starts.
        self.ensure_host_provisioned()
