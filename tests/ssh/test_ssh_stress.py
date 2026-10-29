import base64
import math
import socket
import statistics
import threading
import paramiko
import time
import pytest
import logging
import queue
import shlex
import uuid
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
    pytest.mark.device_type("vpp"),
]

START_BGP_NBRS = "sudo config bgp startup all"
STOP_BGP_NBRS = "sudo config bgp shutdown all"

CONFIGURE_ACL = "acl-loader update full /tmp/acl.json"
REMOVE_ACL = "acl-loader delete"

ADD_PORTCHANNEL = "sudo config portchannel add PortChannel0010"
REMOVE_PORTCHANNEL = "sudo config portchannel del PortChannel0010"

ACL_TABLE_NAME = "DATAACL"
STRESS_PORTCHANNEL = "PortChannel0010"
STRESS_ROUTE_PREFIX = "2.2.3.4/32"

COMMAND_TIMEOUT = 60
CALIBRATION_COMMAND_TIMEOUT = 180
MAX_COMMAND_TIMEOUT = 180
COMMAND_CANCEL_TIMEOUT = 20
COMMAND_POLL_INTERVAL = 0.1
SSH_CONNECT_TIMEOUT = 30
THREAD_JOIN_TIMEOUT = (
    2 * (MAX_COMMAND_TIMEOUT + COMMAND_CANCEL_TIMEOUT) + 10
)
COMMAND_HELPER_SOURCE = "ssh/files/ssh_stress_command.py"
VPP_COMMAND_SETTLE_TIME = 1
HEALTH_RECOVERY_TIMEOUT = 180
ROUTE_CHECK_RECOVERY_TIMEOUT = 900
QUIESCENCE_STABILITY_INTERVAL = 10
BASELINE_ITERATIONS = 5
RESOURCE_BASELINE_SAMPLES = 3
STRESS_DURATION = 300
STRESS_PERCENTILE = 0.95
MAX_STRESS_CYCLES = 20
MIN_STRESS_CYCLES = 3
STRESS_COMMAND_MARGIN = 1

# Preserve the test's long-standing 20-point recovery guard. This is a
# compatibility guardrail rather than a product resource-utilization SLO.
RECOVER_THRESHOLD = 0.2
SETTLE_INTERVAL = 5


def _restore_command(commands):
    if commands[0] == START_BGP_NBRS:
        return commands[0]
    return commands[1]


def _control_plane_is_healthy(duthost, portchannels, bgp_neighbors):
    for portchannel in portchannels:
        result = duthost.shell(
            "timeout 10 sudo docker exec teamd teamdctl {} state dump".format(
                portchannel
            ),
            module_ignore_errors=True,
        )
        if result.get("rc", 1) != 0:
            return False
    return duthost.check_bgp_session_state_all_asics(bgp_neighbors)


def _route_checker_is_healthy(duthost):
    result = duthost.command("sudo route_check.py", module_ignore_errors=True)
    if result["rc"] != 0:
        return False
    # Monit can retain a churn-time failure until its next scheduled check.
    status = duthost.get_monit_services_status()["routeCheck"]["service_status"]
    return status.lower() in ("status ok", "ok")


def _config_key_parts(key):
    if isinstance(key, (list, tuple)):
        return tuple(str(part) for part in key)
    return tuple(str(key).split("|"))


def _config_has_key_component(table, component):
    """Find a component in flat or nested config-facts table keys."""
    if not isinstance(table, dict):
        return False
    return any(
        component in _config_key_parts(key)
        or _config_has_key_component(value, component)
        for key, value in table.items()
    )


def _stress_state_is_quiescent(
    duthost, portchannels, bgp_neighbors, stress_portchannel
):
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running"
    )["ansible_facts"]

    if _config_has_key_component(
        config_facts.get("PORTCHANNEL", {}), STRESS_PORTCHANNEL
    ):
        return False
    if _config_has_key_component(
        config_facts.get("STATIC_ROUTE", {}), STRESS_ROUTE_PREFIX
    ):
        return False
    if _config_has_key_component(
        config_facts.get("ACL_RULE", {}), ACL_TABLE_NAME
    ):
        return False

    configured_portchannel = next((
        value
        for key, value in config_facts.get("PORTCHANNEL", {}).items()
        if stress_portchannel in _config_key_parts(key)
    ), None)
    interface_facts = duthost.interface_facts()["ansible_facts"].get(
        "ansible_interface_facts", {}
    )
    portchannel_link = interface_facts.get(stress_portchannel, {}).get("link")
    if (
        configured_portchannel is None
        or configured_portchannel.get("admin_status") != "up"
        or portchannel_link is not True
    ):
        return False

    return _control_plane_is_healthy(
        duthost, portchannels, bgp_neighbors
    )


def _stress_state_is_stably_quiescent(
    duthost, portchannels, bgp_neighbors, stress_portchannel
):
    if not _stress_state_is_quiescent(
        duthost, portchannels, bgp_neighbors, stress_portchannel
    ):
        return False
    time.sleep(QUIESCENCE_STABILITY_INTERVAL)
    return _stress_state_is_quiescent(
        duthost, portchannels, bgp_neighbors, stress_portchannel
    )


def _install_stress_artifacts(duthost, command_helper):
    try:
        duthost.template(
            src="acl/templates/acltb_test_rules.j2",
            dest="/tmp/acl.json",
            mode="0755",
        )
        duthost.copy(
            src=COMMAND_HELPER_SOURCE,
            dest=command_helper,
            mode="0755",
        )
    except Exception:
        try:
            duthost.file(path="/tmp/acl.json", state="absent")
        finally:
            duthost.file(path=command_helper, state="absent")
        raise


def _setup_stress(duthost, request):
    is_vpp = duthost.facts["asic_type"] == "vpp"
    if is_vpp:
        command_settle_time = VPP_COMMAND_SETTLE_TIME
    else:
        command_settle_time = 0

    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running"
    )["ansible_facts"]
    portchannels = sorted(config_facts.get("PORTCHANNEL", {}))
    pytest_assert(
        portchannels, "No configured port channel available for stress"
    )
    pytest_assert(
        not _config_has_key_component(
            config_facts.get("PORTCHANNEL", {}), STRESS_PORTCHANNEL
        ),
        "Temporary stress port channel {} already exists".format(
            STRESS_PORTCHANNEL
        ),
    )

    bgp_neighbors = duthost.get_bgp_neighbors_per_asic(state="all")
    ipv4_neighbors = sorted(
        neighbor
        for neighbors in bgp_neighbors.values()
        for neighbor in neighbors
        if ":" not in neighbor
    )
    pytest_assert(ipv4_neighbors, "No IPv4 BGP nexthop available for stress")

    portchannel = portchannels[0]
    nexthop = ipv4_neighbors[0]
    command_pairs = [
        (START_BGP_NBRS, STOP_BGP_NBRS),
        (
            "sudo config interface shutdown {}".format(portchannel),
            "sudo config interface startup {}".format(portchannel),
        ),
        (CONFIGURE_ACL, REMOVE_ACL),
        (
            "sudo config route add prefix {} nexthop {}".format(
                STRESS_ROUTE_PREFIX, nexthop
            ),
            "sudo config route del prefix {} nexthop {}".format(
                STRESS_ROUTE_PREFIX, nexthop
            ),
        ),
        (ADD_PORTCHANNEL, REMOVE_PORTCHANNEL),
    ]

    harness_creds = request.getfixturevalue("creds")
    duthost.host.options["variable_manager"].extra_vars.update(
        {"acl_table_name": ACL_TABLE_NAME, "dualtor": False}
    )
    run_id = uuid.uuid4().hex
    command_helper = "/tmp/ssh_stress_command_{}.py".format(run_id)
    command_state_root = "/tmp/ssh-stress-command-state-{}".format(run_id)
    _install_stress_artifacts(duthost, command_helper)

    return {
        "bgp_neighbors": bgp_neighbors,
        "command_pairs": command_pairs,
        "command_settle_time": command_settle_time,
        "command_helper": command_helper,
        "command_state_root": command_state_root,
        "portchannels": portchannels,
        "stress_portchannel": portchannel,
        "username": harness_creds["sonicadmin_user"],
        "password": harness_creds["sonicadmin_password"],
    }


def _fence_remote_commands(duthost, context):
    command = "sudo -n timeout {} python3 {} --state-root {} cancel-all".format(
        THREAD_JOIN_TIMEOUT,
        shlex.quote(context["command_helper"]),
        shlex.quote(context["command_state_root"]),
    )
    result = duthost.command(command, module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        logging.error(
            "Could not fence SSH stress commands: stdout=%r stderr=%r",
            result.get("stdout"), result.get("stderr"),
        )
        return False
    return True


def _restore_stress_state(duthost, context):
    if not _fence_remote_commands(duthost, context):
        return False

    for commands in reversed(context["command_pairs"]):
        duthost.shell(
            _restore_command(commands), module_ignore_errors=True
        )

    return wait_until(
        HEALTH_RECOVERY_TIMEOUT,
        10,
        0,
        _stress_state_is_stably_quiescent,
        duthost,
        context["portchannels"],
        context["bgp_neighbors"],
        context["stress_portchannel"],
    )


def _teardown_stress(duthost, context):
    state_restored = False
    try:
        state_restored = _restore_stress_state(duthost, context)
        pytest_assert(
            state_restored,
            "SSH stress state did not recover after the test",
        )
        if duthost.facts["asic_type"] == "vpp":
            pytest_assert(
                wait_until(
                    ROUTE_CHECK_RECOVERY_TIMEOUT,
                    20,
                    0,
                    _route_checker_is_healthy,
                    duthost,
                ),
                "Route consistency or monit routeCheck did not recover after "
                "SSH stress",
            )
    finally:
        try:
            duthost.file(path="/tmp/acl.json", state="absent")
        finally:
            if state_restored:
                try:
                    duthost.file(
                        path=context["command_helper"], state="absent"
                    )
                finally:
                    duthost.file(
                        path=context["command_state_root"], state="absent"
                    )


@pytest.fixture
def setup_teardown(duthosts, rand_one_dut_hostname, request):
    duthost = duthosts[rand_one_dut_hostname]
    context = _setup_stress(duthost, request)
    yield context
    _teardown_stress(duthost, context)


def get_system_stats(duthost):
    """Return the DUT's current memory and CPU usage, each as a fraction (0-1).

    Plain ``vmstat`` reports CPU usage averaged since boot. Over a short test
    that average barely moves, so the peak seen during the test and the reading
    taken afterwards look almost the same. ``vmstat 1 2`` adds a second row
    measured over one second, so we read that last row to get the load right
    now.
    """
    # The last line is the 1-second sample; line [2] is the boot average.
    stdout_lines = duthost.command("vmstat 1 2")["stdout_lines"]
    return _parse_vmstat_line(stdout_lines[-1])


def _get_usage_baseline(duthost, sample_count=RESOURCE_BASELINE_SAMPLES):
    """Return median current memory and CPU usage from multiple samples."""
    samples = [get_system_stats(duthost) for _ in range(sample_count)]
    baseline_mem = statistics.median(sample[0] for sample in samples)
    baseline_cpu = statistics.median(sample[1] for sample in samples)
    logging.info(
        "Usage baseline samples=%s median CPU=%.3f MEM=%.3f",
        samples, baseline_cpu, baseline_mem,
    )
    return baseline_mem, baseline_cpu


def _parse_vmstat_line(line):
    data = list(map(float, line.split()))
    if len(data) < 15:
        raise ValueError("Unexpected vmstat output: {!r}".format(line))

    total_memory = sum(data[2:6])
    used_memory = sum(data[4:6])

    total_cpu = sum(data[12:15])
    used_cpu = sum(data[12:14])

    return used_memory/total_memory, used_cpu/total_cpu


def start_SSH_connection(dut_mgmt_ip, username, password):
    """Start a bounded SSH connection to the provided IP."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            dut_mgmt_ip,
            username=username,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            timeout=SSH_CONNECT_TIMEOUT,
            banner_timeout=SSH_CONNECT_TIMEOUT,
            auth_timeout=SSH_CONNECT_TIMEOUT,
        )
    except Exception:
        ssh.close()
        raise
    return ssh


class _RemoteCommandFenceError(RuntimeError):
    pass


class _CommandRunner:
    def __init__(
        self,
        command_ssh,
        control_ssh,
        control_channel,
        command_helper,
        command_state_root,
        username,
    ):
        self.command_ssh = command_ssh
        self.control_ssh = control_ssh
        self.control_channel = control_channel
        self.control_buffer = bytearray()
        self.command_helper = command_helper
        self.command_state_root = command_state_root
        self.username = username

    def close(self):
        try:
            self.control_channel.close()
        finally:
            self.control_ssh.close()
            self.command_ssh.close()


def _remaining_time(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("SSH command deadline expired")
    return remaining


def _dispatch_channel_command(channel, command, deadline):
    completed = threading.Event()
    errors = []

    def dispatch():
        try:
            channel.exec_command(command)
        except Exception as error:
            errors.append(error)
        finally:
            completed.set()

    thread = threading.Thread(
        target=dispatch,
        name="ssh-command-dispatch",
        daemon=True,
    )
    thread.start()
    if not completed.wait(_remaining_time(deadline)):
        channel.close()
        raise socket.timeout("SSH exec request exceeded its deadline")
    if errors:
        raise errors[0]


def _read_channel_line(channel, buffer, deadline):
    while True:
        newline = buffer.find(b"\n")
        if newline >= 0:
            line = bytes(buffer[:newline]).decode("utf-8", errors="replace")
            del buffer[:newline + 1]
            return line
        if channel.recv_ready():
            buffer.extend(channel.recv(65536))
            continue
        if channel.closed or channel.exit_status_ready():
            raise RuntimeError("SSH command-control channel ended unexpectedly")
        time.sleep(min(COMMAND_POLL_INTERVAL, _remaining_time(deadline)))


def _start_command_runner(
    dut_mgmt_ip, username, password, command_helper, command_state_root
):
    command_ssh = start_SSH_connection(dut_mgmt_ip, username, password)
    control_ssh = None
    control_channel = None
    try:
        control_ssh = start_SSH_connection(dut_mgmt_ip, username, password)
        deadline = time.monotonic() + COMMAND_TIMEOUT
        control_channel = control_ssh.get_transport().open_session(
            timeout=_remaining_time(deadline)
        )
        control_channel.settimeout(_remaining_time(deadline))
        control_command = "sudo -n python3 {} --state-root {} control".format(
            shlex.quote(command_helper),
            shlex.quote(command_state_root),
        )
        _dispatch_channel_command(
            control_channel, control_command, deadline
        )
        control_buffer = bytearray()
        ready = _read_channel_line(
            control_channel, control_buffer, deadline
        )
        if ready != "READY":
            raise RuntimeError(
                "Unexpected SSH command-control startup response: {!r}".format(
                    ready
                )
            )
        runner = _CommandRunner(
            command_ssh,
            control_ssh,
            control_channel,
            command_helper,
            command_state_root,
            username,
        )
        runner.control_buffer = control_buffer
        return runner
    except Exception:
        if control_channel is not None:
            control_channel.close()
        if control_ssh is not None:
            control_ssh.close()
        command_ssh.close()
        raise


def monitor_system(ssh, stop_event, failures, ready, metrics):
    """Monitor system usage through one persistent vmstat process."""
    stdout = None

    try:
        _, stdout, _ = ssh.exec_command(
            "env LC_ALL=C vmstat -n 1", timeout=COMMAND_TIMEOUT
        )
        skipped_since_boot_sample = False
        while True:
            with metrics["lock"]:
                sample_epoch = metrics["epoch"]
            line = stdout.readline()
            if not line:
                if stop_event.is_set():
                    break
                raise RuntimeError(
                    "vmstat monitoring stream ended unexpectedly"
                )
            if stop_event.is_set():
                break
            try:
                dut_stats = _parse_vmstat_line(line)
            except ValueError:
                continue

            if not skipped_since_boot_sample:
                skipped_since_boot_sample = True
                continue

            ready.set()
            logging.info("Memory Usage: {}% | CPU Usage: {}%".format(
                dut_stats[0]*100, dut_stats[1]*100))
            _record_usage_sample(metrics, sample_epoch, dut_stats)
    except Exception as error:
        failures.put("system monitor: {}".format(error))
        stop_event.set()
        ready.set()
    finally:
        if stdout is not None:
            stdout.channel.close()


def _new_usage_metrics():
    return {
        "max_mem": 0,
        "max_cpu": 0,
        "epoch": 0,
        "recording": False,
        "lock": threading.Lock(),
    }


def _record_usage_sample(metrics, sample_epoch, dut_stats):
    """Record a sample only if it belongs to the active measurement phase."""
    with metrics["lock"]:
        if not metrics["recording"] or sample_epoch != metrics["epoch"]:
            return False
        metrics["max_mem"] = max(metrics["max_mem"], dut_stats[0])
        metrics["max_cpu"] = max(metrics["max_cpu"], dut_stats[1])
        return True


def _reset_usage_peaks(metrics, baseline_mem, baseline_cpu):
    """Exclude setup/calibration load from the measured stress peaks."""
    with metrics["lock"]:
        metrics["epoch"] += 1
        metrics["max_mem"] = baseline_mem
        metrics["max_cpu"] = baseline_cpu
        metrics["recording"] = True


def _decode_output_lines(chunks):
    return b"".join(chunks).decode("utf-8", errors="replace").splitlines()


def _drain_ready_output(channel, chunks, deadline, stderr=False):
    ready = channel.recv_stderr_ready if stderr else channel.recv_ready
    receive = channel.recv_stderr if stderr else channel.recv
    while ready():
        _remaining_time(deadline)
        chunks.append(receive(65536))


def _send_control_request(runner, action, token, deadline):
    try:
        runner.control_channel.settimeout(_remaining_time(deadline))
        runner.control_channel.sendall(
            "{} {}\n".format(action, token).encode("ascii")
        )
        response = _read_channel_line(
            runner.control_channel,
            runner.control_buffer,
            deadline,
        )
    except Exception as error:
        raise _RemoteCommandFenceError(
            "Remote command {} failed for {}: {}".format(
                action.lower(), token, error
            )
        )
    response_action = {
        "RESERVE": "RESERVED",
        "CANCEL": "CANCELLED",
    }[action]
    expected = "{} {}".format(response_action, token)
    if response != expected:
        raise _RemoteCommandFenceError(
            "Remote command {} failed for {}: {!r}".format(
                action.lower(), token, response
            )
        )


def _reserve_remote_command(runner, token, deadline):
    _send_control_request(runner, "RESERVE", token, deadline)


def _drain_output_until_eof(
    channel, stdout_chunks, stderr_chunks, deadline
):
    while True:
        _drain_ready_output(channel, stdout_chunks, deadline)
        _drain_ready_output(
            channel, stderr_chunks, deadline, stderr=True
        )
        if channel.closed or getattr(channel, "eof_received", False):
            _drain_ready_output(channel, stdout_chunks, deadline)
            _drain_ready_output(
                channel, stderr_chunks, deadline, stderr=True
            )
            return
        time.sleep(min(COMMAND_POLL_INTERVAL, _remaining_time(deadline)))


def _cancel_remote_command(runner, token):
    deadline = time.monotonic() + COMMAND_CANCEL_TIMEOUT
    _send_control_request(runner, "CANCEL", token, deadline)


def _remote_run_command(runner, token, command):
    encoded_command = base64.b64encode(command.encode("utf-8")).decode("ascii")
    return (
        "sudo -n python3 {} --state-root {} run --run-user {} {} {}"
    ).format(
        shlex.quote(runner.command_helper),
        shlex.quote(runner.command_state_root),
        shlex.quote(runner.username),
        token,
        encoded_command,
    )


def _run_command(runner, command, command_timeout=None):
    """Run a command under one deadline and fence it before timeout returns."""
    if command_timeout is None:
        command_timeout = COMMAND_TIMEOUT
    start_time = time.monotonic()
    deadline = start_time + command_timeout
    token = uuid.uuid4().hex
    channel = None
    request_started = False
    try:
        _reserve_remote_command(runner, token, deadline)
        transport = runner.command_ssh.get_transport()
        channel = transport.open_session(timeout=_remaining_time(deadline))
        channel.settimeout(_remaining_time(deadline))
        request_started = True
        _dispatch_channel_command(
            channel,
            _remote_run_command(runner, token, command),
            deadline,
        )
        dispatch_duration = time.monotonic() - start_time
        stdout_chunks = []
        stderr_chunks = []

        while True:
            _drain_ready_output(channel, stdout_chunks, deadline)
            _drain_ready_output(
                channel, stderr_chunks, deadline, stderr=True
            )
            if channel.exit_status_ready():
                exit_status = channel.recv_exit_status()
                _drain_output_until_eof(
                    channel,
                    stdout_chunks,
                    stderr_chunks,
                    deadline,
                )
                completed_at = time.monotonic()
                if completed_at > deadline:
                    raise socket.timeout(
                        "Command {!r} did not complete within {} seconds".format(
                            command, command_timeout
                        )
                    )
                break
            time.sleep(
                min(COMMAND_POLL_INTERVAL, _remaining_time(deadline))
            )

        stdout_lines = _decode_output_lines(stdout_chunks)
        stderr_lines = _decode_output_lines(stderr_chunks)
        if exit_status != 0:
            raise AssertionError(
                "Command {!r} failed with rc={}: stdout={!r}, "
                "stderr={!r}".format(
                    command, exit_status, stdout_lines, stderr_lines
                )
            )
        return dispatch_duration, completed_at - start_time
    except socket.timeout:
        if request_started:
            _cancel_remote_command(runner, token)
        raise socket.timeout(
            "Command {!r} did not complete within {} seconds".format(
                command, command_timeout
            )
        )
    except Exception:
        if request_started:
            _cancel_remote_command(runner, token)
        raise
    finally:
        if channel is not None:
            channel.close()


def _get_baseline_times(ssh_clients, command_pairs, command_settle_time):
    """Measure commands serially on established worker clients."""
    if len(ssh_clients) != len(command_pairs):
        raise ValueError("Each command pair must have one SSH worker client")

    baseline_times = []
    for ssh, commands in zip(ssh_clients, command_pairs):
        samples = [[], []]
        restore_command = _restore_command(commands)
        state_restored = True
        rollback_safe = True
        try:
            for _ in range(BASELINE_ITERATIONS):
                for command_ind, command in enumerate(commands):
                    state_restored = False
                    _, completion_duration = _run_command(
                        ssh, command, CALIBRATION_COMMAND_TIMEOUT
                    )
                    if command == restore_command:
                        state_restored = True
                    samples[command_ind].append(completion_duration)
                    time.sleep(command_settle_time)
        except _RemoteCommandFenceError:
            rollback_safe = False
            raise
        finally:
            if not state_restored and rollback_safe:
                _run_command(
                    ssh, restore_command, CALIBRATION_COMMAND_TIMEOUT
                )
                time.sleep(command_settle_time)

        medians = tuple(statistics.median(values) for values in samples)
        for command, values, median_value in zip(commands, samples, medians):
            logging.info(
                "Baseline command %s samples=%s median=%.2fs",
                command, values, median_value,
            )
        baseline_times.append(medians)
    return baseline_times


def _nearest_rank_percentile(values, percentile):
    if not values:
        raise ValueError("Cannot calculate a percentile without samples")
    rank = max(1, int(math.ceil(percentile * len(values))))
    return sorted(values)[rank - 1]


def _derive_stress_requirements(
    command_pairs, baseline_times, command_settle_time
):
    """Normalize throughput and command watchdogs to this DUT's baselines."""
    if len(command_pairs) != len(baseline_times):
        raise ValueError("Each command pair must have serial baselines")

    for commands, baselines in zip(command_pairs, baseline_times):
        if len(commands) != len(baselines):
            raise ValueError("Each command must have one serial baseline")
        if any(baseline <= 0 for baseline in baselines):
            raise ValueError("Serial command baselines must be positive")

    # Each worker can have only one command in flight. One command therefore
    # competes with at most the slower direction from every other pair.
    relative_command_budget = min(
        MAX_COMMAND_TIMEOUT,
        sum(max(baselines) for baselines in baseline_times)
        + len(command_pairs) * STRESS_COMMAND_MARGIN,
    )
    command_timeout = max(COMMAND_TIMEOUT, relative_command_budget)

    # One restored cycle from every worker consumes both directions from every
    # pair. Settle waits overlap across workers, while per-command margins model
    # scheduling/transport overhead that the serial medians do not include.
    serial_round_duration = sum(
        sum(baselines) for baselines in baseline_times
    )
    allowed_round_duration = (
        serial_round_duration
        + sum(len(commands) for commands in command_pairs)
        * STRESS_COMMAND_MARGIN
        + max(len(commands) for commands in command_pairs)
        * command_settle_time
    )

    requirements = []
    for commands, baselines in zip(command_pairs, baseline_times):
        initial_restore_budget = 0
        if _restore_command(commands) == commands[0]:
            initial_restore_budget = (
                relative_command_budget + command_settle_time
            )
        available_duration = max(
            0, STRESS_DURATION - initial_restore_budget
        )
        adaptive_cycles = int(
            available_duration // allowed_round_duration
        )
        required_cycles = max(
            MIN_STRESS_CYCLES,
            min(MAX_STRESS_CYCLES, adaptive_cycles),
        )
        requirements.append({
            "required_cycles": required_cycles,
            "serial_cycle_duration": (
                sum(baselines) + len(commands) * command_settle_time
            ),
            "allowed_cycle_duration": allowed_round_duration,
            "command_budgets": (relative_command_budget,) * len(commands),
            "command_timeouts": (command_timeout,) * len(commands),
            "initial_restore_budget": initial_restore_budget,
        })
    return requirements


def _record_stress_completion(
    durations, command_ind, completion_duration, completed_at, deadline
):
    """Record only commands completed inside the fixed stress window."""
    if completed_at > deadline:
        return False
    durations[command_ind].append(completion_duration)
    return True


def _completed_stress_cycles(commands, durations):
    """Return cycles that reached the pair's restored state in the window."""
    restore_ind = commands.index(_restore_command(commands))
    mutation_ind = 1 - restore_ind
    restored_completions = len(durations[restore_ind])

    # BGP starts in its restored state and its restore command is first. Its
    # initial no-op startup does not complete a shutdown/startup cycle.
    if restore_ind == 0:
        restored_completions = max(0, restored_completions - 1)

    return min(len(durations[mutation_ind]), restored_completions)


def _assert_stress_progress(
    command_pairs,
    baseline_times,
    stress_durations,
    requirements,
):
    progress_failures = []

    for commands, baselines, durations, requirement in zip(
        command_pairs, baseline_times, stress_durations, requirements
    ):
        completed_cycles = _completed_stress_cycles(commands, durations)
        required_cycles = requirement["required_cycles"]
        logging.info(
            "Stress command pair %s completed_cycles=%d required_cycles=%d "
            "serial_cycle=%.2fs allowed_cycle=%.2fs",
            commands,
            completed_cycles,
            required_cycles,
            requirement["serial_cycle_duration"],
            requirement["allowed_cycle_duration"],
        )
        if completed_cycles < required_cycles:
            progress_failures.append(
                "Command pair {} completed only {} full cycles; at least {} "
                "are required in {} seconds from its {:.2f}s serial cycle "
                "baseline and {:.2f}s contention budget".format(
                    commands,
                    completed_cycles,
                    required_cycles,
                    STRESS_DURATION,
                    requirement["serial_cycle_duration"],
                    requirement["allowed_cycle_duration"],
                )
            )

        for command, baseline, samples, budget in zip(
            commands,
            baselines,
            durations,
            requirement["command_budgets"],
        ):
            if not samples:
                logging.info(
                    "Stress command %s samples=0 baseline_median=%.2fs",
                    command, baseline,
                )
                continue

            p95 = _nearest_rank_percentile(samples, STRESS_PERCENTILE)
            slowdown = p95 / baseline if baseline > 0 else float("inf")
            logging.info(
                "Stress command %s samples=%d p95=%.2fs max=%.2fs "
                "baseline_median=%.2fs p95_slowdown=%.2fx "
                "relative_budget=%.2fs",
                command,
                len(samples),
                p95,
                max(samples),
                baseline,
                slowdown,
                budget,
            )
            if p95 >= budget:
                progress_failures.append(
                    "Command {} p95 {:.2f}s exceeded the {:.2f}s "
                    "mixed-workload budget derived from all serial "
                    "baselines; max {:.2f}s".format(
                        command, p95, budget, max(samples)
                    )
                )

    pytest_assert(
        not progress_failures,
        "SSH stress progress failures: {}".format(progress_failures),
    )


def work(
    ssh,
    commands,
    failures,
    command_settle_time,
    ready_barrier,
    start_event,
    stop_event,
    stress_deadline,
    durations,
    command_timeouts=None,
):
    """Run a synchronized command pair and collect completion durations."""
    command_ind = 0
    command_dispatched = False
    restore_command = _restore_command(commands)
    state_restored = True
    rollback_safe = True
    try:
        ready_barrier.wait()
        start_event.wait()
        deadline = stress_deadline[0]
        if deadline is None:
            raise RuntimeError("Stress phase ended before workers were released")
        while not stop_event.is_set():
            if time.monotonic() >= deadline:
                break
            command = commands[command_ind]
            command_dispatched = True
            state_restored = False
            command_timeout = COMMAND_TIMEOUT
            if command_timeouts is not None:
                command_timeout = command_timeouts[command_ind]
            result = _run_command(ssh, command, command_timeout)
            _, completion_duration = result
            if command == restore_command:
                state_restored = True
            completed_at = time.monotonic()
            if not _record_stress_completion(
                durations,
                command_ind,
                completion_duration,
                completed_at,
                deadline,
            ):
                break
            if stop_event.wait(command_settle_time):
                break
            command_ind += 1 if not command_ind else -1
    except Exception as error:
        if isinstance(error, _RemoteCommandFenceError):
            rollback_safe = False
        failures.put("{}: {}".format(commands, error))
        stop_event.set()
    finally:
        if command_dispatched and not state_restored and rollback_safe:
            try:
                if command_timeouts is None:
                    _run_command(ssh, restore_command)
                else:
                    restore_ind = commands.index(restore_command)
                    _run_command(
                        ssh, restore_command, command_timeouts[restore_ind]
                    )
            except Exception as error:
                failures.put("rollback for {}: {}".format(commands, error))
                stop_event.set()
        ssh.close()


def run_post_test_system_check(
    init_mem, init_cpu, duthost, peak_mem, peak_cpu
):
    """Accept the first current sample recovered near the pre-test baseline."""
    lowest_mem, lowest_cpu = 1.0, 1.0
    latest_mem, latest_cpu = 1.0, 1.0
    start_time = time.monotonic()
    deadline = start_time + HEALTH_RECOVERY_TIMEOUT
    next_poll = start_time + SETTLE_INTERVAL
    max_polls = int(math.ceil(
        HEALTH_RECOVERY_TIMEOUT / SETTLE_INTERVAL
    ))
    poll = 0

    while True:
        now = time.monotonic()
        if now >= deadline:
            break
        time.sleep(min(max(0, next_poll - now), deadline - now))
        if time.monotonic() >= deadline:
            break
        poll += 1
        mem, cpu = get_system_stats(duthost)
        completed_at = time.monotonic()
        if completed_at > deadline:
            break
        latest_mem, latest_cpu = mem, cpu
        lowest_mem = min(lowest_mem, mem)
        lowest_cpu = min(lowest_cpu, cpu)
        recovered = (
            cpu - init_cpu < RECOVER_THRESHOLD
            and mem - init_mem < RECOVER_THRESHOLD
        )
        logging.info(
            "Waiting for usage recovery: poll=%d/%d CPU=%.3f MEM=%.3f "
            "recovered=%s",
            poll, max_polls, cpu, mem, recovered,
        )
        if recovered:
            return
        while next_poll <= completed_at:
            next_poll += SETTLE_INTERVAL

    pytest_assert(
        False,
        "CPU and memory usage did not return within {:.0f} points of their "
        "pre-test baselines during the {}-second recovery window. Baseline "
        "CPU: {:.3f}, MEM: {:.3f}; in-test peak CPU: {:.3f}, MEM: {:.3f}; "
        "latest CPU: {:.3f}, MEM: {:.3f}; lowest CPU: {:.3f}, MEM: {:.3f}"
        .format(
            RECOVER_THRESHOLD * 100,
            HEALTH_RECOVERY_TIMEOUT,
            init_cpu,
            init_mem,
            peak_cpu,
            peak_mem,
            latest_cpu,
            latest_mem,
            lowest_cpu,
            lowest_mem,
        ),
    )


def _drain_failures(failures):
    drained = []
    while True:
        try:
            drained.append(failures.get_nowait())
        except queue.Empty:
            return drained


def _join_threads(threads, clients, failures):
    deadline = time.monotonic() + THREAD_JOIN_TIMEOUT
    for thread in threads:
        thread.join(max(0, deadline - time.monotonic()))

    if any(thread.is_alive() for thread in threads):
        for client in clients:
            client.close()
        deadline = time.monotonic() + 5
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))

    for thread in threads:
        if thread.is_alive():
            failures.put(
                "Thread {} did not stop".format(thread.name)
            )


def test_ssh_stress(duthosts, rand_one_dut_hostname, setup_teardown):
    """Exercise concurrent SSH configuration with strict recovery checks."""
    duthost = duthosts[rand_one_dut_hostname]
    dut_mgmt_ip = duthost.mgmt_ip
    username = setup_teardown["username"]
    password = setup_teardown["password"]
    command_pairs = setup_teardown["command_pairs"]
    command_settle_time = setup_teardown["command_settle_time"]

    worker_failures = queue.Queue()
    stress_durations = [[[], []] for _ in command_pairs]
    ready_barrier = threading.Barrier(len(command_pairs) + 1)
    start_event = threading.Event()
    stop_event = threading.Event()
    stress_deadline = [None]
    monitor_ready = threading.Event()
    metrics = _new_usage_metrics()
    clients = []
    threads = []

    try:
        logging.info(
            "Pre-establishing SSH command and cancellation-control sessions"
        )
        for _ in command_pairs:
            clients.append(
                _start_command_runner(
                    dut_mgmt_ip,
                    username,
                    password,
                    setup_teardown["command_helper"],
                    setup_teardown["command_state_root"],
                )
            )
        monitor_ssh = start_SSH_connection(
            dut_mgmt_ip, username, password
        )
        clients.append(monitor_ssh)

        logging.info("Starting persistent system monitoring stream")
        monitor_thread = threading.Thread(
            target=monitor_system,
            args=(
                monitor_ssh,
                stop_event,
                worker_failures,
                monitor_ready,
                metrics,
            ),
            name="ssh-stress-monitor",
            daemon=True,
        )
        monitor_thread.start()
        threads.append(monitor_thread)

        pytest_assert(
            monitor_ready.wait(COMMAND_TIMEOUT),
            "System monitor did not produce a live vmstat sample",
        )
        monitor_startup_failures = _drain_failures(worker_failures)
        pytest_assert(
            not monitor_startup_failures and not stop_event.is_set(),
            "SSH stress monitor startup failures: {}".format(
                monitor_startup_failures
            ),
        )

        logging.info(
            "Collecting serial baselines on the established worker clients"
        )
        baseline_times = _get_baseline_times(
            clients[:-1], command_pairs, command_settle_time
        )
        stress_requirements = _derive_stress_requirements(
            command_pairs, baseline_times, command_settle_time
        )

        logging.info("Preparing synchronized SSH command workers")
        for ind, worker_ssh in enumerate(clients[:-1]):
            new_thread = threading.Thread(
                target=work,
                args=(
                    worker_ssh,
                    command_pairs[ind],
                    worker_failures,
                    command_settle_time,
                    ready_barrier,
                    start_event,
                    stop_event,
                    stress_deadline,
                    stress_durations[ind],
                    stress_requirements[ind]["command_timeouts"],
                ),
                name="ssh-stress-worker-{}".format(ind),
                daemon=True,
            )
            new_thread.start()
            threads.append(new_thread)

        ready_barrier.wait(timeout=COMMAND_TIMEOUT)
        pytest_assert(
            not stop_event.is_set(),
            "SSH stress stopped while preparing workers",
        )

        logging.info("Waiting for baseline side effects to drain")
        pytest_assert(
            _restore_stress_state(duthost, setup_teardown),
            "SSH stress state did not recover after baseline collection",
        )
        startup_failures = _drain_failures(worker_failures)
        pytest_assert(
            not startup_failures and not stop_event.is_set(),
            "SSH stress startup failures: {}".format(startup_failures),
        )

        logging.info("Collecting pre-stress CPU and memory baseline")
        init_mem, init_cpu = _get_usage_baseline(duthost)
        _reset_usage_peaks(metrics, init_mem, init_cpu)

        logging.info("Releasing synchronized SSH command workers")
        stress_deadline[0] = time.monotonic() + STRESS_DURATION
        start_event.set()
        stop_event.wait(max(0, stress_deadline[0] - time.monotonic()))
    finally:
        stop_event.set()
        start_event.set()
        ready_barrier.abort()
        logging.info("Stopping SSH command workers and monitor")
        _join_threads(threads, clients, worker_failures)
        for client in clients:
            client.close()

    failures = _drain_failures(worker_failures)
    pytest_assert(
        not failures,
        "SSH stress worker failures: {}".format(failures),
    )
    _assert_stress_progress(
        command_pairs,
        baseline_times,
        stress_durations,
        stress_requirements,
    )

    logging.info("Running post-test system check")
    run_post_test_system_check(
        init_mem,
        init_cpu,
        duthost,
        metrics["max_mem"],
        metrics["max_cpu"],
    )

    logging.info(
        "Multi-tool SSH connections succeeded without exceeding memory or "
        "CPU capacity"
    )

    monitor_failures = queue.Queue()
    monitor_stop = threading.Event()
    monitor_ready = threading.Event()
    metrics = _new_usage_metrics()
    monitor_ssh = None
    monitor_thread = None
    ssh_connections = []

    logging.info("Checking maximum number of SSH connections")
    try:
        monitor_ssh = start_SSH_connection(
            dut_mgmt_ip, username, password
        )
        monitor_thread = threading.Thread(
            target=monitor_system,
            args=(
                monitor_ssh,
                monitor_stop,
                monitor_failures,
                monitor_ready,
                metrics,
            ),
            name="ssh-session-monitor",
            daemon=True,
        )
        monitor_thread.start()
        pytest_assert(
            monitor_ready.wait(COMMAND_TIMEOUT),
            "System monitor did not produce a live vmstat sample",
        )
        startup_failures = _drain_failures(monitor_failures)
        pytest_assert(
            not startup_failures and not monitor_stop.is_set(),
            "SSH session monitor startup failures: {}".format(
                startup_failures
            ),
        )

        logging.info("Collecting pre-session CPU and memory baseline")
        init_mem, init_cpu = _get_usage_baseline(duthost)
        _reset_usage_peaks(metrics, init_mem, init_cpu)

        for _ in range(20):
            if monitor_stop.is_set():
                break
            ssh = start_SSH_connection(dut_mgmt_ip, username, password)
            ssh_connections.append(ssh)
            try:
                stdin, stdout, stderr = ssh.exec_command(
                    "show mac", timeout=10
                )
                stdout.readlines()
            except socket.timeout:
                logging.debug(
                    "stdin: {}\n\nstdout: {}\n\nstderr:{}".format(
                        stdin, stdout, stderr
                    )
                )
                break

        logging.info(
            "Max SSH sessions reached: {}".format(len(ssh_connections))
        )
    finally:
        for ssh_con in ssh_connections:
            ssh_con.close()
        monitor_stop.set()
        if monitor_thread is not None:
            _join_threads(
                [monitor_thread],
                [monitor_ssh],
                monitor_failures,
            )
        if monitor_ssh is not None:
            monitor_ssh.close()

    failures = _drain_failures(monitor_failures)
    pytest_assert(
        not failures,
        "SSH session monitor failures: {}".format(failures),
    )

    logging.info("Running post-test system check")
    run_post_test_system_check(
        init_mem,
        init_cpu,
        duthost,
        metrics["max_mem"],
        metrics["max_cpu"],
    )
