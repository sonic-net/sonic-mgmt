import math
import socket
import statistics
import threading
import paramiko
import time
import pytest
import logging
import queue
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
SSH_CONNECT_TIMEOUT = 30
THREAD_JOIN_TIMEOUT = COMMAND_TIMEOUT + 10
VPP_COMMAND_SETTLE_TIME = 1
HEALTH_RECOVERY_TIMEOUT = 180
ROUTE_CHECK_RECOVERY_TIMEOUT = 900
QUIESCENCE_STABILITY_INTERVAL = 10
VPP_SETTLE_POLLS = 18
BASELINE_ITERATIONS = 5
STRESS_DURATION = 300
STRESS_PERCENTILE = 0.95
MIN_STRESS_SAMPLES = 20

# After the stress test, CPU and memory should drop back close to where they started.
# We take a few readings while things settle and keep the lowest one, then allow it to
# sit at most RECOVER_THRESHOLD above the pre-test baseline before calling it a failure.
RECOVER_THRESHOLD = 0.2    # how far a metric may stay above its pre-test baseline (fraction)
SETTLE_POLLS = 6           # how many readings to take while waiting for usage to settle
SETTLE_INTERVAL = 5        # seconds to wait between those readings


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
    return any(
        component in _config_key_parts(key)
        for key in table
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
    if (
        configured_portchannel is None
        or configured_portchannel.get("admin_status") != "up"
        or not duthost.is_interface_status_up(stress_portchannel)
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


def _setup_stress(duthost, request):
    is_vpp = duthost.facts["asic_type"] == "vpp"
    if is_vpp:
        command_settle_time = VPP_COMMAND_SETTLE_TIME
        settle_polls = VPP_SETTLE_POLLS
    else:
        command_settle_time = 0
        settle_polls = SETTLE_POLLS

    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running"
    )["ansible_facts"]
    portchannels = sorted(config_facts.get("PORTCHANNEL", {}))
    pytest_assert(portchannels, "No configured port channel available for stress")
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

    duthost.host.options["variable_manager"].extra_vars.update(
        {"acl_table_name": ACL_TABLE_NAME, "dualtor": False}
    )
    duthost.template(
        src="acl/templates/acltb_test_rules.j2",
        dest="/tmp/acl.json",
        mode="0755",
    )

    harness_creds = request.getfixturevalue("creds")
    return {
        "bgp_neighbors": bgp_neighbors,
        "command_pairs": command_pairs,
        "command_settle_time": command_settle_time,
        "portchannels": portchannels,
        "settle_polls": settle_polls,
        "stress_portchannel": portchannel,
        "username": harness_creds["sonicadmin_user"],
        "password": harness_creds["sonicadmin_password"],
    }


def _restore_stress_state(duthost, context):
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
    try:
        pytest_assert(
            _restore_stress_state(duthost, context),
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
        duthost.file(path="/tmp/acl.json", state="absent")


@pytest.fixture
def setup_teardown(duthosts, rand_one_dut_hostname, request):
    duthost = duthosts[rand_one_dut_hostname]
    context = _setup_stress(duthost, request)
    yield context
    _teardown_stress(duthost, context)


def get_system_stats(duthost):
    """Return the DUT's current memory and CPU usage, each as a fraction (0-1).

    Plain ``vmstat`` reports CPU usage averaged since boot. Over a short test that
    average barely moves, so the peak seen during the test and the reading taken
    afterwards look almost the same. ``vmstat 1 2`` adds a second row measured over
    one second, so we read that last row to get the load right now.
    """
    # The last line of `vmstat 1 2` is the 1-second (current) sample; line [2] would
    # be the since-boot average.
    stdout_lines = duthost.command("vmstat 1 2")["stdout_lines"]
    return _parse_vmstat_line(stdout_lines[-1])


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


def monitor_system(ssh, stop_event, failures, ready, metrics):
    """Monitor system usage through one persistent vmstat process."""
    stdout = None

    try:
        _, stdout, _ = ssh.exec_command(
            "env LC_ALL=C vmstat -n 1", timeout=COMMAND_TIMEOUT
        )
        skipped_since_boot_sample = False
        while True:
            line = stdout.readline()
            if not line:
                if stop_event.is_set():
                    break
                raise RuntimeError("vmstat monitoring stream ended unexpectedly")
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
            metrics["max_mem"] = max(metrics["max_mem"], dut_stats[0])
            metrics["max_cpu"] = max(metrics["max_cpu"], dut_stats[1])
    except Exception as error:
        failures.put("system monitor: {}".format(error))
        stop_event.set()
        ready.set()
    finally:
        if stdout is not None:
            stdout.channel.close()


def _run_command(ssh, command):
    """Run one churn command to completion and require success."""
    start_time = time.time()
    _, stdout, stderr = ssh.exec_command(command, timeout=COMMAND_TIMEOUT)
    dispatch_duration = time.time() - start_time
    stdout_lines = stdout.readlines()
    stderr_lines = stderr.readlines()
    exit_status = stdout.channel.recv_exit_status()

    if exit_status != 0:
        raise AssertionError(
            "Command {!r} failed with rc={}: stdout={!r}, stderr={!r}".format(
                command, exit_status, stdout_lines, stderr_lines
            )
        )
    return dispatch_duration, time.time() - start_time


def _get_baseline_times(ssh, command_pairs, command_settle_time):
    """Measure five serial samples per command and return each median."""
    baseline_times = []
    for commands in command_pairs:
        samples = [[], []]
        last_completed_command = None
        try:
            for _ in range(BASELINE_ITERATIONS):
                for command_ind, command in enumerate(commands):
                    _, completion_duration = _run_command(ssh, command)
                    last_completed_command = command
                    samples[command_ind].append(completion_duration)
                    time.sleep(command_settle_time)
        finally:
            restore_command = _restore_command(commands)
            if last_completed_command != restore_command:
                _run_command(ssh, restore_command)
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


def _assert_stress_timings(
    command_pairs,
    baseline_times,
    stress_durations,
):
    parallel_task_count = len(command_pairs)
    timing_failures = []

    for commands, baselines, durations in zip(
        command_pairs, baseline_times, stress_durations
    ):
        for command, baseline, samples in zip(commands, baselines, durations):
            if len(samples) < MIN_STRESS_SAMPLES:
                timing_failures.append(
                    "Command {} produced only {} stress samples; at least {} "
                    "are required for p95".format(
                        command, len(samples), MIN_STRESS_SAMPLES
                    )
                )
                continue

            p95 = _nearest_rank_percentile(samples, STRESS_PERCENTILE)
            completion_limit = parallel_task_count * baseline
            logging.info(
                "Stress command %s samples=%d p95=%.2fs max=%.2fs "
                "baseline_median=%.2fs limit=%.2fs",
                command, len(samples), p95, max(samples), baseline,
                completion_limit,
            )
            if p95 >= completion_limit:
                timing_failures.append(
                    "Command {} p95 {:.2f}s from {} samples exceeded "
                    "the {:.2f}s limit ({} parallel tasks * {:.2f}s "
                    "baseline median); max {:.2f}s".format(
                        command,
                        p95,
                        len(samples),
                        completion_limit,
                        parallel_task_count,
                        baseline,
                        max(samples),
                    )
                )

    pytest_assert(
        not timing_failures,
        "SSH stress timing failures: {}".format(timing_failures),
    )


def work(
    ssh,
    commands,
    failures,
    command_settle_time,
    ready_barrier,
    start_event,
    stop_event,
    durations,
):
    """Run a synchronized command pair and collect completion durations."""
    command_ind = 0
    last_completed_command = None
    try:
        ready_barrier.wait()
        start_event.wait()
        while not stop_event.is_set():
            _, completion_duration = _run_command(ssh, commands[command_ind])
            last_completed_command = commands[command_ind]
            durations[command_ind].append(completion_duration)
            if stop_event.wait(command_settle_time):
                break
            command_ind += 1 if not command_ind else -1
    except Exception as error:
        failures.put("{}: {}".format(commands, error))
        stop_event.set()
    finally:
        restore_command = _restore_command(commands)
        if last_completed_command != restore_command:
            try:
                _run_command(ssh, restore_command)
            except Exception as error:
                failures.put("rollback for {}: {}".format(commands, error))
                stop_event.set()
        ssh.close()


def _assert_usage_recovered(resource, baseline, peak, lowest):
    """Fail if a resource did not settle back near its pre-test baseline after the test.

    ``resource`` is a label used only in the message ("CPU" / "Memory"); ``baseline``,
    ``peak`` and ``lowest`` are usage fractions (0-1).
    """
    pytest_assert(
        lowest - baseline < RECOVER_THRESHOLD,
        "{} usage did not recover after the test: it stayed more than {:.0f} points above the "
        "pre-test baseline.\nBaseline: {}, In-test peak: {}, Lowest after test: {}".format(
            resource, RECOVER_THRESHOLD * 100, baseline, peak, lowest))


def run_post_test_system_check(
    init_mem, init_cpu, duthost, settle_polls, peak_mem, peak_cpu
):
    """Check that CPU and memory settle back near their pre-test baseline.

    The SSH worker threads stop asynchronously, so the first reading taken after the
    test can still be high. We take several readings, keep the lowest (most recovered)
    one, and compare it to the pre-test baseline.

    We compare against the baseline on purpose, not against the in-test peak. The old
    check ("peak minus a single later reading") failed whenever that later reading
    happened to be at or above the peak -- reporting a problem even when usage had
    actually recovered.
    """
    lowest_mem, lowest_cpu = 1.0, 1.0
    for _ in range(settle_polls):
        time.sleep(SETTLE_INTERVAL)
        mem, cpu = get_system_stats(duthost)
        lowest_mem = min(lowest_mem, mem)
        lowest_cpu = min(lowest_cpu, cpu)
        logging.info(
            "Waiting for usage to settle: CPU={:.3f} MEM={:.3f} (lowest so far CPU={:.3f} MEM={:.3f})".format(
                cpu, mem, lowest_cpu, lowest_mem))
        # Stop early once both have come back down near the baseline.
        if lowest_cpu - init_cpu < RECOVER_THRESHOLD and lowest_mem - init_mem < RECOVER_THRESHOLD:
            break

    _assert_usage_recovered("CPU", init_cpu, peak_cpu, lowest_cpu)
    _assert_usage_recovered("Memory", init_mem, peak_mem, lowest_mem)


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

    init_mem, init_cpu = get_system_stats(duthost)

    logging.info("Collecting serial baseline times for commands")
    ssh = start_SSH_connection(dut_mgmt_ip, username, password)
    try:
        baseline_times = _get_baseline_times(
            ssh, command_pairs, command_settle_time
        )
    finally:
        ssh.close()

    worker_failures = queue.Queue()
    stress_durations = [[[], []] for _ in command_pairs]
    ready_barrier = threading.Barrier(len(command_pairs) + 1)
    start_event = threading.Event()
    stop_event = threading.Event()
    monitor_ready = threading.Event()
    metrics = {"max_mem": 0, "max_cpu": 0}
    clients = []
    threads = []

    try:
        logging.info("Pre-establishing SSH connections for stress workers")
        for _ in command_pairs:
            clients.append(
                start_SSH_connection(dut_mgmt_ip, username, password)
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
                    stress_durations[ind],
                ),
                name="ssh-stress-worker-{}".format(ind),
                daemon=True,
            )
            new_thread.start()
            threads.append(new_thread)

        ready_barrier.wait(timeout=COMMAND_TIMEOUT)
        pytest_assert(
            monitor_ready.wait(COMMAND_TIMEOUT),
            "System monitor did not produce a live vmstat sample",
        )
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

        logging.info("Releasing synchronized SSH command workers")
        start_event.set()
        stop_event.wait(STRESS_DURATION)
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
    _assert_stress_timings(
        command_pairs,
        baseline_times,
        stress_durations,
    )

    logging.info("Running post-test system check")
    run_post_test_system_check(
        init_mem,
        init_cpu,
        duthost,
        setup_teardown["settle_polls"],
        metrics["max_mem"],
        metrics["max_cpu"],
    )

    logging.info(
        "Multi-tool SSH connections succeeded without exceeding memory or CPU capacity")

    init_mem, init_cpu = get_system_stats(duthost)
    monitor_failures = queue.Queue()
    monitor_stop = threading.Event()
    monitor_ready = threading.Event()
    metrics = {"max_mem": 0, "max_cpu": 0}
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
        setup_teardown["settle_polls"],
        metrics["max_mem"],
        metrics["max_cpu"],
    )
