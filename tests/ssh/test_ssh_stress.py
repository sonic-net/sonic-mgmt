import socket
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

COMMAND_TIMEOUT = 60
VPP_COMMAND_SETTLE_TIME = 1
HEALTH_RECOVERY_TIMEOUT = 180
VPP_SETTLE_POLLS = 18

done = False
max_cpu = 0
max_mem = 0

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
            "sudo config route add prefix 2.2.3.4/32 nexthop {}".format(nexthop),
            "sudo config route del prefix 2.2.3.4/32 nexthop {}".format(nexthop),
        ),
        (ADD_PORTCHANNEL, REMOVE_PORTCHANNEL),
    ]

    duthost.host.options["variable_manager"].extra_vars.update(
        {"acl_table_name": "DATAACL", "dualtor": False}
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
        "username": harness_creds["sonicadmin_user"],
        "password": harness_creds["sonicadmin_password"],
    }


def _teardown_stress(duthost, context):
    duthost.file(path="/tmp/acl.json", state="absent")
    for commands in reversed(context["command_pairs"]):
        duthost.shell(
            _restore_command(commands), module_ignore_errors=True
        )

    pytest_assert(
        wait_until(
            HEALTH_RECOVERY_TIMEOUT,
            10,
            0,
            _control_plane_is_healthy,
            duthost,
            context["portchannels"],
            context["bgp_neighbors"],
        ),
        "Teamd/BGP control plane did not recover after SSH stress",
    )


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
    data = list(map(float, stdout_lines[-1].split()))

    total_memory = sum(data[2:6])
    used_memory = sum(data[4:6])

    total_cpu = sum(data[12:15])
    used_cpu = sum(data[12:14])

    return used_memory/total_memory, used_cpu/total_cpu


def start_SSH_connection(dut_mgmt_ip, username, password):
    """Starts SSH connection to provided IP"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(dut_mgmt_ip, username=username, password=password,
                allow_agent=False, look_for_keys=False)

    return ssh


def monitor_system(duthost):
    """Monitors system memory and CPU for duration of test"""
    global max_mem, max_cpu

    while not done:
        dut_stats = get_system_stats(duthost)
        logging.info("Memory Usage: {}% | CPU Usage: {}%".format(
            dut_stats[0]*100, dut_stats[1]*100))

        max_mem = max(max_mem, dut_stats[0])
        max_cpu = max(max_cpu, dut_stats[1])
        time.sleep(1)


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
    """Measure alternating command pairs without leaving state behind."""
    baseline_times = []
    for commands in command_pairs:
        totals = [0, 0]
        for _ in range(5):
            for command_ind, command in enumerate(commands):
                _, completion_duration = _run_command(ssh, command)
                totals[command_ind] += completion_duration
                time.sleep(command_settle_time)

        restore_command = _restore_command(commands)
        if restore_command != commands[-1]:
            _run_command(ssh, restore_command)
            time.sleep(command_settle_time)

        baseline_times.append(tuple(total / 5 for total in totals))
    return baseline_times


def work(
    dut_mgmt_ip,
    commands,
    baselines,
    username,
    password,
    failures,
    command_settle_time,
):
    """Run a stress command pair and report failures to the main test thread."""
    command_ind = 0
    last_completed_command = None
    ssh = None
    try:
        ssh = start_SSH_connection(dut_mgmt_ip, username, password)
        while not done:
            duration, _ = _run_command(ssh, commands[command_ind])
            last_completed_command = commands[command_ind]
            if duration >= 3 * baselines[command_ind]:
                raise AssertionError(
                    "Command {} took more than 3 times as long as baseline".format(
                        commands[command_ind]
                    )
                )
            time.sleep(command_settle_time)
            command_ind += 1 if not command_ind else -1
    except Exception as error:
        failures.put("{}: {}".format(commands, error))
    finally:
        restore_command = _restore_command(commands)
        if ssh is not None and last_completed_command != restore_command:
            try:
                _run_command(ssh, restore_command)
            except Exception as error:
                failures.put("rollback for {}: {}".format(commands, error))
        if ssh is not None:
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


def run_post_test_system_check(init_mem, init_cpu, duthost, settle_polls):
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

    _assert_usage_recovered("CPU", init_cpu, max_cpu, lowest_cpu)
    _assert_usage_recovered("Memory", init_mem, max_mem, lowest_mem)


def test_ssh_stress(duthosts, rand_one_dut_hostname, setup_teardown):
    """This test creates several SSH connections that all run different commands. CPU/Memory are tracked throughout"""
    global done, max_mem, max_cpu

    duthost = duthosts[rand_one_dut_hostname]
    dut_mgmt_ip = duthost.mgmt_ip
    username = setup_teardown["username"]
    password = setup_teardown["password"]

    # Gets initial memory and CPU stats
    init_mem, init_cpu = get_system_stats(duthost)

    # List of threads running ssh connections
    threads = []

    # Commands threads will be running on the DUT
    command_pairs = setup_teardown["command_pairs"]
    worker_failures = queue.Queue()

    logging.info("Collecting baseline times for commands")
    ssh = start_SSH_connection(dut_mgmt_ip, username, password)
    baseline_times = _get_baseline_times(
        ssh, command_pairs, setup_teardown["command_settle_time"]
    )
    ssh.close()

    logging.info("Starting system monitoring thread.")
    # Starts thread that will be monitoring cpu and memory usage
    monitor_thread = threading.Thread(target=monitor_system, args=(duthost,))
    monitor_thread.start()
    threads.append(monitor_thread)

    logging.info("Starting SSH Connections and running commands")
    # Initiates threads
    for ind in range(len(command_pairs)):
        new_thread = threading.Thread(target=work, args=(
            dut_mgmt_ip,
            command_pairs[ind],
            baseline_times[ind],
            username,
            password,
            worker_failures,
            setup_teardown["command_settle_time"],
        ))
        new_thread.start()
        threads.append(new_thread)

    # Waits 5 minutes to make sure that we get a lot of system data
    time.sleep(300)

    done = True

    logging.info("Stopping SSH Connections")
    for t in threads:
        t.join()

    failures = []
    while not worker_failures.empty():
        failures.append(worker_failures.get())
    pytest_assert(
        not failures,
        "SSH stress worker failures: {}".format(failures),
    )

    logging.info("Running post-test system check")
    # Get post-test cpu and memory stats (after waiting for stats to stabalize)
    run_post_test_system_check(
        init_mem, init_cpu, duthost, setup_teardown["settle_polls"]
    )

    logging.info(
        "Multi-tool ssh conections succeeded without exceeding memory or cpu capacity")

    # Reset vars for next test
    init_mem, init_cpu = get_system_stats(duthost)
    max_mem = 0
    max_cpu = 0
    done = False

    logging.info("Checking maximum number of ssh connections")
    # The following will test how many ssh connections can be simultaneously made (max 20)
    monitor_thread = threading.Thread(target=monitor_system, args=(duthost,))
    monitor_thread.start()

    ssh_connections = []

    for ind in range(20):
        ssh = start_SSH_connection(dut_mgmt_ip, username, password)
        ssh_connections.append(ssh)
        try:
            stdin, stdout, stderr = ssh.exec_command("show mac", timeout=10)
            stdout.readlines()
        except socket.timeout:
            logging.debug("stdin: {}\n\nstdout: {}\n\nstderr:{}".format(
                stdin, stdout, stderr))
            break

    logging.info("Max SSH sessions reached: {}".format(ind))

    for ssh_con in ssh_connections:
        ssh_con.close()

    done = True
    monitor_thread.join()

    logging.info("Running post-test system check")
    run_post_test_system_check(
        init_mem, init_cpu, duthost, setup_teardown["settle_polls"]
    )
