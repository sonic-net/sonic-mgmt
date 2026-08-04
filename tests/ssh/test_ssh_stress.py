import socket
import threading
import paramiko
import time
import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.constants import DEFAULT_SSH_CONNECT_PARAMS
from tests.common.utilities import get_image_type
from tests.common.fixtures.tacacs import get_aaa_sub_options_value

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
    pytest.mark.device_type("vpp"),
]

START_BGP_NBRS = "sudo config bgp startup all"
STOP_BGP_NBRS = "sudo config bgp shutdown all"

SHUTDOWN_INTERFACE = "sudo config interface shutdown PortChannel0001"
STARTUP_INTERFACE = "sudo config interface startup PortChannel0001"

CONFIGURE_ACL = "acl-loader update full /tmp/acl.json"
REMOVE_ACL = "acl-loader delete"

ADD_ROUTE = "sudo config route add prefix 2.2.3.4/32 nexthop vrf Vrf-RED 30.0.0.9"
REMOVE_ROUTE = "sudo config route del prefix 2.2.3.4/32 nexthop vrf Vrf-RED 30.0.0.9"

ADD_PORTCHANNEL = "sudo config portchannel add PortChannel0010"
REMOVE_PORTCHANNEL = "sudo config portchannel del PortChannel0010"

done = False
max_cpu = 0
max_mem = 0

# After the stress test, CPU and memory should drop back close to where they started.
# We take a few readings while things settle and keep the lowest one, then allow it to
# sit at most RECOVER_THRESHOLD above the pre-test baseline before calling it a failure.
RECOVER_THRESHOLD = 0.2    # how far a metric may stay above its pre-test baseline (fraction)
SETTLE_POLLS = 6           # how many readings to take while waiting for usage to settle
SETTLE_INTERVAL = 5        # seconds to wait between those readings


@pytest.fixture
def setup_teardown(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    # Ensure the DUT password matches DEFAULT_SSH_CONNECT_PARAMS
    creds = DEFAULT_SSH_CONNECT_PARAMS[get_image_type(duthost=duthost)]

    # Capture the pre-test password so we can restore it in teardown
    hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    original_password = hostvars.get('ansible_password', hostvars.get('ansible_ssh_pass', 'password'))

    duthost.shell("echo '{}:{}' | sudo chpasswd".format(creds["username"], creds["password"]))

    # Disable TACACS if configured (follows same pattern as test_ssh_limit.py)
    aaa_login_disabled = False
    aaa_login_value = get_aaa_sub_options_value(duthost, "authentication", "login")
    if aaa_login_value.startswith("tacacs+"):
        duthost.shell("sudo config aaa authentication login default")
        aaa_login_disabled = True

    # Copies over ACL configs for the ACL commands
    duthost.host.options["variable_manager"].extra_vars.update({"dualtor": False})
    duthost.copy(src="acl/templates/acltb_test_rules.j2",
                 dest="/tmp/acl.json", mode="0755")

    yield

    duthost.file(path="/tmp/acl.json", state="absent")

    for cmd in [START_BGP_NBRS, STARTUP_INTERFACE, REMOVE_ACL, REMOVE_ROUTE, REMOVE_PORTCHANNEL]:
        duthost.shell(cmd, module_ignore_errors=True)

    # Restore pre-test password and TACACS state
    try:
        duthost.shell("echo '{}:{}' | sudo chpasswd".format(creds["username"], original_password))
    finally:
        if aaa_login_disabled:
            duthost.shell("sudo config aaa authentication login tacacs+")


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


def work(dut_mgmt_ip, commands, baselines, username, password):
    """Runs commands over ssh on the DUT"""
    command_ind = 0

    ssh = start_SSH_connection(dut_mgmt_ip, username, password)

    while not done:
        if not commands:
            time.sleep(1)
            continue
        start_time = time.time()
        stdin, stdout, stderr = ssh.exec_command(commands[command_ind])
        duration = time.time() - start_time

        logging.debug("output for command {} :\n{}".format(
            commands[command_ind], stdout))

        pytest_assert(duration < 3*baselines[command_ind],
                      "Command {} took more than 3 times as long as baseline".format(commands[command_ind]))

        # The commands are executed asyncronously. Reading from stdout will ensure that a command
        # is not sent again on the same ssh connection before this one is done.
        stdout.readlines()
        command_ind += 1 if not command_ind else -1

    # Ran in case ACL is still loaded
    ssh.exec_command(REMOVE_ACL)
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


def run_post_test_system_check(init_mem, init_cpu, duthost):
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
    for _ in range(SETTLE_POLLS):
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


def get_baseline_time(ssh, command):
    """Calculates average time to run a command. Used to ensure that, under stress, commands don't take too long"""
    tot_time = 0
    for _ in range(5):
        start_time = time.time()
        stdin, stdout, stdinfo = ssh.exec_command(command)
        stdout.readlines()
        tot_time += time.time() - start_time
    logging.info("Baseline time for command {} : {} seconds".format(
        command, tot_time/5))
    return tot_time/5


def test_ssh_stress(duthosts, rand_one_dut_hostname, setup_teardown):
    """This test creates several SSH connections that all run different commands. CPU/Memory are tracked throughout"""
    global done, max_mem, max_cpu

    duthost = duthosts[rand_one_dut_hostname]
    dut_mgmt_ip = duthost.mgmt_ip

    # Get SSH credentials from image type
    creds = DEFAULT_SSH_CONNECT_PARAMS[get_image_type(duthost=duthost)]
    username = creds["username"]
    password = creds["password"]

    # Gets initial memory and CPU stats
    init_mem, init_cpu = get_system_stats(duthost)

    # List of threads running ssh connections
    threads = []

    # Commands threads will be running on the DUT
    command_pairs = [
        (START_BGP_NBRS, STOP_BGP_NBRS),
        (SHUTDOWN_INTERFACE, STARTUP_INTERFACE),
        (CONFIGURE_ACL, REMOVE_ACL),
        (ADD_ROUTE, REMOVE_ROUTE),
        (ADD_PORTCHANNEL, REMOVE_PORTCHANNEL)
    ]

    logging.info("Collecting baseline times for commands")
    ssh = start_SSH_connection(dut_mgmt_ip, username, password)
    baseline_times = [tuple((get_baseline_time(ssh, com)
                            for com in pair)) for pair in command_pairs]

    logging.info("Starting system monitoring thread.")
    # Starts thread that will be monitoring cpu and memory usage
    monitor_thread = threading.Thread(target=monitor_system, args=(duthost,))
    monitor_thread.start()
    threads.append(monitor_thread)

    logging.info("Starting SSH Connections and running commands")
    # Initiates threads
    for ind in range(len(command_pairs)):
        new_thread = threading.Thread(target=work, args=(
            dut_mgmt_ip, command_pairs[ind], baseline_times[ind], username, password,))
        new_thread.start()
        threads.append(new_thread)

    # Waits 5 minutes to make sure that we get a lot of system data
    time.sleep(300)

    done = True

    logging.info("Stopping SSH Connections")
    for t in threads:
        t.join()

    logging.info("Running post-test system check")
    # Get post-test cpu and memory stats (after waiting for stats to stabalize)
    run_post_test_system_check(init_mem, init_cpu, duthost)

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
    run_post_test_system_check(init_mem, init_cpu, duthost)
