import time
import logging
import pytest
import allure

from tests.common.plugins.loganalyzer.loganalyzer import DisableLogrotateCronContext
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer
]

LOG_FOLDER = '/var/log'
SMALL_VAR_LOG_PARTITION_SIZE = '300M'
FAKE_IP = '10.20.30.40'
FAKE_MAC = 'aa:bb:cc:dd:11:22'


@pytest.fixture(scope='module', autouse=True)
def disable_logrotate_cron_job(rand_selected_dut):
    with DisableLogrotateCronContext(rand_selected_dut):
        yield


@pytest.fixture(scope='module', autouse=True)
def backup_syslog(rand_selected_dut):
    """
    Back up current syslog file
    :param rand_selected_dut: The fixture returns a randomly selected DUT
    """
    duthost = rand_selected_dut
    logger.info('Backup syslog file to syslog_bk')
    duthost.shell('sudo cp -f /var/log/syslog /var/log/syslog_bk')

    yield

    logger.info('Recover syslog file to syslog')
    duthost.shell('sudo mv /var/log/syslog_bk /var/log/syslog')

    logger.info('Restart rsyslog service')
    duthost.shell('sudo service rsyslog restart')


@pytest.fixture(scope='function')
def simulate_small_var_log_partition(rand_selected_dut, localhost):
    """
    Simulate a small var log partition
    :param rand_selected_dut: The fixture returns a randomly selected DUT
    """
    duthost = rand_selected_dut
    with allure.step('Create a small var log partition with size of {}'.format(SMALL_VAR_LOG_PARTITION_SIZE)):
        logger.info('Create a small var log partition with size of {}'.format(SMALL_VAR_LOG_PARTITION_SIZE))
        duthost.shell('sudo fallocate -l {} log-new-partition'.format(SMALL_VAR_LOG_PARTITION_SIZE))
        duthost.shell('sudo losetup -P  /dev/loop2 log-new-partition')
        duthost.shell('sudo mkfs.ext4 /dev/loop2')
        duthost.shell('sudo mount /dev/loop2 /var/log')

        config_reload(duthost, safe_reload=True)

        logger.info('Start logrotate-config service')
        duthost.shell('sudo service logrotate-config restart')

    yield

    with allure.step('Recovery var log'):
        logger.info('Umount and unload the small var log partition')
        duthost.shell('sudo umount -l /dev/loop2')
        duthost.shell('sudo losetup -d /dev/loop2')

        logger.info('Remove the small var log partition')
        duthost.shell('sudo rm -f log-new-partition')

        config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)

        logger.info('Restart logrotate-config service')
        duthost.shell('sudo service logrotate-config restart')


def get_var_log_size(duthost):
    """
    Check the size of /var/log folder
    :param duthost: DUT host object
    :return: size value
    """
    size = duthost.shell("sudo df -k /var/log | sed -n 2p | awk '{ print $2 }'")['stdout']
    return int(size)


def get_syslog_file_count(duthost):
    """
    Check the rotated syslog file number
    :param duthost: DUT host object
    :return: file number value
    """
    logger.info('Check rotated syslog file number')
    num = duthost.shell('sudo ls -l /var/log | grep -Ec "syslog\\.[0-9]{1,4}[\\.gz]{0,1}"',
                        module_ignore_errors=True)['stdout']
    logger.debug('There are {} rotated syslog files'.format(num))
    return int(num)


def create_temp_syslog_file(duthost, size):
    """
    Create a temp syslog file with specific size and
    :param duthost: DUT host object
    :param size: file size with unit, such as 16M or 1024K, the unit could be M or K
    """
    logger.info('Create a temp syslog file as {}'.format(size))
    duthost.shell('sudo fallocate -l {} /var/log/syslog'.format(size))


def run_logrotate(duthost, force=False):
    """
    Run logrotate command
    :param duthost: DUT host object
    :param force: force logrotate run immediately even the syslog size is very small, value is True or False
    """
    if force:
        logger.debug('Make sure there is no big /var/log/syslog exist by forcing execute logrotate')
        cmd = 'sudo /usr/sbin/logrotate -f /etc/logrotate.conf > /dev/null 2>&1'
    else:
        cmd = 'sudo /usr/sbin/logrotate /etc/logrotate.conf > /dev/null 2>&1'
    logger.info('Run logrotate command: {}'.format(cmd))
    duthost.shell(cmd)


def multiply_with_unit(logrotate_threshold, num):
    """
    Multiply logrotate_threshold with number, and return the value
    Such as '1024K' * 0.5, return '512K'
    :param logrotate_threshold: string type threshold value with unit, such as '1024K'
    :param num: the number need to multiply with
    :return: value with unit, such as '512K'
    """
    return str(int(logrotate_threshold[:-1]) * num) + logrotate_threshold[-1]


def validate_logrotate_function(duthost, logrotate_threshold, small_size):
    """
    Validate logrotate function
    :param duthost: DUT host object
    :param logrotate_threshold: logrotate threshold, such as 16M or 1024K
    """
    with allure.step('Run logrotate with force option to prepare clean syslog environment'):
        run_logrotate(duthost, force=True)

    with allure.step('There should be no logrotate process when rsyslog size is smaller than threshold {}'.format(
            logrotate_threshold)):
        syslog_number_origin = get_syslog_file_count(duthost)
        logger.info('There are {} syslog gz files'.format(syslog_number_origin))
        if small_size:
            create_temp_syslog_file(duthost, multiply_with_unit(logrotate_threshold, 0.5))
        else:
            create_temp_syslog_file(duthost, multiply_with_unit(logrotate_threshold, 0.9))
        run_logrotate(duthost)
        syslog_number_no_rotate = get_syslog_file_count(duthost)
        logger.info('There are {} syslog gz files after running logrotate'.format(syslog_number_no_rotate))
        assert syslog_number_origin == syslog_number_no_rotate, \
            'Unexpected logrotate happens, there should be no logrotate executed'

    with allure.step('There will be logrotate process when rsyslog size is larger than threshold {}'.format(
            logrotate_threshold)):
        create_temp_syslog_file(duthost, multiply_with_unit(logrotate_threshold, 1.1))
        run_logrotate(duthost)
        syslog_number_with_rotate = get_syslog_file_count(duthost)
        logger.info('There are {} syslog gz files after running logrotate'.format(syslog_number_with_rotate))
        assert syslog_number_origin + 1 == syslog_number_with_rotate, \
            'No logrotate happens, there should be one time logrotate executed'


def get_threshold_based_on_memory(duthost):
    """
    Get the available memory from DUT to determine what is the threshold for the logrotate.
    :param duthost: DUT host object
    :return: value with unit, such as '1024K' which represents the logrotate size threshold.
    """
    available_memory = int(duthost.shell("df -k /var/log | sed -n 2p")["stdout_lines"][0].split()[1])
    if available_memory <= 204800:
        return "1024K"
    elif available_memory <= 409600:
        return "2048K"
    else:
        return "16M"


@pytest.mark.disable_loganalyzer
def test_logrotate_normal_size(rand_selected_dut):
    """
    Test case of logrotate under normal size /var/log, test steps are listed

    Stop logrotate cron job, make sure no logrotate executes during this test
    Back up current syslog file, name the backup file as 'syslog_bk'
    Check current /var/log is lower than 200MB, else skip this test
    Check current syslog.x file number and save it
    Create a temp file with size of rotate_size * 90% , and rename it as 'syslog', run logrotate command
    There would be no logrotate happens - by checking the 'syslog.x' file number not increased
    Create a temp file with size of rotate_size * 110%, and rename it as 'syslog', run logrotate command
    There would be logrotate happens - by checking the 'syslog.x' file number increased by 1
    Remove the temp 'syslog' file and recover the 'syslog_bk' to 'syslog'

    :param rand_selected_dut: The fixture returns a randomly selected DUT
    """
    duthost = rand_selected_dut
    with allure.step('Check whether the DUT is a small flash DUT'):
        if get_var_log_size(duthost) < 200 * 1024:
            pytest.skip('{} size is lower than 200MB, skip this test'.format(LOG_FOLDER))
    rotate_large_threshold = get_threshold_based_on_memory(duthost)
    validate_logrotate_function(duthost, rotate_large_threshold, False)


@pytest.mark.disable_loganalyzer
def test_logrotate_small_size(rand_selected_dut, simulate_small_var_log_partition):
    """
    Test case of logrotate under a simulated small size /var/log, test steps are listed

    Create a temp device which is around 100MB large, then mount it to /var/log
    Execute config reload to active the mount
    Stop logrotate cron job, make sure no logrotate executes during this test
    Check current syslog.x file number and save it
    Create a temp file with size of rotate_size * 50%, and rename it as 'syslog', run logrotate command
    There would be no logrotate happens - by checking the 'syslog.x' file number not increased
    Create a temp file with size of rotate_size * 110%, and rename it as 'syslog', run logrotate command
    There would be logrotate happens - by checking the 'syslog.x' file number increased by 1
    Reboot the dut to recover original /var/log mount

    :param rand_selected_dut: The fixture returns a randomly selected DUT
    :param simulate_small_var_log_partition: The fixture simulates a small var log partition
    """
    duthost = rand_selected_dut
    rotate_small_threshold = get_threshold_based_on_memory(duthost)
    validate_logrotate_function(duthost, rotate_small_threshold, True)


def get_pending_entries(duthost, ignore_list=None):
    pending_entries = set(duthost.shell('sonic-db-cli APPL_DB keys "_*"')['stdout'].split())

    if ignore_list:
        for entry in ignore_list:
            try:
                pending_entries.remove(entry)
            except ValueError:
                continue
            except KeyError:
                continue
    pending_entries = list(pending_entries)
    logger.info('Pending entries in APPL_DB: {}'.format(pending_entries))
    return pending_entries


def clear_pending_entries(duthost):
    pending_entries = get_pending_entries(duthost)
    if pending_entries:
        # Publishing to any table channel should publish all pending entries in all tables
        logger.info('Clearing pending entries in APPL_DB: {}'.format(pending_entries))
        duthost.shell('sonic-db-cli APPL_DB publish "NEIGH_TABLE_CHANNEL" ""')


def no_pending_entries(duthost, ignore_list=None):
    return not bool(get_pending_entries(duthost, ignore_list=ignore_list))


@pytest.fixture
def orch_logrotate_setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo,
                         enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if duthost.sonichost.is_multi_asic:
        asic_id = enum_rand_one_frontend_asic_index
    else:
        asic_id = ''
    clear_pending_entries(duthost)
    duthost.shell('sudo ip neigh flush {}'.format(FAKE_IP))
    if duthost.sonichost.is_multi_asic:
        target_asic = duthost.asics[enum_rand_one_frontend_asic_index]
        target_port = next(iter(target_asic.get_active_ip_interfaces(tbinfo)))
    else:
        target_port = duthost.get_up_ip_ports()[0]

    permanent_pending_entries = get_pending_entries(duthost)

    yield permanent_pending_entries, target_port

    if duthost.sonichost.is_multi_asic:
        duthost.shell('sudo ip -n asic{} neigh del {} dev {}'.format(asic_id, FAKE_IP, target_port))
    else:
        duthost.shell('sudo ip neigh del {} dev {}'.format(FAKE_IP, target_port))
    # Unpause orchagent in case the test gets interrupted
    duthost.control_process('orchagent', pause=False, namespace=asic_id)
    clear_pending_entries(duthost)


# Sometimes other activity on the DUT can flush the missed notification during the test,
# leading to a false positive pass. Repeat the test multiple times to make sure that it's
# not a false positive
@pytest.mark.repeat(5)
def test_orchagent_logrotate(orch_logrotate_setup, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                             enum_rand_one_frontend_asic_index):
    """
    Tests for the issue where an orchagent logrotate can cause a missed APPL_DB notification
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if duthost.sonichost.is_multi_asic:
        asic_id = enum_rand_one_frontend_asic_index
    else:
        asic_id = ''
    ignore_entries, target_port = orch_logrotate_setup
    duthost.control_process('orchagent', pause=True, namespace=asic_id)
    duthost.control_process('orchagent', namespace=asic_id, signal='SIGHUP')
    if duthost.sonichost.is_multi_asic:
        duthost.shell('sudo ip -n asic{} neigh add {} lladdr {} dev {}'.format(
            asic_id, FAKE_IP, FAKE_MAC, target_port))
    else:
        duthost.shell('sudo ip neigh add {} lladdr {} dev {}'.format(FAKE_IP, FAKE_MAC, target_port))
    duthost.control_process('orchagent', pause=False, namespace=asic_id)
    pytest_assert(
        wait_until(30, 1, 0, no_pending_entries, duthost, ignore_list=ignore_entries),
        "Found pending entries in APPL_DB"
    )


def get_var_log_avail_kb(duthost):
    """Return 'Available' KB for /var/log filesystem"""
    out = duthost.shell("sudo df -k /var/log | sed -n 2p | awk '{ print $4 }'")["stdout"]
    return int(out)


def is_var_log_full(duthost):
    return get_var_log_avail_kb(duthost) == 0


def delete_all_archives_under_var_log(duthost):
    """
    Ensure there are no archived logs before reproducing the bug.
    """
    duthost.shell(
        r"sudo find /var/log -type f -regextype posix-extended "
        r"-regex '.*\.[0-9]+(\.gz)?$' -delete",
        module_ignore_errors=True
    )
    duthost.shell("sudo find /var/log -type f -name '*.1.gz' -delete", module_ignore_errors=True)


def count_archives_under_var_log(duthost):
    out = duthost.shell(
        r"sudo find /var/log -type f -regextype posix-extended "
        r"-regex '.*\.[0-9]+(\.gz)?$' | wc -l"
    )["stdout"]
    return int(out)


def build_origin_log_targets(duthost):
    targets = [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/cron.log",
        "/var/log/teamd.log",
        "/var/log/telemetry.log",
        "/var/log/gnmi.log",
    ]

    duthost.shell("sudo mkdir -p /var/log/swss")

    if duthost.sonichost.is_multi_asic:
        # create per-asic origin logs to look like real multi-asic devices
        for i in range(len(duthost.asics)):
            targets.append(f"/var/log/swss/swss.asic{i}.rec")
            targets.append(f"/var/log/swss/sairedis.asic{i}.rec")
    else:
        targets.append("/var/log/swss/swss.rec")
        targets.append("/var/log/swss/sairedis.rec")

    return targets


def fill_var_log_with_origin_logs_until_full(duthost, chunk_kb=10 * 1024):
    """
    Fill /var/log to 100%.
    Repeatedly grow origin log files until df Available becomes 0.
    """
    targets = build_origin_log_targets(duthost)

    # Ensure files exist (origin logs)
    for p in targets:
        duthost.shell(f"sudo touch {p}")

    idx = 0
    while True:
        avail_kb = get_var_log_avail_kb(duthost)
        if avail_kb <= 0:
            break

        # Allocate up to what's available
        alloc_kb = min(chunk_kb, avail_kb)
        p = targets[idx % len(targets)]

        cur_bytes = int(duthost.shell(f"sudo stat -c%s {p}")["stdout"] or "0")
        new_bytes = cur_bytes + (alloc_kb * 1024)

        duthost.shell(f"sudo fallocate -l {new_bytes} {p}", module_ignore_errors=True)
        idx += 1

    pytest_assert(is_var_log_full(duthost), "Failed to fill /var/log to 100% (Available != 0)")


def syslog_contains_marker(duthost, marker):
    out = duthost.shell(f"sudo grep -F '{marker}' /var/log/syslog", module_ignore_errors=True)
    return out.get("rc", 1) == 0


@pytest.mark.disable_loganalyzer
def test_logrotate_full_partition_no_archives_cleanup(rand_selected_dut, simulate_small_var_log_partition):
    """
    Covers the corner case:
      - /var/log is 100% full
      - space is consumed by origin logs only
      - no archived logs exist yet
    Expectation after fix:
      - running logrotate -f should free space
      - syslog becomes writable again
    """
    duthost = rand_selected_dut

    # Precondition: no archives exist
    delete_all_archives_under_var_log(duthost)
    pytest_assert(count_archives_under_var_log(duthost) == 0, "Precondition failed: archived logs exist")

    # Precondition: /var/log becomes 100% full due to origin logs
    fill_var_log_with_origin_logs_until_full(duthost)
    pytest_assert(is_var_log_full(duthost), "Precondition failed: /var/log is not full")

    # Trigger: forced logrotate. This should rotate logs (creating .1) then cleanup archives in postrotate(syslog)
    run_logrotate(duthost, force=True)

    # Validate: space is available again
    pytest_assert(get_var_log_avail_kb(duthost) > 0, "Expected /var/log to have free space after logrotate cleanup")

    # Validate: syslog writable again (functional)
    marker = f"logrotate-full-no-archives-{int(time.time())}"
    duthost.shell(f"logger -t logrotate-test '{marker}'", module_ignore_errors=True)
    pytest_assert(
        wait_until(30, 1, 0, syslog_contains_marker, duthost, marker),
        "Expected syslog to be writable after cleanup, but marker not found"
    )
