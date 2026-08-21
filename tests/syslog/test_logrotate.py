import time
import logging
import pytest
import allure

from contextlib import contextmanager
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
SYSLOG_BACKUP_FILE = '/tmp/syslog_bk'
LOGROTATE_TEST_STATE_FILE = '/tmp/logrotate-test.status'
SDK_DUMP_CONFIG = '/etc/logrotate.d/sdk-dump'
SDK_DUMP_ROOTS = [
    '/var/log/sdk_dbg',
    '/var/log/sai_failure_dump',
    '/var/log/mellanox/sdk-dumps',
    '/var/log/bluefield/sdk-dumps',
]
# Just past the minage of the config, so that reclaiming these while the dumps written
# during the test are held back pins that minage to a day rather than bracketing it
SDK_DUMP_STALE_AGE = '25 hours ago'
# Any past date does, it only has to be far enough back that the hourly schedule of the
# config has elapsed by the time the run under test reads it
SDK_DUMP_LAST_ROTATED = '2020-1-1-1:0:0'
# Only the NVIDIA/Mellanox SDK produces these dumps, so only these platforms have
# anything for the config to clean up
SDK_DUMP_ASIC_TYPES = ['mellanox', 'nvidia-bluefield']


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
    logger.info('Backup syslog file to {}'.format(SYSLOG_BACKUP_FILE))
    duthost.shell('sudo cp -f /var/log/syslog {}'.format(SYSLOG_BACKUP_FILE))
    duthost.shell('sudo rm -f {}'.format(LOGROTATE_TEST_STATE_FILE), module_ignore_errors=True)

    yield

    logger.info('Recover syslog file to syslog')
    duthost.shell('sudo mv {} /var/log/syslog'.format(SYSLOG_BACKUP_FILE), module_ignore_errors=True)
    duthost.shell('sudo rm -f {}'.format(LOGROTATE_TEST_STATE_FILE), module_ignore_errors=True)

    logger.info('Restart rsyslog service')
    duthost.shell('sudo service rsyslog restart')


@pytest.fixture(scope='function')
def simulate_small_var_log_partition(rand_selected_dut, localhost):
    """
    Simulate a small var log partition
    :param rand_selected_dut: The fixture returns a randomly selected DUT
    """
    duthost = rand_selected_dut
    setup_finished = False
    try:
        with allure.step('Create a small var log partition with size of {}'.format(SMALL_VAR_LOG_PARTITION_SIZE)):
            logger.info('Create a small var log partition with size of {}'.format(SMALL_VAR_LOG_PARTITION_SIZE))
            duthost.shell('sudo fallocate -l {} log-new-partition'.format(SMALL_VAR_LOG_PARTITION_SIZE))
            duthost.shell('sudo losetup -P  /dev/loop2 log-new-partition')
            duthost.shell('sudo mkfs.ext4 /dev/loop2')
            duthost.shell('sudo mount /dev/loop2 /var/log')
            duthost.shell('sudo cp -f {} /var/log/syslog'.format(SYSLOG_BACKUP_FILE))
            duthost.shell('sudo rm -f {}'.format(LOGROTATE_TEST_STATE_FILE), module_ignore_errors=True)

            config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)

            logger.info('Start logrotate-config service')
            duthost.shell('sudo service logrotate-config restart')
            setup_finished = True

        yield
    finally:
        with allure.step('Recovery var log'):
            logger.info('Umount and unload the small var log partition')
            duthost.shell('sudo umount -l /dev/loop2', module_ignore_errors=True)
            duthost.shell('sudo losetup -d /dev/loop2', module_ignore_errors=True)

            logger.info('Remove the small var log partition')
            duthost.shell('sudo rm -f log-new-partition', module_ignore_errors=True)

            if setup_finished:
                config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)
            else:
                try:
                    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)
                except Exception:
                    logger.exception('Failed to recover config after small var log setup failure')

            logger.info('Restart logrotate-config service')
            duthost.shell('sudo service logrotate-config restart', module_ignore_errors=not setup_finished)


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


def collect_syslog_rotate_state(duthost):
    """Collect logrotate state useful for debugging intermittent failures."""
    cmds = [
        'ls -l /var/log/syslog* || true',
        'du -k /var/log/syslog || true',
        'cat {} || true'.format(LOGROTATE_TEST_STATE_FILE),
        'cat /var/lib/logrotate/status || true',
    ]
    result = duthost.shell('sudo sh -c {}'.format(repr(' ; '.join(cmds))), module_ignore_errors=True)
    logger.info('Syslog/logrotate state:\nstdout:\n{}\nstderr:\n{}'.format(
        result.get('stdout', ''), result.get('stderr', '')
    ))
    return result.get('stdout', '')


def get_oldest_syslog_checksum(duthost):
    checksum = "0"

    # 1. Get the oldest file
    res = duthost.shell('sudo ls -lrt /var/log/syslog.*', module_ignore_errors=True)
    if not res['stdout_lines']:
        return checksum      # Return "0" if no syslog files found

    line = res['stdout_lines'][0]
    filename = line.split()[-1]

    # 2. Get the checksum with error handling
    md5_res = duthost.shell('sudo md5sum {}'.format(filename), module_ignore_errors=True)

    # Check if the output is valid before splitting
    if md5_res['rc'] == 0 and md5_res['stdout_lines']:
        checksum = md5_res['stdout_lines'][0].split()[0]

    logger.debug('=== {}: md5sum: {} === '.format(filename, checksum))
    return checksum


def run_logrotate(duthost, force=False):
    """
    Run logrotate command
    :param duthost: DUT host object
    :param force: force logrotate run immediately even the syslog size is very small, value is True or False
    """
    if force:
        logger.debug('Make sure there is no big /var/log/syslog exist by forcing execute logrotate')
        cmd = 'sudo /usr/sbin/logrotate -s {} -f /etc/logrotate.conf'.format(LOGROTATE_TEST_STATE_FILE)
    else:
        cmd = 'sudo /usr/sbin/logrotate -s {} /etc/logrotate.conf'.format(LOGROTATE_TEST_STATE_FILE)
    logger.info('Run logrotate command: {}'.format(cmd))
    result = duthost.shell(cmd, module_ignore_errors=True)
    logger.info(
        'Logrotate result rc={} stdout={} stderr={}'.format(
            result.get('rc'), result.get('stdout', ''), result.get('stderr', '')
        )
    )
    return result


def assert_logrotate_success(duthost, result):
    if result.get('rc') != 0:
        state = collect_syslog_rotate_state(duthost)
        pytest.fail(
            'Logrotate command failed unexpectedly. rc={}, stdout={}, stderr={}, state={}'.format(
                result.get('rc'), result.get('stdout', ''), result.get('stderr', ''), state
            )
        )


def multiply_with_unit(logrotate_threshold, num):
    """
    Multiply logrotate_threshold with number, and return the value
    Such as '1024K' * 0.5, return '512K'
    :param logrotate_threshold: string type threshold value with unit, such as '1024K'
    :param num: the number need to multiply with
    :return: value with unit, such as '512K'
    """
    return str(int(int(logrotate_threshold[:-1]) * num)) + logrotate_threshold[-1]


def validate_logrotate_function(duthost, logrotate_threshold, small_size):
    """
    Validate logrotate function
    :param duthost: DUT host object
    :param logrotate_threshold: logrotate threshold, such as 16M or 1024K
    """
    with allure.step('Run logrotate with force option to prepare clean syslog environment'):
        logrotate_result = run_logrotate(duthost, force=True)
        assert_logrotate_success(duthost, logrotate_result)

    with allure.step('There should be no logrotate process when rsyslog size is smaller than threshold {}'.format(
            logrotate_threshold)):
        syslog_number_origin = get_syslog_file_count(duthost)
        logger.info('There are {} syslog gz files'.format(syslog_number_origin))
        if small_size:
            create_temp_syslog_file(duthost, multiply_with_unit(logrotate_threshold, 0.5))
        else:
            create_temp_syslog_file(duthost, multiply_with_unit(logrotate_threshold, 0.9))

        oldest_checksum_before_rotate = get_oldest_syslog_checksum(duthost)
        logrotate_result = run_logrotate(duthost)
        assert_logrotate_success(duthost, logrotate_result)
        syslog_number_no_rotate = get_syslog_file_count(duthost)
        logger.info('There are {} syslog gz files after running logrotate'.format(syslog_number_no_rotate))
        # For no rotation happen, both two conditions has to be satisfied
        # 1. the number of syslog files keep the same
        # 2. the oldest log file's checksum keep the same
        oldest_checksum_after_rotate = get_oldest_syslog_checksum(duthost)
        if (syslog_number_origin != syslog_number_no_rotate or
                oldest_checksum_before_rotate != oldest_checksum_after_rotate):
            state = collect_syslog_rotate_state(duthost)
            pytest.fail(
                'Unexpected logrotate happens, there should be no logrotate executed. '
                'origin={}, after={}, checksum_before={}, checksum_after={}, rc={}, state={}'.format(
                    syslog_number_origin, syslog_number_no_rotate,
                    oldest_checksum_before_rotate, oldest_checksum_after_rotate,
                    logrotate_result.get('rc'), state
                )
            )

    with allure.step('There will be logrotate process when rsyslog size is larger than threshold {}'.format(
            logrotate_threshold)):
        create_temp_syslog_file(duthost, multiply_with_unit(logrotate_threshold, 1.1))
        oldest_checksum_before_rotate = get_oldest_syslog_checksum(duthost)
        logrotate_result = run_logrotate(duthost)
        assert_logrotate_success(duthost, logrotate_result)
        syslog_number_with_rotate = get_syslog_file_count(duthost)
        logger.info('There are {} syslog gz files after running logrotate'.format(syslog_number_with_rotate))
        oldest_checksum_after_rotate = get_oldest_syslog_checksum(duthost)
        # For rotation happen,
        # 1. If the number of syslog file the same, the oldest log file checksum has to be different
        #    This is the corner case that number of log files reach the rotate limit.
        # 2. Otherwise, number of log file has to increase by 1
        if syslog_number_origin == syslog_number_with_rotate:
            if oldest_checksum_before_rotate == oldest_checksum_after_rotate:
                state = collect_syslog_rotate_state(duthost)
                pytest.fail(
                    'No logrotate happens, both syslog file number and timestamp are the same. '
                    'origin={}, after={}, checksum_before={}, checksum_after={}, rc={}, state={}'.format(
                        syslog_number_origin, syslog_number_with_rotate,
                        oldest_checksum_before_rotate, oldest_checksum_after_rotate,
                        logrotate_result.get('rc'), state
                    )
                )
        elif syslog_number_origin + 1 != syslog_number_with_rotate:
            state = collect_syslog_rotate_state(duthost)
            pytest.fail(
                'No logrotate happens, the number of syslog files does not increase by 1. '
                'origin={}, after={}, checksum_before={}, checksum_after={}, rc={}, state={}'.format(
                    syslog_number_origin, syslog_number_with_rotate,
                    oldest_checksum_before_rotate, oldest_checksum_after_rotate,
                    logrotate_result.get('rc'), state
                )
            )


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


def get_existing_paths(duthost, paths):
    """
    Return the subset of the given paths that exist on the DUT
    :param duthost: DUT host object
    :param paths: list of absolute paths
    :return: set of the paths that exist
    """
    result = duthost.shell(
        """sudo sh -c 'for f in {}; do [ -e "$f" ] && echo "$f"; done; exit 0'""".format(" ".join(paths)))
    return set(result["stdout_lines"])


def build_sdk_dump_tree(root, unique):
    """
    Build the paths of the dumps one SDK dump run leaves under a dump root
    :param root: dump root the run writes under
    :param unique: token that keeps this run's paths clear of any other dump on the DUT
    :return: one dump at each of the depths the config globs cover, and the directories
        holding them
    """
    dump = '{}/sai_sdk_dump_{}'.format(root, unique)
    extras = '{}/sai_sdk_dump_{}_extras'.format(dump, unique)
    dumps = ['{}/sdk_dump_ext_{}_dev1_summary.txt'.format(root, unique),
             '{}/sai_sdk_dump_{}.json'.format(dump, unique),
             '{}/PORT_0.json'.format(extras),
             '{}/subdir/VLAN_1.json'.format(extras)]
    dirs = [dump, extras, '{}/subdir'.format(extras)]
    return dumps, dirs


@contextmanager
def sdk_dump_files_created(duthost):
    """
    Create a stale and a fresh SDK dump at every depth the config globs, under every
    dump root

    The two runs are identical apart from their unique token, so a dump and the dump
    held against it are matched by exactly the same globs, and every glob in the config
    ends up with a dump on each side of its minage to read its decision from.

    Cleanup only removes the paths created here, and any dump root or root parent it
    had to create. Dumps that were already on the DUT are not restored, as the logrotate
    run under test reclaims those too.

    :param duthost: DUT host object
    :return: the dump directories the config must leave in place, the dumps backdated
        past its minage, and the dumps left inside it
    """
    unique = 'sonicmgmt{}'.format(int(time.time()))
    stale_unique = '{}stale'.format(unique)
    fresh_unique = '{}fresh'.format(unique)
    parents = [parent for parent in {root.rsplit('/', 1)[0] for root in SDK_DUMP_ROOTS} if parent != LOG_FOLDER]
    preexisting = get_existing_paths(duthost, SDK_DUMP_ROOTS + parents)
    stale, fresh, dirs = [], [], list(SDK_DUMP_ROOTS)
    for root in SDK_DUMP_ROOTS:
        stale_dumps, stale_dirs = build_sdk_dump_tree(root, stale_unique)
        fresh_dumps, fresh_dirs = build_sdk_dump_tree(root, fresh_unique)
        # `rotate 0` deletes by renaming first, so without `dateext` rotating a dump
        # clobbers its own `.1` sibling, which fails the run and orphans a `.2`
        collide = '{}/sdk_dump_ext_{}_dev1_collide.txt'.format(root, stale_unique)
        stale += stale_dumps + [collide, '{}.1'.format(collide)]
        fresh += fresh_dumps
        dirs += stale_dirs + fresh_dirs

    try:
        with allure.step('Create stale and fresh SDK dumps at every depth under every dump root'):
            logger.info('Create temp SDK dump files under {}'.format(SDK_DUMP_ROOTS))
            duthost.shell('sudo mkdir -p {}'.format(' '.join(dirs)))
            duthost.shell("""sudo sh -c 'for f in {}; do head -c 4096 /dev/urandom > "$f"; done'""".format(
                ' '.join(stale + fresh)))
            duthost.shell('sudo touch -d "{}" {}'.format(SDK_DUMP_STALE_AGE, ' '.join(stale)))

        yield dirs, stale, fresh
    finally:
        with allure.step('Remove the temp SDK dump files'):
            logger.info('Remove the temp SDK dump files')
            for root in SDK_DUMP_ROOTS:
                duthost.shell("sudo find {} -name '*{}*' -exec rm -rf {{}} +".format(root, unique),
                              module_ignore_errors=True)
                if root not in preexisting:
                    duthost.shell('sudo rm -rf {}'.format(root), module_ignore_errors=True)
            # Removing a root can leave the directory holding it behind, as `mkdir -p`
            # creates that too. `rmdir` keeps one that is still in use on the DUT
            for parent in parents:
                if parent not in preexisting:
                    duthost.shell('sudo rmdir {}'.format(parent), module_ignore_errors=True)
            # Back to the empty state the module starts from, so that a state seeded for
            # the dumps here does not decide the runs of the tests that follow
            duthost.shell('sudo rm -f {}'.format(LOGROTATE_TEST_STATE_FILE), module_ignore_errors=True)


@pytest.mark.disable_loganalyzer
def test_sdk_dump_logrotate_minage(rand_selected_dut):
    """
    Test case of the sdk-dump logrotate config holding back the dumps inside its minage

    The other case forces the run, which overrides the minage, so this is where a
    config that reclaims a dump still being collected would be caught.

    :param rand_selected_dut: The fixture returns a randomly selected DUT
    """
    duthost = rand_selected_dut
    if duthost.shell('test -f {}'.format(SDK_DUMP_CONFIG), module_ignore_errors=True)['rc'] != 0:
        pytest.skip('{} is not present on this image, nothing to test'.format(SDK_DUMP_CONFIG))

    # Checked here rather than in a conditional mark, as the conditional mark plugin
    # evaluates asic_type against the first DUT of the testbed, not the selected one
    asic_type = duthost.facts['asic_type']
    if asic_type not in SDK_DUMP_ASIC_TYPES:
        pytest.skip('{} does not produce SDK dumps, nothing for the config to clean up'.format(asic_type))

    with sdk_dump_files_created(duthost) as (_, stale_dumps, fresh_dumps):
        with allure.step('Run logrotate without force so the minage of the config applies'):
            # The config rotates hourly, so a dump logrotate holds no state for is stamped
            # at the current hour and held as already rotated, short of the minage check
            state = ['logrotate state -- version 2']
            state += ['"{}" {}'.format(dump, SDK_DUMP_LAST_ROTATED) for dump in stale_dumps + fresh_dumps]
            duthost.copy(content='\n'.join(state) + '\n', dest=LOGROTATE_TEST_STATE_FILE)
            logrotate_result = run_logrotate(duthost)
            assert_logrotate_success(duthost, logrotate_result)

        remaining = get_existing_paths(duthost, stale_dumps + fresh_dumps)

        with allure.step('Check the dumps past the minage are reclaimed'):
            kept = sorted(set(stale_dumps) & remaining)
            pytest_assert(not kept, 'dumps backdated to {} were not reclaimed: {}'.format(
                repr(SDK_DUMP_STALE_AGE), kept))

        with allure.step('Check the dumps inside the minage are held back'):
            reclaimed = sorted(set(fresh_dumps) - remaining)
            pytest_assert(not reclaimed, 'dumps written just now were reclaimed: {}'.format(reclaimed))


@pytest.mark.disable_loganalyzer
def test_sdk_dump_logrotate(rand_selected_dut):
    """
    Test case of the sdk-dump logrotate config reclaiming SDK dumps

    The globs do not recurse, so the config carries one pattern per depth per dump
    root, and a depth missing from that list is silently never cleaned up. The check
    walks the roots rather than the seeded paths, so if the SDK ever starts dumping
    deeper than the globs reach, that dump is left behind and fails this test, which
    is the signal to add the next depth to the config. The minage is not covered
    here, as forcing overrides it.

    :param rand_selected_dut: The fixture returns a randomly selected DUT
    """
    duthost = rand_selected_dut
    if duthost.shell('test -f {}'.format(SDK_DUMP_CONFIG), module_ignore_errors=True)['rc'] != 0:
        pytest.skip('{} is not present on this image, nothing to test'.format(SDK_DUMP_CONFIG))

    # Checked here rather than in a conditional mark, as the conditional mark plugin
    # evaluates asic_type against the first DUT of the testbed, not the selected one
    asic_type = duthost.facts['asic_type']
    if asic_type not in SDK_DUMP_ASIC_TYPES:
        pytest.skip('{} does not produce SDK dumps, nothing for the config to clean up'.format(asic_type))

    with sdk_dump_files_created(duthost) as (dirs, _, _):
        with allure.step('Run logrotate with force option to reclaim the SDK dumps'):
            logrotate_result = run_logrotate(duthost, force=True)
            assert_logrotate_success(duthost, logrotate_result)

        with allure.step('Check no dumps are left under any dump root'):
            # Walking the roots rather than the seeded paths, so leftovers from a suffix
            # collision and dumps nested deeper than the globs reach are caught too
            find_result = duthost.shell('sudo find {} -type f'.format(' '.join(SDK_DUMP_ROOTS)),
                                        module_ignore_errors=True)
            remaining = [path for path in find_result['stdout_lines'] if path.strip()]
            pytest_assert(not remaining, 'SDK dumps were not cleaned up: {}'.format(sorted(remaining)))

        with allure.step('Check the dump directories are preserved'):
            deleted = set(dirs) - get_existing_paths(duthost, dirs)
            pytest_assert(not deleted, 'SDK dump directories were removed: {}'.format(sorted(deleted)))
