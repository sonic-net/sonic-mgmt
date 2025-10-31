import logging
import pytest
import json
import tests.platform_tests.test_reboot

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.utilities import check_skip_release, wait
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
]

# ============ GLOBALS ============ #

PMON_SUPERVISORD_PREFIX = "pmon#supervisord"
PMON_SUPERVISORD_STORMON_LOG_KILL = "exited: stormond (terminated by SIGKILL; not expected)"  # noqa: E501
PMON_SUPERVISORD_STORMON_SPAWNED = "spawned: 'stormond' with pid"
STORMON_LOG_PREFIX = "pmon#stormond"
STORMON_LOG_START = "Starting Storage Monitoring Daemon"
STORMON_LOG_EXPECT_POLLING_INTERVAL = "Polling Interval set to {} seconds"
STORMON_LOG_EXPECT_SYNC_INTERVAL = "FSIO JSON file Interval set to {} seconds"
STORMON_LOG_SIGTERM = "Caught signal 'SIGTERM'"
STORMON_LOG_SYNC_TO_JSON = "Syncing total and latest procfs reads and writes from STATE_DB to JSON file"  # noqa: E501
STORMON_LOG_EXIT = "Shutting down Storage Monitoring Daemon"

default_polling_interval = 3600
default_sync_interval = 86400

CONFIGDB_STORMOND_SET_INTERVALS_CMD = 'redis-cli -n 4 HSET "STORMOND_CONFIG|INTERVALS" "daemon_polling_interval" "{0}" "fsstats_sync_interval" "{1}"'  # noqa: E501
CONFIGDB_STORMOND_GET_INTERVALS_CMD = 'redis-cli -n 4 HGETALL "STORMOND_CONFIG|INTERVALS"'  # noqa: E501
CONFIGDB_STORMOND_DEL_INTERVALS = 'redis-cli -n 4 DEL "STORMOND_CONFIG|INTERVALS"'  # noqa: E501
CONFIGDB_STORMOND_SET_INTERVALS_OUTPUT = "2"

STORMOND_STATUS_CMD = "docker exec pmon supervisorctl status stormond"
STORMOND_RESTART_CMD = "docker exec pmon supervisorctl restart stormond"

STORAGE_INFO_KEYS = "redis-cli -n 6 KEYS \"STORAGE_INFO*\""
STORAGE_INFO_FSSTATS_SYNC_KEY = "FSSTATS_SYNC"
STORAGE_INFO_HGETALL = "redis-cli -n 6 HGETALL \"STORAGE_INFO|{}\""
STORAGE_INFO_GET_FIELD = "redis-cli -n 6 HGET \"STORAGE_INFO|{}\" \"{}\""

JSON_FILE_NAME = "fsio-rw-stats.json"
JSON_FILE_LOCATION_HOST = "/host/pmon/stormond"
JSON_FILE_LOCATION_CONTAINER = "/usr/share/stormond"

PROC_DISKSTATS_CMD = "cat /proc/diskstats"
RUN_CMD_IN_PMON_CONTAINER = "docker exec pmon"
SIGKILL_STORMOND = "pkill -f -9 /usr/local/bin/stormond"
LIST_INODE_OF_FILE = "ls -i"
LIST_ERROR_MSG = "No such file or directory"


storage_devices = {}
duthost = None

# ============ TEST SETUP FIXTURE ============ #


@pytest.fixture(scope="module", autouse=True)
def establish_baseline(duthosts, enum_rand_one_per_hwsku_hostname, localhost, conn_graph_facts, xcvr_skip_list):  # noqa: E501
    logging.info("In establish_baseline function")
    global duthost
    global storage_devices
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Skip test for certain images

    skip, reason = check_skip_release(duthost, ["201811", "201911", "202012", "202205", "202305", "202311"])  # noqa: E501
    if skip is True:
        pytest.skip("Skip test 'stormond' for {} running image {} due to reason: {}".format(duthost.facts['platform'], duthost.os_version, reason))  # noqa: E501

    # Get storage devices and supported fields per disk
    keys = [key.strip('\"').split('|')[-1] for key in duthost.command(STORAGE_INFO_KEYS)["stdout_lines"]]  # noqa: E501

    for key in keys:
        if key == STORAGE_INFO_FSSTATS_SYNC_KEY: continue  # noqa: E701
        storage_devices[key] = duthost.command(STORAGE_INFO_HGETALL.format(key))["stdout_lines"][::2]  # noqa: E501
        logging.info("{} : {}".format(key, storage_devices[key]))

    # Delete the fsio-rw-stats.json file if it exists and restart stormond with default intervals  # noqa: E501
    _ = duthost.command("rm -f {}/{}".format(JSON_FILE_LOCATION_HOST, JSON_FILE_NAME))  # noqa: E501
    add_configdb_stormon_intervals(default_polling_interval, default_sync_interval)  # noqa: E501
    restart_stormond()

    yield

    # Clean up configDB after all the tests are done running

    logging.info("Clean up configDB to prevent config_check failures")
    _ = duthost.command(CONFIGDB_STORMOND_DEL_INTERVALS)
    restart_stormond()


# ============ HELPER FUNCTIONS ============ #


def add_configdb_stormon_intervals(polling_interval, json_interval):

    # Clear up previously set intervals
    _ = duthost.command(CONFIGDB_STORMOND_DEL_INTERVALS)

    # Adds the stormon intervals to configDB
    logging.info("Setting polling interval to: {}s and json interval to {}s".format(polling_interval, json_interval))  # noqa: E501

    hset_output = duthost.command(CONFIGDB_STORMOND_SET_INTERVALS_CMD.format(polling_interval, json_interval))["stdout_lines"]  # noqa: E501
    rc = any(CONFIGDB_STORMOND_SET_INTERVALS_OUTPUT in line for line in hset_output)  # noqa: E501
    return rc


def get_configdb_stormon_intervals():

    # Gets the polling and JSON intervals from configDB
    logging.info("Getting polling interval and JSON interval from configDB")

    hgetall_output = duthost.command(CONFIGDB_STORMOND_GET_INTERVALS_CMD)["stdout_lines"][1::2]  # noqa: E501
    return hgetall_output


def restart_stormond():

    logging.info("Restarting Storage Monitoring Daemon")
    restart_output = duthost.command(STORMOND_RESTART_CMD)["stdout_lines"]
    wait(5, "Wait 5s for the daemon to restart")
    return True if (restart_output[0] == "stormond: stopped" and restart_output[1] == "stormond: started") else False  # noqa: E501


def get_stormond_status():

    status_output = duthost.command(STORMOND_STATUS_CMD)["stdout_lines"][0].split()  # noqa: E501

    status = status_output[1]
    logging.info("stormon status: {}".format(status_output))
    return (True, status_output[3][:-1]) if status.lower() == "running" else (False, "-1")  # Ignore trailing comma if process is running  # noqa: E501


def get_storage_info_field_value(key, field):
    rc = duthost.command(STORAGE_INFO_GET_FIELD.format(key, field))["stdout_lines"]  # noqa: E501
    return rc[0] if rc is not None else None


def parse_diskstats(diskstats, key):

    for line in diskstats:
        if key in line:
            return int(line.split()[3]), int(line.split()[7])
    return None, None


# ============ ASSERTION FUNCTIONS ============ #


def json_file_assertion():

    """
    Assert that the JSON file exists on the host and return the JSON file
    """

    # Assert JSON file persisted through the reboot
    host_rc = duthost.command("{} {}/{}".format(LIST_INODE_OF_FILE, JSON_FILE_LOCATION_HOST, JSON_FILE_NAME))["stdout_lines"][0]  # noqa: E501
    assert (LIST_ERROR_MSG not in host_rc)

    # Get the JSON file values
    json_file_str = duthost.command("cat {}/{}".format(JSON_FILE_LOCATION_HOST, JSON_FILE_NAME))["stdout_lines"][0]  # noqa: E501
    json_file = json.loads(json_file_str)

    return json_file


def cold_soft_reboot_assertions():

    """
    Assert that:
        1. Total FSIO reads and writes are available in StateDB
        2. Total FSIO RW on StateDB >= corresponding values in JSON file
    """

    json_file = json_file_assertion()

    global storage_devices
    for key in storage_devices.keys():
        total_fsio_reads = get_storage_info_field_value(key, "total_fsio_reads")  # noqa: E501
        total_fsio_writes = get_storage_info_field_value(key, "total_fsio_writes")  # noqa: E501

        # Assert that StateDB has these values
        assert (total_fsio_reads is not None)
        assert (total_fsio_writes is not None)

        # Assert that the latest total reads/writes are >= those from the JSON file  # noqa: E501
        assert (total_fsio_reads >= json_file[key]["total_fsio_reads"])  # noqa: E501
        assert (total_fsio_writes >= json_file[key]["total_fsio_writes"])  # noqa: E501


def fast_warm_reboot_assertions(prev_statedb_total_fsio_reads, prev_statedb_total_fsio_writes):  # noqa: E501

    """
    Assert that:
        1. Total FSIO reads and writes are available in StateDB
        2. Total FSIO RW on StateDB >= previous values
        3. FSIO JSON file is synced with the procfs reads and writes values in StateDB  # noqa: E501
    """

    json_file = json_file_assertion()

    global storage_devices
    for key in storage_devices.keys():
        logging.info("Verifying STORAGE_INFO|{}".format(key))
        current_total_fsio_reads = get_storage_info_field_value(key, "total_fsio_reads")  # noqa: E501
        current_total_fsio_writes = get_storage_info_field_value(key, "total_fsio_writes")  # noqa: E501

        # Assert that StateDB has these values
        assert (current_total_fsio_reads is not None)
        assert (current_total_fsio_writes is not None)

        # Assert that the latest total reads/writes are >= those from the previous reboot  # noqa: E501
        assert (current_total_fsio_reads >= prev_statedb_total_fsio_reads[key])
        assert (current_total_fsio_writes >= prev_statedb_total_fsio_writes[key])  # noqa: E501

        # Assert that the previous totals (before reboot) are equal to the JSON file values  # noqa: E501
        assert (prev_statedb_total_fsio_reads[key] == json_file[key]["total_fsio_reads"])  # noqa: E501
        assert (prev_statedb_total_fsio_writes[key] == json_file[key]["total_fsio_writes"])  # noqa: E501

# ============ TESTS ============ #


class TestStormonDaemon():

    def test_init_state_default_intervals(self):

        """
        This test asserts that stormond:
            1. Is in the expected, running state
            2. Has started with default polling and JSON intervals
        """

        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=STORMON_LOG_PREFIX)  # noqa: E501
        loganalyzer.expect_regex = [STORMON_LOG_START, STORMON_LOG_EXPECT_POLLING_INTERVAL.format(default_polling_interval),  # noqa: E501
                                    STORMON_LOG_EXPECT_SYNC_INTERVAL.format(default_sync_interval)]  # noqa: E501
        with loganalyzer:
            assert (restart_stormond())
            is_running, pid = get_stormond_status()

            assert (is_running)
            assert (pid is not None)

    def test_init_state_custom_intervals(self):

        """
        This test asserts that stormond:
            1. Is in the expected, running state
            2. Has started with custom polling and JSON intervals
        """

        polling_interval = 60
        json_interval = 300

        # Add custom intervals to configdb
        pytest_assert(add_configdb_stormon_intervals(polling_interval, json_interval))  # noqa: E501

        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=STORMON_LOG_PREFIX)  # noqa: E501
        loganalyzer.expect_regex = [STORMON_LOG_START, STORMON_LOG_EXPECT_POLLING_INTERVAL.format(polling_interval),  # noqa: E501
                                    STORMON_LOG_EXPECT_SYNC_INTERVAL.format(json_interval)]  # noqa: E501
        with loganalyzer:
            assert (restart_stormond())
            wait(10, "Wait 10s for the daemon to settle")
            is_running, pid = get_stormond_status()

            assert (is_running)
            assert (pid is not None)

    @pytest.mark.disable_loganalyzer
    def test_running_state(self):

        """
        This test asserts the following:
            1. stormond is running.
            2. Has the correct polling and JSON intervals.
            3. All supported fields for storage devices are correctly posted to the StateDB.  # noqa: E501
        """

        # Ensure that stormond is still running
        assert (get_stormond_status() != (False, None))

        # Assert that the polling and JSON intervals are 60s and 300s
        intervals = get_configdb_stormon_intervals()

        assert (intervals == ['60', '300'])

        # Assert that all the supported fields are posted to StateDB
        global storage_devices

        for key in storage_devices.keys():
            for field in storage_devices[key]:
                assert (get_storage_info_field_value(key, field) is not None)

    @pytest.mark.disable_loganalyzer
    def test_fsstats_sync(self):

        """
        This test asserts the following:
            1. The stormond is running.
            2. The service has the correct polling and JSON intervals.  # noqa: E501
            3. Filesystem statistics synchronization is successful and the relevant key is present in the StateDB.  # noqa: E501
            4. The JSON file is correctly created and exists in the expected location on the host.  # noqa: E501
        """

        # Ensure that stormond is still running
        assert (get_stormond_status() != (False, None))

        # Assert that the polling and JSON intervals are 60s and 300s
        intervals = get_configdb_stormon_intervals()
        assert (intervals == ['60', '300'])

        # Assert that STORAGE_INFO|FSSTATS_SYNC key is present after waiting JSON interval seconds  # noqa: E501
        wait(int(intervals[1]), "Waiting {}s for JSON file to be created".format(intervals[1]))  # noqa: E501
        assert (get_storage_info_field_value("FSSTATS_SYNC", "successful_sync_time") is not None)  # noqa: E501

        # Assert that the JSON file exists in the expected location on the host
        host_rc = duthost.command("{} {}/{}".format(LIST_INODE_OF_FILE, JSON_FILE_LOCATION_HOST, JSON_FILE_NAME))["stdout_lines"][0]  # noqa: E501
        assert (LIST_ERROR_MSG not in host_rc)

        # Confirm that the bind mount between /host/pmon/stormond and pmon:/usr/share/stormond is in effect  # noqa: E501
        # by asserting that the inode of the JSON file is the same in both locations  # noqa: E501

        json_file_inode = host_rc.split()[0]

        pmon_rc = duthost.command("{} {} {}/{}".format(RUN_CMD_IN_PMON_CONTAINER, LIST_INODE_OF_FILE, JSON_FILE_LOCATION_CONTAINER, JSON_FILE_NAME))["stdout_lines"][0]  # noqa: E501

        assert (LIST_ERROR_MSG not in pmon_rc)
        assert (json_file_inode == pmon_rc.split()[0])

    @pytest.mark.disable_loganalyzer
    def test_crash_before_planned_reboot(self):

        """
        This test ensures that the system can handle
        a stormond crash gracefully and verifies
        the service's state before and after the crash.
        """
        polling_interval = 60
        json_interval = 300

        storage_info_before_crash = {}
        storage_info_after_crash = {}

        # Ensure that stormond is still running
        assert (get_stormond_status() != (False, None))

        # Add custom intervals to configdb
        pytest_assert(add_configdb_stormon_intervals(polling_interval, json_interval))  # noqa: E501

        # Get storage information of all disks on the device before daemon crash  # noqa: E501

        global storage_devices
        for key in storage_devices.keys():
            storage_info_before_crash[key] = {}
            for field in storage_devices[key]:
                storage_info_before_crash[key][field] = get_storage_info_field_value(key, field)  # noqa: E501

        # Crash the daemon
        _ = duthost.command("{} {}".format(RUN_CMD_IN_PMON_CONTAINER, SIGKILL_STORMOND))["stdout_lines"]  # noqa: E501

        # Assert that the daemon has crashed
        status, _ = get_stormond_status()
        assert (status is False)

        # Get storage information of all disks on the device after daemon crash
        for key in storage_devices.keys():
            storage_info_after_crash[key] = {}
            for field in storage_devices[key]:
                storage_info_after_crash[key][field] = get_storage_info_field_value(key, field)  # noqa: E501

        # Wait for the daemon to restart
        wait(5, "Wait 5s for the daemon to restart")

        # Assert that the daemon is running
        assert (get_stormond_status() != (False, None))

        # Assert that the storage information values before crash are <= values after the crash  # noqa: E501
        for key in storage_devices.keys():
            for field in storage_devices[key]:
                assert (storage_info_before_crash[key][field] <= storage_info_after_crash[key][field])  # noqa: E501

    @pytest.mark.disable_loganalyzer
    def test_stormon_after_cold_reboot(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, conn_graph_facts, xcvr_skip_list):  # noqa: E501

        """
        This test asserts the following:
            1. stormond is running correctly after a cold reboot
            2. JSON file persists through the reboot
            3. procfs reads/writes are reset as expected.
        """
        # Cold reboot the device
        tests.platform_tests.test_reboot.test_cold_reboot(duthosts, enum_rand_one_per_hwsku_hostname,  # noqa: E501
                                                          localhost, conn_graph_facts, xcvr_skip_list)  # noqa: E501

        # Assert stormond is running
        assert (get_stormond_status() != (False, None))

        cold_soft_reboot_assertions()

    @pytest.mark.disable_loganalyzer
    def test_stormon_after_soft_reboot(self, duthosts, enum_rand_one_per_hwsku_hostname,  # noqa: E501
                                       localhost, conn_graph_facts, xcvr_skip_list):  # noqa: E501

        """
        This test asserts the following:
            1. stormond is running correctly after a soft reboot
            2. JSON file persists through the reboot
            3. procfs reads/writes are reset as expected.
        """

        # Soft reboot the device
        tests.platform_tests.test_reboot.test_soft_reboot(duthosts, enum_rand_one_per_hwsku_hostname,  # noqa: E501
                                                          localhost, conn_graph_facts, xcvr_skip_list)  # noqa: E501

        # Assert stormond is running
        assert (get_stormond_status() != (False, None))

        cold_soft_reboot_assertions()

    @pytest.mark.disable_loganalyzer
    def test_stormon_after_fast_reboot(self, duthosts, enum_rand_one_per_hwsku_hostname,  # noqa: E501
                                       localhost, conn_graph_facts, xcvr_skip_list):  # noqa: E501

        """
        This test asserts the following:
            1. stormond is running correctly after a fast reboot
            2. the JSON file persists through the reboot
            3. the StateDB persists through the reboot
            4. procfs reads/writes are reset as expected.
        """
        total_fsio_reads = {}
        total_fsio_writes = {}

        # Get the latest procfs reads and writes values for each disk on device before the reboot  # noqa: E501
        global storage_devices
        for key in storage_devices.keys():
            total_fsio_reads[key] = get_storage_info_field_value(key, "total_fsio_reads")  # noqa: E501
            total_fsio_writes[key] = get_storage_info_field_value(key, "total_fsio_writes")  # noqa: E501

        # Fast reboot the device if supported
        tests.platform_tests.test_reboot.test_fast_reboot(duthosts, enum_rand_one_per_hwsku_hostname,  # noqa: E501
                                                          localhost, conn_graph_facts, xcvr_skip_list)  # noqa: E501

        # Assert stormond is running
        assert (get_stormond_status() != (False, None))

        fast_warm_reboot_assertions(total_fsio_reads, total_fsio_writes)

    @pytest.mark.disable_loganalyzer
    def test_stormon_after_warm_reboot(self, duthosts, enum_rand_one_per_hwsku_hostname,  # noqa: E501
                                       localhost, conn_graph_facts, xcvr_skip_list):  # noqa: E501

        """
        This test asserts the following:
            1. stormond is running correctly after a warm reboot
            2. the JSON file persists through the reboot
            3. the StateDB persists through the reboot
            4. procfs reads/writes are reset as expected.
        """

        total_fsio_reads = {}
        total_fsio_writes = {}

        # Get the latest procfs reads and writes values for each disk on device before the reboot  # noqa: E501
        global storage_devices
        for key in storage_devices.keys():
            total_fsio_reads[key] = get_storage_info_field_value(key, "total_fsio_reads")  # noqa: E501
            total_fsio_writes[key] = get_storage_info_field_value(key, "total_fsio_writes")  # noqa: E501

        # Warm reboot the device
        tests.platform_tests.test_reboot.test_warm_reboot(duthosts, enum_rand_one_per_hwsku_hostname,  # noqa: E501
                                                          localhost, conn_graph_facts, xcvr_skip_list)  # noqa: E501

        # Assert stormond is running
        assert (get_stormond_status() != (False, None))

        fast_warm_reboot_assertions(total_fsio_reads, total_fsio_writes)
