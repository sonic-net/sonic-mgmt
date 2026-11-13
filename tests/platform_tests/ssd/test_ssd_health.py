import json
import logging
import os
import re
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.platform_tests.cli.util import parse_colon_speparated_lines

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
]

# Number of iostat samples during a stress load. The interval between samples depends on the runtime
SSD_IOSTAT_SAMPLE_COUNT = 12

# Kernel messages that show an error of the SSD.
DISK_ERROR_PATTERNS = [
    r"error, dev {disk}\b",
    r"Buffer I/O error on dev(ice)? {disk}(p?\d+)?\b",
    r"EXT4-fs error \(device {partition}\)",
    r"EXT4-fs \({partition}\): Remounting filesystem read-only",
]
# Kernel messages that exist only for one disk type.
DISK_TYPE_ERROR_PATTERNS = {
    "sata": [r"ata\d+(\.\d+)?: (exception Emask|failed command|hard resetting link)"],
    "nvme": [r"{controller}: (I/O \d+.*timeout|controller is down|.*reset controller|Removing after probe failure)",
             r"{disk}: I/O Cmd.*I/O Error"],
}


class SataHealth:
    """
    @summary: Collect the health information of a SATA SSD.
    """
    DEVICE_TYPE = "sata"

    # SMART attributes that are only logged, and have the same meaning on practically all SATA SSDs
    ATTRIBUTE_IDS = {
        "crc_errors": 199,
    }

    def __init__(self, duthost, ssd_device, thresholds):
        self.duthost = duthost
        self.disk = ssd_device["disk"]
        self.media_error_ids = thresholds["media_error_ids"]

    def collect(self):
        """
        @summary: Read the health information of the disk.
        @return: Dictionary with the health fields. A field that the disk does not report is None.
        """
        smartctl_data = self._read_smartctl()
        sonic_health = self._read_sonic_health()
        return self._parse(smartctl_data, sonic_health)

    def _read_smartctl(self):
        # The smartctl exit code is a bitmask, so a non-zero code can still come with valid output
        output = self.duthost.command("smartctl -a -j {}".format(self.disk), module_ignore_errors=True)["stdout"]
        try:
            return json.loads(output)
        except ValueError:
            logger.warning("Could not parse the smartctl output of {}".format(self.disk))
            return {}

    def _read_sonic_health(self):
        output_lines = self.duthost.command("show platform ssdhealth {}".format(self.disk))["stdout_lines"]
        health_value = parse_colon_speparated_lines(output_lines).get("Health", "N/A")
        try:
            return float(health_value.strip("%"))
        except ValueError:
            logger.warning("Could not read the SONiC health value of {}: '{}'".format(self.disk, health_value))
            return None

    def _parse(self, smartctl_data, sonic_health):
        attributes = smartctl_data.get("ata_smart_attributes", {}).get("table", [])
        health = {
            "device_type": self.DEVICE_TYPE,
            "wear_used_percent": round(100 - sonic_health, 2) if sonic_health is not None else None,
            "smart_passed": smartctl_data.get("smart_status", {}).get("passed"),
            "temperature_c": smartctl_data.get("temperature", {}).get("current"),
            "power_on_hours": smartctl_data.get("power_on_time", {}).get("hours"),
            "error_log_count": smartctl_data.get("ata_smart_error_log", {}).get("summary", {}).get("count"),
        }
        for name, attribute_id in self.ATTRIBUTE_IDS.items():
            health[name] = self._get_attribute(attributes, attribute_id).get("raw", {}).get("value")
        health["media_error_counters"] = {}
        for attribute_id in self.media_error_ids:
            attribute = self._get_attribute(attributes, attribute_id)
            counter_name = "{} (ID {})".format(attribute.get("name", "Missing"), attribute_id)
            health["media_error_counters"][counter_name] = attribute.get("raw", {}).get("value")
        return health

    def _get_attribute(self, attributes, attribute_id):
        for attribute in attributes:
            if attribute["id"] == attribute_id:
                return attribute
        return {}


class NvmeHealth:
    """
    @summary: Collect the health information of an NVMe SSD.
    """
    DEVICE_TYPE = "nvme"

    # The NVMe smart-log reports the temperature in Kelvin
    KELVIN_OFFSET = 273

    def __init__(self, duthost, ssd_device, thresholds):
        self.duthost = duthost
        self.disk = ssd_device["disk"]

    def collect(self):
        """
        @summary: Read the health information of the disk.
        """
        smart_log = self._read_smart_log()
        return self._parse(smart_log)

    def _read_smart_log(self):
        output = self.duthost.command("nvme smart-log {} -o json".format(self.disk),
                                      module_ignore_errors=True)["stdout"]
        try:
            return json.loads(output)
        except ValueError:
            logger.warning("Could not parse the nvme smart-log output of {}".format(self.disk))
            return {}

    def _parse(self, smart_log):
        temperature = smart_log.get("temperature")
        return {
            "device_type": self.DEVICE_TYPE,
            "wear_used_percent": smart_log.get("percent_used"),
            "critical_warning": smart_log.get("critical_warning"),
            "temperature_c": temperature - self.KELVIN_OFFSET if temperature is not None else None,
            "power_on_hours": smart_log.get("power_on_hours"),
            "error_log_count": smart_log.get("num_err_log_entries"),
            "media_error_counters": {"media_errors": smart_log.get("media_errors")},
        }


# Health class for each disk type
HEALTH_HANDLERS = {
    "sata": SataHealth,
    "nvme": NvmeHealth,
}


def get_health_handler(duthost, ssd_device, thresholds):
    """
    @summary: Create the health class that matches the type of the disk.
    """
    return HEALTH_HANDLERS[ssd_device["type"]](duthost, ssd_device, thresholds)


def get_critical_health_problems(health, thresholds):
    """
    @summary: Check the fields that show that the disk is in a bad state right now:
              the overall health verdict of the disk, the NVMe critical warning and the temperature.
              A field that is not part of the dictionary or is None is skipped.
    """
    problems = []
    if health.get("smart_passed") is False:
        problems.append("SMART overall-health self-assessment is FAILED")
    critical_warning = health.get("critical_warning")
    if critical_warning:
        problems.append("NVMe critical warning is set: {}".format(critical_warning))
    temperature = health.get("temperature_c")
    if temperature and temperature >= thresholds["max_temperature_c"]:
        problems.append("Temperature is {} C, expected less than {} C".format(
            temperature, thresholds["max_temperature_c"]))
    return problems


def validate_health_snapshot(health, thresholds, skip_media_check=False):
    """
    @summary: Verify that the health dictionary returned by collect() shows a healthy disk.
              A field that is not part of the dictionary does not belong to this disk type and is ignored.
              A field that is part of the dictionary but is None was not reported by the disk and is skipped.
              All the failures are reported together.
    @param skip_media_check: Do not check the media error counters against the threshold. Used before a stress
                             load, where the counters are compared with the values after the load instead.
    """
    logger.info("SSD health: {}".format(health))
    checked_fields = {}
    for field in ["smart_passed", "critical_warning", "temperature_c", "wear_used_percent"]:
        if field in health:
            checked_fields[field] = health[field]
    checked_fields.update(health["media_error_counters"])
    missing_fields = [field for field, value in checked_fields.items() if value is None]
    if missing_fields:
        logger.info("Fields not reported by the disk, their checks are skipped: {}".format(missing_fields))
    if len(missing_fields) == len(checked_fields):
        pytest.skip("The disk does not report any of the checked health fields")

    failures = get_critical_health_problems(health, thresholds)

    if not skip_media_check:
        for name, count in health["media_error_counters"].items():
            if count and count > thresholds["max_media_errors"]:
                failures.append("{} is {}, expected at most {}".format(name, count, thresholds["max_media_errors"]))

    wear = health.get("wear_used_percent")
    if wear and not 0 <= wear <= thresholds["max_wear_used_percent"]:
        failures.append("Wear used is {}%, expected between 0 and {}%".format(
            wear, thresholds["max_wear_used_percent"]))

    pytest_assert(not failures, "SSD health check failed:\n{}".format("\n".join(failures)))


def validate_health_delta(before, after, thresholds):
    """
    @summary: Verify that a stress load did not hurt the disk, by comparing the health before and after the load.
    """
    logger.info("Health after the load: {}".format(after))
    failures = ["After the load: {}".format(problem) for problem in get_critical_health_problems(after, thresholds)]

    for name, count_before in before["media_error_counters"].items():
        if count_before is None:
            continue
        count_after = after["media_error_counters"].get(name)
        if count_after is None:
            failures.append("{} was {} before the load and is not reported after it".format(name, count_before))
        elif count_after > count_before:
            failures.append("{} increased from {} to {} during the load".format(name, count_before, count_after))

    pytest_assert(not failures, "SSD health changed during the load:\n{}".format("\n".join(failures)))


def run_fio(duthost, test_file, runtime, fio_args):
    """
    @summary: Run a bounded fio job on the test file, and fail if fio reported an I/O error.
    """
    command = ("sudo fio --name=ssd_stress --filename={} --size={}M --direct=1 --ioengine=libaio "
               "--time_based --runtime={} --end_fsync=1 --output-format=json {}").format(
                   test_file["path"], test_file["size_mb"], runtime, fio_args)
    result = duthost.command(command, module_ignore_errors=True)
    try:
        job = json.loads(result["stdout"])["jobs"][0]
    except (ValueError, KeyError, IndexError):
        pytest.fail("fio did not return a valid result: {}".format(result["stderr"]))
    logger.info("fio result: error {}, read {} KiB/s {} IOPS, write {} KiB/s {} IOPS".format(
        job["error"], job["read"]["bw"], job["read"]["iops"], job["write"]["bw"], job["write"]["iops"]))
    pytest_assert(job["error"] == 0, "fio reported error {}: {}".format(job["error"], result["stderr"]))
    return job


def run_fio_with_iostat(duthost, ssd_device, test_file, runtime, fio_args):
    """
    @summary: Run a fio job with run_fio while iostat samples the SSD in parallel, and log the iostat samples.
    @return: The result of the fio job, from the fio JSON output.
    """
    interval = max(1, runtime // SSD_IOSTAT_SAMPLE_COUNT)
    iostat_command = "iostat -xm -y -d -o JSON {} {} {}".format(
        os.path.basename(ssd_device["disk"]), interval, SSD_IOSTAT_SAMPLE_COUNT)
    iostat_task, iostat_result = duthost.command(iostat_command, module_async=True)

    fio_result = run_fio(duthost, test_file, runtime, fio_args)

    iostat_output = iostat_result.get(timeout=interval * SSD_IOSTAT_SAMPLE_COUNT)
    iostat_task.close()
    iostat_task.join()
    statistics = json.loads(iostat_output["stdout"])["sysstat"]["hosts"][0]["statistics"]
    samples = [statistic["disk"][0] for statistic in statistics]
    for index, sample in enumerate(samples, 1):
        logger.info("iostat sample {}/{}: read {} IOPS {} MB/s {} ms, write {} IOPS {} MB/s {} ms, "
                    "queue size {}, utilization {}%".format(
                        index, len(samples), sample.get("r/s"), sample.get("rMB/s"), sample.get("r_await"),
                        sample.get("w/s"), sample.get("wMB/s"), sample.get("w_await"),
                        sample.get("aqu-sz"), sample.get("util")))
    return fio_result


def validate_no_new_disk_errors(duthost, ssd_device, start_time):
    """
    @summary: Verify that the kernel did not log errors of the SSD since start_time.
    """
    disk = os.path.basename(ssd_device["disk"])
    names = {
        "disk": re.escape(disk),
        "partition": re.escape(os.path.basename(ssd_device["partition"])),
        "controller": re.escape(re.sub(r"n\d+$", "", disk)),
    }
    templates = DISK_ERROR_PATTERNS + DISK_TYPE_ERROR_PATTERNS[ssd_device["type"]]
    patterns = [template.format(**names) for template in templates]

    start_time_text = start_time.strftime("%Y-%m-%d %H:%M:%S")
    output_lines = duthost.command("sudo dmesg --since '{}'".format(start_time_text))["stdout_lines"]
    disk_errors = [line for line in output_lines
                   if any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns)]
    pytest_assert(not disk_errors, "New disk errors in dmesg since {}:\n{}".format(
        start_time_text, "\n".join(disk_errors)))


def test_ssd_smart_health_baseline(duthosts, rand_one_dut_hostname, ssd_device, ssd_thresholds):
    """
    @summary: Verify that the SSD of the DUT is healthy, from a single health snapshot.
    """
    duthost = duthosts[rand_one_dut_hostname]
    health_handler = get_health_handler(duthost, ssd_device, ssd_thresholds)
    health = health_handler.collect()
    validate_health_snapshot(health, ssd_thresholds)


def test_ssd_write_stress_endurance(duthosts, rand_one_dut_hostname, ssd_device, ssd_thresholds, ssd_test_file,
                                    pytestconfig):
    """
    @summary: Verify that a bounded sequential write load does not hurt the SSD,
              by comparing the health of the disk before and after the load and checking the kernel log.
    """
    duthost = duthosts[rand_one_dut_hostname]
    health_handler = get_health_handler(duthost, ssd_device, ssd_thresholds)
    with allure.step("Collect and validate SSD health before the load"):
        before = health_handler.collect()
        validate_health_snapshot(before, ssd_thresholds, skip_media_check=True)
    with allure.step("Run sequential write load with fio"):
        start_time = duthost.get_now_time()
        fio_result = run_fio(duthost, ssd_test_file, pytestconfig.getoption("ssd_stress_runtime"),
                             "--rw=write --bs=1M --iodepth=32")
        pytest_assert(fio_result["write"]["bw"] > 0 and fio_result["write"]["iops"] > 0,
                      "fio did not write any data to {}".format(ssd_test_file["path"]))
    with allure.step("Collect SSD health after the load"):
        after = health_handler.collect()
    with allure.step("Validate no new disk errors in dmesg"):
        validate_no_new_disk_errors(duthost, ssd_device, start_time)
    with allure.step("Validate SSD health after the load"):
        validate_health_delta(before, after, ssd_thresholds)


def test_ssd_mixed_io_stress(duthosts, rand_one_dut_hostname, ssd_device, ssd_thresholds, ssd_test_file,
                             pytestconfig):
    """
    @summary: Verify that a bounded mixed random read/write load does not hurt the SSD,
              by comparing the health of the disk before and after the load and checking the kernel log.
    """
    duthost = duthosts[rand_one_dut_hostname]
    health_handler = get_health_handler(duthost, ssd_device, ssd_thresholds)
    with allure.step("Collect and validate SSD health before the load"):
        before = health_handler.collect()
        validate_health_snapshot(before, ssd_thresholds, skip_media_check=True)
    with allure.step("Run mixed random read/write load with fio and iostat"):
        start_time = duthost.get_now_time()
        fio_result = run_fio_with_iostat(duthost, ssd_device, ssd_test_file,
                                         pytestconfig.getoption("ssd_stress_runtime"),
                                         "--rw=randrw --rwmixread=70 --bs=4k --iodepth=32")
        for direction in ["read", "write"]:
            pytest_assert(fio_result[direction]["bw"] > 0 and fio_result[direction]["iops"] > 0,
                          "fio did not {} any data on {}".format(direction, ssd_test_file["path"]))
    with allure.step("Collect SSD health after the load"):
        after = health_handler.collect()
    with allure.step("Validate no new disk errors in dmesg"):
        validate_no_new_disk_errors(duthost, ssd_device, start_time)
    with allure.step("Validate SSD health after the load"):
        validate_health_delta(before, after, ssd_thresholds)
