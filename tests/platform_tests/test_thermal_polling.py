"""
Tests for thermalctld per-component polling intervals

Validates that per-component polling intervals configured via platform.json
produce expected polling behavior in thermalctld.
"""
import json
import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)

# Default thermalctld polling interval when no per-component config is present
DEFAULT_POLLING_INTERVAL = 60

# Tolerance factor for timestamp-based polling interval verification
POLLING_TOLERANCE = 0.35


def get_platform_json(duthost):
    """Read and parse platform.json from the DUT. Returns None if not found or malformed."""
    platform = duthost.facts["platform"]
    result = duthost.shell(
        "cat /usr/share/sonic/device/{}/platform.json".format(platform),
        module_ignore_errors=True
    )
    if result["rc"] != 0:
        return None
    try:
        return json.loads(result["stdout"])
    except (ValueError, json.JSONDecodeError):
        logger.warning("platform.json is malformed or empty for platform %s", platform)
        return None


def get_polling_intervals_from_platform_json(platform_json):
    """
    Extract per-component polling intervals from platform.json.

    Returns a dict:
        {
            "fan_drawers": <int or None>,
            "psus": <int or None>,
            "thermals": {<name>: <int>, ...}
        }
    """
    intervals = {"fan_drawers": None, "psus": None, "thermals": {}}

    if not platform_json:
        return intervals

    chassis = platform_json.get("chassis", platform_json)

    # Fan drawer polling interval: first entry without 'name' key
    fan_drawers = chassis.get("fan_drawers", [])
    for entry in fan_drawers:
        if "name" not in entry and "polling_interval" in entry:
            intervals["fan_drawers"] = int(entry["polling_interval"])
            break

    # PSU polling interval: first entry without 'name' key
    psus = chassis.get("psus", [])
    for entry in psus:
        if "name" not in entry and "polling_interval" in entry:
            intervals["psus"] = int(entry["polling_interval"])
            break

    # Per-thermal polling intervals
    thermals = chassis.get("thermals", [])
    for entry in thermals:
        if "name" in entry and "polling_interval" in entry:
            intervals["thermals"][entry["name"]] = int(entry["polling_interval"])

    return intervals


class TestPerComponentPollingIntervals:
    """
    Validate that per-component polling intervals configured in platform.json
    produce expected polling behavior in thermalctld.
    """

    def test_platform_json_polling_intervals_parsed(
            self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Verify that platform.json contains per-component polling intervals
        and thermalctld is running (prerequisite for polling behavior).
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        platform_json = get_platform_json(duthost)
        pytest_assert(platform_json is not None,
                      "platform.json not found on DUT")

        intervals = get_polling_intervals_from_platform_json(platform_json)
        has_any_interval = (
            intervals["fan_drawers"] is not None or
            intervals["psus"] is not None or
            len(intervals["thermals"]) > 0
        )

        if not has_any_interval:
            pytest.skip("No per-component polling intervals configured in platform.json")

        # Verify thermalctld is running
        result = duthost.shell(
            "docker exec pmon supervisorctl status thermalctld",
            module_ignore_errors=True
        )
        pytest_assert("RUNNING" in result["stdout"],
                      "thermalctld is not running")

        logger.info("Per-component polling intervals found: %s", json.dumps(intervals, indent=2))

    def test_thermal_sensors_update_at_configured_intervals(
            self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        For thermals with a polling_interval in platform.json, verify that
        TEMPERATURE_INFO entries are updated at approximately the configured rate.

        Test strategy:
        - Pick a fast-polling thermal and a slow-polling thermal (if available).
        - Sample timestamps over a window and verify the update frequency
          matches the configured interval within tolerance.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        platform_json = get_platform_json(duthost)
        if platform_json is None:
            pytest.skip("platform.json not found")

        intervals = get_polling_intervals_from_platform_json(platform_json)
        if not intervals["thermals"]:
            pytest.skip("No per-thermal polling intervals configured in platform.json")

        # Verify thermalctld is running
        result = duthost.shell(
            "docker exec pmon supervisorctl status thermalctld",
            module_ignore_errors=True
        )
        pytest_assert("RUNNING" in result["stdout"],
                      "thermalctld is not running")

        # Pick the thermal with the shortest configured interval
        sorted_thermals = sorted(intervals["thermals"].items(), key=lambda x: x[1])
        fast_thermal_name, fast_interval = sorted_thermals[0]

        logger.info("Testing fast-polling thermal '%s' with interval %ds",
                    fast_thermal_name, fast_interval)

        # Verify the sensor exists in STATE_DB
        check_result = duthost.shell(
            'sonic-db-cli STATE_DB EXISTS "TEMPERATURE_INFO|{}"'.format(fast_thermal_name),
            module_ignore_errors=True
        )
        if check_result["rc"] != 0 or check_result["stdout"].strip() == "0":
            pytest.skip("Thermal sensor '{}' not found in STATE_DB TEMPERATURE_INFO".format(
                fast_thermal_name))

        # Collect timestamps over observation window
        # Observe for at least 3x the interval to get meaningful samples,
        # but cap at 300s to avoid excessively long test runs.
        MAX_OBSERVATION_TIME = 300
        if fast_interval > MAX_OBSERVATION_TIME // 2:
            pytest.skip("Fastest thermal polling interval ({}s) is too long for real-time "
                        "verification (max observation {}s)".format(fast_interval, MAX_OBSERVATION_TIME))
        observation_time = min(max(fast_interval * 3, 30), MAX_OBSERVATION_TIME)
        sample_interval = max(fast_interval // 2, 2)
        num_samples = observation_time // sample_interval

        logger.info("Collecting %d samples over %ds (sample every %ds)",
                    num_samples, observation_time, sample_interval)

        timestamps = []
        for _ in range(num_samples):
            ts = duthost.shell(
                'sonic-db-cli STATE_DB HGET "TEMPERATURE_INFO|{}" timestamp'.format(
                    fast_thermal_name),
                module_ignore_errors=True
            )
            if ts["rc"] == 0 and ts["stdout"].strip():
                timestamps.append(ts["stdout"].strip())
            time.sleep(sample_interval)

        # Count unique timestamps (each unique timestamp = one update cycle)
        unique_timestamps = []
        for ts in timestamps:
            if not unique_timestamps or unique_timestamps[-1] != ts:
                unique_timestamps.append(ts)

        # We expect approximately observation_time / fast_interval updates
        expected_updates = observation_time / fast_interval
        actual_updates = len(unique_timestamps)

        logger.info("Expected ~%.1f updates, observed %d unique timestamps",
                    expected_updates, actual_updates)

        # Verify update frequency is within tolerance
        min_expected = expected_updates * (1 - POLLING_TOLERANCE)

        pytest_assert(
            actual_updates >= min_expected,
            "Thermal '{}' updated {} times in {}s, expected at least {:.0f} "
            "(interval={}s, tolerance={}%)".format(
                fast_thermal_name, actual_updates, observation_time,
                min_expected, fast_interval, POLLING_TOLERANCE * 100
            )
        )

        # If there's also a slow-polling thermal, verify it updates less frequently
        if len(sorted_thermals) > 1:
            slow_thermal_name, slow_interval = sorted_thermals[-1]
            if slow_interval > fast_interval * 2:
                logger.info("Also checking slow-polling thermal '%s' (interval=%ds)",
                            slow_thermal_name, slow_interval)

                # Check sensor exists
                slow_check = duthost.shell(
                    'sonic-db-cli STATE_DB EXISTS "TEMPERATURE_INFO|{}"'.format(slow_thermal_name),
                    module_ignore_errors=True
                )
                if slow_check["rc"] == 0 and slow_check["stdout"].strip() != "0":
                    # Sample slow sensor
                    slow_unique = []
                    for _ in range(min(num_samples, 5)):
                        ts = duthost.shell(
                            'sonic-db-cli STATE_DB HGET "TEMPERATURE_INFO|{}" timestamp'.format(
                                slow_thermal_name),
                            module_ignore_errors=True
                        )
                        if ts["rc"] == 0 and ts["stdout"].strip():
                            if not slow_unique or slow_unique[-1] != ts["stdout"].strip():
                                slow_unique.append(ts["stdout"].strip())
                        time.sleep(sample_interval)

                    # Slow thermal should have fewer updates than fast thermal
                    logger.info("Slow thermal '%s': %d unique timestamps vs fast thermal: %d",
                                slow_thermal_name, len(slow_unique), actual_updates)
                    pytest_assert(
                        len(slow_unique) <= actual_updates,
                        "Slow thermal '{}' (interval={}s) should not update more often than "
                        "fast thermal '{}' (interval={}s)".format(
                            slow_thermal_name, slow_interval,
                            fast_thermal_name, fast_interval
                        )
                    )

    def test_fan_drawer_polling_interval(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Verify fan drawer updates respect the configured polling interval.
        Checks FAN_INFO entries in STATE_DB for update cadence.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        platform_json = get_platform_json(duthost)
        if platform_json is None:
            pytest.skip("platform.json not found")

        intervals = get_polling_intervals_from_platform_json(platform_json)
        if intervals["fan_drawers"] is None:
            pytest.skip("No fan_drawers polling interval configured in platform.json")

        fan_interval = intervals["fan_drawers"]
        logger.info("Fan drawer polling interval configured: %ds", fan_interval)

        MAX_OBSERVATION_TIME = 300
        if fan_interval > MAX_OBSERVATION_TIME // 2:
            pytest.skip("Fan drawer polling interval ({}s) is too long for real-time "
                        "verification (max observation {}s)".format(fan_interval, MAX_OBSERVATION_TIME))

        # Get a fan name from FAN_INFO
        fan_keys_result = duthost.shell(
            'sonic-db-cli STATE_DB KEYS "FAN_INFO|*"',
            module_ignore_errors=True
        )
        if fan_keys_result["rc"] != 0 or not fan_keys_result["stdout"].strip():
            pytest.skip("No FAN_INFO entries found in STATE_DB")

        fan_keys = fan_keys_result["stdout"].strip().split("\n")
        fan_key = fan_keys[0]
        fan_name = fan_key.split("|", 1)[1]

        logger.info("Monitoring fan '%s' for update cadence", fan_name)

        # Collect timestamp samples
        observation_time = min(max(fan_interval * 3, 60), MAX_OBSERVATION_TIME)
        sample_interval = max(fan_interval // 3, 5)
        num_samples = observation_time // sample_interval

        timestamps = []
        for _ in range(num_samples):
            ts = duthost.shell(
                'sonic-db-cli STATE_DB HGET "{}" timestamp'.format(fan_key),
                module_ignore_errors=True
            )
            if ts["rc"] == 0 and ts["stdout"].strip():
                timestamps.append(ts["stdout"].strip())
            time.sleep(sample_interval)

        unique_timestamps = []
        for ts in timestamps:
            if not unique_timestamps or unique_timestamps[-1] != ts:
                unique_timestamps.append(ts)

        expected_updates = observation_time / fan_interval
        actual_updates = len(unique_timestamps)

        logger.info("Fan updates: expected ~%.1f, observed %d",
                    expected_updates, actual_updates)

        min_expected = expected_updates * (1 - POLLING_TOLERANCE)
        pytest_assert(
            actual_updates >= min_expected,
            "Fan '{}' updated {} times in {}s, expected at least "
            "{:.0f} (interval={}s)".format(
                fan_name, actual_updates, observation_time,
                min_expected, fan_interval
            )
        )

    def test_psu_polling_interval(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Verify PSU updates respect the configured polling interval.
        Checks PSU_INFO entries in STATE_DB for update cadence.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        platform_json = get_platform_json(duthost)
        if platform_json is None:
            pytest.skip("platform.json not found")

        intervals = get_polling_intervals_from_platform_json(platform_json)
        if intervals["psus"] is None:
            pytest.skip("No PSU polling interval configured in platform.json")

        psu_interval = intervals["psus"]
        logger.info("PSU polling interval configured: %ds", psu_interval)

        MAX_OBSERVATION_TIME = 300
        if psu_interval > MAX_OBSERVATION_TIME // 2:
            pytest.skip("PSU polling interval ({}s) is too long for real-time "
                        "verification (max observation {}s)".format(psu_interval, MAX_OBSERVATION_TIME))

        # Get a PSU name from PSU_INFO
        psu_keys_result = duthost.shell(
            'sonic-db-cli STATE_DB KEYS "PSU_INFO|*"',
            module_ignore_errors=True
        )
        if psu_keys_result["rc"] != 0 or not psu_keys_result["stdout"].strip():
            pytest.skip("No PSU_INFO entries found in STATE_DB")

        psu_keys = psu_keys_result["stdout"].strip().split("\n")
        psu_key = psu_keys[0]
        psu_name = psu_key.split("|", 1)[1]

        logger.info("Monitoring PSU '%s' for update cadence", psu_name)

        # Collect timestamp samples
        observation_time = min(max(psu_interval * 3, 60), MAX_OBSERVATION_TIME)
        sample_interval = max(psu_interval // 3, 5)
        num_samples = observation_time // sample_interval

        timestamps = []
        for _ in range(num_samples):
            ts = duthost.shell(
                'sonic-db-cli STATE_DB HGET "{}" timestamp'.format(psu_key),
                module_ignore_errors=True
            )
            if ts["rc"] == 0 and ts["stdout"].strip():
                timestamps.append(ts["stdout"].strip())
            time.sleep(sample_interval)

        unique_timestamps = []
        for ts in timestamps:
            if not unique_timestamps or unique_timestamps[-1] != ts:
                unique_timestamps.append(ts)

        expected_updates = observation_time / psu_interval
        actual_updates = len(unique_timestamps)

        logger.info("PSU updates: expected ~%.1f, observed %d",
                    expected_updates, actual_updates)

        min_expected = expected_updates * (1 - POLLING_TOLERANCE)
        pytest_assert(
            actual_updates >= min_expected,
            "PSU '{}' updated {} times in {}s, expected at least "
            "{:.0f} (interval={}s)".format(
                psu_name, actual_updates, observation_time,
                min_expected, psu_interval
            )
        )

    def test_default_polling_without_config(self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        If platform.json has no per-component polling intervals,
        thermalctld uses the default 60s interval for all components.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        platform_json = get_platform_json(duthost)
        if platform_json is None:
            pytest.skip("platform.json not found")

        intervals = get_polling_intervals_from_platform_json(platform_json)
        has_any_interval = (
            intervals["fan_drawers"] is not None or
            intervals["psus"] is not None or
            len(intervals["thermals"]) > 0
        )

        if has_any_interval:
            pytest.skip("Per-component polling intervals are configured; "
                        "this test is for the no-config case")

        # Verify thermalctld is running
        result = duthost.shell(
            "docker exec pmon supervisorctl status thermalctld",
            module_ignore_errors=True
        )
        pytest_assert("RUNNING" in result["stdout"],
                      "thermalctld is not running")

        # Get any thermal sensor
        temp_keys = duthost.shell(
            'sonic-db-cli STATE_DB KEYS "TEMPERATURE_INFO|*"',
            module_ignore_errors=True
        )
        if temp_keys["rc"] != 0 or not temp_keys["stdout"].strip():
            pytest.skip("No TEMPERATURE_INFO entries found in STATE_DB")

        keys = temp_keys["stdout"].strip().split("\n")
        sensor_key = keys[0]
        sensor_name = sensor_key.split("|", 1)[1]

        logger.info("Checking default polling for sensor '%s'", sensor_name)

        # Sample over 3x the default interval to observe at least 3 update cycles
        observation_time = DEFAULT_POLLING_INTERVAL * 3
        sample_interval = DEFAULT_POLLING_INTERVAL // 3
        num_samples = observation_time // sample_interval

        timestamps = []
        for _ in range(num_samples):
            ts = duthost.shell(
                'sonic-db-cli STATE_DB HGET "{}" timestamp'.format(sensor_key),
                module_ignore_errors=True
            )
            if ts["rc"] == 0 and ts["stdout"].strip():
                timestamps.append(ts["stdout"].strip())
            time.sleep(sample_interval)

        unique_timestamps = []
        for ts in timestamps:
            if not unique_timestamps or unique_timestamps[-1] != ts:
                unique_timestamps.append(ts)

        # Over 3 default cycles, expect at least 2 updates
        expected_updates = observation_time / DEFAULT_POLLING_INTERVAL
        min_expected = expected_updates * (1 - POLLING_TOLERANCE)
        pytest_assert(
            len(unique_timestamps) >= min_expected,
            "Sensor '{}' should update at least {:.0f} times in {}s with default "
            "{}s polling (got {} unique timestamps)".format(
                sensor_name, min_expected, observation_time,
                DEFAULT_POLLING_INTERVAL, len(unique_timestamps))
        )
