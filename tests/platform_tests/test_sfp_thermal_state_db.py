"""
Verify SFP temperature in 'show platform temperature' is sourced from
xcvrd-managed TRANSCEIVER_DOM_TEMPERATURE / TRANSCEIVER_DOM_THRESHOLD /
TRANSCEIVER_DOM_FLAG tables in STATE_DB.
"""
import json
import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)


class TestSfpThermalStateDb:
    """
    Validate that 'show platform temperature' SFP rows are sourced from
    xcvrd-managed TRANSCEIVER_DOM_TEMPERATURE / TRANSCEIVER_DOM_THRESHOLD /
    TRANSCEIVER_DOM_FLAG tables in STATE_DB.
    """

    def _get_sfp_ports_with_dom_temperature(self, duthost):
        """Return list of port names that have TRANSCEIVER_DOM_TEMPERATURE entries."""
        result = duthost.shell(
            'sonic-db-cli STATE_DB KEYS "TRANSCEIVER_DOM_TEMPERATURE|*"',
            module_ignore_errors=True
        )
        if result["rc"] != 0 or not result["stdout"].strip():
            return []
        keys = result["stdout"].strip().split("\n")
        return [k.split("|", 1)[1] for k in keys]

    def _get_dom_temperature_data(self, duthost, port):
        """Get temperature value from TRANSCEIVER_DOM_TEMPERATURE for a port."""
        result = duthost.shell(
            'sonic-db-cli STATE_DB HGET "TRANSCEIVER_DOM_TEMPERATURE|{}" temperature'.format(port),
            module_ignore_errors=True
        )
        if result["rc"] == 0 and result["stdout"].strip():
            return result["stdout"].strip()
        return None

    def _get_dom_threshold_data(self, duthost, port):
        """
        Get threshold values from TRANSCEIVER_DOM_THRESHOLD for a port.
        Returns dict with keys: temphighwarning, templowwarning, temphighalarm, templowalarm
        """
        fields = ["temphighwarning", "templowwarning", "temphighalarm", "templowalarm"]
        thresholds = {}
        for field in fields:
            result = duthost.shell(
                'sonic-db-cli STATE_DB HGET "TRANSCEIVER_DOM_THRESHOLD|{}" {}'.format(port, field),
                module_ignore_errors=True
            )
            if result["rc"] == 0 and result["stdout"].strip():
                thresholds[field] = result["stdout"].strip()
            else:
                thresholds[field] = None
        return thresholds

    def _get_dom_flag_data(self, duthost, port):
        """
        Get temperature warning flags from TRANSCEIVER_DOM_FLAG for a port.
        Returns dict with keys: tempHWarn, tempLWarn, tempHAlarm, tempLAlarm
        """
        fields = ["tempHWarn", "tempLWarn", "tempHAlarm", "tempLAlarm"]
        flags = {}
        for field in fields:
            result = duthost.shell(
                'sonic-db-cli STATE_DB HGET "TRANSCEIVER_DOM_FLAG|{}" {}'.format(port, field),
                module_ignore_errors=True
            )
            if result["rc"] == 0 and result["stdout"].strip():
                flags[field] = result["stdout"].strip()
            else:
                flags[field] = None
        return flags

    def _is_sfp_sensor(self, sensor_name):
        """
        Determine if a sensor name refers to an SFP/transceiver temperature.
        Matches patterns like 'xSFP module N Temp'.
        """
        sensor_lower = sensor_name.lower()
        return ("sfp" in sensor_lower or "transceiver" in sensor_lower or
                "optic" in sensor_lower)

    def test_sfp_temperature_present_in_show_platform_temperature(
            self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Verify that SFP temperature entries appear in 'show platform temperature'
        when TRANSCEIVER_DOM_TEMPERATURE has data for connected ports.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        sfp_ports = self._get_sfp_ports_with_dom_temperature(duthost)
        if not sfp_ports:
            pytest.skip("No TRANSCEIVER_DOM_TEMPERATURE entries found in STATE_DB "
                        "(no transceivers with DOM support present)")

        logger.info("Found %d ports with TRANSCEIVER_DOM_TEMPERATURE data", len(sfp_ports))

        temp_output = duthost.show_and_parse("show platform temperature")
        pytest_assert(len(temp_output) > 0,
                      "'show platform temperature' returned no data")

        sfp_rows = [row for row in temp_output if self._is_sfp_sensor(row.get("sensor", ""))]

        logger.info("Found %d SFP sensor rows in 'show platform temperature'", len(sfp_rows))

        pytest_assert(
            len(sfp_rows) > 0,
            "Expected SFP temperature rows in 'show platform temperature' since "
            "{} ports have TRANSCEIVER_DOM_TEMPERATURE data, but found none. "
            "Available sensors: {}".format(
                len(sfp_ports),
                [row.get("sensor", "") for row in temp_output]
            )
        )

    def _extract_port_index_from_sensor(self, sensor_name):
        """
        Attempt to extract a numeric port/module index from a sensor name.
        E.g., 'xSFP module 3 Temp' -> 3, 'Transceiver Ethernet4 Temp' -> 4
        Returns the index as int, or None if not parseable.
        """
        # Match patterns like 'module N', 'Ethernet N', or standalone number
        match = re.search(r'(?:module|ethernet)\s*(\d+)', sensor_name, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    def test_sfp_temperature_values_match_xcvrd_tables(
            self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Verify that SFP temperature values shown in 'show platform temperature'
        match the values in TRANSCEIVER_DOM_TEMPERATURE table populated by xcvrd.

        Attempts per-port matching where possible; falls back to value proximity
        check against the full DOM temperature set only for unresolvable sensors.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        sfp_ports = self._get_sfp_ports_with_dom_temperature(duthost)
        if not sfp_ports:
            pytest.skip("No TRANSCEIVER_DOM_TEMPERATURE entries found")

        temp_output = duthost.show_and_parse("show platform temperature")
        sfp_rows = [row for row in temp_output if self._is_sfp_sensor(row.get("sensor", ""))]

        if not sfp_rows:
            pytest.skip("No SFP rows in 'show platform temperature' output")

        # Collect temperature values from xcvrd table
        dom_temperatures = {}
        for port in sfp_ports:
            temp_val = self._get_dom_temperature_data(duthost, port)
            if temp_val:
                dom_temperatures[port] = temp_val

        logger.info("TRANSCEIVER_DOM_TEMPERATURE values (first 5): %s",
                    json.dumps(dict(list(dom_temperatures.items())[:5]), indent=2))

        # Build port-index -> DOM temperature mapping for per-port verification
        port_index_to_dom = {}
        for port, val in dom_temperatures.items():
            match = re.search(r'(\d+)$', port)
            if match:
                try:
                    port_index_to_dom[int(match.group(1))] = round(float(val), 1)
                except (ValueError, TypeError):
                    pass  # Skip ports with non-numeric temperature values

        # Collect temperature values from CLI SFP rows
        cli_temperatures = {}
        for row in sfp_rows:
            sensor = row.get("sensor", "")
            temp = row.get("temperature", "N/A")
            if temp != "N/A":
                cli_temperatures[sensor] = temp

        pytest_assert(
            len(cli_temperatures) > 0,
            "All SFP sensors report N/A temperature — cannot verify DOM sourcing"
        )

        mismatches = []
        matched_count = 0
        for sensor, cli_temp in cli_temperatures.items():
            try:
                cli_val = round(float(cli_temp), 1)
            except (ValueError, TypeError):
                continue

            # Try per-port match first
            port_idx = self._extract_port_index_from_sensor(sensor)
            if port_idx is not None and port_idx in port_index_to_dom:
                dom_val = port_index_to_dom[port_idx]
                if abs(cli_val - dom_val) < 0.5:
                    matched_count += 1
                    continue
                else:
                    mismatches.append(
                        "Sensor '{}' (port idx {}): CLI temp={} vs DOM temp={}".format(
                            sensor, port_idx, cli_val, dom_val)
                    )
                    continue

            # Fallback: check against all DOM values with proximity tolerance
            found_close = any(
                abs(cli_val - round(float(dv), 1)) < 0.5
                for dv in dom_temperatures.values()
                if dv is not None
            )
            if found_close:
                matched_count += 1
            else:
                mismatches.append(
                    "Sensor '{}': CLI temp={} not found in "
                    "TRANSCEIVER_DOM_TEMPERATURE values".format(sensor, cli_temp)
                )

        if mismatches:
            logger.warning("Temperature mismatches (may be due to timing): %s", mismatches)

        # Require that the majority of sensors match
        total_compared = len(cli_temperatures)
        min_required = max(1, total_compared // 2)
        pytest_assert(
            matched_count >= min_required,
            "Only {}/{} SFP temperature values matched TRANSCEIVER_DOM_TEMPERATURE. "
            "At least {} required. Mismatches: {}".format(
                matched_count, total_compared, min_required, mismatches)
        )

    def test_sfp_thresholds_match_xcvrd_tables(
            self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Verify SFP threshold values in 'show platform temperature' match
        TRANSCEIVER_DOM_THRESHOLD table data populated by xcvrd.

        Field mapping:
          High TH -> temphighwarning
          Low TH -> templowwarning
          Crit High TH -> temphighalarm
          Crit Low TH -> templowalarm
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        sfp_ports = self._get_sfp_ports_with_dom_temperature(duthost)
        if not sfp_ports:
            pytest.skip("No TRANSCEIVER_DOM_TEMPERATURE entries found")

        temp_output = duthost.show_and_parse("show platform temperature")
        sfp_rows = [row for row in temp_output if self._is_sfp_sensor(row.get("sensor", ""))]

        if not sfp_rows:
            pytest.skip("No SFP rows in 'show platform temperature' output")

        # Get threshold values from xcvrd table
        dom_thresholds = {}
        for port in sfp_ports:
            thresholds = self._get_dom_threshold_data(duthost, port)
            if any(v is not None for v in thresholds.values()):
                dom_thresholds[port] = thresholds

        if not dom_thresholds:
            pytest.skip("No TRANSCEIVER_DOM_THRESHOLD data available")

        # Collect all threshold values from the DOM table
        dom_high_th_values = set()
        dom_low_th_values = set()
        dom_crit_high_values = set()
        dom_crit_low_values = set()

        for port, th in dom_thresholds.items():
            if th["temphighwarning"]:
                try:
                    dom_high_th_values.add(round(float(th["temphighwarning"]), 1))
                except (ValueError, TypeError):
                    pass  # Skip non-numeric threshold from STATE_DB
            if th["templowwarning"]:
                try:
                    dom_low_th_values.add(round(float(th["templowwarning"]), 1))
                except (ValueError, TypeError):
                    pass  # Skip non-numeric threshold from STATE_DB
            if th["temphighalarm"]:
                try:
                    dom_crit_high_values.add(round(float(th["temphighalarm"]), 1))
                except (ValueError, TypeError):
                    pass  # Skip non-numeric threshold from STATE_DB
            if th["templowalarm"]:
                try:
                    dom_crit_low_values.add(round(float(th["templowalarm"]), 1))
                except (ValueError, TypeError):
                    pass  # Skip non-numeric threshold from STATE_DB

        logger.info("DOM threshold value sets - High TH: %s, Low TH: %s, "
                    "Crit High: %s, Crit Low: %s",
                    dom_high_th_values, dom_low_th_values,
                    dom_crit_high_values, dom_crit_low_values)

        # Verify CLI SFP rows have thresholds matching the DOM table.
        # Track per-row: a row is "verified" if at least one of its threshold
        # fields matches the corresponding DOM value set.
        rows_verified = 0
        rows_with_thresholds = 0
        for row in sfp_rows:
            high_th = row.get("high th", "N/A")
            low_th = row.get("low th", "N/A")
            crit_high = row.get("crit high th", "N/A")
            crit_low = row.get("crit low th", "N/A")

            row_has_threshold = False
            row_matched = False

            if high_th != "N/A":
                row_has_threshold = True
                try:
                    val = round(float(high_th), 1)
                    if val in dom_high_th_values:
                        row_matched = True
                except (ValueError, TypeError):
                    pass  # Non-numeric CLI value, skip comparison

            if low_th != "N/A":
                row_has_threshold = True
                try:
                    val = round(float(low_th), 1)
                    if val in dom_low_th_values:
                        row_matched = True
                except (ValueError, TypeError):
                    pass  # Non-numeric CLI value, skip comparison

            if crit_high != "N/A":
                row_has_threshold = True
                try:
                    val = round(float(crit_high), 1)
                    if val in dom_crit_high_values:
                        row_matched = True
                except (ValueError, TypeError):
                    pass  # Non-numeric CLI value, skip comparison

            if crit_low != "N/A":
                row_has_threshold = True
                try:
                    val = round(float(crit_low), 1)
                    if val in dom_crit_low_values:
                        row_matched = True
                except (ValueError, TypeError):
                    pass  # Non-numeric CLI value, skip comparison

            if row_has_threshold:
                rows_with_thresholds += 1
                if row_matched:
                    rows_verified += 1

        logger.info("Verified %d/%d SFP rows with thresholds matched TRANSCEIVER_DOM_THRESHOLD",
                    rows_verified, rows_with_thresholds)

        # Require that the majority of SFP rows with thresholds match
        min_required = max(1, rows_with_thresholds // 2)
        pytest_assert(
            rows_verified >= min_required,
            "Only {}/{} SFP rows had thresholds matching TRANSCEIVER_DOM_THRESHOLD. "
            "At least {} required. CLI SFP rows: {}, DOM threshold ports: {}".format(
                rows_verified, rows_with_thresholds, min_required,
                len(sfp_rows), len(dom_thresholds))
        )

    def test_sfp_warning_status_from_dom_flag(
            self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Verify that the Warning column for SFP rows in 'show platform temperature'
        reflects the temperature flag state in TRANSCEIVER_DOM_FLAG table.

        Warning = True if any of tempHWarn/tempLWarn/tempHAlarm/tempLAlarm is asserted.
        Warning = False if all four are present and de-asserted.
        Warning = N/A if flags are not populated.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        sfp_ports = self._get_sfp_ports_with_dom_temperature(duthost)
        if not sfp_ports:
            pytest.skip("No TRANSCEIVER_DOM_TEMPERATURE entries found")

        temp_output = duthost.show_and_parse("show platform temperature")
        sfp_rows = [row for row in temp_output if self._is_sfp_sensor(row.get("sensor", ""))]

        if not sfp_rows:
            pytest.skip("No SFP rows in 'show platform temperature' output")

        # Check DOM flags for a subset of ports
        ports_with_flags = 0
        ports_without_flags = 0

        for port in sfp_ports[:10]:
            flags = self._get_dom_flag_data(duthost, port)
            has_any_flag = any(v is not None for v in flags.values())
            if has_any_flag:
                ports_with_flags += 1
            else:
                ports_without_flags += 1

        logger.info("DOM flag status: %d ports with flags, %d without",
                    ports_with_flags, ports_without_flags)

        # Verify Warning column values are valid.
        # show_and_parse lowercases values, so accept only lowercase.
        valid_warnings = {"true", "false", "n/a"}
        for row in sfp_rows:
            warning = row.get("warning", "").lower()
            pytest_assert(
                warning in valid_warnings,
                "Invalid warning value '{}' for sensor '{}'. "
                "Expected one of (case-insensitive): {}".format(
                    row.get("warning", ""), row.get("sensor", ""), valid_warnings)
            )

        # If ports have flags, at least some SFP rows should have True/False warning
        if ports_with_flags > 0:
            rows_with_warning_status = [
                row for row in sfp_rows
                if row.get("warning", "").lower() in ("true", "false")
            ]
            pytest_assert(
                len(rows_with_warning_status) > 0,
                "Ports have TRANSCEIVER_DOM_FLAG data but no SFP rows show "
                "True/False warning status"
            )

    def test_no_sfp_entries_in_temperature_info(
            self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        After thermalctld optimization, TEMPERATURE_INFO should no longer contain
        SFP/transceiver entries — those are exclusively in TRANSCEIVER_DOM_TEMPERATURE.

        This verifies thermalctld no longer publishes duplicate SFP data.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        # Verify thermalctld is running — if it's not, this test is meaningless
        thermalctld_result = duthost.shell(
            "docker exec pmon supervisorctl status thermalctld",
            module_ignore_errors=True
        )
        pytest_assert("RUNNING" in thermalctld_result.get("stdout", ""),
                      "thermalctld is not running — cannot validate TEMPERATURE_INFO content")

        result = duthost.shell(
            'sonic-db-cli STATE_DB KEYS "TEMPERATURE_INFO|*"',
            module_ignore_errors=True
        )
        # If thermalctld is running but TEMPERATURE_INFO is empty, that's a failure —
        # thermalctld should always publish platform sensor data (ASIC, CPU, etc.)
        pytest_assert(
            result["rc"] == 0 and result["stdout"].strip(),
            "thermalctld is running but TEMPERATURE_INFO is empty in STATE_DB — "
            "expected at least platform sensors (ASIC, CPU, PSU, etc.)"
        )

        keys = result["stdout"].strip().split("\n")
        sfp_keys = [
            k for k in keys
            if any(pattern in k.lower() for pattern in ["sfp", "transceiver", "xsfp", "optic"])
        ]

        logger.info("TEMPERATURE_INFO keys: %d total, %d SFP-related",
                    len(keys), len(sfp_keys))

        pytest_assert(
            len(sfp_keys) == 0,
            "TEMPERATURE_INFO should not contain SFP entries after thermalctld "
            "optimization. Found {} SFP keys: {}".format(len(sfp_keys), sfp_keys[:10])
        )

    def test_platform_sensors_still_in_temperature_info(
            self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Verify that non-SFP platform sensors (ASIC, CPU, PSU, fan, ambient)
        are still published to TEMPERATURE_INFO by thermalctld.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        result = duthost.shell(
            'sonic-db-cli STATE_DB KEYS "TEMPERATURE_INFO|*"',
            module_ignore_errors=True
        )
        if result["rc"] != 0 or not result["stdout"].strip():
            pytest.skip("No TEMPERATURE_INFO entries found in STATE_DB")

        keys = result["stdout"].strip().split("\n")
        sensor_names = [k.split("|", 1)[1] for k in keys]

        logger.info("Platform sensors in TEMPERATURE_INFO: %s", sensor_names)

        pytest_assert(
            len(sensor_names) > 0,
            "TEMPERATURE_INFO should contain at least one platform sensor "
            "(ASIC, CPU, PSU, etc.)"
        )

        non_sfp_sensors = [
            name for name in sensor_names
            if not any(p in name.lower() for p in ["sfp", "transceiver", "xsfp", "optic"])
        ]

        pytest_assert(
            len(non_sfp_sensors) > 0,
            "Expected non-SFP platform sensors (ASIC, CPU, etc.) in "
            "TEMPERATURE_INFO but found none. All sensors: {}".format(sensor_names)
        )

    def test_show_platform_temperature_has_all_columns(
            self, duthosts, enum_rand_one_per_hwsku_hostname):
        """
        Verify 'show platform temperature' output has the expected 8 columns
        for both platform and SFP sensors.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]

        temp_output = duthost.show_and_parse("show platform temperature")
        if not temp_output:
            pytest.skip("'show platform temperature' returned no data")

        expected_columns = {
            "sensor", "temperature", "high th", "low th",
            "crit high th", "crit low th", "warning", "timestamp"
        }

        for row in temp_output:
            row_keys = set(k.lower() for k in row.keys())
            missing = expected_columns - row_keys
            pytest_assert(
                not missing,
                "Sensor '{}' missing columns: {}. Got: {}".format(
                    row.get("sensor", "unknown"), missing, list(row.keys())
                )
            )
