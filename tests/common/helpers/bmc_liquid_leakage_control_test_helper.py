import logging
from abc import ABC, abstractmethod

from tests.common.helpers.liquid_leakage_control_test_helper import LiquidLeakageMocker
from tests.common.platform.bmc_utils import get_sensor_data, get_system_leak_status

logger = logging.getLogger(__name__)

VALID_SENSOR_STATES = ('None', 'MINOR', 'CRITICAL', 'FAULT')

# CLI commands used to discover sensors and read their live status.
LEAK_STATUS_CMD = 'show platform leak status'
LEAK_PROFILES_CMD = 'show platform leak profiles'

# Column headers as produced by show_and_parse (lowercased, hyphens preserved).
COL_NAME = 'name'
COL_LEAK_SENSOR_TYPE = 'leak-sensor-type'
PROFILE_COL_SENSOR_TYPE = 'sensor-type'
PROFILE_COL_MAX_MINOR_DURATION = 'max-minor-duration-sec'


class LiquidLeakageMockerBMC(LiquidLeakageMocker, ABC):
    """
    BMC liquid leakage mocker base class.

    Discovers leak sensors through the 'show platform leak' CLI and exposes
    helpers to read per-sensor and system-wide leak status. Vendor-specific
    subclasses must implement the hardware mocking hooks.
    """

    def __init__(self, dut):
        super().__init__(dut)
        self.sensors = self._discover_sensors()
        self.sensor_names = list(self.sensors.keys())

    def _discover_sensors(self):
        """
        Discover leak sensors from CLI, keyed by sensor name.

        'show platform leak status' provides each sensor's name and sensor type,
        and 'show platform leak profiles' provides max_minor_duration_sec per
        sensor type. Returns {name: {'leak_sensor_type', 'max_minor_duration_sec'}}.
        """
        max_minor_by_type = self._get_max_minor_duration_by_type()
        sensors = {}
        for row in self.dut.show_and_parse(LEAK_STATUS_CMD):
            name = row.get(COL_NAME)
            if not name:
                continue
            sensor_type = row.get(COL_LEAK_SENSOR_TYPE)
            sensors[name] = {
                'leak_sensor_type': sensor_type,
                'max_minor_duration_sec': max_minor_by_type.get(sensor_type),
            }
        logger.info("Discovered %d BMC leak sensor(s): %s", len(sensors), sensors)
        return sensors

    def _get_max_minor_duration_by_type(self):
        """Parse 'show platform leak profiles' into {sensor_type: max_minor_duration_sec}."""
        max_minor_by_type = {}
        for row in self.dut.show_and_parse(LEAK_PROFILES_CMD):
            sensor_type = row.get(PROFILE_COL_SENSOR_TYPE)
            if not sensor_type:
                continue
            raw = row.get(PROFILE_COL_MAX_MINOR_DURATION)
            max_minor_by_type[sensor_type] = self._parse_int(raw)
        return max_minor_by_type

    def get_device_leak_status(self):
        """Return SYSTEM_LEAK_STATUS|system device_leak_status from STATE_DB."""
        return get_system_leak_status(self.dut)

    def get_sensor_name(self, index):
        """Return the sensor name for a sensor by index."""
        self._validate_sensor_index(index)
        return self.sensor_names[index]

    def get_sensor_status(self, index):
        """
        Return the current leak status for a sensor by index.

        Reads LIQUID_COOLING_INFO|<name> from STATE_DB and returns a tuple of
        (leak, leak_severity, leak_sensor_status):
          - leak: True when the leaking field is 'Yes'.
          - leak_severity: one of 'None', 'MINOR', or 'CRITICAL'.
          - leak_sensor_status: raw leak_sensor_status string from STATE_DB.
        """
        name = self.get_sensor_name(index)
        sensor_data = get_sensor_data(self.dut, name)
        leak = self._normalize_leak_bool(sensor_data.get('leaking'))
        leak_severity = self._normalize_severity(sensor_data.get('leak_severity'))
        leak_sensor_status = sensor_data.get('leak_sensor_status')
        return leak, leak_severity, leak_sensor_status

    @abstractmethod
    def restore_all_sensors(self):
        """Restore all mocked leak sensors to their original state."""
        pass

    @abstractmethod
    def set_sensor_state(self, index, state):
        """
        Set a sensor by index to the requested leak state.

        :param index: Leak sensor index.
        :param state: One of 'None', 'MINOR', or 'CRITICAL'.
        """
        pass

    def deinit(self):
        """Restore all sensors on teardown, then chain to the base mocker."""
        self.restore_all_sensors()
        super().deinit()

    def _validate_sensor_index(self, index):
        if index < 0 or index >= len(self.sensor_names):
            raise ValueError(
                "Sensor index {} out of range for {} discovered sensor(s)".format(
                    index, len(self.sensor_names)))

    def _validate_sensor_state(self, state):
        if state not in VALID_SENSOR_STATES:
            raise ValueError(
                "Sensor state {!r} not in {}".format(state, VALID_SENSOR_STATES))

    @staticmethod
    def _normalize_severity(raw):
        """Map a leak_severity field ('None', 'MINOR', 'CRITICAL', ...) to a valid state."""
        severity = (raw or '').strip().upper()
        if severity in ('MINOR', 'CRITICAL'):
            return severity
        return 'None'

    @staticmethod
    def _normalize_leak_bool(raw):
        """Map a leaking field ('Yes', 'No', 'N/A', ...) to a bool."""
        leak = (raw or '').strip().upper()
        return leak == 'YES'

    @staticmethod
    def _parse_int(raw):
        try:
            return int(str(raw).strip())
        except (TypeError, ValueError):
            return None
