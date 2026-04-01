import logging
import pytest

from tests.common.helpers.platform_api import chassis, pdb
from tests.common.utilities import wait_until
from tests.common.fixtures.duthost_utils import check_pdb_support
from tests.common.platform.device_utils import platform_api_conn, start_platform_api_service    # noqa: F401
from .power_api_test_base import TestPowerApi

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]

POWER_TOLERANCE = 0.1


class TestPdbApi(TestPowerApi):
    """Platform API test cases for the PDB class.

    Inherits shared power-unit tests (name, presence, model, serial, revision,
    status, thermals) from TestPowerApi.
    Overrides PSU-specific tests and adds PDB-specific ones.
    """

    power_unit_api = pdb
    power_unit_label = "PDB"
    facts_key = "pdbs"

    def _get_num_power_units(self, conn):
        return chassis.get_num_pdbs(conn)

    def _handle_num_power_units_exception(self, duthost):
        if check_pdb_support(duthost):
            pytest.fail("get_num_pdbs returned non-integer but STATE_DB shows PDB is supported")
        pytest.skip("get_num_pdbs API not supported on this platform")

    def _handle_no_power_units(self, duthost):
        if check_pdb_support(duthost):
            pytest.fail("get_num_pdbs returned 0 but STATE_DB shows PDB is supported")
        pytest.skip("No PDBs found on device")

    # ------------------------------------------------------------------
    # Overridden tests with PDB-specific logic
    # ------------------------------------------------------------------

    def test_is_replaceable(self, platform_api_conn):  # noqa: F811
        """PDB: only check API returns successfully (not None)."""
        logger.info(f"test_is_replaceable: Starting for {self.num_power_units} PDB(s)")
        for pdb_id in range(self.num_power_units):
            if self._skip_absent_power_unit(pdb_id, platform_api_conn):
                continue
            logger.info(f"test_is_replaceable: Checking PDB {pdb_id}")
            replaceable = self.power_unit_api.is_replaceable(platform_api_conn, pdb_id)
            logger.info(f"test_is_replaceable: PDB {pdb_id} is_replaceable={replaceable}")
            self.expect(replaceable is not None,
                        f"Failed to perform is_replaceable for {self.power_unit_label} {pdb_id}")
        self.assert_expectations()

    def test_temperature(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa: F811
        """PDB temperature: check float in reasonable range (no threshold API)."""
        logger.info(f"test_temperature: Starting for {self.num_power_units} PDB(s)")
        for pdb_id in range(self.num_power_units):
            if self._skip_absent_power_unit(pdb_id, platform_api_conn):
                continue
            logger.info(f"test_temperature: Reading temperature for PDB {pdb_id}")
            temperature = self.power_unit_api.get_temperature(platform_api_conn, pdb_id)
            logger.info(f"test_temperature: PDB {pdb_id} temperature={temperature}")
            if self.expect(temperature is not None,
                           f"Failed to retrieve temperature of {self.power_unit_label} {pdb_id}"):
                if self.expect(isinstance(temperature, float),
                               f"{self.power_unit_label} {pdb_id} temperature appears incorrect"):
                    self.expect(-20.0 <= temperature <= 150.0,
                                f"{self.power_unit_label} {pdb_id} temperature {temperature} "
                                "is out of reasonable range")
        self.assert_expectations()

    def test_power(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa: F811
        """PDB power: input/output voltage, current, power and max supplied power."""
        logger.info(f"test_power: Starting for {self.num_power_units} PDB(s)")
        in_voltage = in_current = in_power = None
        out_voltage = out_current = out_power = None

        def check_pdb_power(failure_count):
            nonlocal in_voltage, in_current, in_power
            nonlocal out_voltage, out_current, out_power

            in_voltage = pdb.get_input_voltage(platform_api_conn, pdb_id)
            in_current = pdb.get_input_current(platform_api_conn, pdb_id)
            in_power = pdb.get_input_power(platform_api_conn, pdb_id)
            out_voltage = pdb.get_output_voltage(platform_api_conn, pdb_id)
            out_current = pdb.get_output_current(platform_api_conn, pdb_id)
            out_power = pdb.get_output_power(platform_api_conn, pdb_id)

            logger.info(
                f"test_power: PDB {pdb_id} readings - "
                f"input(V={in_voltage}, I={in_current}, P={in_power}) "
                f"output(V={out_voltage}, I={out_current}, P={out_power})"
            )

            failure_occurred = self.get_len_failed_expectations() > failure_count

            for label, val in [("input voltage", in_voltage), ("input current", in_current),
                               ("input power", in_power), ("output voltage", out_voltage),
                               ("output current", out_current), ("output power", out_power)]:
                if self.expect(val is not None,
                               f"Failed to retrieve {label} of PDB {pdb_id}"):
                    self.expect(isinstance(val, float),
                                f"PDB {pdb_id} {label} appears incorrect")

            for v, c, p, side in [(in_voltage, in_current, in_power, "input"),
                                  (out_voltage, out_current, out_power, "output")]:
                if v and c and p:
                    is_within_tolerance = abs(p - (v * c)) < p * POWER_TOLERANCE
                    if not failure_occurred and not is_within_tolerance:
                        logger.info(f"test_power: PDB {pdb_id} {side} tolerance check failed, will retry")
                        return False
                    self.expect(is_within_tolerance,
                                f"PDB {pdb_id} {side} readings do not make sense "
                                f"(power:{p}, voltage:{v}, current:{c})")

            return True

        for pdb_id in range(self.num_power_units):
            if self._skip_absent_power_unit(pdb_id, platform_api_conn):
                continue
            logger.info(f"test_power: Checking power readings for PDB {pdb_id}")
            failure_count = self.get_len_failed_expectations()
            in_voltage = in_current = in_power = None
            out_voltage = out_current = out_power = None

            check_result = wait_until(30, 10, 0, check_pdb_power, failure_count)
            self.expect(check_result,
                        f"PDB {pdb_id} readings do not make sense "
                        f"(in: V={in_voltage}, I={in_current}, P={in_power} / "
                        f"out: V={out_voltage}, I={out_current}, P={out_power})")

            logger.info(f"test_power: Checking maximum supplied power for PDB {pdb_id}")
            max_power = pdb.get_maximum_supplied_power(platform_api_conn, pdb_id)
            logger.info(f"test_power: PDB {pdb_id} max_supplied_power={max_power}")
            if self.expect(max_power is not None,
                           f"Failed to retrieve maximum supplied power of PDB {pdb_id}"):
                self.expect(isinstance(max_power, float),
                            f"PDB {pdb_id} maximum supplied power appears incorrect")
                if out_power and isinstance(max_power, float):
                    self.expect(max_power >= out_power,
                                f"PDB {pdb_id} max_power ({max_power}) < output_power ({out_power})")

        self.assert_expectations()
