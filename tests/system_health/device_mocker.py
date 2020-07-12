import os
import pytest
import sys


class DeviceMocker:
    def deinit(self):
        pass

    def mock_fan_presence(self, status):
        return False, None

    def mock_fan_status(self, status):
        return False, None

    def mock_fan_speed(self, good):
        return False, None

    def mock_asic_temperature(self, good):
        return False

    def mock_psu_presence(self, status):
        return False, None

    def mock_psu_status(self, status):
        return False, None

    def mock_psu_temperature(self, good):
        return False, None

    def mock_psu_voltage(self, good):
        return False, None


@pytest.fixture
def device_mocker_factory():
    """
    Fixture for system health data mocker factory.
    :return: A function for creating system health related data mocker.
    """
    mockers = []

    def _create_mocker(dut):
        """
        Create vendor specified mocker object by mocker name.
        :param dut: DUT object representing a SONiC switch under test.
        :return: Created mocker instance.
        """
        asic = dut.facts['asic_type']
        mocker_object = None
        if 'mellanox' in asic:
            from .mellanox.mellanox_device_mocker import MellanoxDeviceMocker
            mocker_object = MellanoxDeviceMocker(dut)
            mockers.append(mocker_object)
        else:
            pytest.skip("No mocker defined for this platform %s")
        return mocker_object

    yield _create_mocker

    for m in mockers:
        m.deinit()
