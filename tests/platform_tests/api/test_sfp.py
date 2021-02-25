import ast
import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis, sfp

from platform_api_test_base import PlatformApiTestBase

###################################################
# TODO: Remove this after we transition to Python 3
import sys
if sys.version_info.major == 3:
    STRING_TYPE = str
else:
    STRING_TYPE = basestring
# END Remove this after we transition to Python 3
###################################################

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]


@pytest.fixture(scope="class")
def gather_facts(request, duthost):
    # Get platform facts from platform.json file
    request.cls.chassis_facts = duthost.facts.get("chassis")


@pytest.mark.usefixtures("gather_facts")
class TestSfpApi(PlatformApiTestBase):
    """
    This class contains test cases intended to verify the functionality and
    proper platform vendor implementation of the SFP class of the SONiC
    platform API.

    NOTE: The tests in this class currently assume that transceivers are
    connected to all ports of the DuT.
    """

    EXPECTED_XCVR_INFO_KEYS = [
        'type',
        'type_abbrv_name',
        'manufacturer',
        'model',
        'hardware_rev',
        'serial',
        'vendor_oui',
        'vendor_date',
        'connector',
        'encoding',
        'ext_identifier',
        'ext_rateselect_compliance',
        'cable_type',
        'cable_length',
        'specification_compliance',
        'nominal_bit_rate',
        'application_advertisement'
    ]

    EXPECTED_XCVR_BULK_STATUS_KEYS = [
        'temperature',
        'voltage',
        'rx1power',
        'tx1bias',
        'tx1power'
    ]

    EXPECTED_XCVR_THRESHOLD_INFO_KEYS = [
        'txpowerlowwarning',
        'temphighwarning',
        'temphighalarm',
        'txbiashighalarm',
        'vcchighalarm',
        'txbiaslowalarm',
        'rxpowerhighwarning',
        'vcclowwarning',
        'txbiaslowwarning',
        'rxpowerlowalarm',
        'vcchighwarning',
        'txpowerhighwarning',
        'rxpowerlowwarning',
        'txbiashighwarning',
        'vcclowalarm',
        'txpowerhighalarm',
        'templowalarm',
        'rxpowerhighalarm',
        'templowwarning',
        'txpowerlowalarm'
    ]

    chassis_facts = None
    duthost_vars = None
    num_sfps = None
    candidate_sfp = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.
    @pytest.fixture(scope="function", autouse=True)
    def setup(self, request, platform_api_conn):
        self.skip_absent_sfp = request.config.getoption("--skip-absent-sfp")

        if self.num_sfps is None:
            try:
                self.num_sfps = int(chassis.get_num_sfps(platform_api_conn))
            except:
                pytest.fail("num_sfps is not an integer")

        self.candidate_sfp = []
        if self.skip_absent_sfp:
            # Skip absent SFP if option "--skip-absent-sfp" set to True 
            for i in range(self.num_sfps):
                try:
                    if sfp.get_presence(platform_api_conn, i):
                        self.candidate_sfp.append(i)
                except Exception:
                    pytest.fail("get_presence API is not supported, failed to compose present SFP list")
        else:
            self.candidate_sfp = range(self.num_sfps)
    #
    # Helper functions
    #

    def compare_value_with_platform_facts(self, key, value, sfp_idx):
        expected_value = None

        if self.chassis_facts:
            expected_sfps = self.chassis_facts.get("sfps")
            if expected_sfps:
                expected_value = expected_sfps[sfp_idx].get(key)

        if self.expect(expected_value is not None,
                       "Unable to get expected value for '{}' from platform.json file for SFP {}".format(key, sfp_idx)):
            self.expect(value == expected_value,
                          "'{}' value is incorrect. Got '{}', expected '{}' for SFP {}".format(key, value, expected_value, sfp_idx))

    def is_xcvr_optical(self, xcvr_info_dict):
        """Returns True if transceiver is optical, False if copper (DAC)"""
        spec_compliance_dict = ast.literal_eval(xcvr_info_dict["specification_compliance"])
        compliance_code = spec_compliance_dict.get("10/40G Ethernet Compliance Code")
        if compliance_code == "40GBASE-CR4":
            return False
        return True

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(self, duthost, localhost, platform_api_conn):
        for i in self.candidate_sfp:
            name = sfp.get_name(platform_api_conn, i)
            if self.expect(name is not None, "Unable to retrieve transceiver {} name".format(i)):
                self.expect(isinstance(name, STRING_TYPE), "Transceiver {} name appears incorrect".format(i))
                self.compare_value_with_platform_facts('name', name, i)
        self.assert_expectations()

    def test_get_presence(self, duthost, localhost, platform_api_conn):
        for i in self.candidate_sfp:
            presence = sfp.get_presence(platform_api_conn, i)
            if self.expect(presence is not None, "Unable to retrieve transceiver {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "Transceiver {} presence appears incorrect".format(i)):
                    self.expect(presence is True, "Transceiver {} is not present".format(i))
        self.assert_expectations()

    def test_get_model(self, duthost, localhost, platform_api_conn):
        for i in self.candidate_sfp:
            model = sfp.get_model(platform_api_conn, i)
            if self.expect(model is not None, "Unable to retrieve transceiver {} model".format(i)):
                self.expect(isinstance(model, STRING_TYPE), "Transceiver {} model appears incorrect".format(i))
        self.assert_expectations()

    def test_get_serial(self, duthost, localhost, platform_api_conn):
        for i in self.candidate_sfp:
            serial = sfp.get_serial(platform_api_conn, i)
            if self.expect(serial is not None, "Unable to retrieve transceiver {} serial number".format(i)):
                self.expect(isinstance(serial, STRING_TYPE), "Transceiver {} serial number appears incorrect".format(i))
        self.assert_expectations()

    def test_get_status(self, duthost, localhost, platform_api_conn):
        for i in self.candidate_sfp:
            status = sfp.get_status(platform_api_conn, i)
            if self.expect(status is not None, "Unable to retrieve transceiver {} status".format(i)):
                self.expect(isinstance(status, bool), "Transceiver {} status appears incorrect".format(i))
        self.assert_expectations()

    def test_get_position_in_parent(self, platform_api_conn):
        for i in self.candidate_sfp:
            position = sfp.get_position_in_parent(platform_api_conn, i)
            if self.expect(position is not None, "Failed to perform get_position_in_parent for sfp {}".format(i)):
                self.expect(isinstance(position, int), "Position value must be an integer value for sfp {}".format(i))
        self.assert_expectations()

    def test_is_replaceable(self, platform_api_conn):
        for sfp_id in self.candidate_sfp:
            replaceable = sfp.is_replaceable(platform_api_conn, sfp_id)
            if self.expect(replaceable is not None, "Failed to perform is_replaceable for sfp {}".format(sfp_id)):
                self.expect(isinstance(replaceable, bool), "Replaceable value must be a bool value for sfp {}".format(sfp_id))
        self.assert_expectations()

    #
    # Functions to test methods defined in SfpBase class
    #

    def test_get_transceiver_info(self, duthost, localhost, platform_api_conn):
        # TODO: Do more sanity checking on transceiver info values
        for i in self.candidate_sfp:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                if self.expect(isinstance(info_dict, dict), "Transceiver {} info appears incorrect".format(i)):
                    actual_keys = info_dict.keys()

                    missing_keys = set(self.EXPECTED_XCVR_INFO_KEYS) - set(actual_keys)
                    for key in missing_keys:
                        self.expect(False, "Transceiver {} info does not contain field: '{}'".format(i, key))

                    unexpected_keys = set(actual_keys) - set(self.EXPECTED_XCVR_INFO_KEYS)
                    for key in unexpected_keys:
                        self.expect(False, "Transceiver {} info contains unexpected field '{}'".format(i, key))
        self.assert_expectations()

    def test_get_transceiver_bulk_status(self, duthost, localhost, platform_api_conn):
        for i in self.candidate_sfp:
            bulk_status_dict = sfp.get_transceiver_bulk_status(platform_api_conn, i)
            if self.expect(bulk_status_dict is not None, "Unable to retrieve transceiver {} bulk status".format(i)):
                if self.expect(isinstance(bulk_status_dict, dict), "Transceiver {} bulk status appears incorrect".format(i)):
                    # TODO: This set of keys should be present no matter how many channels are present on the xcvr
                    #       If the xcvr has multiple channels, we should adjust the fields here accordingly
                    actual_keys = bulk_status_dict.keys()

                    missing_keys = set(self.EXPECTED_XCVR_BULK_STATUS_KEYS) - set(actual_keys)
                    for key in missing_keys:
                        self.expect(False, "Transceiver {} bulk status does not contain field: '{}'".format(i, key))
        self.assert_expectations()

    def test_get_transceiver_threshold_info(self, duthost, localhost, platform_api_conn):
        # TODO: Do more sanity checking on transceiver threshold info values
        for i in self.candidate_sfp:
            thold_info_dict = sfp.get_transceiver_threshold_info(platform_api_conn, i)
            if self.expect(thold_info_dict is not None, "Unable to retrieve transceiver {} threshold info".format(i)):
                if self.expect(isinstance(thold_info_dict, dict), "Transceiver {} threshold info appears incorrect".format(i)):
                    actual_keys = thold_info_dict.keys()

                    missing_keys = set(self.EXPECTED_XCVR_THRESHOLD_INFO_KEYS) - set(actual_keys)
                    for key in missing_keys:
                        self.expect(False, "Transceiver {} threshold info does not contain field: '{}'".format(i, key))

                    unexpected_keys = set(actual_keys) - set(self.EXPECTED_XCVR_THRESHOLD_INFO_KEYS)
                    for key in unexpected_keys:
                        self.expect(False, "Transceiver {} threshold info contains unexpected field '{}'".format(i, key))
        self.assert_expectations()

    def test_get_reset_status(self, duthost, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        for i in self.candidate_sfp:
            reset_status = sfp.get_reset_status(platform_api_conn, i)
            if self.expect(reset_status is not None, "Unable to retrieve transceiver {} reset status".format(i)):
                self.expect(isinstance(reset_status, bool), "Transceiver {} reset status appears incorrect".format(i))
        self.assert_expectations()

    def test_get_rx_los(self, duthost, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        for i in self.candidate_sfp:
            rx_los = sfp.get_rx_los(platform_api_conn, i)
            if self.expect(rx_los is not None, "Unable to retrieve transceiver {} RX loss-of-signal data".format(i)):
                self.expect(isinstance(rx_los, list) and (all(isinstance(item, bool) for item in rx_los)),
                            "Transceiver {} RX loss-of-signal data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_tx_fault(self, duthost, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        for i in self.candidate_sfp:
            tx_fault = sfp.get_tx_fault(platform_api_conn, i)
            if self.expect(tx_fault is not None, "Unable to retrieve transceiver {} TX fault data".format(i)):
                self.expect(isinstance(tx_fault, list) and (all(isinstance(item, bool) for item in tx_fault)),
                            "Transceiver {} TX fault data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_temperature(self, duthost, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        for i in self.candidate_sfp:
            temp = sfp.get_temperature(platform_api_conn, i)
            if self.expect(temp is not None, "Unable to retrieve transceiver {} temperatue".format(i)):
                self.expect(isinstance(temp, float), "Transceiver {} temperature appears incorrect".format(i))
        self.assert_expectations()

    def test_get_voltage(self, duthost, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        for i in self.candidate_sfp:
            voltage = sfp.get_voltage(platform_api_conn, i)
            if self.expect(voltage is not None, "Unable to retrieve transceiver {} voltage".format(i)):
                self.expect(isinstance(voltage, float), "Transceiver {} voltage appears incorrect".format(i))
        self.assert_expectations()

    def test_get_tx_bias(self, duthost, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        for i in self.candidate_sfp:
            tx_bias = sfp.get_tx_bias(platform_api_conn, i)
            if self.expect(tx_bias is not None, "Unable to retrieve transceiver {} TX bias data".format(i)):
                self.expect(isinstance(tx_bias, list) and (all(isinstance(item, float) for item in tx_bias)),
                            "Transceiver {} TX bias data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_rx_power(self, duthost, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        # TODO: Should we should expect get_rx_power() to return None or a list of "N/A" strings
        # if the transceiver is non-optical, e.g., DAC
        for i in self.candidate_sfp:
            # Determine whether the transceiver type supports RX power
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_optical(info_dict):
                logger.warning("test_get_rx_power: Skipping transceiver {} (not applicable for this transceiver type)".format(i))
                continue

            rx_power = sfp.get_rx_power(platform_api_conn, i)
            if self.expect(rx_power is not None, "Unable to retrieve transceiver {} RX power data".format(i)):
                self.expect(isinstance(rx_power, list) and (all(isinstance(item, float) for item in rx_power)),
                            "Transceiver {} RX power data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_tx_power(self, duthost, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        for i in self.candidate_sfp:
            tx_power = sfp.get_tx_power(platform_api_conn, i)
            if self.expect(tx_power is not None, "Unable to retrieve transceiver {} TX power data".format(i)):
                continue

            # Determine whether the transceiver type supports RX power
            # If the transceiver is non-optical, e.g., DAC, we should receive a list of "N/A" strings
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_optical(info_dict):
                self.expect(isinstance(tx_power, list) and (all(item == "N/A" for item in tx_power)),
                            "Transceiver {} TX power data appears incorrect".format(i))
            else:
                self.expect(isinstance(tx_power, list) and (all(isinstance(item, float) for item in tx_power)),
                            "Transceiver {} TX power data appears incorrect".format(i))
        self.assert_expectations()

    def test_reset(self, duthost, localhost, platform_api_conn):
        # TODO: Verify that the transceiver was actually reset
        for i in self.candidate_sfp:
            ret = sfp.reset(platform_api_conn, i)
            self.expect(ret is True, "Failed to reset transceiver {}".format(i))
        self.assert_expectations()

    def test_tx_disable(self, duthost, localhost, platform_api_conn):
        """This function tests both the get_tx_disable() and tx_disable() APIs"""
        for i in self.candidate_sfp:
            # First ensure that the transceiver type supports setting TX disable
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_optical(info_dict):
                logger.warning("test_tx_disable: Skipping transceiver {} (not applicable for this transceiver type)".format(i))
                continue

            for state in [True, False]:
                ret = sfp.tx_disable(platform_api_conn, i, state)
                if self.expect(ret is True, "Failed to {} TX disable for transceiver {}".format("set" if state is True else "clear", i)):
                    tx_disable = sfp.get_tx_disable(platform_api_conn, i)
                    if self.expect(tx_disable is not None, "Unable to retrieve transceiver {} TX disable data".format(i)):
                        self.expect(isinstance(tx_disable, list) and (all(item == state) for item in tx_disable),
                                    "Transceiver {} TX disable data is incorrect".format(i))
        self.assert_expectations()

    def test_tx_disable_channel(self, duthost, localhost, platform_api_conn):
        """This function tests both the get_tx_disable_channel() and tx_disable_channel() APIs"""
        for i in self.candidate_sfp:
            # First ensure that the transceiver type supports setting TX disable on individual channels
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_optical(info_dict):
                logger.warning("test_tx_disable_channel: Skipping transceiver {} (not applicable for this transceiver type)".format(i))
                continue

            # Test all TX disable combinations for a four-channel transceiver (i.e., 0x0 through 0xF)
            # We iterate in reverse here so that we end with 0x0 (no channels disabled)
            for expected_mask in range(0xF, 0x0, -1):
                # Enable TX on all channels
                ret = sfp.tx_disable_channel(platform_api_conn, i, 0xF, False)
                self.expect(ret is True, "Failed to enable TX on all channels for transceiver {}".format(i))

                ret = sfp.tx_disable_channel(platform_api_conn, i, expected_mask, True)
                self.expect(ret is True, "Failed to disable TX channels using mask '{}' for transceiver {}".format(expected_mask, i))

                tx_disable_chan_mask = sfp.get_tx_disable_channel(platform_api_conn, i)
                if self.expect(tx_disable_chan_mask is not None, "Unable to retrieve transceiver {} TX disabled channel data".format(i)):
                    self.expect(tx_disable_chan_mask == expected_mask, "Transceiver {} TX disabled channel data is incorrect".format(i))
        self.assert_expectations()

    def test_lpmode(self, duthost, localhost, platform_api_conn):
        """This function tests both the get_lpmode() and set_lpmode() APIs"""
        for i in self.candidate_sfp:
            # First ensure that the transceiver type supports low-power mode
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_optical(info_dict):
                logger.warning("test_lpmode: Skipping transceiver {} (not applicable for this transceiver type)".format(i))
                continue

            # Enable and disable low-power mode on each transceiver
            for state in [True, False]:
                ret = sfp.set_lpmode(platform_api_conn, i, state)
                self.expect(ret is True, "Failed to {} low-power mode for transceiver {}".format("enable" if state is True else "disable", i))
                lpmode = sfp.get_lpmode(platform_api_conn, i)
                if self.expect(lpmode is not None, "Unable to retrieve transceiver {} low-power mode".format(i)):
                    self.expect(lpmode == state, "Transceiver {} low-power is incorrect".format(i))
        self.assert_expectations()

    def test_power_override(self, duthost, localhost, platform_api_conn):
        """This function tests both the get_power_override() and set_power_override() APIs"""
        for i in self.candidate_sfp:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_optical(info_dict):
                logger.warning("test_power_override: Skipping transceiver {} (not applicable for this transceiver type)".format(i))
                continue

            # Enable power override in both low-power and high-power modes
            for state in [True, False]:
                ret = sfp.set_power_override(platform_api_conn, i, True, state)
                self.expect(ret is True, "Failed to {} power override for transceiver {}".format("enable" if state is True else "disable", i))
                power_override = sfp.get_power_override(platform_api_conn, i)
                if self.expect(power_override is not None, "Unable to retrieve transceiver {} power override data".format(i)):
                    self.expect(power_override is True, "Transceiver {} power override data is incorrect".format(i))

            # Disable power override
            ret = sfp.set_power_override(platform_api_conn, i, False, None)
            self.expect(ret is True, "Failed to disable power override for transceiver {}".format(i))
            power_override = sfp.get_power_override(platform_api_conn, i)
            if self.expect(power_override is not None, "Unable to retrieve transceiver {} power override data".format(i)):
                self.expect(power_override is False, "Transceiver {} power override data is incorrect".format(i))
        self.assert_expectations()

    def test_thermals(self, platform_api_conn):
        for sfp_id in self.candidate_sfp:
            try:
                num_thermals = int(sfp.get_num_thermals(platform_api_conn, sfp_id))
            except Exception:
                pytest.fail("SFP {}: num_thermals is not an integer".format(sfp_id))

            thermal_list = sfp.get_all_thermals(platform_api_conn, sfp_id)
            pytest_assert(thermal_list is not None, "Failed to retrieve thermals for sfp {}".format(sfp_id))
            pytest_assert(isinstance(thermal_list, list) and len(thermal_list) == num_thermals, "Thermals appear to be incorrect for sfp {}".format(sfp_id))

            for thermal_index in range(num_thermals):
                thermal = sfp.get_thermal(platform_api_conn, sfp_id, thermal_index)
                self.expect(thermal and thermal == thermal_list[thermal_index], "Thermal {} is incorrect for sfp {}".format(thermal_index, sfp_id))
        self.assert_expectations()
