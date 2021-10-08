import ast
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import sfp
from tests.common.utilities import skip_version
from tests.common.utilities import skip_release_for_platform
from tests.common.platform.interface_utils import get_physical_port_indices
from tests.common.utilities import wait_until
from tests.common.fixtures.conn_graph_facts import conn_graph_facts

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
def setup(request, duthosts, enum_rand_one_per_hwsku_hostname, xcvr_skip_list, conn_graph_facts):
    sfp_setup = {}
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    
    if duthost.is_supervisor_node():
        pytest.skip("skipping for supervisor node")

    # We are interested only in ports that are used for device connection
    physical_intfs = conn_graph_facts["device_conn"][duthost.hostname]

    physical_port_index_map = get_physical_port_indices(duthost, physical_intfs)
  
    sfp_port_indices = set([physical_port_index_map[intf] \
        for intf in physical_port_index_map.keys()])
    sfp_setup["sfp_port_indices"] = sorted(sfp_port_indices)

    if len(xcvr_skip_list[duthost.hostname]):
        logging.info("Skipping tests on {}".format(xcvr_skip_list[duthost.hostname]))

    sfp_port_indices = set([physical_port_index_map[intf] for intf in \
                                                physical_port_index_map.keys() \
                                                if intf not in xcvr_skip_list[duthost.hostname]])
    sfp_setup["sfp_test_port_indices"] = sorted(sfp_port_indices)
    if request.cls is not None:
        request.cls.sfp_setup = sfp_setup

@pytest.mark.usefixtures("setup")
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
    ]

    # These are fields which have been added in the common parsers
    # in sonic-platform-common/sonic_sfp, but since some vendors are
    # using their own custom parsers, they do not yet provide these
    # fields. So we treat them differently. Rather than failing the test
    # if these fields are not present or 'N/A', we will simply log warnings
    # until all vendors utilize the common parsers. At that point, we should
    # add these into EXPECTED_XCVR_INFO_KEYS.
    NEWLY_ADDED_XCVR_INFO_KEYS = [
        'type_abbrv_name',
        'application_advertisement',
        'is_replaceable',
        'dom_capability'
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

    #
    # Helper functions
    #

    def compare_value_with_platform_facts(self, key, value, sfp_idx, duthost):
        expected_value = None
        sfp_id = self.sfp_setup["sfp_port_indices"].index(sfp_idx)
        if duthost.facts.get("chassis"):
            expected_sfps = duthost.facts.get("chassis").get("sfps")
            if expected_sfps:
                expected_value = expected_sfps[sfp_id].get(key)

        if self.expect(expected_value is not None,
                       "Unable to get expected value for '{}' from platform.json file for SFP {}".format(key, sfp_idx)):
            self.expect(value == expected_value,
                        "'{}' value is incorrect. Got '{}', expected '{}' for SFP {}".format(key, value, expected_value,
                                                                                             sfp_idx))

    def is_xcvr_optical(self, xcvr_info_dict):
        """Returns True if transceiver is optical, False if copper (DAC)"""
        #For QSFP-DD specification compliance will return type as passive or active
        if xcvr_info_dict["type_abbrv_name"] == "QSFP-DD" or xcvr_info_dict["type_abbrv_name"] == "OSFP-8X":
            if xcvr_info_dict["specification_compliance"] == "passive_copper_media_interface":
               return False
        else:
            spec_compliance_dict = ast.literal_eval(xcvr_info_dict["specification_compliance"])
            if xcvr_info_dict["type_abbrv_name"] == "SFP":
                compliance_code = spec_compliance_dict.get("SFP+CableTechnology")
                if compliance_code == "Passive Cable":
                   return False
            else:
                compliance_code = spec_compliance_dict.get("10/40G Ethernet Compliance Code")
                if compliance_code == "40GBASE-CR4":
                   return False
        return True

    def is_xcvr_resettable(self, xcvr_info_dict):
        xcvr_type = xcvr_info_dict.get("type_abbrv_name")
        if xcvr_type == "SFP":
            return False
        return True

    def is_xcvr_support_lpmode(self, xcvr_info_dict):
        """Returns True if transceiver is support low power mode, False if not supported"""
        xcvr_type = xcvr_info_dict["type"]
        ext_identifier = xcvr_info_dict["ext_identifier"]
        if not "QSFP" in xcvr_type or "Power Class 1" in ext_identifier:
            return False
        return True

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(self,  duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in self.sfp_setup["sfp_test_port_indices"]:
            name = sfp.get_name(platform_api_conn, i)
            if self.expect(name is not None, "Unable to retrieve transceiver {} name".format(i)):
                self.expect(isinstance(name, STRING_TYPE), "Transceiver {} name appears incorrect".format(i))
                self.compare_value_with_platform_facts('name', name, i, duthosts[enum_rand_one_per_hwsku_hostname])
        self.assert_expectations()

    def test_get_presence(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        for i in self.sfp_setup["sfp_test_port_indices"]:
            presence = sfp.get_presence(platform_api_conn, i)
            if self.expect(presence is not None, "Unable to retrieve transceiver {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "Transceiver {} presence appears incorrect".format(i)):
                    self.expect(presence is True, "Transceiver {} is not present".format(i))
        self.assert_expectations()

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            model = sfp.get_model(platform_api_conn, i)
            if self.expect(model is not None, "Unable to retrieve transceiver {} model".format(i)):
                self.expect(isinstance(model, STRING_TYPE), "Transceiver {} model appears incorrect".format(i))
        self.assert_expectations()

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            serial = sfp.get_serial(platform_api_conn, i)
            if self.expect(serial is not None, "Unable to retrieve transceiver {} serial number".format(i)):
                self.expect(isinstance(serial, STRING_TYPE), "Transceiver {} serial number appears incorrect".format(i))
        self.assert_expectations()

    def test_is_replaceable(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])
        for sfp_id in self.sfp_setup["sfp_test_port_indices"]:
            replaceable = sfp.is_replaceable(platform_api_conn, sfp_id)
            if self.expect(replaceable is not None, "Failed to perform is_replaceable for sfp {}".format(sfp_id)):
                self.expect(isinstance(replaceable, bool), "Replaceable value must be a bool value for sfp {}".format(sfp_id))
        self.assert_expectations()

    #
    # Functions to test methods defined in SfpBase class
    #

    def test_get_transceiver_info(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        # TODO: Do more sanity checking on transceiver info values
        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                if self.expect(isinstance(info_dict, dict), "Transceiver {} info appears incorrect".format(i)):
                    actual_keys = info_dict.keys()

                    missing_keys = set(self.EXPECTED_XCVR_INFO_KEYS) - set(actual_keys)
                    for key in missing_keys:
                        self.expect(False, "Transceiver {} info does not contain field: '{}'".format(i, key))

                    # TODO: Remove this once we can include these keys in EXPECTED_XCVR_INFO_KEYS
                    for key in self.NEWLY_ADDED_XCVR_INFO_KEYS:
                        if key not in actual_keys:
                            logger.warning("test_get_transceiver_info: Transceiver {} info missing field '{}'. Vendor needs to add support.".format(i, key))
                        elif info_dict[key] == "N/A":
                            logger.warning("test_get_transceiver_info: Transceiver {} info value for '{}' is 'N/A'. Vendor needs to add support.".format(i, key))

                    unexpected_keys = set(actual_keys) - set(self.EXPECTED_XCVR_INFO_KEYS + self.NEWLY_ADDED_XCVR_INFO_KEYS)
                    for key in unexpected_keys:
                        self.expect(False, "Transceiver {} info contains unexpected field '{}'".format(i, key))
        self.assert_expectations()

    def test_get_transceiver_bulk_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
            platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
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

    def test_get_transceiver_threshold_info(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                                localhost, platform_api_conn):
        # TODO: Do more sanity checking on transceiver threshold info values
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
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

    def test_get_reset_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        # TODO: Do more sanity checking on the data we retrieve
        for i in self.sfp_setup["sfp_test_port_indices"]:
            reset_status = sfp.get_reset_status(platform_api_conn, i)
            if self.expect(reset_status is not None, "Unable to retrieve transceiver {} reset status".format(i)):
                self.expect(isinstance(reset_status, bool), "Transceiver {} reset status appears incorrect".format(i))
        self.assert_expectations()

    def test_get_rx_los(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            rx_los = sfp.get_rx_los(platform_api_conn, i)
            if self.expect(rx_los is not None, "Unable to retrieve transceiver {} RX loss-of-signal data".format(i)):
                self.expect(isinstance(rx_los, list) and (all(isinstance(item, bool) for item in rx_los)),
                            "Transceiver {} RX loss-of-signal data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_tx_fault(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            tx_fault = sfp.get_tx_fault(platform_api_conn, i)
            if self.expect(tx_fault is not None, "Unable to retrieve transceiver {} TX fault data".format(i)):
                self.expect(isinstance(tx_fault, list) and (all(isinstance(item, bool) for item in tx_fault)),
                            "Transceiver {} TX fault data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_temperature(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            temp = sfp.get_temperature(platform_api_conn, i)
            if self.expect(temp is not None, "Unable to retrieve transceiver {} temperatue".format(i)):
                self.expect(isinstance(temp, float), "Transceiver {} temperature appears incorrect".format(i))
        self.assert_expectations()

    def test_get_voltage(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            voltage = sfp.get_voltage(platform_api_conn, i)
            if self.expect(voltage is not None, "Unable to retrieve transceiver {} voltage".format(i)):
                self.expect(isinstance(voltage, float), "Transceiver {} voltage appears incorrect".format(i))
        self.assert_expectations()

    def test_get_tx_bias(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        # TODO: Do more sanity checking on the data we retrieve
        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            # Determine whether the transceiver type supports TX Bias
            if not self.is_xcvr_optical(info_dict):
                logger.warning("test_get_tx_bias: Skipping transceiver {} (not applicable for this transceiver type)".format(i))
                continue
            tx_bias = sfp.get_tx_bias(platform_api_conn, i)
            if self.expect(tx_bias is not None, "Unable to retrieve transceiver {} TX bias data".format(i)):
                self.expect(isinstance(tx_bias, list) and (all(isinstance(item, float) for item in tx_bias)),
                            "Transceiver {} TX bias data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_rx_power(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        # TODO: Do more sanity checking on the data we retrieve
        # TODO: Should we should expect get_rx_power() to return None or a list of "N/A" strings
        # if the transceiver is non-optical, e.g., DAC
        for i in self.sfp_setup["sfp_test_port_indices"]:
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

    def test_get_tx_power(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        # TODO: Do more sanity checking on the data we retrieve
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
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

    def test_reset(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        # TODO: Verify that the transceiver was actually reset
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
               continue

            ret = sfp.reset(platform_api_conn, i)
            if self.is_xcvr_resettable(info_dict):
               self.expect(ret is True, "Failed to reset transceiver {}".format(i))
            else:
               self.expect(ret is False, "Resetting transceiver {} succeeded but should have failed".format(i))
        self.assert_expectations()

    def test_tx_disable(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        """This function tests both the get_tx_disable() and tx_disable() APIs"""
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
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

    def test_tx_disable_channel(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        """This function tests both the get_tx_disable_channel() and tx_disable_channel() APIs"""
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
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

    def _check_lpmode_status(self, sfp,platform_api_conn, i, state):
        return state ==  sfp.get_lpmode(platform_api_conn, i)

    def test_lpmode(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        """This function tests both the get_lpmode() and set_lpmode() APIs"""
        for i in self.sfp_setup["sfp_test_port_indices"]:
            # First ensure that the transceiver type supports low-power mode
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_support_lpmode(info_dict):
                logger.warning("test_lpmode: Skipping transceiver {} (not applicable for this transceiver type)".format(i))
                continue

            # Enable and disable low-power mode on each transceiver
            for state in [True, False]:
                ret = sfp.set_lpmode(platform_api_conn, i, state)
                if ret is None:
                    logger.warning("test_lpmode: Skipping transceiver {} (not supported on this platform)".format(i))
                    break
                self.expect(ret is True, "Failed to {} low-power mode for transceiver {}".format("enable" if state is True else "disable", i))
                self.expect(wait_until(5, 1, self._check_lpmode_status, sfp, platform_api_conn, i, state),
                            "Transceiver {} expected low-power state {} is not aligned with the real state".format(i, "enable" if state is True else "disable"))
        self.assert_expectations()

    def test_power_override(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        """This function tests both the get_power_override() and set_power_override() APIs"""
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
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

    def test_get_error_description(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
        """This function tests get_error_description() API (supported on 202106 and above)"""
        skip_version(duthosts[enum_rand_one_per_hwsku_hostname], ["201811", "201911", "202012"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            error_description = sfp.get_error_description(platform_api_conn, i)
            if self.expect(error_description is not None, "Unable to retrieve transceiver {} error description".format(i)):
                if "Not implemented" in error_description:
                    pytest.skip("get_error_description isn't implemented. Skip the test")
                if self.expect(isinstance(error_description, str) or isinstance(error_description, unicode), "Transceiver {} error description appears incorrect".format(i)):
                    self.expect(error_description == "OK", "Transceiver {} is not present".format(i))
        self.assert_expectations()

    def test_thermals(self, platform_api_conn):
        for sfp_id in self.sfp_setup["sfp_test_port_indices"]:
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
