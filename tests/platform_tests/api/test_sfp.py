import ast
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import sfp
from tests.common.utilities import skip_release
from tests.common.utilities import skip_release_for_platform
from tests.common.platform.interface_utils import get_physical_port_indices
from tests.common.utilities import wait_until
from tests.common.fixtures.conn_graph_facts import conn_graph_facts     # noqa F401
from tests.common.fixtures.duthost_utils import shutdown_ebgp           # noqa F401
from tests.common.platform.device_utils import platform_api_conn    # noqa F401

from .platform_api_test_base import PlatformApiTestBase

###################################################
# TODO: Remove this after we transition to Python 3
import sys
if sys.version_info.major >= 3:
    STRING_TYPE = str
else:
    STRING_TYPE = basestring    # noqa F821
# END Remove this after we transition to Python 3
###################################################

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]


@pytest.fixture(scope="class")
def setup(request, duthosts, enum_rand_one_per_hwsku_hostname,
          xcvr_skip_list, conn_graph_facts, shutdown_ebgp):     # noqa F811
    sfp_setup = {}
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if duthost.is_supervisor_node():
        pytest.skip("skipping for supervisor node")

    # We are interested only in ports that are used for device connection
    physical_intfs = conn_graph_facts["device_conn"][duthost.hostname]

    physical_port_index_map = get_physical_port_indices(duthost, physical_intfs)
    sfp_setup["physical_port_index_map"] = physical_port_index_map

    sfp_port_indices = set([physical_port_index_map[intf] for intf in list(physical_port_index_map.keys())])
    sfp_setup["sfp_port_indices"] = sorted(sfp_port_indices)

    if len(xcvr_skip_list[duthost.hostname]):
        logging.info("Skipping tests on {}".format(xcvr_skip_list[duthost.hostname]))

    sfp_port_indices = set([physical_port_index_map[intf] for
                            intf in list(physical_port_index_map.keys())
                            if intf not in xcvr_skip_list[duthost.hostname]])
    if not sfp_port_indices:
        pytest.skip("skip the tests due to no spf port")
    sfp_setup["sfp_test_port_indices"] = sorted(sfp_port_indices)

    # Fetch SFP names from platform.json
    sfp_fact_names = []
    sfp_fact_list = duthost.facts.get("chassis").get("sfps")
    for sfp_fact in sfp_fact_list:
        sfp_fact_names.append(sfp_fact.get('name'))
    sfp_setup["sfp_fact_names"] = sfp_fact_names

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
        'vendor_rev',
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

    # some new keys added for QSFP-DD and OSFP in 202205 or later branch
    EXPECTED_XCVR_NEW_QSFP_DD_OSFP_INFO_KEYS = ['host_lane_count',
                                                'media_lane_count',
                                                'cmis_rev',
                                                'host_lane_assignment_option',
                                                'media_interface_technology',
                                                'media_interface_code',
                                                'host_electrical_interface',
                                                'media_lane_assignment_option']

    EXPECTED_XCVR_NEW_QSFP_DD_OSFP_FIRMWARE_INFO_KEYS = ['active_firmware',
                                                         'inactive_firmware']

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

    EXPECTED_XCVR_COMMON_THRESHOLD_INFO_KEYS = [
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

    # To get all the keys supported by QSFP-DD modules
    # below list should be appended with
    # EXPECTED_XCVR_COMMON_THRESHOLD_INFO_KEYS
    QSFPDD_EXPECTED_XCVR_THRESHOLD_INFO_KEYS = [
        'lasertemphighwarning',
        'lasertemplowwarning',
        'lasertemplowalarm',
        'lasertemphighalarm'
    ]

    # To get all the keys supported by QSFP-ZR modules
    # below list should be appended with
    # EXPECTED_XCVR_COMMON_THRESHOLD_INFO_KEYS + QSFPDD_EXPECTED_XCVR_THRESHOLD_INFO_KEYS
    QSFPZR_EXPECTED_XCVR_THRESHOLD_INFO_KEYS = [
        'prefecberhighalarm',
        'prefecberlowalarm',
        'prefecberhighwarning',
        'prefecberlowwarning',
        'postfecberhighalarm',
        'postfecberlowalarm',
        'postfecberhighwarning',
        'postfecberlowwarning',
        'biasxihighalarm',
        'biasxilowalarm',
        'biasxihighwarning',
        'biasxilowwarning',
        'biasxqhighalarm',
        'biasxqlowalarm',
        'biasxqhighwarning',
        'biasxqlowwarning',
        'biasxphighalarm',
        'biasxplowalarm',
        'biasxphighwarning',
        'biasxplowwarning',
        'biasyihighalarm',
        'biasyilowalarm',
        'biasyihighwarning',
        'biasyilowwarning',
        'biasyqhighalarm',
        'biasyqlowalarm',
        'biasyqhighwarning',
        'biasyqlowwarning',
        'biasyphighalarm',
        'biasyplowalarm',
        'biasyphighwarning',
        'biasyplowwarning',
        'cdshorthighalarm',
        'cdshortlowalarm',
        'cdshorthighwarning',
        'cdshortlowwarning',
        'cdlonghighalarm',
        'cdlonglowalarm',
        'cdlonghighwarning',
        'cdlonglowwarning',
        'dgdhighalarm',
        'dgdlowalarm',
        'dgdhighwarning',
        'dgdlowwarning',
        'sopmdhighalarm',
        'sopmdlowalarm',
        'sopmdhighwarning',
        'sopmdlowwarning',
        'pdlhighalarm',
        'pdllowalarm',
        'pdlhighwarning',
        'pdllowwarning',
        'osnrhighalarm',
        'osnrlowalarm',
        'osnrhighwarning',
        'osnrlowwarning',
        'esnrhighalarm',
        'esnrlowalarm',
        'esnrhighwarning',
        'esnrlowwarning',
        'cfohighalarm',
        'cfolowalarm',
        'cfohighwarning',
        'cfolowwarning',
        'txcurrpowerhighalarm',
        'txcurrpowerlowalarm',
        'txcurrpowerhighwarning',
        'txcurrpowerlowwarning',
        'rxtotpowerhighalarm',
        'rxtotpowerlowalarm',
        'rxtotpowerhighwarning',
        'rxtotpowerlowwarning',
        'rxsigpowerhighalarm',
        'rxsigpowerlowalarm',
        'rxsigpowerhighwarning',
        'rxsigpowerlowwarning'
    ]

    # EXPECTED_QSFPZR COMMON_INFO_KEYS
    QSFPZR_EXPECTED_XCVR_INFO_KEYS = [
        'supported_min_laser_freq',
        'supported_max_laser_freq',
        'supported_min_tx_power',
        'supported_max_tx_power'
    ]

    chassis_facts = None
    duthost_vars = None

    #
    # Helper functions
    #
    def is_xcvr_optical(self, xcvr_info_dict):
        """Returns True if transceiver is optical, False if copper (DAC)"""
        # For QSFP-DD specification compliance will return type as passive or active
        if xcvr_info_dict["type_abbrv_name"] == "QSFP-DD" or xcvr_info_dict["type_abbrv_name"] == "OSFP-8X" \
                or xcvr_info_dict["type_abbrv_name"] == "QSFP+C":
            if xcvr_info_dict["specification_compliance"] == "Passive Copper Cable" or \
                    xcvr_info_dict["specification_compliance"] == "passive_copper_media_interface":
                return False
        else:
            spec_compliance_dict = ast.literal_eval(xcvr_info_dict["specification_compliance"])
            if xcvr_info_dict["type_abbrv_name"] == "SFP":
                compliance_code = spec_compliance_dict.get("SFP+CableTechnology")
                if compliance_code == "Passive Cable":
                    return False
            else:
                compliance_code = spec_compliance_dict.get("10/40G Ethernet Compliance Code", " ")
                if "CR" in compliance_code:
                    return False
                extended_code = spec_compliance_dict.get("Extended Specification Compliance", " ")
                if "CR" in extended_code:
                    return False
        return True

    def is_xcvr_resettable(self, request, xcvr_info_dict):
        not_resettable_xcvr_type = request.config.getoption("--unresettable_xcvr_types")
        xcvr_type = xcvr_info_dict.get("type_abbrv_name")
        return xcvr_type not in not_resettable_xcvr_type

    def lp_mode_assert_delay(self, xcvr_info_dict):
        xcvr_type = xcvr_info_dict["type_abbrv_name"]
        if "QSFP" in xcvr_type and xcvr_type != "QSFP-DD":
            return 0.1
        return 0

    def lp_mode_deassert_delay(self, xcvr_info_dict):
        xcvr_type = xcvr_info_dict["type_abbrv_name"]
        if "QSFP" in xcvr_type and xcvr_type != "QSFP-DD":
            return 0.3
        return 0

    def is_xcvr_support_lpmode(self, xcvr_info_dict):
        """Returns True if transceiver is support low power mode, False if not supported"""
        xcvr_type = xcvr_info_dict["type"]
        ext_identifier = xcvr_info_dict["ext_identifier"]
        if ("QSFP" not in xcvr_type and "OSFP" not in xcvr_type) or "Power Class 1" in ext_identifier:
            return False
        return True

    def is_xcvr_support_power_override(self, xcvr_info_dict):
        """Returns True if transceiver supports power override, False if not supported"""
        xcvr_type = xcvr_info_dict["type_abbrv_name"]
        is_valid_xcvr_type = "QSFP" in xcvr_type and xcvr_type != "QSFP-DD"
        return self.is_xcvr_optical(xcvr_info_dict) and is_valid_xcvr_type

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(self,  duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn): # noqa F811
        expected_sfp_names = self.sfp_setup["sfp_fact_names"]
        for i in self.sfp_setup["sfp_test_port_indices"]:
            name = sfp.get_name(platform_api_conn, i)
            if self.expect(name is not None, "Unable to retrieve transceiver {} name".format(i)):
                self.expect(isinstance(name, STRING_TYPE), "Transceiver {} name appears incorrect".format(i))
                self.expect(name in expected_sfp_names,
                            "Transceiver name '{}' for PORT{} NOT found in platform.json".format(name, i))
        self.assert_expectations()

    def test_get_presence(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
        for i in self.sfp_setup["sfp_test_port_indices"]:
            presence = sfp.get_presence(platform_api_conn, i)
            if self.expect(presence is not None, "Unable to retrieve transceiver {} presence".format(i)):
                if self.expect(isinstance(presence, bool), "Transceiver {} presence appears incorrect".format(i)):
                    self.expect(presence is True, "Transceiver {} is not present".format(i))
        self.assert_expectations()

    def test_get_model(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn): # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            model = sfp.get_model(platform_api_conn, i)
            if self.expect(model is not None, "Unable to retrieve transceiver {} model".format(i)):
                self.expect(isinstance(model, STRING_TYPE), "Transceiver {} model appears incorrect".format(i))
        self.assert_expectations()

    def test_get_serial(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            serial = sfp.get_serial(platform_api_conn, i)
            if self.expect(serial is not None, "Unable to retrieve transceiver {} serial number".format(i)):
                self.expect(isinstance(serial, STRING_TYPE),
                            "Transceiver {} serial number appears incorrect".format(i))
        self.assert_expectations()

    def test_is_replaceable(self, duthosts, enum_rand_one_per_hwsku_hostname, platform_api_conn):   # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])
        for sfp_id in self.sfp_setup["sfp_test_port_indices"]:
            replaceable = sfp.is_replaceable(platform_api_conn, sfp_id)
            if self.expect(replaceable is not None, "Failed to perform is_replaceable for sfp {}".format(sfp_id)):
                self.expect(isinstance(replaceable, bool),
                            "Replaceable value must be a bool value for sfp {}".format(sfp_id))
        self.assert_expectations()

    #
    # Functions to test methods defined in SfpBase class
    #

    def test_get_transceiver_info(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                                  platform_api_conn):   # noqa F811
        # TODO: Do more sanity checking on transceiver info values
        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                if self.expect(isinstance(info_dict, dict), "Transceiver {} info appears incorrect".format(i)):
                    actual_keys = list(info_dict.keys())
                    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
                    # NOTE: No more releases to be added here. Platform should use SFP-refactor.
                    # 'hardware_rev' is ONLY applicable to QSFP-DD/OSFP modules
                    if duthost.sonic_release in ["201811", "201911", "202012", "202106", "202111"]:
                        UPDATED_EXPECTED_XCVR_INFO_KEYS = [
                            key if key != 'vendor_rev' else 'hardware_rev' for key in self.EXPECTED_XCVR_INFO_KEYS]
                    else:

                        if info_dict["type_abbrv_name"] in ["QSFP-DD", "OSFP-8X"]:
                            active_apsel_hostlane_count = 8
                            UPDATED_EXPECTED_XCVR_INFO_KEYS = self.EXPECTED_XCVR_INFO_KEYS + \
                                self.EXPECTED_XCVR_NEW_QSFP_DD_OSFP_INFO_KEYS + \
                                self.EXPECTED_XCVR_NEW_QSFP_DD_OSFP_FIRMWARE_INFO_KEYS + \
                                ["active_apsel_hostlane{}".format(n) for n in range(1, active_apsel_hostlane_count + 1)]
                            firmware_info_dict = sfp.get_transceiver_info_firmware_versions(platform_api_conn, i)
                            if self.expect(firmware_info_dict is not None,
                                           "Unable to retrieve transceiver {} firmware info".format(i)):
                                if self.expect(isinstance(firmware_info_dict, dict),
                                               "Transceiver {} firmware info appears incorrect".format(i)):
                                    actual_keys.extend(list(firmware_info_dict.keys()))
                            if 'ZR' in info_dict['media_interface_code']:
                                UPDATED_EXPECTED_XCVR_INFO_KEYS = UPDATED_EXPECTED_XCVR_INFO_KEYS + \
                                                                  self.QSFPZR_EXPECTED_XCVR_INFO_KEYS
                        else:
                            UPDATED_EXPECTED_XCVR_INFO_KEYS = self.EXPECTED_XCVR_INFO_KEYS
                    missing_keys = set(UPDATED_EXPECTED_XCVR_INFO_KEYS) - set(actual_keys)
                    for key in missing_keys:
                        self.expect(False, "Transceiver {} info does not contain field: '{}'".format(i, key))

                    # TODO: Remove this once we can include these keys in EXPECTED_XCVR_INFO_KEYS
                    for key in self.NEWLY_ADDED_XCVR_INFO_KEYS:
                        if key not in actual_keys:
                            logger.warning("test_get_transceiver_info: Transceiver {} info missing field '{}'. "
                                           "Vendor needs to add support.".format(i, key))
                        elif info_dict[key] == "N/A":
                            logger.warning("test_get_transceiver_info: Transceiver {} info value for '{}' is 'N/A'. "
                                           "Vendor needs to add support.".format(i, key))

                    unexpected_keys = set(actual_keys) - set(UPDATED_EXPECTED_XCVR_INFO_KEYS +
                                                             self.NEWLY_ADDED_XCVR_INFO_KEYS)
                    for key in unexpected_keys:
                        # hardware_rev is applicable only for QSFP-DD or OSFP
                        if key == 'hardware_rev' and info_dict["type_abbrv_name"] in ["QSFP-DD", "OSFP-8X"]:
                            continue
                        self.expect(False, "Transceiver {} info contains unexpected field '{}'".format(i, key))
        self.assert_expectations()

    def test_get_transceiver_bulk_status(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                         localhost, platform_api_conn, port_list_with_flat_memory): # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        index_physical_port_map = {port: index for index, port in self.sfp_setup["physical_port_index_map"].items()}
        for i in self.sfp_setup["sfp_test_port_indices"]:
            if index_physical_port_map[i] in port_list_with_flat_memory[duthost.hostname]:
                logger.info(f"skip test on spf {i} due to the port with flat memory")
                continue
            bulk_status_dict = sfp.get_transceiver_bulk_status(platform_api_conn, i)
            if self.expect(bulk_status_dict is not None, "Unable to retrieve transceiver {} bulk status".format(i)):
                if self.expect(isinstance(bulk_status_dict, dict),
                               "Transceiver {} bulk status appears incorrect".format(i)):
                    # TODO: This set of keys should be present no matter how many channels are present on the xcvr
                    #       If the xcvr has multiple channels, we should adjust the fields here accordingly
                    actual_keys = list(bulk_status_dict.keys())

                    missing_keys = set(self.EXPECTED_XCVR_BULK_STATUS_KEYS) - set(actual_keys)
                    for key in missing_keys:
                        self.expect(
                            False, "Transceiver {} bulk status does not contain field: '{}'".format(i, key))
        self.assert_expectations()

    def test_get_transceiver_threshold_info(self, duthosts, enum_rand_one_per_hwsku_hostname,
                                            localhost, platform_api_conn):      # noqa F811
        # TODO: Do more sanity checking on transceiver threshold info values
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)

            if not self.is_xcvr_optical(info_dict):
                logger.info("test_get_transceiver_threshold_info: \
                               Skipping transceiver {} (not applicable for this transceiver type)".format(i))
                continue

            thold_info_dict = sfp.get_transceiver_threshold_info(platform_api_conn, i)
            if self.expect(thold_info_dict is not None,
                           "Unable to retrieve transceiver {} threshold info".format(i)):
                if self.expect(isinstance(thold_info_dict, dict),
                               "Transceiver {} threshold info appears incorrect".format(i)):
                    actual_keys = list(thold_info_dict.keys())

                    expected_keys = list(self.EXPECTED_XCVR_COMMON_THRESHOLD_INFO_KEYS)
                    if info_dict["type_abbrv_name"] in ["QSFP-DD", "OSFP-8X"]:
                        expected_keys += self.QSFPDD_EXPECTED_XCVR_THRESHOLD_INFO_KEYS
                        if 'ZR' in info_dict["media_interface_code"]:
                            if 'INPHI CORP' in info_dict['manufacturer'] and 'IN-Q3JZ1-TC' in info_dict['model']:
                                logger.info("INPHI CORP Transceiver is not populating the associated threshold fields \
                                             in redis TRANSCEIVER_DOM_THRESHOLD table. Skipping this transceiver")
                                continue
                            expected_keys += self.QSFPZR_EXPECTED_XCVR_THRESHOLD_INFO_KEYS

                    missing_keys = set(expected_keys) - set(actual_keys)
                    for key in missing_keys:
                        self.expect(
                            False, "Transceiver {} threshold info does not contain field: '{}'".format(i, key))

                    unexpected_keys = set(actual_keys) - set(expected_keys)
                    for key in unexpected_keys:
                        self.expect(
                            False, "Transceiver {} threshold info contains unexpected field '{}'".format(i, key))
        self.assert_expectations()

    def test_get_reset_status(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                              platform_api_conn):  # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        # TODO: Do more sanity checking on the data we retrieve
        for i in self.sfp_setup["sfp_test_port_indices"]:
            reset_status = sfp.get_reset_status(platform_api_conn, i)
            if self.expect(reset_status is not None, "Unable to retrieve transceiver {} reset status".format(i)):
                self.expect(isinstance(reset_status, bool),
                            "Transceiver {} reset status appears incorrect".format(i))
        self.assert_expectations()

    def test_get_rx_los(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa F811
        # TODO: Do more sanity checking on the data we retrieve
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)

            if not self.is_xcvr_optical(info_dict):
                logger.info(
                    "test_get_rx_los: Skipping transceiver {} (not applicable for this transceiver type)"
                    .format(i))
                continue

            rx_los = sfp.get_rx_los(platform_api_conn, i)
            if self.expect(rx_los is not None,
                           "Unable to retrieve transceiver {} RX loss-of-signal data".format(i)):
                self.expect(isinstance(rx_los, list) and (all(isinstance(item, bool) for item in rx_los)),
                            "Transceiver {} RX loss-of-signal data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_tx_fault(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
        # TODO: Do more sanity checking on the data we retrieve
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)

            if not self.is_xcvr_optical(info_dict):
                logger.info(
                    "test_get_tx_fault: Skipping transceiver {} (not applicable for this transceiver type)"
                    .format(i))
                continue

            tx_fault = sfp.get_tx_fault(platform_api_conn, i)
            if self.expect(tx_fault is not None, "Unable to retrieve transceiver {} TX fault data".format(i)):
                self.expect(isinstance(tx_fault, list) and (all(isinstance(item, bool) for item in tx_fault)),
                            "Transceiver {} TX fault data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_temperature(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                             platform_api_conn):   # noqa F811
        # TODO: Do more sanity checking on the data we retrieve
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)

            if not self.is_xcvr_optical(info_dict):
                logger.info(
                    "test_get_temperature: Skipping transceiver {} (not applicable for this transceiver type)"
                    .format(i))
                continue

            temp = sfp.get_temperature(platform_api_conn, i)
            if self.expect(temp is not None, "Unable to retrieve transceiver {} temperatue".format(i)):
                self.expect(isinstance(temp, float), "Transceiver {} temperature appears incorrect".format(i))
        self.assert_expectations()

    def test_get_voltage(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):   # noqa F811
        # TODO: Do more sanity checking on the data we retrieve
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)

            if not self.is_xcvr_optical(info_dict):
                logger.info(
                    "test_get_voltage: Skipping transceiver {} (not applicable for this transceiver type)"
                    .format(i))
                continue

            voltage = sfp.get_voltage(platform_api_conn, i)
            if self.expect(voltage is not None, "Unable to retrieve transceiver {} voltage".format(i)):
                self.expect(isinstance(voltage, float), "Transceiver {} voltage appears incorrect".format(i))
        self.assert_expectations()

    def test_get_tx_bias(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):   # noqa F811
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        # TODO: Do more sanity checking on the data we retrieve
        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            # Determine whether the transceiver type supports TX Bias
            if not self.is_xcvr_optical(info_dict):
                logger.warning(
                    "test_get_tx_bias: Skipping transceiver {} (not applicable for this transceiver type)"
                    .format(i))
                continue
            tx_bias = sfp.get_tx_bias(platform_api_conn, i)
            if self.expect(tx_bias is not None, "Unable to retrieve transceiver {} TX bias data".format(i)):
                self.expect(isinstance(tx_bias, list) and (all(isinstance(item, float) for item in tx_bias)),
                            "Transceiver {} TX bias data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_rx_power(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
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
                logger.warning(
                    "test_get_rx_power: Skipping transceiver {} (not applicable for this transceiver type)"
                    .format(i))
                continue

            rx_power = sfp.get_rx_power(platform_api_conn, i)
            if self.expect(rx_power is not None, "Unable to retrieve transceiver {} RX power data".format(i)):
                self.expect(isinstance(rx_power, list) and (all(isinstance(item, float) for item in rx_power)),
                            "Transceiver {} RX power data appears incorrect".format(i))
        self.assert_expectations()

    def test_get_tx_power(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):  # noqa F811
        # TODO: Do more sanity checking on the data we retrieve
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)

            if not self.is_xcvr_optical(info_dict):
                logger.info(
                    "test_get_tx_power: Skipping transceiver {} (not applicable for this transceiver type)"
                    .format(i))
                continue

            tx_power = sfp.get_tx_power(platform_api_conn, i)
            if self.expect(tx_power is not None, "Unable to retrieve transceiver {} TX power data".format(i)):
                continue

            # Determine whether the transceiver type supports RX power
            # If the transceiver is non-optical, e.g., DAC, we should receive a list of "N/A" strings
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_optical(info_dict):
                self.expect(isinstance(tx_power, list) and (all(item == "N/A" for item in tx_power)),
                            "Transceiver {} TX power data appears incorrect".format(i))
            else:
                self.expect(isinstance(tx_power, list) and (all(isinstance(item, float) for item in tx_power)),
                            "Transceiver {} TX power data appears incorrect".format(i))
        self.assert_expectations()

    def test_reset(self, request, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn): # noqa F811
        # TODO: Verify that the transceiver was actually reset
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            ret = sfp.reset(platform_api_conn, i)
            if self.is_xcvr_resettable(request, info_dict):
                self.expect(ret is True, "Failed to reset transceiver {}".format(i))
            else:
                self.expect(ret is False, "Resetting transceiver {} succeeded but should have failed".format(i))
        self.assert_expectations()

    def test_tx_disable(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa F811
        """This function tests both the get_tx_disable() and tx_disable() APIs"""
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            # First ensure that the transceiver type supports setting TX disable
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_optical(info_dict):
                logger.warning("test_tx_disable: Skipping transceiver {} (not applicable for this transceiver type)"
                               .format(i))
                continue

            for state in [True, False]:
                ret = sfp.tx_disable(platform_api_conn, i, state)
                if self.expect(ret is True, "Failed to {} TX disable for transceiver {}"
                               .format("set" if state is True else "clear", i)):
                    tx_disable = sfp.get_tx_disable(platform_api_conn, i)
                    if self.expect(tx_disable is not None,
                                   "Unable to retrieve transceiver {} TX disable data".format(i)):
                        self.expect(isinstance(tx_disable, list) and (all(item == state) for item in tx_disable),
                                    "Transceiver {} TX disable data is incorrect".format(i))
        self.assert_expectations()

    def test_tx_disable_channel(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                                platform_api_conn):     # noqa F811
        """This function tests both the get_tx_disable_channel() and tx_disable_channel() APIs"""
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx", "nokia"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            # First ensure that the transceiver type supports setting TX disable on individual channels
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_optical(info_dict):
                logger.warning(
                    "test_tx_disable_channel: Skipping transceiver {} (not applicable for this transceiver type)"
                    .format(i))
                continue

            if info_dict["type_abbrv_name"] == "QSFP-DD" or info_dict["type_abbrv_name"] == "OSFP-8X":
                # Test all channels for a eight-channel transceiver
                all_channel_mask = 0xFF
                expected_mask = 0x80
            elif info_dict["type_abbrv_name"] == "SFP":
                # Test all channels for a single-channel transceiver
                all_channel_mask = 0x1
                expected_mask = 0x1
            else:
                # Test all channels for a four-channel transceiver
                all_channel_mask = 0XF
                expected_mask = 0x8

            # We iterate in reverse here so that we end with 0x0 (no channels disabled)
            while expected_mask >= 0:
                # Enable TX on all channels
                ret = sfp.tx_disable_channel(platform_api_conn, i, all_channel_mask, False)
                self.expect(ret is True, "Failed to enable TX on all channels for transceiver {}".format(i))

                ret = sfp.tx_disable_channel(platform_api_conn, i, expected_mask, True)
                self.expect(ret is True,
                            "Failed to disable TX channels using mask '{}' for transceiver {}"
                            .format(expected_mask, i))

                tx_disable_chan_mask = sfp.get_tx_disable_channel(platform_api_conn, i)
                if self.expect(tx_disable_chan_mask is not None,
                               "Unable to retrieve transceiver {} TX disabled channel data".format(i)):
                    self.expect(tx_disable_chan_mask == expected_mask,
                                "Transceiver {} TX disabled channel data is incorrect".format(i))

                if expected_mask == 0:
                    break
                else:
                    expected_mask = expected_mask >> 1
        self.assert_expectations()

    def _check_lpmode_status(self, sfp, platform_api_conn, i, state):   # noqa F811
        return state == sfp.get_lpmode(platform_api_conn, i)

    def test_lpmode(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):    # noqa F811
        """This function tests both the get_lpmode() and set_lpmode() APIs"""
        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            # Ensure that the transceiver type supports low-power mode
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_support_lpmode(info_dict):
                logger.warning(
                    "test_lpmode: Skipping transceiver {} (not applicable for this transceiver type)"
                    .format(i))
                continue

            lpmode_state_pretest = sfp.get_lpmode(platform_api_conn, i)
            if lpmode_state_pretest is None:
                logger.warning("test_lpmode: Skipping transceiver {} (not supported on this platform)".format(i))
                break
            # This order makes sure lpmode will get restored to pretest value after test
            lpmode_states_to_be_tested = [not lpmode_state_pretest, lpmode_state_pretest]

            # Enable and disable low-power mode on each transceiver
            for state in lpmode_states_to_be_tested:
                ret = sfp.set_lpmode(platform_api_conn, i, state)
                if ret is None:
                    logger.warning("test_lpmode: Skipping transceiver {} (not supported on this platform)".format(i))
                    break
                if state is True:
                    delay = self.lp_mode_assert_delay(info_dict)
                else:
                    delay = self.lp_mode_deassert_delay(info_dict)
                self.expect(ret is True, "Failed to {} low-power mode for transceiver {}"
                            .format("enable" if state is True else "disable", i))
                self.expect(wait_until(5, 1, delay,
                                       self._check_lpmode_status, sfp, platform_api_conn, i, state),
                            "Transceiver {} expected low-power state {} is not aligned with the real state"
                            .format(i, "enable" if state is True else "disable"))
        self.assert_expectations()

    def test_power_override(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                            platform_api_conn):    # noqa F811
        """This function tests both the get_power_override() and set_power_override() APIs"""
        duthost = duthosts[enum_rand_one_per_hwsku_hostname]
        skip_release_for_platform(duthost, ["202012"], ["arista", "mlnx", "nokia"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            info_dict = sfp.get_transceiver_info(platform_api_conn, i)
            if not self.expect(info_dict is not None, "Unable to retrieve transceiver {} info".format(i)):
                continue

            if not self.is_xcvr_support_power_override(info_dict):
                logger.warning(
                    "test_power_override: Skipping transceiver {} (not applicable for this transceiver type)"
                    .format(i))
                continue

            power_override_bit_value_pretest = sfp.get_power_override(
                platform_api_conn, i)
            self.expect(power_override_bit_value_pretest is not None,
                        "Unable to retrieve transceiver {} power override data".format(i))

            # Enable power override in both low-power and high-power modes
            for state in [True, False]:
                ret = sfp.set_power_override(platform_api_conn, i, True, state)
                self.expect(ret is True, "Failed to {} power override for transceiver {}"
                            .format("enable" if state is True else "disable", i))
                power_override = sfp.get_power_override(platform_api_conn, i)
                if self.expect(power_override is not None,
                               "Unable to retrieve transceiver {} power override data".format(i)):
                    self.expect(power_override is True, "Transceiver {} power override data is incorrect".format(i))

            # Restore power_override to pretest value.
            # For power_set bit, it's set to False eventually, which will be fine in either of the cases:
            # 1) if platform uses power_override, then optics will be in high power mode, which is pretest mode.
            # 2) if platform doesn't use power_override, then power_set bit is not playing a role and in default value.
            ret = sfp.set_power_override(
                platform_api_conn, i, power_override_bit_value_pretest, None)
            self.expect(ret is True, "Failed to restore power_override bit to {} for transceiver {}".format(
                power_override_bit_value_pretest, i))
            power_override = sfp.get_power_override(platform_api_conn, i)
            if self.expect(power_override is not None,
                           "Unable to retrieve transceiver {} power override data".format(i)):
                self.expect(power_override is power_override_bit_value_pretest,
                            "Transceiver {} power override data is incorrect".format(i))
        self.assert_expectations()

    def test_get_error_description(self, duthosts, enum_rand_one_per_hwsku_hostname, localhost,
                                   platform_api_conn):      # noqa F811
        """This function tests get_error_description() API (supported on 202106 and above)"""
        skip_release(duthosts[enum_rand_one_per_hwsku_hostname], ["201811", "201911", "202012"])

        for i in self.sfp_setup["sfp_test_port_indices"]:
            error_description = sfp.get_error_description(platform_api_conn, i)
            if self.expect(error_description is not None,
                           "Unable to retrieve transceiver {} error description".format(i)):
                if "Not implemented" in error_description:
                    pytest.skip("get_error_description isn't implemented. Skip the test")
                if "Not supported" in error_description:
                    logger.warning("test_get_error_description: Skipping transceiver {} as error description not "
                                   "supported on this port)".format(i))
                    continue
                if self.expect(isinstance(error_description, str) or isinstance(error_description, str),
                               "Transceiver {} error description appears incorrect".format(i)):
                    self.expect(error_description == "OK", "Transceiver {} is not present".format(i))
        self.assert_expectations()

    def test_thermals(self, platform_api_conn):     # noqa F811
        for sfp_id in self.sfp_setup["sfp_test_port_indices"]:
            try:
                num_thermals = int(sfp.get_num_thermals(platform_api_conn, sfp_id))
            except Exception:
                pytest.fail("SFP {}: num_thermals is not an integer".format(sfp_id))

            thermal_list = sfp.get_all_thermals(platform_api_conn, sfp_id)
            pytest_assert(thermal_list is not None, "Failed to retrieve thermals for sfp {}".format(sfp_id))
            pytest_assert(isinstance(thermal_list, list) and len(thermal_list) == num_thermals,
                          "Thermals appear to be incorrect for sfp {}".format(sfp_id))

            for thermal_index in range(num_thermals):
                thermal = sfp.get_thermal(platform_api_conn, sfp_id, thermal_index)
                self.expect(thermal and thermal == thermal_list[thermal_index],
                            "Thermal {} is incorrect for sfp {}".format(thermal_index, sfp_id))
        self.assert_expectations()
