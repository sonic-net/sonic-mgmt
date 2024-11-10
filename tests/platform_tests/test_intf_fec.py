import logging
import pytest
import time

from tests.common.utilities import skip_release, wait_until
from tests.common.platform.interface_utils import get_valid_interfaces

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

SUPPORTED_PLATFORMS = [
    "mlnx_msn",
    "8101_32fh",
    "8111_32eh"
]

SUPPORTED_SPEEDS = [
    "100G", "200G", "400G", "800G", "1600G"
]


@pytest.fixture(autouse=True)
def is_supported_platform(duthost):
    if any(platform in duthost.facts['platform'] for platform in SUPPORTED_PLATFORMS):
        skip_release(duthost, ["201811", "201911", "202012", "202205", "202211", "202305"])
    else:
        pytest.skip("DUT has platform {}, test is not supported".format(duthost.facts['platform']))


def test_verify_fec_oper_mode(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_frontend_asic_index, conn_graph_facts):
    """
    @Summary: Verify the FEC operational mode is valid, for all the interfaces with
    SFP present, supported speeds and link is up using 'show interface status'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get valid interfaces
    valid_interfaces = get_valid_interfaces(duthost, SUPPORTED_SPEEDS)

    for intf in valid_interfaces:
        # Verify the FEC operational mode is valid
        fec = duthost.get_port_fec(intf)
        logging.info("FEC mode for interface {}: {}".format(intf, fec))
        if fec == "n/a":
            pytest.fail("FEC status is N/A for interface {}".format(intf))


def test_config_fec_oper_mode(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_frontend_asic_index, conn_graph_facts):
    """
    @Summary: Configure the FEC operational mode for all the interfaces, then check
    FEC operational mode is restored to 'rs' FEC mode
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get valid interfaces
    valid_interfaces = get_valid_interfaces(duthost, SUPPORTED_SPEEDS)

    for intf in valid_interfaces:
        config_status = duthost.set_port_fec(intf, "rs")
        if config_status:
            wait_until(30, 2, 0, duthost.is_interface_status_up, intf)
            # Verify the FEC operational mode is restored
            fec = duthost.get_port_fec(intf)
            logging.info("FEC mode for interface {} after configuration: {}".format(intf, fec))
            if not (fec == "rs"):
                pytest.fail("FEC status is not restored for interface {}".format(intf))


def test_verify_fec_stats_counters(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                   enum_frontend_asic_index, conn_graph_facts):
    """
    @Summary: Verify the FEC stats counters are valid
    Also, check for any uncorrectable FEC errors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    logging.info("Get output of 'show interfaces counters fec-stats'")
    intf_status = duthost.show_and_parse("show interfaces counters fec-stats")

    for intf in intf_status:
        intf_name = intf['iface']
        speed = duthost.get_speed(intf_name)
        if speed not in SUPPORTED_SPEEDS:
            continue

        fec_corr = intf.get('fec_corr', '').lower()
        fec_uncorr = intf.get('fec_uncorr', '').lower()
        fec_symbol_err = intf.get('fec_symbol_err', '').lower()
        # Check if fec_corr, fec_uncorr, and fec_symbol_err are valid integers
        try:
            fec_corr_int = int(fec_corr.replace(',', ''))
            fec_uncorr_int = int(fec_uncorr.replace(',', ''))
            fec_symbol_err_int = int(fec_symbol_err.replace(',', ''))
        except ValueError:
            pytest.fail("FEC stat counters are not valid integers for interface {}, \
                        fec_corr: {} fec_uncorr: {} fec_symbol_err: {}"
                        .format(intf_name, fec_corr, fec_uncorr, fec_symbol_err))

        # Check for non-zero FEC uncorrectable errors
        if fec_uncorr_int > 0:
            pytest.fail("FEC uncorrectable errors are non-zero for interface {}: {}"
                        .format(intf_name, fec_uncorr_int))

        # Check for valid FEC correctable codeword errors > FEC symbol errors
        if fec_symbol_err_int > fec_corr_int:
            pytest.fail("FEC symbol errors:{} are higher than FEC correctable errors:{} for interface {}"
                        .format(intf_name, fec_symbol_err_int, fec_corr_int))


def get_fec_histogram(duthost, intf_name):
    """
    @Summary: Fetch FEC histogram for a given interface.
    """
    try:
        logging.info("Get output of 'show interfaces counters fec-histogram {}'".format(intf_name))
        fec_hist = duthost.show_and_parse("show interfaces counters fec-histogram {}".format(intf_name))
    except Exception as e:
        logging.error("Failed to execute 'show interfaces counters fec-histogram {}': {}".format(intf_name, e))
        pytest.fail("Command 'show interfaces counters fec-histogram {}' not found \
                or failed: {}".format(intf_name, str(e)))
        return None

    if not fec_hist:
        pytest.fail("No FEC histogram data found for interface {}".format(intf_name))

    logging.info("FEC histogram for interface {}: {}".format(intf_name, fec_hist))
    return fec_hist


def validate_fec_histogram(duthost, intf_name):
    """
    @Summary: Validate FEC histogram critical bins for any errors. Fail the test if bin value > 0
    """

    fec_hist = get_fec_histogram(duthost, intf_name)
    if not fec_hist:
        pytest.fail("FEC histogram data not found for interface {}".format(intf_name))

    critical_bins = range(7, 16)
    for bin_index in critical_bins:
        bin_value = int(fec_hist[bin_index].get('codewords', 0))
        if bin_value > 0:
            pytest.fail("FEC histogram bin {} has errors for interface {}: {}"
                        .format(bin_index, intf_name, bin_value))


def test_verify_fec_histogram(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_frontend_asic_index, conn_graph_facts):
    """
    @Summary: Verify the FEC histogram is valid and check for errors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get valid interfaces
    valid_interfaces = get_valid_interfaces(duthost, SUPPORTED_SPEEDS)

    for intf_name in valid_interfaces:
        wait_until(30, 10, 0, validate_fec_histogram, duthost, intf_name)
