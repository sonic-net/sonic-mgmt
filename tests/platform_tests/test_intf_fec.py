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
        logging.info("Get output of '{} {}'".format("show interfaces fec status", intf))
        fec_status = duthost.show_and_parse("show interfaces fec status {}".format(intf))
        fec = fec_status[0].get('fec oper', '').lower()
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
        config_status = duthost.command("sudo config interface fec {} rs".format(intf))
        if config_status:
            wait_until(30, 2, 0, duthost.is_interface_status_up, intf["interface"])
            # Verify the FEC operational mode is restored
            logging.info("Get output of '{} {}'".format("show interfaces fec status", intf))
            fec_status = duthost.show_and_parse("show interfaces fec status {}".format(intf))
            fec = fec_status[0].get('fec oper', '').lower()

            if not (fec == "rs"):
                pytest.fail("FEC status is not restored for interface {}".format(intf))


def get_interface_speed(duthost, interface_name):
    """
    Get the speed of a specific interface on the DUT.

    :param duthost: The DUT host object.
    :param interface_name: The name of the interface.
    :return: The speed of the interface as a string.
    """
    logging.info(f"Getting speed for interface {interface_name}")
    intf_status = duthost.show_and_parse("show interfaces status {}".format(interface_name))

    speed = intf_status[0].get('speed')
    logging.info(f"Interface {interface_name} has speed {speed}")
    return speed

    pytest.fail(f"Interface {interface_name} not found")


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
        speed = get_interface_speed(duthost, intf_name)
        if speed not in SUPPORTED_SPEEDS:
            continue

        fec_corr = intf.get('fec_corr', '').lower()
        fec_uncorr = intf.get('fec_uncorr', '').lower()
        fec_symbol_err = intf.get('fec_symbol_err', '').lower()
        # Check if fec_corr, fec_uncorr, and fec_symbol_err are valid integers
        try:
            fec_corr_int = int(fec_corr)
            fec_uncorr_int = int(fec_uncorr)
            fec_symbol_err_int = int(fec_symbol_err)
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
        logging.info("Get output of 'show interfaces counters fec-histogram {intf_name}'")
        fec_hist = duthost.show_and_parse("show interfaces counters fec-histogram {intf_name}")
    except Exception as e:
        logging.error("Failed to execute 'show interfaces counters fec-histogram {intf_name}': {str(e)}")
        pytest.fail("Command 'show interfaces counters fec-histogram {intf_name}' not found \
                or failed: {str(e)}")
        return None

    if not fec_hist:
        pytest.fail("No FEC histogram data found for interface {intf_name}")

    logging.info("FEC histogram for interface {intf_name}: {fec_hist}")
    return fec_hist


def collect_fec_histogram_samples(duthost, intf_name, num_samples=3, interval=10):
    """
    @Summary: Collect FEC histogram samples over a period of time.
    """
    fec_hist_samples = []
    for sample_index in range(num_samples):
        fec_hist = get_fec_histogram(duthost, intf_name)
        fec_hist_samples.append(fec_hist)

        # Log bin values for each sample
        for bin_index in range(16):
            bin_label = fec_hist[bin_index].get('symbol errors per codeword')  # noqa: F841
            bin_value = fec_hist[bin_index].get('codewords')  # noqa: F841
            logging.info("Sample {sample_index + 1} - Interface {intf_name}: {bin_label} -> {bin_value}")

        if sample_index < num_samples - 1:
            time.sleep(interval)

    return fec_hist_samples


def validate_fec_histogram(fec_hist_samples, intf_name, critical_bins=range(7, 16)):
    """
    @Summary: Validate FEC histogram bins to ensure no increasing errors.
    """
    for bin_index in critical_bins:
        previous_value = int(fec_hist_samples[0][bin_index].get('codewords', 0))
        current_value = int(fec_hist_samples[2][bin_index].get('codewords', 0))

        if current_value > previous_value:
            pytest.fail("Increasing symbol errors found in bin {fec_hist_samples[2][bin_index].\
                    get('symbol errors per codeword')} (from {previous_value} to {current_value}) \
                    on interface {intf_name}")


def test_verify_fec_histogram(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_frontend_asic_index, conn_graph_facts):
    """
    @Summary: Verify the FEC histogram is valid and check for errors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get valid interfaces
    valid_interfaces = get_valid_interfaces(duthost, SUPPORTED_SPEEDS)

    for intf_name in valid_interfaces:
        # Collect FEC histogram samples
        fec_hist_samples = collect_fec_histogram_samples(duthost, intf_name)

        # Validate FEC histogram
        validate_fec_histogram(fec_hist_samples, intf_name)
