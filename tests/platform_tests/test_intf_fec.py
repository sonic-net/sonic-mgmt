import logging
import pytest
import time

from tests.common.utilities import skip_release, wait_until

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

    logging.info("Get output of '{}'".format("show interface status"))
    intf_status = duthost.show_and_parse("show interface status")

    for intf in intf_status:
        sfp_presence = duthost.show_and_parse("sudo sfpshow presence -p {}"
                                              .format(intf['interface']))
        if sfp_presence:
            presence = sfp_presence[0].get('presence', '').lower()
            oper = intf.get('oper', '').lower()
            speed = intf.get('speed', '')

            if presence == "present" and oper == "up" and speed in SUPPORTED_SPEEDS:
                # Verify the FEC operational mode is valid
                logging.info("Get output of '{} {}'".format("show interfaces fec status", intf['interface']))
                fec_status = duthost.show_and_parse("show interfaces fec status {}".format(intf['interface']))
                fec = fec_status[0].get('fec oper', '').lower()
                if fec == "n/a":
                    pytest.fail("FEC status is N/A for interface {}".format(intf['interface']))


def test_config_fec_oper_mode(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_frontend_asic_index, conn_graph_facts):
    """
    @Summary: Configure the FEC operational mode for all the interfaces, then check
    FEC operational mode is restored to 'rs' FEC mode
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    logging.info("Get output of '{}'".format("show interface status"))
    intf_status = duthost.show_and_parse("show interface status")

    for intf in intf_status:
        sfp_presence = duthost.show_and_parse("sudo sfpshow presence -p {}"
                                              .format(intf['interface']))
        if sfp_presence:
            presence = sfp_presence[0].get('presence', '').lower()
            oper = intf.get('oper', '').lower()
            speed = intf.get('speed', '')

            if presence == "not present" or oper != "up" or speed not in SUPPORTED_SPEEDS:
                continue

        config_status = duthost.command("sudo config interface fec {} rs"
                                        .format(intf['interface']))
        if config_status:
            wait_until(30, 2, 0, duthost.is_interface_status_up, intf["interface"])
            # Verify the FEC operational mode is restored
            logging.info("Get output of '{} {}'".format("show interfaces fec status", intf['interface']))
            fec_status = duthost.show_and_parse("show interfaces fec status {}".format(intf['interface']))
            fec = fec_status[0].get('fec oper', '').lower()

            if not (fec == "rs"):
                pytest.fail("FEC status is not restored for interface {}".format(intf['interface']))


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


def test_verify_fec_histogram(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_frontend_asic_index, conn_graph_facts):
    """
    @Summary: Verify the FEC histogram is valid and check for errors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    logging.info("Get output of 'show interface status'")
    intf_status = duthost.show_and_parse("show interface status")

    for intf in intf_status:
        intf_name = intf['interface']
        sfp_presence = duthost.show_and_parse("sudo sfpshow presence -p {}".format(intf_name))
        if sfp_presence:
            presence = sfp_presence[0].get('presence', '').lower()
            oper = intf.get('oper', '').lower()
            speed = intf.get('speed', '')

            # Skip interfaces that are not up or have no SFP module present or for unsupported speeds
            if presence == "not present" or oper != "up" or speed not in SUPPORTED_SPEEDS:
                logging.info("Skip the test_verify_fec_histogram for {}: sfp_presence:{} oper_state:{} speed:{}'"
                             .format(intf_name, presence, oper, speed))
                continue

            # Verify the FEC histogram
            logging.info("Get output of 'show interfaces counters fec-histogram {}'".format(intf_name))
            fec_hist = duthost.show_and_parse("show interfaces counters fec-histogram {}".format(intf_name))

            # Check if the FEC histogram data is present
            if not fec_hist:
                pytest.fail("No FEC histogram data found for interface {}".format(intf_name))

            # Check and log FEC histogram bins
            logging.info("FEC histogram for interface {}: {}".format(intf_name, fec_hist))

            # Set thresholds for FEC histogram validation
            acceptable_error_threshold = 0
            critical_bins = range(7, 16)  # Higher bins indicating serious transmission issues

            # Initialize lists to hold FEC histogram samples
            fec_hist_samples = []

            for sample_index in range(3):  # Take 3 samples
                # Verify the FEC histogram
                logging.info("Get output of 'show interfaces counters fec-histogram {}'".format(intf_name))
                fec_hist = duthost.show_and_parse("show interfaces counters fec-histogram {}".format(intf_name))

                # Check if the FEC histogram data is present
                if not fec_hist:
                    pytest.fail("No FEC histogram data found for interface {}".format(intf_name))

                # Check and log FEC histogram bins
                logging.info("FEC histogram for interface {}: {}".format(intf_name, fec_hist))

                # Store the sample
                fec_hist_samples.append(fec_hist)

                # Log the bin values
                for bin_index in range(16):
                    bin_label = fec_hist[bin_index].get('symbol errors per codeword')
                    bin_value = fec_hist[bin_index].get('codewords')
                    logging.info("Sample {} - Interface {}: {} -> {}"
                                 .format(sample_index + 1, intf_name, bin_label, bin_value))

                # Sleep for 10 seconds before taking the next sample (except after the last one)
                if sample_index < 2:
                    time.sleep(10)

            # Validate FEC histogram counters
            for bin_index in critical_bins:
                previous_value = int(fec_hist_samples[0][bin_index].get('codewords', 0))
                current_value = int(fec_hist_samples[2][bin_index].get('codewords', 0))

                # Fail the test if the counter for this bin has increased
                if current_value > previous_value:
                    pytest.fail("Increasing symbol errors found in bin {} (from {} to {}) on interface {}".format(
                        fec_hist_samples[2][bin_index].get('symbol errors per codeword'), previous_value, current_value,
                        intf_name))
