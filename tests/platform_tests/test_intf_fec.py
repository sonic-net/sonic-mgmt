import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release, wait_until
from tests.common.platform.interface_utils import get_fec_eligible_interfaces

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

SUPPORTED_PLATFORMS = [
    "mlnx_msn",
    "8101_32fh",
    "8111_32eh",
    "arista",
    "x86_64-nvidia",
    "x86_64-88_lc0_36fh_m-r0",
    "nexthop",
    "marvell"
]

SUPPORTED_SPEEDS = [
    "50G", "100G", "200G", "400G", "800G", "1600G"
]


@pytest.fixture(autouse=True)
def is_supported_platform(duthost):
    if any(platform in duthost.facts['platform'] for platform in SUPPORTED_PLATFORMS):
        skip_release(duthost, ["201811", "201911", "202012", "202205", "202211", "202305"])
    else:
        pytest.skip("DUT has platform {}, test is not supported".format(duthost.facts['platform']))


def get_fec_oper_mode(duthost, interface):
    """
    @Return: FEC operational mode for a specific interface
    """
    logging.info("Get output of '{} {}'".format("show interfaces fec status", interface))
    fec_status = duthost.show_and_parse("show interfaces fec status {}".format(interface))
    return fec_status[0].get('fec oper', '').lower()


def check_intf_fec_mode(duthost, intf, exp_fec_mode):
    post_fec = get_fec_oper_mode(duthost, intf)
    if post_fec == exp_fec_mode:
        return True
    return False


def test_verify_fec_oper_mode(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    @Summary: Verify the FEC operational mode is valid, for all the interfaces with
    SFP present, supported speeds and link is up using 'show interface status'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if "broadcom" in duthost.facts.get('platform_asic'):
        pytest.skip("Skipping this test on platforms with Broadcom ASICs")

    # Get interfaces that are operationally up and have supported speeds.
    interfaces = get_fec_eligible_interfaces(duthost, SUPPORTED_SPEEDS)

    if not interfaces:
        pytest.skip("Skipping this test as there is no fec eligible interface")

    for intf in interfaces:
        # Verify the FEC operational mode is valid
        fec = get_fec_oper_mode(duthost, intf)
        if fec == "n/a":
            pytest.fail("FEC status is N/A for interface {}".format(intf))


def test_config_fec_oper_mode(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    @Summary: Configure the FEC operational mode for all the interfaces, then check
    FEC operational mode is restored to 'rs' FEC mode
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if "broadcom" in duthost.facts.get('platform_asic'):
        pytest.skip("Skipping this test on platforms with Broadcom ASICs")

    # Get interfaces that are operationally up and have supported speeds.
    interfaces = get_fec_eligible_interfaces(duthost, SUPPORTED_SPEEDS)

    if not interfaces:
        pytest.skip("Skipping this test as there is no fec eligible interface")

    for intf in interfaces:
        fec_mode = get_fec_oper_mode(duthost, intf)
        if fec_mode == "n/a":
            pytest.fail("FEC status is N/A for interface {}".format(intf))

        asic_cli_option = duthost.get_port_asic_instance(intf).cli_ns_option

        config_status = duthost.command("sudo config interface {} fec {} {}"
                                        .format(asic_cli_option, intf, fec_mode))
        if config_status:
            pytest_assert(wait_until(30, 2, 0, duthost.is_interface_status_up, intf),
                          "Interface {} did not come up after configuring FEC mode".format(intf))
            # Verify the FEC operational mode is restored
            pytest_assert(wait_until(30, 2, 0, check_intf_fec_mode, duthost, intf, fec_mode),
                          f"FEC status of Interface {intf} is not restored to {fec_mode}")


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


def test_verify_fec_stats_counters(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    @Summary: Verify the FEC stats counters are valid
    Also, check for any uncorrectable FEC errors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get operationally up and interfaces with supported speeds
    interfaces = get_fec_eligible_interfaces(duthost, SUPPORTED_SPEEDS)

    if not interfaces:
        pytest.skip("Skipping this test as there is no fec eligible interface")

    logging.info("Get output of 'show interfaces counters fec-stats'")
    intf_status = duthost.show_and_parse("show interfaces counters fec-stats")

    def skip_ber_counters_test(intf_status: dict) -> bool:
        """
        Check whether the BER fields (Pre-FEC and Post-FEC BER)
        exists in the "show interfaces counters fec-stats"
        CLI output
        """
        if intf_status.get('fec_pre_ber') is None or intf_status.get('fec_post_ber') is None:
            pytest.skip("Pre-FEC and Post-FEC BER fields missing on interface. intf_status: {}".format(intf_status))
            return True
        return False

    for intf in intf_status:
        intf_name = intf['iface']
        speed = duthost.get_speed(intf_name)
        # Speed is a empty string if the port isn't up
        if speed == '':
            continue
        # Convert the speed to gbps format
        speed_gbps = f"{int(speed) // 1000}G"
        if speed_gbps not in SUPPORTED_SPEEDS:
            continue

        # Removes commas from "show interfaces counters fec-stats" (i.e. 12,354 --> 12354) to allow int conversion
        fec_corr = intf.get('fec_corr', '').replace(',', '').lower()
        fec_uncorr = intf.get('fec_uncorr', '').replace(',', '').lower()
        fec_symbol_err = intf.get('fec_symbol_err', '').replace(',', '').lower()
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

        # FEC correctable codeword errors should always be less than actual FEC symbol errors, check it
        if fec_corr_int > 0 and fec_corr_int > fec_symbol_err_int:
            pytest.fail("FEC symbol errors:{} are higher than FEC correctable errors:{} for interface {}"
                        .format(fec_symbol_err_int, fec_corr_int, intf_name))

        if skip_ber_counters_test(intf):
            continue
        fec_pre_ber = intf.get('fec_pre_ber', '').lower()
        fec_post_ber = intf.get('fec_post_ber', '').lower()
        try:
            if fec_pre_ber != "n/a":
                float(fec_pre_ber)
            if fec_post_ber != "n/a":
                float(fec_post_ber)
        except ValueError:
            pytest.fail("Pre-FEC and Post-FEC BER are not valid floats for interface {}, \
                    fec_pre_ber: {} fec_post_ber: {}"
                        .format(intf_name, fec_pre_ber, fec_post_ber))


def get_fec_histogram(duthost, intf_name):
    """
    @Summary: Fetch FEC histogram for a given interface.
    """
    try:
        logging.info("Get output of 'show interfaces counters fec-histogram {}'".format(intf_name))
        asic_cli_option = duthost.get_port_asic_instance(intf_name).cli_ns_option
        fec_hist = duthost.show_and_parse("show interfaces counters fec-histogram {} {}".format(asic_cli_option,
                                                                                                intf_name))
    except Exception as e:
        logging.error("Failed to execute 'show interfaces counters fec-histogram {}': {}".format(intf_name, e))
        pytest.skip("Command 'show interfaces counters fec-histogram {}' not found \
                or failed: {}".format(intf_name, str(e)))
        return None

    logging.info("FEC histogram for interface {}: {}".format(intf_name, fec_hist))
    return fec_hist


def validate_fec_histogram(duthost, intf_name, init, prev=None):
    """
    @Summary: Validate FEC histogram critical bins for any errors. Fail the test if bin value > 0
    for a stable link over last two snapshots.
    """
    if not init and not prev:
        pytest.fail("FEC histogram from previous snapshot is not provided")

    fec_hist = get_fec_histogram(duthost, intf_name)
    if not fec_hist:
        pytest.fail("FEC histogram data not found or incomplete for interface {}".format(intf_name))

    critical_bins = range(7, 16)
    error_bins = []
    for bin_index in critical_bins:
        bin_value = int(fec_hist[bin_index].get('codewords', 0))
        if init:
            if bin_value > 0:
                error_bins.append((bin_index, bin_value))
        else:
            prev_bin_value = int(prev[bin_index].get('codewords', 0))
            if bin_value - prev_bin_value > 0:
                error_bins.append((bin_index, bin_value))

    if error_bins:
        error_messages = ["FEC histogram bin {} has errors for interface {}: {} (init: {})".format(
                              bin_index, intf_name, bin_value, init)
                          for bin_index, bin_value in error_bins]
        if init:
            logging.info("\n".join(error_messages))
        else:
            logging.error("\n".join(error_messages))
        return False, fec_hist

    return True, fec_hist


def test_verify_fec_histogram(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    @Summary: Verify the FEC histogram is valid and check for errors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if "broadcom" in duthost.facts.get('platform_asic'):
        if "7060x6" not in duthost.facts['platform']:
            pytest.skip("Skipping this test on platforms with Broadcom ASICs")

    # Get operationally up and interfaces with supported speeds
    interfaces = get_fec_eligible_interfaces(duthost, SUPPORTED_SPEEDS)

    if not interfaces:
        pytest.skip("Skipping this test as there is no fec eligible interface")

    # It's possible there are some transient FEC symbol errors on interface
    # state transition. Hence, this test uses the first check to read the current
    # FEC histogram counters to see whether there are stale errors. If so,
    # it will increase the waiting time for the next read and compare any
    # changes in the critical bins between 2 snapshots. For a stable link, no
    # increments in these critical bins are expected.
    snapshots = {}
    sleep_time = 10
    for intf_name in interfaces:
        valid, fec_hist = validate_fec_histogram(duthost, intf_name, True)
        if not valid:
            logging.info("Update test sleep time to 10 min due to bin errors in the initial snapshot")
            sleep_time = 10 * 60
        snapshots[intf_name] = fec_hist

    for _ in range(2):
        time.sleep(sleep_time)
        for intf_name in interfaces:
            prev_fec_hist = snapshots[intf_name]
            valid, fec_hist = validate_fec_histogram(duthost, intf_name, False, prev_fec_hist)
            if not valid:
                pytest.fail("FEC histogram validation failed for interface {}".format(intf_name))
            snapshots[intf_name] = fec_hist
