import logging
import pytest

from tests.common.utilities import skip_release, wait_until

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

SUPPORTED_PLATFORMS = [
    "mlnx_msn",
    "8101_32fh",
    "8111_32eh",
    "arista"
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

    if "broadcom" in duthost.facts.get('platform_asic'):
        pytest.skip("Skipping this test on platforms with Broadcom ASICs")

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

    if "broadcom" in duthost.facts.get('platform_asic'):
        pytest.skip("Skipping this test on platforms with Broadcom ASICs")

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

    def skip_ber_counters_test(intf_status: dict) -> bool:
        """
        Check whether the BER fields (Pre-FEC and Post-FEC BER)
        exists in the "show interfaces counters fec-stats"
        CLI output
        """
        if intf_status.get('fec_pre_ber') is None or intf_status.get('fec_post_ber') is None:
            pytest.fail("Pre-FEC and Port-FEC BER fields missing on interface. intf_status: {}".format(intf_status))
            return True
        return False

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
