import logging
import pytest

from tests.common.utilities import skip_release

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


def is_supported_platform(duthost):
    if any(platform in duthost.facts['platform'] for platform in SUPPORTED_PLATFORMS):
        skip_release(duthost, ["201811", "201911", "202012", "202205", "202211", "202305"])
        return True
    else:
        pytest.skip("DUT has platform {}, test is not supported".format(duthost.facts['platform']))
        return False


def test_verify_fec_oper_mode(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_frontend_asic_index, conn_graph_facts):
    """
    @Summary: Verify the FEC operational mode is valid, for all the interfaces with
    SFP present, supported speeds and link is up using 'show interface status'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if not is_supported_platform(duthost):
        return

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
    FEC operational mode is retored to default FEC mode
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if not is_supported_platform(duthost):
        return

    logging.info("Get output of '{}'".format("show interface status"))
    intf_status = duthost.show_and_parse("show interface status")

    for intf in intf_status:
        sfp_presence = duthost.show_and_parse("sudo sfpshow presence -p {}"
                                              .format(intf['interface']))
        if sfp_presence:
            presence = sfp_presence[0].get('presence', '').lower()
            oper = intf.get('oper', '').lower()

            if presence == "not present" or oper != "up":
                continue

        config_status = duthost.command("sudo config interface fec {} rs"
                                        .format(intf['interface']))
        if config_status:
            duthost.command("sleep 2")
            # Verify the FEC operational mode is restored
            logging.info("Get output of '{} {}'".format("show interfaces fec status", intf['interface']))
            fec_status = duthost.show_and_parse("show interfaces fec status {}".format(intf['interface']))
            fec = fec_status[0].get('fec oper', '').lower()

            if not (fec == "rs"):
                pytest.fail("FEC status is not restored for interface {}".format(intf['interface']))


def test_verify_fec_stats_counters(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                   enum_frontend_asic_index, conn_graph_facts):
    """
    @Summary: Verify the FEC stats counters are valid
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if not is_supported_platform(duthost):
        return

    logging.info("Get output of '{}'".format("show interfaces counters fec-stats"))
    intf_status = duthost.show_and_parse("show interfaces counters fec-stats")

    for intf in intf_status:
        sfp_presence = duthost.show_and_parse("sudo sfpshow presence -p {}"
                                              .format(intf['iface']))
        if sfp_presence:
            presence = sfp_presence[0].get('presence', '').lower()
            if presence == "not present":
                continue

        fec_corr = intf.get('fec_corr', '').lower()
        fec_uncorr = intf.get('fec_uncorr', '').lower()
        fec_symbol_err = intf.get('fec_symbol_err', '').lower()
        if fec_corr == "n/a" or fec_uncorr == "n/a" or fec_symbol_err == "n/a":
            # Verify the FEC stat counters are valid
            pytest.fail("FEC stat counters are not valid for interface {}".format(intf['iface']))
