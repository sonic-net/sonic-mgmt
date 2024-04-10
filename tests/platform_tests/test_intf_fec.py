import logging
import pytest

from tests.common.utilities import skip_release

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

SUPPORTED_PLATFORMS = [
    "mlnx_msn",
    "8101",
    "8111"
]


def test_verify_fec_oper_mode(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_frontend_asic_index, conn_graph_facts):
    """
    @Summary: Check the FEC operational mode, if links are up using 'show interface status'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
  
    if any(platform in duthost.facts['platform'] for platform in SUPPORTED_PLATFORMS):
        # Not supported on 202305 and older releases
        skip_release(duthost, ['201811', '201911', '202012', '202205', '202211', '202305'])
    else:
        pytest.skip("DUT has platform {}, test is not supported".format(duthost.facts['platform']))

    logging.info("Get output of '{}'".format("show interface status"))
    intf_status = duthost.show_and_parse("show interface status")

    for intf in intf_status:
        if intf['oper'].lower() == "up":
            if intf['fec'].lower() == "n/a":
                pytest.fail("FEC status is N/A for interface {}".format(intf['interface']))