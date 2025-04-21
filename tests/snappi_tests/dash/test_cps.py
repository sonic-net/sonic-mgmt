from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config  # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import config_uhd_connect, config_smartswitch
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa: F401
from tests.snappi_tests.dash.ha.ha_helper import *
from tests.common.snappi_tests.ixload.snappi_fixtures import config_snappi_ixl

import time
import pytest
import snappi
import requests
import json
import ipaddress
import os
import macaddress
import time


SNAPPI_POLL_DELAY_SEC = 2

ipp = ipaddress.ip_address
maca = macaddress.MAC


pytestmark = [pytest.mark.topology('snappi')]
@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('ha_test_case', ['cps'])
def test_cps_baby_hero(
                       duthost,
                       localhost,
                       conn_graph_facts,
                       fanout_graph_facts,
                       get_snappi_ports,
                       ha_test_case,
                       config_snappi_ixl,): # noqa F811


    run_ha_test(
                duthost,
                localhost,
                conn_graph_facts,
                fanout_graph_facts,
                get_snappi_ports,
                ha_test_case,
                config_snappi_ixl)

    return
