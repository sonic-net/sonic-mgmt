'''This script is to test the EBGP Authentication feature of SONiC.
'''
# import json
import logging
# import time
# import yaml

import pytest
# import requests
# import ipaddr as ipaddress

# from jinja2 import Template
# from natsort import natsorted
# from tests.common.helpers.assertions import pytest_assert
# from tests.common.helpers.constants import DEFAULT_NAMESPACE
# from tests.common.helpers.parallel import reset_ansible_local_tmp
# from tests.common.helpers.parallel import parallel_run
#from bgp_helpers import get_routes_not_announced_to_bgpmon

# pytestmark = [
#     pytest.mark.topology('t1'),
#     pytest.mark.device_type('vs')
# ]

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.sanity_check(skip_sanity=True)]

def test_bgp_session_established(duthosts, rand_one_dut_hostname):
    duthost=duthosts[rand_one_dut_hostname]
    logger.info("DUT set to {}".format(duthost))
