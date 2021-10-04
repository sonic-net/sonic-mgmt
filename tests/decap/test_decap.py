import json
import logging
from datetime import datetime

import pytest
import requests
from jinja2 import Template
from netaddr import IPNetwork
from ansible.plugins.filter.core import to_bool

from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses         # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import ptf_test_port_map
from tests.common.fixtures.fib_utils import fib_info_files
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.dualtor.mux_simulator_control import mux_server_url
from tests.common.utilities import wait

logger = logging.getLogger(__name__)

PTFRUNNER_QLEN = 1000
FIB_INFO_DEST = "/root/fib_info.txt"

pytestmark = [
    pytest.mark.topology('any')
]


@pytest.fixture(scope='module')
def ttl_dscp_params(duthost, supported_ttl_dscp_params):
    if "uniform" in supported_ttl_dscp_params.values() and ("201811" in duthost.os_version or "201911" in duthost.os_version):
        pytest.skip('uniform ttl/dscp mode is available from 202012. Current version is %s' % duthost.os_version)
    
    return supported_ttl_dscp_params


@pytest.fixture(scope="module")
def setup_teardown(request, duthosts, fib_info_files, duts_running_config_facts, ttl_dscp_params):

    is_multi_asic = duthosts[0].sonichost.is_multi_asic

    ecn_mode = "copy_from_outer"
    dscp_mode = ttl_dscp_params['dscp']
    ttl_mode = ttl_dscp_params['ttl']

    # The hostvars dict has definitions defined in ansible/group_vars/sonic/variables
    hostvars = duthosts[0].host.options["variable_manager"]._hostvars[duthosts[0].hostname]
    sonic_hwsku = duthosts[0].sonichost.facts["hwsku"]
    mellanox_hwskus = hostvars.get("mellanox_hwskus", [])

    if sonic_hwsku in mellanox_hwskus:
        dscp_mode = "uniform"
        ecn_mode = "standard"

    setup_info = {
        "outer_ipv4": to_bool(request.config.getoption("outer_ipv4")),
        "outer_ipv6": to_bool(request.config.getoption("outer_ipv6")),
        "inner_ipv4": to_bool(request.config.getoption("inner_ipv4")),
        "inner_ipv6": to_bool(request.config.getoption("inner_ipv6")),
        "dscp_mode": dscp_mode,
        "ecn_mode": ecn_mode,
        "ttl_mode": ttl_mode,
        "fib_info_files": fib_info_files[:3],  # Test at most 3 DUTs in case of multi-DUT
        "ignore_ttl": True if is_multi_asic else False,
        "max_internal_hops": 3 if is_multi_asic else 0,
    }

    # config decap
    decap_conf_template = Template(open("../ansible/roles/test/templates/decap_conf.j2").read())

    lo_ips = []
    lo_ipv6s = []
    for duthost in duthosts:
        cfg_facts = duts_running_config_facts[duthost.hostname]
        lo_ip = None
        lo_ipv6 = None
        # Loopback0 ip is same on all ASICs
        for addr in cfg_facts[0]["LOOPBACK_INTERFACE"]["Loopback0"]:
            ip = IPNetwork(addr).ip
            if ip.version == 4 and not lo_ip:
                lo_ip = str(ip)
            elif ip.version == 6 and not lo_ipv6:
                lo_ipv6 = str(ip)
        lo_ips.append(lo_ip)
        lo_ipv6s.append(lo_ipv6)

        decap_conf_vars = {
            "lo_ip": lo_ip,
            "lo_ipv6": lo_ipv6,
            "op": "SET"
        }
        decap_conf_vars.update(setup_info)

        duthost.copy(content=decap_conf_template.render(
            **decap_conf_vars), dest="/tmp/decap_conf.json")

        decap_conf_vars["op"] = "DEL"
        duthost.copy(content=decap_conf_template.render(
            **decap_conf_vars), dest="/tmp/decap_conf_del.json")

        for asic_id in duthost.get_frontend_asic_ids():
            duthost.shell("docker cp /tmp/decap_conf.json swss{}:/decap_conf.json"
                        .format(asic_id if asic_id is not None else ""))
            duthost.shell('docker exec swss{} sh -c "swssconfig /decap_conf.json"'
                        .format(asic_id if asic_id is not None else ""))

    setup_info['lo_ips'] = lo_ips
    setup_info['lo_ipv6s'] = lo_ipv6s
    setup_info['router_macs'] = [duthost.facts['router_mac'] for duthost in duthosts]

    logger.info(json.dumps(setup_info, indent=2))

    yield setup_info

    # Remove decap configuration
    for duthost in duthosts:
        for asic_id in duthost.get_frontend_asic_ids():
            duthost.shell("docker cp /tmp/decap_conf_del.json swss{}:/decap_conf_del.json"
                        .format(asic_id if asic_id is not None else ""))
            duthost.shell('docker exec swss{} sh -c "swssconfig /decap_conf_del.json"'
                        .format(asic_id if asic_id is not None else ""))


def set_mux_side(tbinfo, mux_server_url, side):
    if 'dualtor' in tbinfo['topo']['name']:
        res = requests.post(mux_server_url, json={"active_side": side})
        pt_assert(res.status_code==200, 'Failed to set active side: {}'.format(res.text))
        return res.json()   # Response is new mux_status of all mux Y-cables.
    return {}


@pytest.fixture
def set_mux_random(tbinfo, mux_server_url):
    return set_mux_side(tbinfo, mux_server_url, 'random')


def test_decap(tbinfo, duthosts, mux_server_url, setup_teardown, ptfhost, set_mux_random, ttl_dscp_params):

    setup_info = setup_teardown

    if 'dualtor' in tbinfo['topo']['name']:
        wait(30, 'Wait some time for mux active/standby state to be stable after toggled mux state')

    log_file = "/tmp/decap.{}.log".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    ptf_runner(ptfhost,
               "ptftests",
               "IP_decap_test.DecapPacketTest",
                platform_dir="ptftests",
                params={"outer_ipv4": setup_info["outer_ipv4"],
                        "outer_ipv6": setup_info["outer_ipv6"],
                        "inner_ipv4": setup_info["inner_ipv4"],
                        "inner_ipv6": setup_info["inner_ipv6"],
                        "lo_ips": setup_info["lo_ips"],
                        "lo_ipv6s": setup_info["lo_ipv6s"],
                        "router_macs": setup_info["router_macs"],
                        "dscp_mode": setup_info["dscp_mode"],
                        "ttl_mode": setup_info["ttl_mode"],
                        "ignore_ttl": setup_info["ignore_ttl"],
                        "max_internal_hops": setup_info["max_internal_hops"],
                        "fib_info_files": setup_info["fib_info_files"],
                        "ptf_test_port_map": ptf_test_port_map(ptfhost, tbinfo, duthosts, mux_server_url)
                        },
                qlen=PTFRUNNER_QLEN,
                log_file=log_file)
