'''This script is to test the EBGP Authentication feature of SONiC.
'''
# import json
import logging
# import time
# import yaml

import pytest
# import requests
from collections import defaultdict
import ipaddr as ipaddress
import time

#from jinja2 import Template
from natsort import natsorted
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
bgp_config_sleeptime = 60
peer_group_v4 = "PEER_V4"
peer_group_v6 = "PEER_V6"
neigh_asn = "64001"
neigh_ip_v4 = "10.0.0.33"
neigh_ip_v6 = "FC00::42"
bgp_pass = "sonic.123"
mismatch_pass = "badpassword"
dut_ip_v4 = "10.0.0.32"
dut_ip_v6 = "fc00::41"

pytestmark = [pytest.mark.sanity_check(skip_sanity=True)]

# @pytest.fixture(scope='module', autouse=True)
# def prepare_pass_config_files(duthosts, rand_one_dut_hostname):
#     duthost = duthosts[rand_one_dut_hostname]
#     bgp_pass_config = Template(open("./bgp/templates/bgp_pass_config.json.j2").read())

#     duthost.copy(content=bgp_pass_config.render(BGP_BBR_STATUS='disabled'), dest='/tmp/disable_bbr.json')
#     duthost.copy(content=bgp_pass_config.render(BGP_BBR_STATUS='enabled'), dest='/tmp/enable_bbr.json')

#     yield

#     duthost.copy(src="./bgp/templates/del_bgp_bbr_config.json", dest='/tmp/del_bgp_bbr_config.json')
#     duthost.shell("configlet -d -j {}".format("/tmp/del_bgp_bbr_config.json"))

def test_bgp_peer_group_password(duthosts, rand_one_dut_hostname, enum_asic_index, nbrhosts, tbinfo):
    duthost=duthosts[rand_one_dut_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" -c "end"'.format(dut_asn, peer_group_v4, bgp_pass, peer_group_v6, bgp_pass)
    
    #Verify BGP neighbors are established before starting test case
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        assert v['state'] == 'established'
    
    tor_neighbors = natsorted([neighbor for neighbor in nbrhosts.keys() if neighbor.endswith('T0')])
    tor1 = tor_neighbors[0]

    # mg_facts = nbrhosts[tor1]["host"].get_extended_minigraph_facts(tbinfo)
    # logger.info(mg_facts)
    # neigh_peer_map = defaultdict(dict)
    # for bgp_neigh in mg_facts['minigraph_bgp']:
    #     name = bgp_neigh['name']
    #     peer_addr = bgp_neigh['peer_addr']
    #     if ipaddress.IPAddress(peer_addr).version == 4:
    #         neigh_peer_map[name].update({'peer_addr': peer_addr})
    #     else:
    #         neigh_peer_map[name].update({'peer_addr_v6': peer_addr})
    # logger.info(neigh_peer_map)

    command_output = duthost.shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False
    
    logger.info(duthost.shell('show run bgp'))

    # nbrhosts[tor1].shell('show run bgp')

    time.sleep(bgp_config_sleeptime)

    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are not established
        assert v['state'] != 'established'

    #set password on neighbor
    # tor_neighbors = natsorted([neighbor for neighbor in nbrhosts.keys() if neighbor.endswith('T0')])
    # tor1 = tor_neighbors[0]
    # tor1_offset = tbinfo['topo']['properties']['topology']['VMs'][tor1]
    # logger.info(tor1_offset)
    nbrhosts[tor1]["host"].eos_command(commands=["show run | section bgp"])
    cmd = ["neighbor {} password 0 {}".format(peer_group_v4, bgp_pass), "neighbor {} password 0 {}".format(peer_group_v6, bgp_pass)]
    logger.info(nbrhosts[tor1]["host"].eos_config(lines=cmd, parents="router bgp {}".format(neigh_asn))) #['stdout'][0]

    time.sleep(bgp_config_sleeptime)

    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp session to neighbors are established
        assert v['state'] == 'established'


    #mismatch peer group passwords
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" -c "end"'.format(dut_asn, peer_group_v4, mismatch_pass, peer_group_v6, mismatch_pass)
    
    command_output = duthost.shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False
    
    logger.info(duthost.shell('show run bgp'))

    time.sleep(bgp_config_sleeptime)

    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp session to neighbor is not established
        assert v['state'] != 'established'

    #turn off peer group passwords on DUT
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "no neighbor {} password {}" -c "no neighbor {} password {}" -c "end"'.format(dut_asn, peer_group_v4, mismatch_pass, peer_group_v6, mismatch_pass)
    
    command_output = duthost.shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False
    
    logger.info(duthost.shell('show run bgp'))

    #remove peer group passwords from neighbor
    cmd = ["no neighbor {} password 0 {}".format(peer_group_v4, bgp_pass), "no neighbor {} password 0 {}".format(peer_group_v6, bgp_pass)]
    nbrhosts[tor1]["host"].eos_config(lines=cmd, parents="router bgp {}".format(neigh_asn)) #['stdout'][0]

    time.sleep(bgp_config_sleeptime)
    
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        assert v['state'] == 'established'

def test_bgp_neighbor_password(duthosts, rand_one_dut_hostname, enum_asic_index, nbrhosts, tbinfo):
    duthost=duthosts[rand_one_dut_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    tor_neighbors = natsorted([neighbor for neighbor in nbrhosts.keys() if neighbor.endswith('T0')])
    tor1 = tor_neighbors[0]

    #verify sessions are established
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        assert v['state'] == 'established'
    
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" -c "end"'.format(dut_asn, neigh_ip_v4, bgp_pass, neigh_ip_v6, bgp_pass)
    
    command_output = duthost.shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False
    
    time.sleep(bgp_config_sleeptime)

    #verify sessions are not established
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        if(v['description'] == tor1):
            assert v['state'] != 'established'
        else:
            assert v['state'] == 'established'

    #configure password on neighbor
    cmd = ["neighbor {} password 0 {}".format(dut_ip_v4, bgp_pass), "neighbor {} password 0 {}".format(dut_ip_v6, bgp_pass)]
    nbrhosts[tor1]["host"].eos_config(lines=cmd, parents="router bgp {}".format(neigh_asn)) #['stdout'][0]

    time.sleep(bgp_config_sleeptime)
    
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        assert v['state'] == 'established'
 
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" -c "end"'.format(dut_asn, neigh_ip_v4, mismatch_pass, neigh_ip_v6, mismatch_pass)
    
    command_output = duthost.shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False
    
    time.sleep(bgp_config_sleeptime)

    #verify sessions are not established
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']

    logger.info(duthost.shell('show ip bgp summary'))
    logger.info(duthost.shell('show ipv6 bgp summary'))
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        if(v['description'] == tor1):
            assert v['state'] != 'established'
        else:
            assert v['state'] == 'established'

    #remove password configs
    cmd = 'vtysh -c "config" -c "router bgp {}" -c "no neighbor {} password {}" -c "no neighbor {} password {}" -c "end"'.format(dut_asn, neigh_ip_v4, mismatch_pass, neigh_ip_v6, mismatch_pass)
    
    command_output = duthost.shell(cmd, module_ignore_errors=True)

    if len(command_output["stdout_lines"]) != 0:
        logger.error("Error configuring BGP password")
        return False

    cmd = ["no neighbor {} password 0 {}".format(dut_ip_v4, bgp_pass), "no neighbor {} password 0 {}".format(dut_ip_v6, bgp_pass)]
    nbrhosts[tor1]["host"].eos_config(lines=cmd, parents="router bgp {}".format(neigh_asn)) #['stdout'][0]

    time.sleep(bgp_config_sleeptime)
    
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        # Verify bgp sessions are established
        assert v['state'] == 'established'