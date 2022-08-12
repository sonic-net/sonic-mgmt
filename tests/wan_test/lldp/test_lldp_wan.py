import re
import json
import logging
import pytest
import pprint


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('wan'),
    pytest.mark.sanity_check(skip_sanity=True)
]


@pytest.fixture(scope="module", autouse="True")
def lldp_setup(duthosts, rand_one_dut_hostname, patch_lldpctl, unpatch_lldpctl, localhost):
    duthost = duthosts[rand_one_dut_hostname]
    patch_lldpctl(localhost, duthost)
    yield
    unpatch_lldpctl(localhost, duthost)


def test_lldp(duthosts, rand_one_dut_hostname, localhost, collect_techsupport_all_duts, enum_frontend_asic_index):
    """ verify the LLDP message on DUT """
    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthost.asic_instance(enum_frontend_asic_index).config_facts(host=duthost.hostname, source="running")['ansible_facts']
    lldpctl_facts = duthost.lldpctl_facts(asic_instance_id=enum_frontend_asic_index, skip_interface_pattern_list=["eth0", "Ethernet-BP", "Ethernet-IB"])['ansible_facts']
    if not lldpctl_facts['lldpctl'].items():
        pytest.fail("No LLDP neighbors received (lldpctl_facts are empty)")
    for k, v in lldpctl_facts['lldpctl'].items():
        # Compare the LLDP neighbor name with minigraph neigbhor name (exclude the management port)
        assert v['chassis']['name'] == config_facts['DEVICE_NEIGHBOR'][k]['name']
        # Compare the LLDP neighbor interface with minigraph neigbhor interface (exclude the management port)
        #assert v['port']['local'] == config_facts['DEVICE_NEIGHBOR'][k]['port']

def find_dut(dutname, dut_collection):
    for k, dutlist in dut_collection.items():
        for dut in dutlist:
            if dutname == dut.hostname:
                return k, dut

def test_lldp_neighbor(duthosts, rand_one_dut_hostname, dut_collection, enum_frontend_asic_index, capsys):
    """ verify the LLDP message with neighbor device """

    duthost = duthosts[rand_one_dut_hostname]
    lldpctl_facts = duthost.lldpctl_facts(asic_instance_id=enum_frontend_asic_index, skip_interface_pattern_list=["eth0", "Ethernet-BP", "Ethernet-IB"])['ansible_facts']

    if not lldpctl_facts['lldpctl'].items():
        pytest.fail("No LLDP neighbors received (lldpctl_facts are empty)")

    for _, v in lldpctl_facts['lldpctl'].items():
        image, nbr_dut = find_dut(v['chassis']['name'], dut_collection)
        if nbr_dut is None:
            pytest.fail("dut_collection would not find dut:{}.".format(v['chassis']['name']))

        if image == 'cisco':
            assert nbr_dut.get_lldp_neighbor(rand_one_dut_hostname, v['port']['ifname'])
        elif image == 'arista':
            facts = nbr_dut.get_lldp_neighbor(v['port']['ifname'])
            # with capsys.disabled():
            #     pprint.pprint('arista device {}, lldp neighbor information: '.format(v['chassis']['name']))
            #     print(json.dumps(facts, indent=4))
            assert len(list(filter(lambda elem: elem['neighborDevice'] == rand_one_dut_hostname, facts['lldpNeighbors']))) > 0
        elif image == 'sonic':
            output = nbr_dut.command('show lldp table')
            pprint.pprint(output['stdout_lines'])
            pattern = rand_one_dut_hostname +'\s+' + v['port']['local']
            assert re.search(str(pattern), str(output['stdout_lines']))
        else:
            pytest.fail("Not supported image: {}, hostname :{}.".format(image, v['chassis']['name']))
