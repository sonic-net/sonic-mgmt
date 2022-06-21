import logging
import pytest
import time

# CONFIG_PATH = '/var/tmp/'
# BASE_DIR = os.path.dirname(os.path.realpath(__file__))
# TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
# ISIS_TEMPLATE = 'isis_config.j2'

# logger = logging.getLogger(__name__)

# def recover_isis_config(duthosts):
#     """ recover isis configuration """
#     isis_vars = {
#          "primary_authentication_key":"rightpass",
#          "primary_authentication_type":"hmac-md5" 
#     }

#     for duthost in duthosts.nodes:
#        duthost.command("mkdir -p {}".format(CONFIG_PATH))
    
#        isis_config = 'isis_config.json'
#        isis_config_path = os.path.join(CONFIG_PATH, isis_config)
#        duthost.host.options['variable_manager'].extra_vars.update(isis_vars)

#        duthost.template(src=os.path.join(TEMPLATE_DIR, ISIS_TEMPLATE), dest=isis_config_path)
#        duthost.command('sonic-cfggen -j {} --write-to-db'.format(isis_config_path))  


# @pytest.fixture(scope="module")
# def common_setup_teardown(ptfhost, duthosts):
#     """clean up configure"""
#     yield None
    
#     #Recover PTF interface and route table
#     ptfhost.shell("""
#                     ip netns exec net1 ip link set dev eth1 netns 1
#                     ip netns del net1
#                     ip link set eth1 up
#                     ip addr del 10.0.0.57 dev eth0
#                     ip route del 10.0.4.0/24 via 10.0.0.56 dev eth0 
#                     """, module_ignore_errors=True)
    
#     recover_isis_config(duthosts)


@pytest.fixture(scope="module")
def dut_collection(duthosts, enum_frontend_asic_index, cisco, arista):
    duts = {}
    dutlist = []
    for duthost in duthosts:
        config_facts = duthost.asic_instance(enum_frontend_asic_index).config_facts(host=duthost.hostname, source="running")['ansible_facts']
        for _, v in config_facts['DEVICE_NEIGHBOR'].items():
            if v['name'] not in dutlist:
                dutlist.append(v['name'])

    duts['sonic'] = [duthost for duthost in duthosts if duthost.hostname in dutlist]
    duts['cisco'] = [duthost for duthost in cisco if duthost.hostname in dutlist]
    duts['arista'] = [duthost for duthost in arista if duthost.hostname in dutlist]

    return duts

