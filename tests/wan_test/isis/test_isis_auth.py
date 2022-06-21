import logging
import pytest
import pprint
import re
import time


logger = logging.getLogger(__name__)

pytestmark = [
   pytest.mark.topology('wan'),
   pytest.mark.sanity_check(skip_sanity=True)
]

CONFIG_PATH = '/var/tmp/'
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
ISIS_TEMPLATE = 'isis_config.j2'

def isis_config_auth(duthost, auth_key):
   """ test jinja2 template to generate configuration """
   duthost.command("mkdir -p {}".format(CONFIG_PATH))

   isis_vars = {}
   isis_config = 'isis_config.json'
   isis_config_path = os.path.join(CONFIG_PATH, isis_config)
   if (auth_key is None):
      isis_vars['primary_authentication_key'] = 'None'
      isis_vars['primary_authentication_type'] = 'None'
   else:
      isis_vars['primary_authentication_key'] = auth_key
      isis_vars['primary_authentication_type'] = 'hmac-md5'

   duthost.host.options['variable_manager'].extra_vars.update(isis_vars)
   duthost.template(src=os.path.join(TEMPLATE_DIR, ISIS_TEMPLATE), dest=isis_config_path)
   duthost.command('sonic-cfggen -j {} --write-to-db'.format(isis_config_path))


def test_isis_auth_same(dut_collection, cisco, capsys):
   """test on authentication key is same, 
      expected neighbor status is up, and route is populated"""

   auth_key = 'rightpass'
   for k, dutlist in dut_collection.items():
      for dut in dutlist:
         if k == 'sonic':
            isis_config_auth(dut, auth_key)
         else:
            dut.isis_config_auth(auth_key)

   time.sleep(20)
   assert(cisco[0].ping_dest('10.0.4.57') == True)


def test_isis_auth_diff(dut_collection, rand_selected_dut, cisco, capsys):
   """test on authentication key is different, expected isis neighbor status is down,
   traffic can not pass through"""

   auth_key = 'wrongpass'
   isis_config_auth(rand_selected_dut, auth_key)

   time.sleep(20)
   assert(cisco[0].ping_dest('10.0.4.57') == False)


def test_isis_auth_revert(dut_collection, rand_selected_dut, cisco, capsys):
   """test on authentication key is same, 
      expected neighbor status is up, and route is populated"""

   auth_key = 'rightpass'
   isis_config_auth(rand_selected_dut, auth_key)

   time.sleep(20)
   assert(cisco[0].ping_dest('10.0.4.57') == True)


def test_isis_auth_delete(dut_collection, cisco, capsys):
   """test on authentication key is removed, expected isis neighbor status is up,
      traffic can pass through"""

   auth_key = 'rightpass'
   for k, dutlist in dut_collection.items():
      for dut in dutlist:
         if k == 'sonic':
            isis_config_auth(dut, None)
         else:
            dut.isis_remove_auth(auth_key)

   time.sleep(20)
   assert(cisco[0].ping_dest('10.0.4.57') == True)


def ping_traffic(ptfhost):
    """ test traffic from ptf passthrough dut """
    
    #configure interface address
    ptfhost.shell("""ifconfig eth0 10.0.0.57/32 up  
                    ip route add 10.0.0.56/31 dev eth0
                    ip route add 10.0.4.0/24 nexthop via 10.0.0.56 dev eth0
                    """, module_ignore_errors=True)

    #configure netns and add another ptf interface into it
    ptfhost.shell("""
                    ip netns add net1
                    ip link set dev eth1 netns net1
                    ip netns exec net1 ifconfig eth1 10.0.0.59 up 
                    ip netns exec net1 ip route add 10.0.0.58/31 dev eth1
                    ip netns exec net1 ip route add 10.0.4.0/24 nexthop via 10.0.0.58 dev eth1
                    """, module_ignore_errors=True)
     
    #test ping traffic
    return ptfhost.command("ping 10.0.4.57 -c 10")


def test_operation_on_host(duthosts):
    for node in duthosts.nodes:
        node.command("mkdir -p {}".format("/var/tmp/tony/"))


def test_copy_on_host(duthosts):
    for node in duthosts.nodes:
        isis_config = 'isis_config.j2'
        isis_config_path = os.path.join(TEMPLATE_DIR, isis_config)
        node.copy(src=isis_config_path, dest='/var/tmp')
