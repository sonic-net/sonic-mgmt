import logging
import time
import paramiko
import sys
import pytest
import re

from tests.common.reboot import logger

from tests.common.helpers.assertions import pytest_assert

from scp import SCPClient, SCPException

from tests.common.utilities import wait_tcp_connection

from .ixanvl_utils import emit_intf_block
from .ixanvl_utils import emit_global_block
from .ixanvl_utils import emit_bgp_global
from .ixanvl_utils import delete_tmp_file
from .ixanvl_utils import create_json_output

pytestmark = [pytest.mark.disable_loganalyzer]

max_bgp_interfaces = 3

@pytest.fixture()
def testnum(pytestconfig):
    return pytestconfig.getoption("testnum")

def increment_ipv4_octet(ipv4_addr, octet=2):
    octets = str(ipv4_addr).split('.')
    third_octet = int(octets[octet])
    third_octet += 1
    octets[octet] = str(third_octet)
    return '.'.join(octets)

def test_anvl_bgp_run(duthost,
                      ptfhost,
                      tbinfo,
                      testnum):
    """
	    1. ANVL run.
    """

    topology = tbinfo["topo"]["properties"]["topology"]

    ptfip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']

    ptfuser = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_user']
    ptfpass = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_password']
    ptf_lic_server = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['license_server']

    logging.info("ixanvl container ip=%s" % ptfip)
    logging.info("ixanvl container ip=%s" % ptfuser)
    logging.info("ixanvl container ip=%s" % ptfpass)
    logging.info("ixanvl container lic_server =%s" % ptf_lic_server)

    testnumber = testnum

    duthost.shell("vtysh -c 'configure terminal' -c 'no router bgp'", module_ignore_errors=True)

    #Copy .prm file to /tmp/ixanvl location
    ptfhost.command("cp /opt/Ixia/IxANVL/DocUser/anvlbgp4.prm /tmp/anvl.prm")

    # Create .cfg file global block
    emit_global_block(ptfhost, duthost, ptf_lic_server, "30.0.0.0", "255.255.255.0")

    emit_bgp_global(ptfhost, 500)

    # Create .cfg file interfaces

    # Intf 
    for index in range(max_bgp_interfaces):
        ptf_intf = "eth{}".format(topology['host_interfaces'][index])
        ip_anvl_addr = "20.0.{}.20".format(topology['host_interfaces'][index])
        ip_dut_addr = "20.0.{}.10".format(topology['host_interfaces'][index])
        emit_intf_block(ptfhost, ptf_intf, ip_anvl_addr, ip_dut_addr, "255.255.255.0")
    

    logging.info("run anvl with static configuration")
    ixanvl_tester=paramiko.SSHClient()
    ##Add missing client key
    ixanvl_tester.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ##connect to ptf
    ixanvl_tester.connect(ptfip,username=ptfuser,password=ptfpass)
    logging.info("SSH connection to %s established" % ptfip)


    scp = SCPClient(ixanvl_tester.get_transport())

    ##Gather commands and read the output from stdout
    if not testnumber:
        logging.info("================= Running ANVL BGP Full Suite ===============\n")
        command_str = "cd /opt/Ixia/IxANVL && ./anvl -l l -f /tmp/anvl bgp4 | tee bgp4.log\n"
    else:
        logging.info("================= Running ANVL BGP Test Case %s ===============\n" % testnumber)
        command_str = "cd /opt/Ixia/IxANVL && ./anvl -l l -f /tmp/anvl bgp4 " + testnumber + " | tee bgp4.log\n"

    stdin, stdout, stderr = ixanvl_tester.exec_command(command_str)

    for line in stdout:
      logging.info(line)

    stdout.channel.recv_exit_status()
    delete_tmp_file(ptfhost)
    scp.get('/opt/Ixia/IxANVL/bgp4.log')

    create_json_output('bgp4.log')
    ixanvl_tester.close()
