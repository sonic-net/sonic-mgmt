import logging
import time
import paramiko
import sys
import pytest
import re

from tests.common.reboot import logger
from tests.common.fixtures.conn_graph_facts import conn_graph_facts

from tests.common.helpers.assertions import pytest_assert

from scp import SCPClient, SCPException

from tests.common.utilities import wait_tcp_connection

pytestmark = [pytest.mark.disable_loganalyzer]

@pytest.fixture()
def testnum(pytestconfig):
    return pytestconfig.getoption("testnum")

def test_anvl_bgp_run(duthost,
                      ptfhost,
                      testnum):
    """
	    1. ANVL run.
    """


    ptfip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']

    ptfuser = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_user']
    ptfpass = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_password']

    logging.info("ixanvl container ip=%s" % ptfip)
    logging.info("ixanvl container ip=%s" % ptfuser)
    logging.info("ixanvl container ip=%s" % ptfpass)

    testnumber = testnum
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
        command_str = "cd /opt/Ixia/IxANVL && ./anvl -l l -f DocUser/anvlbgp4 bgp4 | tee bgp4.log\n"
    else:
        logging.info("================= Running ANVL BGP Test Case %s ===============\n" % testnumber)
        command_str = "cd /opt/Ixia/IxANVL && ./anvl -l l -f DocUser/anvlbgp4 bgp4 " + testnumber + " | tee bgp4.log\n"

    stdin, stdout, stderr = ixanvl_tester.exec_command(command_str)

    for line in stdout:
      logging.info(line)

    stdout.channel.recv_exit_status()
    scp.get('/opt/Ixia/IxANVL/bgp4.log')

    ixanvl_tester.close()
