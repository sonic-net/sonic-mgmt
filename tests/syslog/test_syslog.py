import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

@pytest.fixture(scope="module")
def config_syslog_srv(ptfhost):
    logger.info( "Configuring the syslog server")

    # add the imudp configuration if not present
    ptfhost.shell('sed -ni \'/module/!p;$a module(load="imudp")\' /etc/rsyslog.conf')
    ptfhost.shell('sed -i \'/input(type/!p;$a input(type="imudp" port="514")\' /etc/rsyslog.conf')

    #Remove local /var/log/syslog   
    ptfhost.shell("rm -rf /var/log/syslog")

    #restart Syslog Daemon 
    ptfhost.shell("service rsyslog restart")

    #Wait a little bit for service to start
    time.sleep(30)

    yield

@pytest.fixture(scope="module")
def config_dut(testbed, duthost):
    logger.info( "Configuring the DUT")
    local_syslog_srv_ip = testbed['ptf_ip']
    logger.info("test_syslog_srv_ip {}".format(local_syslog_srv_ip))
    
    #Add Rsyslog destination for testing
    duthost.shell("sudo config syslog add {}".format(local_syslog_srv_ip))

    yield

    #remove the syslog configuration
    duthost.shell("sudo config syslog del {}".format(local_syslog_srv_ip))

def test_syslog(duthost, ptfhost, config_dut, config_syslog_srv):
    logger.info( "Starting syslog tests")
    test_message = "Basic Test Message"
    
    #generate a syslog from the DUT
    duthost.shell(" logger --priority INFO {}".format(test_message))

    #Check syslog messages for the test message
    result = ptfhost.shell("grep {} /var/log/syslog | grep \"{}\" | grep -v ansible".format(duthost.hostname, test_message))['stdout_lines']
    pytest_assert(len(result) > 0, "Test syslog not seen on the server")


    


    


