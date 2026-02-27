"""
Tests for the supervisord processes in SONiC
"""
import re
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.syslog.test_syslog_rate_limit import verify_container_rate_limit, verify_host_rate_limit, LOCAL_LOG_GENERATOR_FILE, REMOTE_LOG_GENERATOR_FILE
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
    pytest.mark.topology('any')
]

@pytest.fixture(autouse=True, scope="module")
def enable_syslog_rate_limit_feature(rand_selected_dut):
    output = rand_selected_dut.command('config syslog --help', module_ignore_errors=True)['stdout']
    feature_supported = 'rate-limit-feature' in output
    
    if feature_supported:
        logger.info("Enabling syslog rate-limit-feature before tests")
        # in 202305, the feature is disabled by default for warmboot/fastboot
        # performance, need manually enable it via command
        rand_selected_dut.command('config syslog rate-limit-feature enable')
        time.sleep(5)  
    
    yield
    
    if feature_supported:
        logger.info("Disabling syslog rate-limit-feature after tests")
        rand_selected_dut.command('config syslog rate-limit-feature disable', module_ignore_errors=True)

def check_for_syncd(duthost):
    """
    @summary: Checks every 30s if the syncd container is up - waits upto 7 minutes, returns false if still not running
    """
    container_output = duthost.command(r'docker ps --format \{\{.Names\}\}')["stdout"]
    check_syncd = "syncd\n" in container_output or "\nsyncd" in container_output
    attempt = 1

    if duthost.is_multi_asic:
        pattern = re.compile(r'syncd(\d+)')
        container_output = duthost.command("docker ps -a | grep syncd")["stdout"].split("\n")
        containers = ["syncd" + str(pattern.search(line).group(1)) for line in container_output]
    else:
        containers = ["syncd"]
    for container in containers:
        logging.info("Restarting syncd container ..")
        result = duthost.command("docker restart %s" % (container))

    while not check_syncd and attempt <= 8:
        logging.info("Waiting for 30s ...")
        time.sleep(30)
        logging.info("Checking again for syncd")
        container_output = duthost.command(r'docker ps --format \{\{.Names\}\}')["stdout"]
        check_syncd = "syncd\n" in container_output or "\nsyncd" in container_output
        attempt += 1
    return check_syncd

def test_containercfgd(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Test if containercfgd is running in the syncd container
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    syncd_status = check_for_syncd(duthost)
    assert syncd_status, "Syncd container not running after waiting 7 minutes"

    pattern = re.compile(r'syncd(\d+)')
    if duthost.is_multi_asic:
        pattern = re.compile(r'syncd(\d+)')
        container_output = duthost.command("docker ps -a | grep syncd")["stdout"].split("\n")
        containers = ["syncd" + str(pattern.search(line).group(1)) for line in container_output]
    else:
        containers = ["syncd"]
    for container in containers:
        check = False
        attempt = 1
        while not check and attempt <= 2:
            logging.info("Restarting syncd container: %s (attempt %d)", container, attempt)
            result = duthost.command("docker restart %s" % (container))
            time.sleep(120)
            check = check_for_syncd(duthost)
            attempt += 1
        assert check, "Unable to start syncd, test cannot be run"
        time.sleep(30)
        try:
            running_processes = duthost.command("docker exec -i %s supervisorctl status containercfgd" % container)["stdout"]
            logging.info("containercfgd status in %s: %s", container, running_processes)
        except Exception as e:
            running_processes = ""
            logging.error("Exception while checking containercfgd in %s: %s", container, str(e))
        
        assert "RUNNING" in running_processes, "containercfgd has not been started in %s" % (container)

def test_syslog_rate_limit(rand_selected_dut):
    """
    @summary: Test for syslog rate limit in the syncd container
    """
    syncd_status = check_for_syncd(rand_selected_dut)
    assert syncd_status, "Syncd container not running after waiting 7 minutes"

    # Copy tests/syslog/log_generator.py to DUT
    rand_selected_dut.copy(src=LOCAL_LOG_GENERATOR_FILE, dest=REMOTE_LOG_GENERATOR_FILE)
    
    feature_data = rand_selected_dut.show_and_parse('show feature status')
    all_features = [item['feature'] for item in feature_data]
    
    skip_feature_list = []
    if rand_selected_dut.is_multi_asic:
        skip_feature_list = [f for f in all_features if not f.startswith("syncd")]
    else:
        skip_feature_list = [f for f in all_features if f != "syncd"]
    
    verify_container_rate_limit(rand_selected_dut, skip_feature_list)
    verify_host_rate_limit(rand_selected_dut)
    rand_selected_dut.command('config save -y')
    config_reload(rand_selected_dut)
    rand_selected_dut.command('config syslog rate-limit-feature enable', module_ignore_errors=True)
    time.sleep(5)

    # database does not support syslog rate limit configuration persist
    verify_container_rate_limit(rand_selected_dut, skip_feature_list)
    verify_host_rate_limit(rand_selected_dut)