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
     pytest.mark.topology('any')
 ]


 def test_containercfgd(duthosts, enum_rand_one_per_hwsku_hostname):
     """
     @summary: Test if containercfgd is running in the syncd container
     """
     pattern = re.compile(r'syncd(\d+)')
     duthost = duthosts[enum_rand_one_per_hwsku_hostname]
     if duthost.is_multi_asic:
         pattern = re.compile(r'syncd(\d+)')
         container_output = duthost.command("docker ps -a | grep syncd")["stdout"].split("\n")
         containers = ["syncd" + str(pattern.search(line).group(1)) for line in container_output]
     else:
         containers = ["syncd"]
     for container in containers:
         result = duthost.command("docker restart %s" % (container))
         logging.info("Waiting for 120s, for all containers to be running")
         time.sleep(120)
         try:
             running_processes = duthost.command("docker exec -i syncd supervisorctl status containercfgd ")["stdout"]
         except:
             running_processes = ""
         logging.info(result)
         logging.info(running_processes)
         assert "RUNNING" in running_processes, "containercfgd has not been started in %s"%(container)

 def test_syslog_rate_limit(rand_selected_dut):
     """
     @summary: Test for syslog rate limit in the syncd container
     """
     # Copy tests/syslog/log_generator.py to DUT
     rand_selected_dut.copy(src=LOCAL_LOG_GENERATOR_FILE, dest=REMOTE_LOG_GENERATOR_FILE)
     skip_container_list = rand_selected_dut.command(r'docker ps --format \{\{.Names\}\}')["stdout_lines"]
     if rand_selected_dut.is_multi_asic:
         for container in skip_container_list:
             if container.startswith("syncd"):
                 skip_container_list.remove(container)
     else:
         skip_container_list.remove("syncd")
     verify_container_rate_limit(rand_selected_dut, skip_container_list)
     verify_host_rate_limit(rand_selected_dut)

     # Save configuration and reload, verify the configuration can be loaded
     logger.info('Persist syslog rate limit configuration to DB and do config reload')
     rand_selected_dut.command('config save -y')
     config_reload(rand_selected_dut)

     # database does not support syslog rate limit configuration persist
     verify_container_rate_limit(rand_selected_dut, ignore_containers=['database'])
     verify_host_rate_limit(rand_selected_dut)
 
