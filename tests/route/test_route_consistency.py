import pytest
import logging
import traceback
import re
import time
import math
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import get_program_info
from tests.common.config_reload import config_reload

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

def kill_process_by_pid(duthost, container_name, program_name, program_pid):
    """Kills a process in the specified container by its pid.

    Args:
        duthost: Hostname of DUT.
        container_name: A string shows container name.
        program_name: A string shows process name.
        program_pid: An integer represents the PID of a process.

    Returns:
        None.
    """
    if "20191130" in duthost.os_version:
        kill_cmd_result = duthost.shell("docker exec {} supervisorctl stop {}".format(container_name, program_name))
    else:
        # If we used the command `supervisorctl stop <proc_name>' to stop process,
        # Supervisord will treat the exit code of process as expected and it will not generate
        # alerting message.
        kill_cmd_result = duthost.shell("docker exec {} kill -SIGKILL {}".format(container_name, program_pid))

    # Get the exit code of 'kill' or 'supervisorctl stop' command
    exit_code = kill_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to stop program '{}' before test".format(program_name))

    logger.info("Program '{}' in container '{}' was stopped successfully"
                .format(program_name, container_name))


def check_and_kill_process(duthost, container_name, program_name):
    """Checks the running status of a critical process. If it is running, kill it. Otherwise,
       fail this test.

    Args:
        duthost: Hostname of DUT.
        container_name: A string shows container name.
        program_name: A string shows process name.
        program_pid: An integer represents the PID of a process.

    Returns:
        None.
    """
    program_status, program_pid = get_program_info(duthost, container_name, program_name)
    if program_status == "RUNNING":
        kill_process_by_pid(duthost, container_name, program_name, program_pid)
    elif program_status in ["EXITED", "STOPPED", "STARTING"]:
        pytest.fail("Program '{}' in container '{}' is in the '{}' state, expected 'RUNNING'"
                    .format(program_name, container_name, program_status))
    else:
        pytest.fail("Failed to find program '{}' in container '{}'"
                    .format(program_name, container_name))


class TestRouteConsistency():
    """ TestRouteConsistency class for testing route consistency across all the Frontend DUTs in the testbed
        It verifies route consistency by taking a snapshot of route table from ASIC_DB from all the DUTs before the test
        and then comparing the snapshot of route table from all the DUTs after the test.
    """

    def extract_dest_ips(self, route_entries):
        dest_ips = set()
        pattern = r'"dest":"(.*?)"'
        for entry in route_entries:
            matches = re.findall(pattern, entry)
            dest_ips.update(matches)
        return dest_ips

    def get_route_prefix_snapshot_from_asicdb(self, duthosts):
        prefix_snapshot = {}
        max_prefix_cnt = 0
        for idx, dut in enumerate(duthosts.frontend_nodes):
            for asic in dut.asics:
                dut_instance_name = dut.hostname + '-' + str(asic.asic_index)
                if dut.facts['switch_type'] == "voq" and idx == 0:
                    dut_instance_name = dut_instance_name + "UpstreamLc"
                prefix_snapshot[dut_instance_name] = \
                    set(self.extract_dest_ips(asic.run_sonic_db_cli_cmd('ASIC_DB KEYS *ROUTE_ENTRY*')['stdout_lines']))
                logger.debug("snapshot of route table from {}: {}".format(dut_instance_name,
                                                                          len(prefix_snapshot[dut_instance_name])))
                max_prefix_cnt = max(max_prefix_cnt, len(prefix_snapshot[dut_instance_name]))
        return prefix_snapshot, max_prefix_cnt

    @pytest.fixture(scope="class", autouse=True)
    def setup(self, duthosts):
        # take the snapshot of route table from all the DUTs
        self.__class__.pre_test_route_snapshot, max_prefix_cnt = self.get_route_prefix_snapshot_from_asicdb(duthosts)
        """sleep interval is calculated based on the max number of prefixes in the route table.
           Addtional 120 seconds is added to the sleep interval to account for the time taken to
           withdraw and advertise the routes by peers.
        """
        self.__class__.sleep_interval = math.ceil(max_prefix_cnt/3000) + 120
        logger.info("max_no_of_prefix: {} sleep_interval: {}".format(max_prefix_cnt, self.sleep_interval))

    def test_route_withdraw_advertise(self, duthosts, tbinfo, localhost):

        # withdraw the routes
        ptf_ip = tbinfo["ptf_ip"]
        topo_name = tbinfo["topo"]["name"]

        try:
            logger.info("withdraw ipv4 and ipv6 routes for {}".format(topo_name))
            localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="withdraw", path="../ansible/")
            time.sleep(self.sleep_interval)

            """ compare the number of routes withdrawn from all the DUTs. In working condition, the number of routes
                withdrawn should be same across all the DUTs.
                On VOQ Upstream LC's will have same route and Downstream LC will have same route.
                Note: this will be noop for single asic pizzabox duts
            """
            post_withdraw_route_snapshot, _ = self.get_route_prefix_snapshot_from_asicdb(duthosts)
            num_routes_withdrawn = 0
            num_routes_withdrawn_upstream_lc = 0
            for dut_instance_name in self.pre_test_route_snapshot.keys():
                if num_routes_withdrawn == 0 and not dut_instance_name.endswith("UpstreamLc"):
                    num_routes_withdrawn = len(self.pre_test_route_snapshot[dut_instance_name] -
                                               post_withdraw_route_snapshot[dut_instance_name])
                    logger.debug("num_routes_withdrawn: {}".format(num_routes_withdrawn))
                elif num_routes_withdrawn_upstream_lc == 0 and dut_instance_name.endswith("UpstreamLc"):
                    num_routes_withdrawn_upstream_lc = len(self.pre_test_route_snapshot[dut_instance_name] -
                                                           post_withdraw_route_snapshot[dut_instance_name])
                else:
                    if dut_instance_name.endswith("UpstreamLc"):
                        assert num_routes_withdrawn_upstream_lc == len(self.pre_test_route_snapshot[dut_instance_name] -
                                                                       post_withdraw_route_snapshot[dut_instance_name])
                    else:
                        assert num_routes_withdrawn == len(self.pre_test_route_snapshot[dut_instance_name] -
                                                           post_withdraw_route_snapshot[dut_instance_name])

            logger.info("advertise ipv4 and ipv6 routes for {}".format(topo_name))
            localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="announce", path="../ansible/")
            time.sleep(self.sleep_interval)

            # take the snapshot of route table from all the DUTs
            post_test_route_snapshot, _ = self.get_route_prefix_snapshot_from_asicdb(duthosts)
            """ compare the snapshot of route table from all the DUTs. In working condition, the snapshot of
                route table should be same across all the DUTs"""
            for dut_instance_name in self.pre_test_route_snapshot.keys():
                assert self.pre_test_route_snapshot[dut_instance_name] == post_test_route_snapshot[dut_instance_name]
            logger.info("Route table is consistent across all the DUTs")
        except Exception as e:
            logger.error("Exception occurred: {}".format(e))
            # announce the routes back in case of any exception
            localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="announce", path="../ansible/")
            time.sleep(self.sleep_interval)
            raise e

    def test_bgp_shut_noshut(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, localhost):
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        logger.info("test_bgp_shut_noshut: DUT{}".format(duthost.hostname))

        try:
            logger.info("shutdown bgp sessions for {}".format(duthost.hostname))
            duthost.shell("sudo config bgp shutdown all")
            time.sleep(self.sleep_interval)

            post_withdraw_route_snapshot, _ = self.get_route_prefix_snapshot_from_asicdb(duthosts)
            num_routes_withdrawn = 0
            for dut_instance_name in self.pre_test_route_snapshot.keys():
                if num_routes_withdrawn == 0:
                    num_routes_withdrawn = len(self.pre_test_route_snapshot[dut_instance_name] -
                                               post_withdraw_route_snapshot[dut_instance_name])
                    logger.debug("num_routes_withdrawn: {}".format(num_routes_withdrawn))
                else:
                    assert num_routes_withdrawn == len(self.pre_test_route_snapshot[dut_instance_name] -
                                                       post_withdraw_route_snapshot[dut_instance_name])

            logger.info("startup bgp sessions for {}".format(duthost.hostname))
            duthost.shell("sudo config bgp startup all")
            time.sleep(self.sleep_interval)

            # take the snapshot of route table from all the DUTs
            post_test_route_snapshot, _ = self.get_route_prefix_snapshot_from_asicdb(duthosts)
            for dut_instance_name in self.pre_test_route_snapshot.keys():
                assert self.pre_test_route_snapshot[dut_instance_name] == post_test_route_snapshot[dut_instance_name]
            logger.info("Route table is consistent across all the DUTs")
        except Exception:
            # startup bgp back in case of any exception
            duthost.shell("sudo config bgp startup all")
            time.sleep(self.sleep_interval)

    @pytest.mark.disable_loganalyzer
    def test_bgpd_crash_and_recover(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        logger.info("test_bgp_crash_and_recover: DUT{}".format(duthost.hostname))

        namespace_ids, succeeded = duthost.get_namespace_ids("bgp")
        pytest_assert(succeeded, "Failed to get namespace ids of container '{}'".format("bgp"))
        logger.info("namespace_ids: {}".format(namespace_ids))

        try:
            logger.info("kill bgpd(s) for {}".format(duthost.hostname))
            for id in namespace_ids:
                if id == None:
                    id = ""
                check_and_kill_process(duthost, "bgp" + str(id), "bgpd")
            time.sleep(30)

            post_withdraw_route_snapshot, _ = self.get_route_prefix_snapshot_from_asicdb(duthosts)
            num_routes_withdrawn = 0
            for dut_instance_name in self.pre_test_route_snapshot.keys():
                if num_routes_withdrawn == 0:
                    num_routes_withdrawn = len(self.pre_test_route_snapshot[dut_instance_name] -
                                               post_withdraw_route_snapshot[dut_instance_name])
                    logger.info("num_routes_withdrawn: {}".format(num_routes_withdrawn))
                else:
                    assert num_routes_withdrawn == len(self.pre_test_route_snapshot[dut_instance_name] -
                                                       post_withdraw_route_snapshot[dut_instance_name])

            logger.info("start bgpd for {}".format(duthost.hostname))
            for id in namespace_ids:
                if id == None:
                    id = ""
                duthost.shell("docker exec {} supervisorctl start {}".format("bgp" + str(id), "bgpd"))
                duthost.shell("docker exec {} supervisorctl restart {}".format("bgp" + str(id), "bgpcfgd"))
            time.sleep(self.sleep_interval)

            # take the snapshot of route table from all the DUTs
            post_test_route_snapshot, _ = self.get_route_prefix_snapshot_from_asicdb(duthosts)
            for dut_instance_name in self.pre_test_route_snapshot.keys():
                assert self.pre_test_route_snapshot[dut_instance_name] == post_test_route_snapshot[dut_instance_name]
            logger.info("Route table is consistent across all the DUTs")
        except Exception:
            # startup bgpd back in case of any exception
            logger.info(traceback.format_exc())
            config_reload(duthost)
            time.sleep(self.sleep_interval)

    @pytest.mark.disable_loganalyzer
    def test_syncd_crash_and_recover(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        logger.info("test_syncd_crash_and_recover: DUT{}".format(duthost.hostname))

        namespace_ids, succeeded = duthost.get_namespace_ids("syncd")
        pytest_assert(succeeded, "Failed to get namespace ids of container '{}'".format("syncd"))
        logger.info("namespace_ids: {}".format(namespace_ids))
        # for id in namespace_ids:
        #     if id == None:
        #         id = ""
        #     duthost.shell("sudo config feature autorestart {} disabled".format("syncd" + str(id)))
        #     logger.info(duthost.shell("show feature status"))

        try:
            logger.info("kill syncd(s) for {}".format(duthost.hostname))
            for id in namespace_ids:
                if id == None:
                    id = ""
                check_and_kill_process(duthost, "syncd" + str(id), "syncd")
            time.sleep(30)

            post_withdraw_route_snapshot, _ = self.get_route_prefix_snapshot_from_asicdb(duthosts)
            num_routes_withdrawn = 0
            for dut_instance_name in self.pre_test_route_snapshot.keys():
                if num_routes_withdrawn == 0:
                    num_routes_withdrawn = len(self.pre_test_route_snapshot[dut_instance_name] -
                                               post_withdraw_route_snapshot[dut_instance_name])
                    logger.info("num_routes_withdrawn: {}".format(num_routes_withdrawn))
                else:
                    assert num_routes_withdrawn == len(self.pre_test_route_snapshot[dut_instance_name] -
                                                       post_withdraw_route_snapshot[dut_instance_name])

            logger.info("Sleep and wait for syncd autorestart on {}".format(duthost.hostname))
            time.sleep(self.sleep_interval)

            # take the snapshot of route table from all the DUTs
            post_test_route_snapshot, _ = self.get_route_prefix_snapshot_from_asicdb(duthosts)
            for dut_instance_name in self.pre_test_route_snapshot.keys():
                assert self.pre_test_route_snapshot[dut_instance_name] == post_test_route_snapshot[dut_instance_name]
            logger.info("Route table is consistent across all the DUTs")
        except Exception:
            # startup bgpd back in case of any exception
            logger.info("Encountered error. Perform a config reload to recover!")
            config_reload(duthost)
            time.sleep(self.sleep_interval)

    @pytest.mark.disable_loganalyzer
    def test_orchagent_crash_and_recover(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        logger.info("test_orchagent_crash_and_recover: DUT{}".format(duthost.hostname))

        namespace_ids, succeeded = duthost.get_namespace_ids("swss")
        pytest_assert(succeeded, "Failed to get namespace ids of container '{}'".format("swss"))
        logger.info("namespace_ids: {}".format(namespace_ids))
        # for id in namespace_ids:
        #     if id == None:
        #         id = ""
        #     duthost.shell("sudo config feature autorestart {} disabled".format("syncd" + str(id)))
        #     logger.info(duthost.shell("show feature status"))

        try:
            logger.info("kill orchagent(s) for {}".format(duthost.hostname))
            for id in namespace_ids:
                if id == None:
                    id = ""
                check_and_kill_process(duthost, "swss" + str(id), "orchagent")
            time.sleep(30)

            post_withdraw_route_snapshot, _ = self.get_route_prefix_snapshot_from_asicdb(duthosts)
            num_routes_withdrawn = 0
            for dut_instance_name in self.pre_test_route_snapshot.keys():
                if num_routes_withdrawn == 0:
                    num_routes_withdrawn = len(self.pre_test_route_snapshot[dut_instance_name] -
                                               post_withdraw_route_snapshot[dut_instance_name])
                    logger.info("num_routes_withdrawn: {}".format(num_routes_withdrawn))
                else:
                    assert num_routes_withdrawn == len(self.pre_test_route_snapshot[dut_instance_name] -
                                                       post_withdraw_route_snapshot[dut_instance_name])

            logger.info("Sleep and wait for swss autorestart on {}".format(duthost.hostname))
            time.sleep(self.sleep_interval)

            # take the snapshot of route table from all the DUTs
            post_test_route_snapshot, _ = self.get_route_prefix_snapshot_from_asicdb(duthosts)
            for dut_instance_name in self.pre_test_route_snapshot.keys():
                assert self.pre_test_route_snapshot[dut_instance_name] == post_test_route_snapshot[dut_instance_name]
            logger.info("Route table is consistent across all the DUTs")
        except Exception:
            # startup bgpd back in case of any exception
            logger.info("Encountered error. Perform a config reload to recover!")
            config_reload(duthost)
            time.sleep(self.sleep_interval)
                    