import pytest
import logging
import threading
import queue
import re
import time
import math
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import get_program_info
from tests.common.config_reload import config_reload
from tests.common.utilities import kill_process_by_pid

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


def check_and_kill_process(duthost, container_name, program_name):
    """Checks the running status of a critical process. If it is running, kill it. Otherwise,
       fail this test.

    Args:
        duthost: Hostname of DUT.
        container_name: A string shows container name.
        program_name: A string shows process name.

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

        def retrieve_route_snapshot(asic, prefix_snapshot, dut_instance_name, signal_queue):
            prefix_snapshot[dut_instance_name] = \
                set(self.extract_dest_ips(asic.run_sonic_db_cli_cmd('ASIC_DB KEYS *ROUTE_ENTRY*')['stdout_lines']))
            logger.debug("snapshot of route table from {}: {}".format(dut_instance_name,
                                                                      len(prefix_snapshot[dut_instance_name])))
            signal_queue.put(1)

        thread_count = 0
        signal_queue = queue.Queue()
        for idx, dut in enumerate(duthosts.frontend_nodes):
            for asic in dut.asics:
                dut_instance_name = dut.hostname + '-' + str(asic.asic_index)
                if dut.facts['switch_type'] == "voq" and idx == 0:
                    dut_instance_name = dut_instance_name + "UpstreamLc"
                    threading.Thread(target=retrieve_route_snapshot, args=(asic, prefix_snapshot,
                                                                           dut_instance_name, signal_queue)).start()
                    thread_count += 1

        ts1 = time.time()
        while signal_queue.qsize() < thread_count:
            ts2 = time.time()
            if (ts2 - ts1) > 60:
                raise TimeoutError("Get route prefix snapshot from asicdb Timeout!")
            continue

        for dut_instance_name in prefix_snapshot.keys():
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
    @pytest.mark.parametrize("container_name, program_name", [
        ("bgp", "bgpd"),
        ("syncd", "syncd"),
        ("swss", "orchagent")
    ])
    def test_critical_process_crash_and_recover(self, duthosts, container_name, program_name):
        duthost = None
        for idx, dut in enumerate(duthosts.frontend_nodes):
            if dut.facts['switch_type'] == "voq" and idx == 0:
                # pick a UpstreamLC to get higher route churn in VoQ chassis
                duthost = dut
        if duthost is None:
            duthost = duthosts[0]
        logger.info("test_{}_crash_and_recover: DUT{}".format(program_name, duthost.hostname))

        namespace_ids, succeeded = duthost.get_namespace_ids(container_name)
        pytest_assert(succeeded, "Failed to get namespace ids of container '{}'".format(container_name))
        logger.info("namespace_ids: {}".format(namespace_ids))

        try:
            logger.info("kill {}(s) for {}".format(program_name, duthost.hostname))
            for id in namespace_ids:
                if id is None:
                    id = ""
                check_and_kill_process(duthost, container_name + str(id), program_name)
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

            logger.info("Recover containers on {}".format(duthost.hostname))
            config_reload(duthost)
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
