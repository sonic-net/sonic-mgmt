import pytest
import logging
import re
import time
import math

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


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
        for dut in duthosts.frontend_nodes:
            for asic in dut.asics:
                dut_instance_name = dut.hostname + '-' + str(asic.asic_index)
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
           Addtional 100 seconds is added to the sleep interval to account for the time taken to
           withdraw and advertise the routes by peers.
        """
        self.__class__.sleep_interval = math.ceil(max_prefix_cnt/3000) + 100
        logger.debug("max_no_of_prefix: {} sleep_interval: {}".format(max_prefix_cnt, self.sleep_interval))

    def test_route_withdraw_advertise(self, duthosts, tbinfo, localhost):

        # withdraw the routes
        ptf_ip = tbinfo["ptf_ip"]
        topo_name = tbinfo["topo"]["name"]

        try:
            logger.info("withdraw ipv4 and ipv6 routes for {}".format(topo_name))
            localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="withdraw", path="../ansible/")
            time.sleep(self.sleep_interval)

            """ compare the number of routes withdrawn from all the DUTs. In working condition, the number of routes
                withdrawn should be same across all the DUTs
                Note: this will be noop for single asic pizzabox duts
            """
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
