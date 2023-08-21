import pytest
from bfd_base import BfdBase
import logging
import time

pytestmark = [
    pytest.mark.topology('t2')
]
logger = logging.getLogger(__name__)

class TestBfdStaticRoute(BfdBase):
    test_case_status = True
    total_iterations = 100

    def test_bfd_deletion(self, duthost, request, duthosts, tbinfo, get_src_dst_asic_and_duts, bfd_base_instance, bfd_cleanup_db):
        """
        Test case #1 - To verify deletion of BFD session between two line cards.
        Test Steps:
            1. Delete BFD on Source dut
            2. Verify that on Source dut BFD gets cleaned up and static route exists.
            3. Verify that on Destination dut BFD goes down and static route will be removed.
            4. Delete BFD on Destination dut.
            5. Verify that on Destination dut BFD gets cleaned up and static route will be added back.
        """
        logger.info("Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix")
        src_asic, dst_asic, src_dut, dst_dut, src_dut_nexthops, dst_dut_nexthops, src_prefix, dst_prefix = self.select_src_dst_dut_with_asic(request, get_src_dst_asic_and_duts, bfd_base_instance)
        
        logger.info("BFD deletion on source dut")    
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD & Static route verifications")
        self.verify_bfd_static_route(dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Removal", "Down", bfd_base_instance)
        self.verify_bfd_static_route(src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Addition", "No BFD sessions found", bfd_base_instance)

        logger.info("BFD deletion on destination dut")    
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        logger.info("BFD & Static route verifications")
        self.verify_bfd_static_route(dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Addition", "No BFD sessions found", bfd_base_instance)
        self.verify_bfd_static_route(src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Addition", "No BFD sessions found", bfd_base_instance)

        assert self.test_case_status, "BFD deletion did not influence static routes"
        logger.info("test_bfd_static_route_deletion completed")

    def verify_bfd_static_route(self, asic, prefix, dut, dut_nexthops, expected_prefix_state, expected_bfd_state, bfd_base_instance):
        #Verification of BFD session
        timeout = 180 # Timeout in seconds (3 minutes)
        start_time = time.time()
        while True:
            bfd_state = bfd_base_instance.extract_current_bfd_state(dut_nexthops.values(), asic.asic_index, dut)
            if bfd_state == expected_bfd_state:
                break
            if time.time() - start_time >= timeout:
                self.test_case_status = False
                assert False, "Expected BFD state '{}' was not reached within {} seconds".format(expected_state, timeout)
            time.sleep(1)
        
        #Verification of static route
        static_route_output = dut.shell("show ip route static", module_ignore_errors=True)["stdout"].encode("utf-8").strip().split("\n")
        asic_routes = bfd_base_instance.extract_routes(static_route_output)
        
        if expected_prefix_state == "Route Removal":
            if prefix in asic_routes["asic{}".format(asic.asic_index)].keys():
                self.test_case_status = False
                logger.info("Prefix being validated: ", prefix)
                logger.info("List of available prefixes now:", asic_routes["asic{}".format(asic.asic_index)].keys())
                assert False, "Prefix removal is not successful"
        elif expected_prefix_state == "Route Addition":
            if prefix not in asic_routes["asic{}".format(asic.asic_index)].keys():
                self.test_case_status = False
                logger.info("Prefix being validated: ", prefix)
                logger.info("List of available prefixes now:", asic_routes["asic{}".format(asic.asic_index)].keys())
                assert False, "Prefix has been removed even though BFD doesnt exist"

    def select_src_dst_dut_with_asic(self, request, get_src_dst_asic_and_duts, bfd_base_instance):
        logger.debug("Selecting source and destination DUTs with ASICs...")
        #Random selection of dut & asic.
        src_asic = get_src_dst_asic_and_duts['src_asic']
        dst_asic = get_src_dst_asic_and_duts['dst_asic']
        src_dut = get_src_dst_asic_and_duts['src_dut']
        dst_dut = get_src_dst_asic_and_duts['dst_dut']

        logger.info("Source Asic: %s", src_asic)
        logger.info("Destination Asic: %s", dst_asic)
        logger.info("Source dut: %s", src_dut)
        logger.info("Destination dut: %s", dst_dut) 

        request.config.src_asic = src_asic
        request.config.dst_asic = dst_asic
        request.config.src_dut = src_dut
        request.config.dst_dut = dst_dut

        #Extracting static routes and corresponding nexthops
        src_dut_static_route_output = src_dut.shell("show ip route static", module_ignore_errors=True)["stdout"].encode("utf-8").strip().split("\n")
        src_asic_routes = bfd_base_instance.extract_routes(src_dut_static_route_output)

        dst_dut_static_route_output = dst_dut.shell("show ip route static", module_ignore_errors=True)["stdout"].encode("utf-8").strip().split("\n")
        dst_asic_routes = bfd_base_instance.extract_routes(dst_dut_static_route_output)

        #Extracting nexthops
        try:
            dst_dut_nexthops = {intf['interface']:intf['ipv4 address/mask'].split("/24")[0] for intf in src_dut.show_and_parse("show ip int -d all -n asic{}".format(src_asic.asic_index)) if "PortChannel" in intf['interface'] and intf['bgp neighbor'] == "N/A" }
            src_dut_nexthops = {intf['interface']:intf['ipv4 address/mask'].split("/24")[0] for intf in dst_dut.show_and_parse("show ip int -d all -n asic{}".format(dst_asic.asic_index)) if "PortChannel" in intf['interface'] and intf['bgp neighbor'] == "N/A" }
        except Exception:
            pytest.fail("Possibily containers are down on {} and {}".format(src_dut, dst_dut))
        
        #Picking a static route to delete correspinding BFD session
        src_prefix = bfd_base_instance.selecting_route_to_delete(src_asic_routes, src_dut_nexthops.values())
        dst_prefix = bfd_base_instance.selecting_route_to_delete(dst_asic_routes, dst_dut_nexthops.values())
        request.config.src_prefix = src_prefix
        request.config.dst_prefix = dst_prefix
        logger.info("Source prefix: %s", src_prefix)
        logger.info("Destination prefix: %s", dst_prefix) 

        #Verification of BFD sessions before deleting them.
        dst_bfd_state = bfd_base_instance.extract_current_bfd_state(dst_dut_nexthops.values(), dst_asic.asic_index, dst_dut)
        if dst_bfd_state != "Up":
            self.test_case_status = False
            assert False, "BFD sessions are expected to stay up at the beginning of the test case but it's down on {}".format(dst_dut)
        src_bfd_state = bfd_base_instance.extract_current_bfd_state(src_dut_nexthops.values(), src_asic.asic_index, src_dut)
        if src_bfd_state != "Up":
            self.test_case_status = False
            assert False, "BFD sessions are expected to stay up at the beginning of the test case but it's down on {}".format(src_dut)
        logger.debug("Source and destination DUTs selection completed")
        
        return src_asic, dst_asic, src_dut, dst_dut, src_dut_nexthops, dst_dut_nexthops, src_prefix, dst_prefix

    def test_bfd_flap(self, duthost, request, duthosts, tbinfo, get_src_dst_asic_and_duts, bfd_base_instance):
        """
        Test case #2 - To flap the BFD session ( Up <--> Down <---> Up) between linecards for 100 times.
            Test Steps:
            1. Delete BFD on Source dut
            2. Verify that on Source dut BFD gets cleaned up and static route exists.
            3. Verify that on Destination dut BFD goes down and static route will be removed.
            4. Add BFD on Source dut.
            5. Verify that on Source dut BFD is up
            6. Verify that on destination dut BFD is up and static route is added back.
            7. Repeat above steps 100 times.
        """
        logger.info("Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix")
        src_asic, dst_asic, src_dut, dst_dut, src_dut_nexthops, dst_dut_nexthops, src_prefix, dst_prefix = self.select_src_dst_dut_with_asic(request, get_src_dst_asic_and_duts, bfd_base_instance)
        
        successful_iterations = 0  # Counter for successful iterations

        for i in range(self.total_iterations):
            logger.info("Iteration {}".format(i))

            logger.info("BFD deletion on source dut")    
            bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)

            logger.info("Waiting for 5s post BFD shutdown")
            time.sleep(5)

            logger.info("BFD & Static route verifications")
            self.verify_bfd_static_route(dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Removal", "Down", bfd_base_instance)
            self.verify_bfd_static_route(src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Addition", "No BFD sessions found", bfd_base_instance)

            logger.info("BFD addition on source dut")   
            bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
            
            logger.info("BFD & Static route verifications")
            self.verify_bfd_static_route(dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Addition", "Up", bfd_base_instance)
            self.verify_bfd_static_route(src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Addition", "Up", bfd_base_instance)

            # Check if both iterations were successful and increment the counter
            if self.test_case_status:
                successful_iterations += 1
        
        # Determine the success rate
        logger.info("successful_iterations: %d", successful_iterations)
        success_rate = (successful_iterations / self.total_iterations) * 100
        
        logger.info("Current success rate: %.2f%%", success_rate)
        # Check if the success rate is above the threshold (e.g., 98%)
        assert success_rate >= 98, "BFD flap verification success rate is below 98% ({}%)".format(success_rate)
        
        logger.info("test_bfd_flap completed")
    
