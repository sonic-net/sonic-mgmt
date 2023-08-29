import pytest
from bfd_base import BfdBase
import logging
import time
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot


pytestmark = [
    pytest.mark.topology('t2')
]
logger = logging.getLogger(__name__)

class TestBfdStaticRoute(BfdBase):
    test_case_status = True
    total_iterations = 100

    def test_bfd_static_route_deletion(self, duthost, request, duthosts, tbinfo, get_src_dst_asic_and_duts, bfd_base_instance, bfd_cleanup_db):
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
        
        # Creation of BFD
        logger.info("BFD addition on source dut")   
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")   
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)
        
        #Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))
        
        logger.info("BFD deletion on source dut")    
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD & Static route verifications")
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"))
        self.verify_static_route(request, dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Removal", bfd_base_instance)
        self.verify_static_route(request, src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Addition", bfd_base_instance)

        logger.info("BFD deletion on destination dut")    
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        logger.info("BFD & Static route verifications")
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"))
        self.verify_static_route(request, dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Addition", bfd_base_instance)
        self.verify_static_route(request, src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Addition", bfd_base_instance)

        assert self.test_case_status, "BFD deletion did not influence static routes"
        logger.info("test_bfd_static_route_deletion completed")

    def verify_static_route(self, request, asic, prefix, dut, dut_nexthops, expected_prefix_state, bfd_base_instance):
        #Verification of static route
        static_route_output = dut.shell("show ip route static", module_ignore_errors=True)["stdout"].encode("utf-8").strip().split("\n")
        asic_routes = bfd_base_instance.extract_routes(static_route_output)
        logger.info("Here are asic routes, {}".format(asic_routes))
         
        if expected_prefix_state == "Route Removal":
            if len(asic_routes) == 0 and request.config.interface_shutdown:
                logger.info("asic routes are empty post interface shutdown")
            else:
                assert len(asic_routes) >  0, "static routes on source dut are empty"
                assert prefix not in asic_routes.get("asic{}".format(asic.asic_index), {}).keys(), "Prefix removal is not successful. Prefix being validated: {}.".format(prefix)
        elif expected_prefix_state == "Route Addition":
            assert prefix in asic_routes.get("asic{}".format(asic.asic_index), {}).keys(), "Prefix has not been added even though BFD is expected. Prefix: {}".format(prefix)


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

        #Extracting static routes
        src_dut_static_route_output = src_dut.shell("show ip route static", module_ignore_errors=True)["stdout"].encode("utf-8").strip().split("\n")
        src_asic_routes = bfd_base_instance.extract_routes(src_dut_static_route_output)
        logger.info("Source asic routes, {}".format(src_asic_routes))
        assert len(src_asic_routes) >  0, "static routes on source dut are empty"
        
        dst_dut_static_route_output = dst_dut.shell("show ip route static", module_ignore_errors=True)["stdout"].encode("utf-8").strip().split("\n")
        dst_asic_routes = bfd_base_instance.extract_routes(dst_dut_static_route_output)
        logger.info("Destination asic routes, {}".format(dst_asic_routes))
        assert len(dst_asic_routes) >  0, "static routes on destination dut are empty"
        
        #Extracting nexthops
        dst_dut_nexthops = bfd_base_instance.extract_ip_addresses_for_backend_portchannels(src_dut, src_asic)
        src_dut_nexthops = bfd_base_instance.extract_ip_addresses_for_backend_portchannels(dst_dut, dst_asic)
        assert len(dst_dut_nexthops) != 0, "Destination Nexthops are empty"
        assert len(src_dut_nexthops) != 0, "Source Nexthops are empty"

        #Picking a static route to delete correspinding BFD session
        src_prefix = bfd_base_instance.selecting_route_to_delete(src_asic_routes, src_dut_nexthops.values())
        dst_prefix = bfd_base_instance.selecting_route_to_delete(dst_asic_routes, dst_dut_nexthops.values())
        logger.info("Source prefix: %s", src_prefix)
        logger.info("Destination prefix: %s", dst_prefix) 

        assert src_prefix is not None and src_prefix != "", "Source prefix not found"
        assert dst_prefix is not None and dst_prefix != "", "Destination prefix not found"

        request.config.src_prefix = src_prefix
        request.config.dst_prefix = dst_prefix
        
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
        
        # Creation of BFD
        logger.info("BFD addition on source dut")   
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")   
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)
        
        #Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))
        
        successful_iterations = 0  # Counter for successful iterations

        for i in range(self.total_iterations):
            logger.info("Iteration {}".format(i))

            logger.info("BFD deletion on source dut")    
            bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)

            logger.info("Waiting for 5s post BFD shutdown")
            time.sleep(5)

            logger.info("BFD & Static route verifications")
            assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"))
            assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"))
            self.verify_static_route(request, dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Removal", bfd_base_instance)
            self.verify_static_route(request, src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Addition", bfd_base_instance)

            logger.info("BFD addition on source dut")   
            bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
            
            logger.info("BFD & Static route verifications")
            assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
            assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))
            self.verify_static_route(request, dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Addition", bfd_base_instance)
            self.verify_static_route(request, src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Addition", bfd_base_instance)

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
    
    def control_interface_state(self, src_dut, dst_dut, src_asic, dst_asic, bfd_base_instance, src_dut_nexthops, dst_dut_nexthops, interface, action):
        int_status = src_dut.show_interface(command="status", include_internal_intfs=True, asic_index=src_asic.asic_index)['ansible_facts']['int_status'][interface]
        oper_state = int_status['oper_state']
        target_state = "down" if action == "shutdown" else "Dw" if "BP" in interface else "Up"
        
        if oper_state != target_state:
            command = "shutdown" if action == "shutdown" else "startup"
            exec_cmd = "sudo ip netns exec asic{0} config interface -n asic{0} {1} {2}".format(src_asic.asic_index, command, interface)
            src_dut.shell(exec_cmd)

            if "BP" in interface:
                assert wait_until(90, 1, 0, lambda: src_dut.show_interface(command="status", include_internal_intfs=True, asic_index=src_asic.asic_index)['ansible_facts']['int_status'][interface]['oper_state'] == target_state)
            else:
                assert wait_until(90, 1, 0, lambda: bfd_base_instance.extract_backend_portchannels(src_dut)[interface]['status'] == target_state)
        else:
            raise ValueError("Invalid action specified")

    def test_bfd_portchannel_interface_flap(self, duthost, request, duthosts, tbinfo, get_src_dst_asic_and_duts, bfd_base_instance, bfd_cleanup_db):
        request.config.interface_shutdown = True

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info("Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix")
        src_asic, dst_asic, src_dut, dst_dut, src_dut_nexthops, dst_dut_nexthops, src_prefix, dst_prefix = self.select_src_dst_dut_with_asic(request, get_src_dst_asic_and_duts, bfd_base_instance)
        
        
        # Creation of BFD
        logger.info("BFD addition on source dut")   
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")   
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)
        
        #Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))

        # Extract portchannel interfaces on src
        list_of_portchannels_on_src = dst_dut_nexthops.keys()

        #Shutdown PortChannels
        for interface in list_of_portchannels_on_src:
            action = "shutdown"
            self.control_interface_state(src_dut, dst_dut, src_asic, dst_asic, bfd_base_instance, src_dut_nexthops, dst_dut_nexthops, interface, action)
        
        # Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Down"))

        # Verify that corresponding static route has been removed on both duts
        logger.info("BFD & Static route verifications")
        self.verify_static_route(request, dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Removal", "Down", bfd_base_instance)
        self.verify_static_route(request, src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Removal", "Down", bfd_base_instance)

        for interface in list_of_portchannels_on_src:
            action = "startup"
            self.control_interface_state(src_dut, dst_dut, src_asic, dst_asic, bfd_base_instance, src_dut_nexthops, dst_dut_nexthops, interface, action)
        
        # Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))

        # Verify that corresponding static route has been added on both duts
        logger.info("BFD & Static route verifications")
        self.verify_static_route(request, dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Addition", bfd_base_instance)
        self.verify_static_route(request, src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Addition", bfd_base_instance)
    

    def test_bfd_portchannel_member_flap(self, duthost, request, duthosts, tbinfo, get_src_dst_asic_and_duts, bfd_base_instance, bfd_cleanup_db):
        request.config.interface_shutdown = True

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info("Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix")
        src_asic, dst_asic, src_dut, dst_dut, src_dut_nexthops, dst_dut_nexthops, src_prefix, dst_prefix = self.select_src_dst_dut_with_asic(request, get_src_dst_asic_and_duts, bfd_base_instance)
        
        # Creation of BFD
        logger.info("BFD addition on source dut")   
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")   
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)
        
        # Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))

        # Extract portchannel interfaces on src
        list_of_portchannels_on_src = dst_dut_nexthops.keys()

        #Shutdown PortChannel members
        for portchannel_interface in list_of_portchannels_on_src:
            action = "shutdown"
            list_of_portchannel_members_on_src = bfd_base_instance.extract_backend_portchannels(src_dut)[portchannel_interface]['members']
            for each_member in list_of_portchannel_members_on_src:
                self.control_interface_state(src_dut, dst_dut, src_asic, dst_asic, bfd_base_instance, src_dut_nexthops, dst_dut_nexthops, each_member, action)
        
        # Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Down"))

        # Verify that corresponding static route has been removed on both duts
        logger.info("BFD & Static route verifications")
        self.verify_static_route(request, dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Removal", bfd_base_instance)
        self.verify_static_route(request, src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Removal", bfd_base_instance)

        # Bring up of PortChannel members
        for portchannel_interface in list_of_portchannels_on_src:
            action = "startup"
            list_of_portchannel_members_on_src = bfd_base_instance.extract_backend_portchannels(src_dut)[portchannel_interface]['members']
            for each_member in list_of_portchannel_members_on_src:
                self.control_interface_state(src_dut, dst_dut, src_asic, dst_asic, bfd_base_instance, src_dut_nexthops, dst_dut_nexthops, each_member, action)
        
        # Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))

        # Verify that corresponding static route has been added on both duts
        logger.info("Static route verifications")
        self.verify_static_route(request, dst_asic, dst_prefix, dst_dut, dst_dut_nexthops, "Route Addition", bfd_base_instance)
        self.verify_static_route(request, src_asic, src_prefix, src_dut, src_dut_nexthops, "Route Addition", bfd_base_instance)
    
    def test_bfd_config_reload(self, duthost, request, duthosts, tbinfo, get_src_dst_asic_and_duts, bfd_base_instance):

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info("Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix")
        src_asic, dst_asic, src_dut, dst_dut, src_dut_nexthops, dst_dut_nexthops, src_prefix, dst_prefix = self.select_src_dst_dut_with_asic(request, get_src_dst_asic_and_duts, bfd_base_instance)
        
        # Creation of BFD
        logger.info("BFD addition on source dut")   
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        
        logger.info("BFD addition on destination dut")   
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)
        
        # Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))
        
        # Savings the configs
        src_dut.shell('sudo config save -y')
        
        # Config reload of Source dut
        config_reload(src_dut)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        # Verification of BFD session state.
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))

        logger.info("BFD deletion on source & destination dut")    
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell('sudo config save -y')
        
        # Config reload of Source dut
        config_reload(src_dut)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        # Verification of BFD session state.
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"))
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"))
    
    def test_bfd_with_lc_reboot(self, localhost, duthost, request, duthosts, tbinfo, get_src_dst_asic_and_duts, bfd_base_instance):

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info("Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix")
        src_asic, dst_asic, src_dut, dst_dut, src_dut_nexthops, dst_dut_nexthops, src_prefix, dst_prefix = self.select_src_dst_dut_with_asic(request, get_src_dst_asic_and_duts, bfd_base_instance)
        
        # Creation of BFD
        logger.info("BFD addition on source dut")   
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        
        logger.info("BFD addition on destination dut")   
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)
        
        # Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))
        
        # Savings the configs
        src_dut.shell('sudo config save -y')
        
        # Perform a cold reboot on source dut
        reboot(src_dut, localhost)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        # Verification of BFD session state.
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))

        logger.info("BFD deletion on source & destination dut")    
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell('sudo config save -y')
        
        # Config reload of Source dut
        reboot(src_dut, localhost)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        # Verification of BFD session state.
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"))
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"))
 
    def test_bfd_with_rp_reboot(self, localhost, duthost, request, duthosts, tbinfo, get_src_dst_asic_and_duts, bfd_base_instance, enum_supervisor_dut_hostname):
        rp = duthosts[enum_supervisor_dut_hostname]

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info("Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix")
        src_asic, dst_asic, src_dut, dst_dut, src_dut_nexthops, dst_dut_nexthops, src_prefix, dst_prefix = self.select_src_dst_dut_with_asic(request, get_src_dst_asic_and_duts, bfd_base_instance)
        
        # Creation of BFD
        logger.info("BFD addition on source dut")   
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        
        logger.info("BFD addition on destination dut")   
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)
        
        # Verification of BFD session state.
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(180, 10, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))
        
        # Savings the configs
        src_dut.shell('sudo config save -y')
        dst_dut.shell('sudo config save -y')
        
        # Perform a cold reboot on source dut
        reboot(rp, localhost)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        # Verification of BFD session state.
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"))
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "Up"))

        logger.info("BFD deletion on source & destination dut")    
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell('sudo config save -y')
        dst_dut.shell('sudo config save -y')
        
        # Config reload of Source dut
        reboot(rp, localhost)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        # Verification of BFD session state.
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"))
        assert wait_until(300, 20, 0, lambda: bfd_base_instance.verify_bfd_state(src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"))
