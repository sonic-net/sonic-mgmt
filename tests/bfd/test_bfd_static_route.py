import logging
import time

import pytest

from tests.bfd.bfd_base import BfdBase
from tests.bfd.bfd_helpers import verify_static_route, select_src_dst_dut_with_asic, control_interface_state, \
    check_bgp_status, add_bfd, verify_bfd_state, delete_bfd, extract_backend_portchannels
from tests.common.config_reload import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology("t2"),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)


class TestBfdStaticRoute(BfdBase):
    COMPLETENESS_TO_ITERATIONS = {
        'debug': 1,
        'basic': 10,
        'confident': 50,
        'thorough': 100,
        'diagnose': 200,
    }

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_with_lc_reboot(
        self,
        localhost,
        duthost,
        request,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_cleanup_db,
        version,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )
        (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        ) = select_src_dst_dut_with_asic(
            request, get_src_dst_asic_and_duts, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            300,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Perform a cold reboot on source dut
        reboot(src_dut, localhost)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Save the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        reboot(src_dut, localhost)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_static_route_deletion(
        self,
        duthost,
        request,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_cleanup_db,
        version,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com

        To verify deletion of BFD session between two line cards.
        Test Steps:
            1. Delete BFD on Source dut
            2. Verify that on Source dut BFD gets cleaned up and static route exists.
            3. Verify that on Destination dut BFD goes down and static route will be removed.
            4. Delete BFD on Destination dut.
            5. Verify that on Destination dut BFD gets cleaned up and static route will be added back.
        """
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )
        (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        ) = select_src_dst_dut_with_asic(
            request, get_src_dst_asic_and_duts, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD & Static route verifications")
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Removal",
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            version,
        )

        logger.info("BFD deletion on destination dut")
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        logger.info("BFD & Static route verifications")
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Addition",
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            version,
        )

        logger.info("BFD deletion did not influence static routes and test completed successfully")

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_flap(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_cleanup_db,
        get_function_completeness_level,
        version,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com

        To flap the BFD session ( Up <--> Down <---> Up) between linecards for 100 times.
            Test Steps:
            1. Delete BFD on Source dut
            2. Verify that on Source dut BFD gets cleaned up and static route exists.
            3. Verify that on Destination dut BFD goes down and static route will be removed.
            4. Add BFD on Source dut.
            5. Verify that on Source dut BFD is up
            6. Verify that on destination dut BFD is up and static route is added back.
            7. Repeat above steps 100 times.
        """
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )
        (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        ) = select_src_dst_dut_with_asic(
            request, get_src_dst_asic_and_duts, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        completeness_level = get_function_completeness_level
        if completeness_level is None:
            completeness_level = "thorough"

        total_iterations = self.COMPLETENESS_TO_ITERATIONS[completeness_level]
        successful_iterations = 0  # Counter for successful iterations
        for i in range(total_iterations):
            logger.info("Iteration {}".format(i))

            logger.info("BFD deletion on source dut")
            delete_bfd(src_asic.asic_index, src_prefix, src_dut)

            logger.info("Waiting for 5s post BFD shutdown")
            time.sleep(5)

            logger.info("BFD & Static route verifications")
            assert wait_until(
                180,
                10,
                0,
                lambda: verify_bfd_state(
                    dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
                ),
            )
            assert wait_until(
                180,
                10,
                0,
                lambda: verify_bfd_state(
                    src_dut,
                    src_dut_nexthops.values(),
                    src_asic,
                    "No BFD sessions found",
                ),
            )
            verify_static_route(
                request,
                dst_asic,
                dst_prefix,
                dst_dut,
                "Route Removal",
                version,
            )
            verify_static_route(
                request,
                src_asic,
                src_prefix,
                src_dut,
                "Route Addition",
                version,
            )

            logger.info("BFD addition on source dut")
            add_bfd(src_asic.asic_index, src_prefix, src_dut)

            logger.info("BFD & Static route verifications")
            assert wait_until(
                180,
                10,
                0,
                lambda: verify_bfd_state(
                    dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
                ),
            )
            assert wait_until(
                180,
                10,
                0,
                lambda: verify_bfd_state(
                    src_dut, src_dut_nexthops.values(), src_asic, "Up"
                ),
            )
            verify_static_route(
                request,
                dst_asic,
                dst_prefix,
                dst_dut,
                "Route Addition",
                version,
            )
            verify_static_route(
                request,
                src_asic,
                src_prefix,
                src_dut,
                "Route Addition",
                version,
            )

            # Check if both iterations were successful and increment the counter
            successful_iterations += 1

        # Determine the success rate
        logger.info("successful_iterations: %d", successful_iterations)
        success_rate = (successful_iterations / total_iterations) * 100

        logger.info("Current success rate: %.2f%%", success_rate)
        # Check if the success rate is above the threshold (e.g., 98%)
        assert (
            success_rate >= 98
        ), "BFD flap verification success rate is below 98% ({}%)".format(success_rate)

        logger.info("test_bfd_flap completed")

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_with_rp_reboot(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
        version,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        rp = duthosts[enum_supervisor_dut_hostname]

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )
        (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        ) = select_src_dst_dut_with_asic(
            request, get_src_dst_asic_and_duts, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Perform a cold reboot on source dut
        reboot(rp, localhost)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload of Source dut
        reboot(rp, localhost)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_remote_link_flap(
        self,
        duthost,
        request,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_cleanup_db,
        version,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        request.config.interface_shutdown = True

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )
        (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        ) = select_src_dst_dut_with_asic(
            request, get_src_dst_asic_and_duts, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Extract portchannel interfaces on dst
        list_of_portchannels_on_dst = src_dut_nexthops.keys()
        request.config.portchannels_on_dut = "dst"
        request.config.selected_portchannels = list_of_portchannels_on_dst

        # Shutdown PortChannels on destination dut
        for interface in list_of_portchannels_on_dst:
            action = "shutdown"
            control_interface_state(
                dst_dut, dst_asic, interface, action
            )

        # Verification of BFD session state on src dut
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Down"
            ),
        )

        # Verify that corresponding static route has been removed on both duts
        logger.info("BFD & Static route verifications")
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Removal",
            version,
        )

        for interface in list_of_portchannels_on_dst:
            action = "startup"
            control_interface_state(
                dst_dut, dst_asic, interface, action
            )

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Verify that corresponding static route has been added on both duts
        logger.info("BFD & Static route verifications")
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Addition",
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            version,
        )

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_lc_asic_shutdown(
        self,
        duthost,
        request,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_cleanup_db,
        version,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        request.config.interface_shutdown = True

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )
        (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        ) = select_src_dst_dut_with_asic(
            request, get_src_dst_asic_and_duts, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Extract portchannel interfaces on src
        list_of_portchannels_on_src = dst_dut_nexthops.keys()
        request.config.portchannels_on_dut = "src"
        request.config.selected_portchannels = list_of_portchannels_on_src

        # Shutdown PortChannels
        for interface in list_of_portchannels_on_src:
            action = "shutdown"
            control_interface_state(
                src_dut, src_asic, interface, action
            )

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Down"
            ),
        )

        # Verify that corresponding static route has been removed on both duts
        logger.info("BFD & Static route verifications")
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Removal",
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Removal",
            version,
        )

        for interface in list_of_portchannels_on_src:
            action = "startup"
            control_interface_state(
                src_dut, src_asic, interface, action
            )

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Verify that corresponding static route has been added on both duts
        logger.info("BFD & Static route verifications")
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Addition",
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            version,
        )

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_portchannel_member_flap(
        self,
        duthost,
        request,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_cleanup_db,
        version,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        request.config.interface_shutdown = True

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )
        (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        ) = select_src_dst_dut_with_asic(
            request, get_src_dst_asic_and_duts, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Extract portchannel interfaces on src
        list_of_portchannels_on_src = dst_dut_nexthops.keys()
        request.config.portchannels_on_dut = "src"
        request.config.selected_portchannels = list_of_portchannels_on_src

        # Shutdown PortChannel members
        for portchannel_interface in list_of_portchannels_on_src:
            action = "shutdown"
            list_of_portchannel_members_on_src = (
                extract_backend_portchannels(src_dut)[
                    portchannel_interface
                ]["members"]
            )
            request.config.selected_portchannel_members = (
                list_of_portchannel_members_on_src
            )
            for each_member in list_of_portchannel_members_on_src:
                control_interface_state(
                    src_dut, src_asic, each_member, action
                )

        # Verification of BFD session state.
        assert wait_until(
            300,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            300,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Down"
            ),
        )

        # Verify that corresponding static route has been removed on both duts
        logger.info("BFD & Static route verifications")
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Removal",
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Removal",
            version,
        )

        # Bring up of PortChannel members
        for portchannel_interface in list_of_portchannels_on_src:
            action = "startup"
            list_of_portchannel_members_on_src = (
                extract_backend_portchannels(src_dut)[
                    portchannel_interface
                ]["members"]
            )
            for each_member in list_of_portchannel_members_on_src:
                control_interface_state(
                    src_dut, src_asic, each_member, action
                )

        # Verification of BFD session state.
        assert wait_until(
            300,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Verify that corresponding static route has been added on both duts
        logger.info("Static route verifications")
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Addition",
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            version,
        )

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_config_reload(
        self,
        duthost,
        request,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_cleanup_db,
        version,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )
        (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        ) = select_src_dst_dut_with_asic(
            request, get_src_dst_asic_and_duts, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(src_dut)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(src_dut)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_with_rp_config_reload(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
        version,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        rp = duthosts[enum_supervisor_dut_hostname]

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )
        (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        ) = select_src_dst_dut_with_asic(
            request, get_src_dst_asic_and_duts, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Perform a cold reboot on source dut
        config_reload(rp)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(rp)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_with_bad_fc_asic(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
        version,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        rp = duthosts[enum_supervisor_dut_hostname]

        # Selecting source, destination dut & prefix & BFD status verification for all nexthops
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )
        (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        ) = select_src_dst_dut_with_asic(
            request, get_src_dst_asic_and_duts, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Extract asic ids
        docker_output = rp.shell("docker ps | grep swss | awk '{print $NF}'")[
            "stdout"
        ].split("\n")
        asic_ids = [int(element.split("swss")[1]) for element in docker_output]

        # Shut down corresponding asic on supervisor to simulate bad asic
        for asic_id in asic_ids:
            rp.shell("systemctl stop swss@{}".format(asic_id))

        # Verify that BFD sessions are down
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Down"
            ),
        )

        # Config reload RP to bring up the swss containers
        config_reload(rp)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload RP
        config_reload(rp)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )
