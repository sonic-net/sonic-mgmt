import pytest
from bfd_base import BfdBase
import logging
import time

from tests.bfd.bfd_helpers import verify_static_route, select_src_dst_dut_with_asic, control_interface_state, \
    check_bgp_status
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot
from tests.common.fixtures.tacacs import tacacs_creds, setup_tacacs    # noqa F401

pytestmark = [pytest.mark.topology("t2")]

logger = logging.getLogger(__name__)


class TestBfdStaticRoute(BfdBase):
    TOTAL_ITERATIONS = 100

    @pytest.fixture(autouse=True, scope="class")
    def modify_bfd_sessions(self, duthosts, bfd_base_instance):
        """
        1. Gather all front end nodes
        2. Modify BFD state to required state & issue config reload.
        3. Wait for Critical processes
        4. Gather all ASICs for each dut
        5. Calls find_bfd_peers_with_given_state using wait_until
            a. Runs ip netns exec asic{} show bfd sum
            b. If expected state is "Total number of BFD sessions: 0" and it is in result, output is True
            c. If expected state is "Up" and no. of down peers is 0, output is True
            d. If expected state is "Down" and no. of up peers is 0, output is True
        """
        try:
            duts = duthosts.frontend_nodes
            for dut in duts:
                bfd_base_instance.modify_all_bfd_sessions(dut, "false")
            for dut in duts:
                # config reload
                config_reload(dut)
                wait_critical_processes(dut)
            # Verification that all BFD sessions are deleted
            for dut in duts:
                asics = [
                    asic.split("asic")[1] for asic in dut.get_asic_namespace_list()
                ]
                for asic in asics:
                    assert wait_until(
                        600,
                        10,
                        0,
                        lambda: bfd_base_instance.find_bfd_peers_with_given_state(
                            dut, asic, "No BFD sessions found"
                        ),
                    )

            yield

        finally:
            duts = duthosts.frontend_nodes
            for dut in duts:
                bfd_base_instance.modify_all_bfd_sessions(dut, "true")
            for dut in duts:
                config_reload(dut)
                wait_critical_processes(dut)
            # Verification that all BFD sessions are added
            for dut in duts:
                asics = [
                    asic.split("asic")[1] for asic in dut.get_asic_namespace_list()
                ]
                for asic in asics:
                    assert wait_until(
                        600,
                        10,
                        0,
                        lambda: bfd_base_instance.find_bfd_peers_with_given_state(
                            dut, asic, "Up"
                        ),
                    )

    def test_bfd_with_lc_reboot_ipv4(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv4"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            300,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Perform a cold reboot on source dut
        reboot(src_dut, localhost)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        assert wait_until(
            300,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        reboot(src_dut, localhost)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        assert wait_until(
            300,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    def test_bfd_with_lc_reboot_ipv6(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv6"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            300,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Perform a cold reboot on source dut
        reboot(src_dut, localhost)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        assert wait_until(
            300,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        reboot(src_dut, localhost)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        assert wait_until(
            300,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    def test_bfd_static_route_deletion_ipv4(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
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
        version = "ipv4"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD & Static route verifications")
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Removal",
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )

        logger.info("BFD deletion on destination dut")
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        logger.info("BFD & Static route verifications")
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )

        logger.info("BFD deletion did not influence static routes and test completed successfully")

    def test_bfd_static_route_deletion_ipv6(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv6"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD & Static route verifications")
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Removal",
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )

        logger.info("BFD deletion on destination dut")
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        logger.info("BFD & Static route verifications")
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )
        verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )

        logger.info("BFD deletion did not influence static routes and test completed successfully")

    def test_bfd_flap_ipv4(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
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
        version = "ipv4"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        successful_iterations = 0  # Counter for successful iterations
        for i in range(self.TOTAL_ITERATIONS):
            logger.info("Iteration {}".format(i))

            logger.info("BFD deletion on source dut")
            bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)

            logger.info("Waiting for 5s post BFD shutdown")
            time.sleep(5)

            logger.info("BFD & Static route verifications")
            assert wait_until(
                180,
                10,
                0,
                lambda: bfd_base_instance.verify_bfd_state(
                    dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
                ),
            )
            assert wait_until(
                180,
                10,
                0,
                lambda: bfd_base_instance.verify_bfd_state(
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
                bfd_base_instance,
                version,
            )
            verify_static_route(
                request,
                src_asic,
                src_prefix,
                src_dut,
                "Route Addition",
                bfd_base_instance,
                version,
            )

            logger.info("BFD addition on source dut")
            bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

            logger.info("BFD & Static route verifications")
            assert wait_until(
                180,
                10,
                0,
                lambda: bfd_base_instance.verify_bfd_state(
                    dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
                ),
            )
            assert wait_until(
                180,
                10,
                0,
                lambda: bfd_base_instance.verify_bfd_state(
                    src_dut, src_dut_nexthops.values(), src_asic, "Up"
                ),
            )
            verify_static_route(
                request,
                dst_asic,
                dst_prefix,
                dst_dut,
                "Route Addition",
                bfd_base_instance,
                version,
            )
            verify_static_route(
                request,
                src_asic,
                src_prefix,
                src_dut,
                "Route Addition",
                bfd_base_instance,
                version,
            )

            # Check if both iterations were successful and increment the counter
            successful_iterations += 1

        # Determine the success rate
        logger.info("successful_iterations: %d", successful_iterations)
        success_rate = (successful_iterations / self.TOTAL_ITERATIONS) * 100

        logger.info("Current success rate: %.2f%%", success_rate)
        # Check if the success rate is above the threshold (e.g., 98%)
        assert (
            success_rate >= 98
        ), "BFD flap verification success rate is below 98% ({}%)".format(success_rate)

        logger.info("test_bfd_flap completed")

    def test_bfd_flap_ipv6(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
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
        version = "ipv6"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        successful_iterations = 0  # Counter for successful iterations
        for i in range(self.TOTAL_ITERATIONS):
            logger.info("Iteration {}".format(i))

            logger.info("BFD deletion on source dut")
            bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)

            logger.info("Waiting for 5s post BFD shutdown")
            time.sleep(5)

            logger.info("BFD & Static route verifications")
            assert wait_until(
                180,
                10,
                0,
                lambda: bfd_base_instance.verify_bfd_state(
                    dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
                ),
            )
            assert wait_until(
                180,
                10,
                0,
                lambda: bfd_base_instance.verify_bfd_state(
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
                bfd_base_instance,
                version,
            )
            verify_static_route(
                request,
                src_asic,
                src_prefix,
                src_dut,
                "Route Addition",
                bfd_base_instance,
                version,
            )

            logger.info("BFD addition on source dut")
            bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

            logger.info("BFD & Static route verifications")
            assert wait_until(
                180,
                10,
                0,
                lambda: bfd_base_instance.verify_bfd_state(
                    dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
                ),
            )
            assert wait_until(
                180,
                10,
                0,
                lambda: bfd_base_instance.verify_bfd_state(
                    src_dut, src_dut_nexthops.values(), src_asic, "Up"
                ),
            )
            verify_static_route(
                request,
                dst_asic,
                dst_prefix,
                dst_dut,
                "Route Addition",
                bfd_base_instance,
                version,
            )
            verify_static_route(
                request,
                src_asic,
                src_prefix,
                src_dut,
                "Route Addition",
                bfd_base_instance,
                version,
            )

            # Check if both iterations were successful and increment the counter
            successful_iterations += 1

        # Determine the success rate
        logger.info("successful_iterations: %d", successful_iterations)
        success_rate = (successful_iterations / self.TOTAL_ITERATIONS) * 100

        logger.info("Current success rate: %.2f%%", success_rate)
        # Check if the success rate is above the threshold (e.g., 98%)
        assert (
            success_rate >= 98
        ), "BFD flap verification success rate is below 98% ({}%)".format(success_rate)

        logger.info("test_bfd_flap completed")

    def test_bfd_with_rp_reboot_ipv4(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv4"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload of Source dut
        reboot(rp, localhost)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    def test_bfd_with_rp_reboot_ipv6(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv6"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload of Source dut
        reboot(rp, localhost)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    def test_bfd_remote_link_flap_ipv4(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv4"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
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
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )

    def test_bfd_remote_link_flap_ipv6(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv6"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
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
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )

    def test_bfd_lc_asic_shutdown_ipv4(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv4"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Removal",
            bfd_base_instance,
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
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )

    def test_bfd_lc_asic_shutdown_ipv6(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv6"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Removal",
            bfd_base_instance,
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
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )

    def test_bfd_portchannel_member_flap_ipv4(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv4"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
                bfd_base_instance.extract_backend_portchannels(src_dut)[
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
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            300,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Removal",
            bfd_base_instance,
            version,
        )

        # Bring up of PortChannel members
        for portchannel_interface in list_of_portchannels_on_src:
            action = "startup"
            list_of_portchannel_members_on_src = (
                bfd_base_instance.extract_backend_portchannels(src_dut)[
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
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )

    def test_bfd_portchannel_member_flap_ipv6(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv6"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)
        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
                bfd_base_instance.extract_backend_portchannels(src_dut)[
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
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            300,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Removal",
            bfd_base_instance,
            version,
        )

        # Bring up of PortChannel members
        for portchannel_interface in list_of_portchannels_on_src:
            action = "startup"
            list_of_portchannel_members_on_src = (
                bfd_base_instance.extract_backend_portchannels(src_dut)[
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
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
            bfd_base_instance,
            version,
        )
        verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            "Route Addition",
            bfd_base_instance,
            version,
        )

    def test_bfd_config_reload_ipv4(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv4"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(src_dut)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        assert wait_until(
            300,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(src_dut)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        assert wait_until(
            300,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    def test_bfd_config_reload_ipv6(
        self,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv6"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(src_dut)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        assert wait_until(
            300,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(src_dut)

        # Waiting for all processes on Source dut
        wait_critical_processes(src_dut)

        assert wait_until(
            300,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    def test_bfd_with_rp_config_reload_ipv4(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv4"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(rp)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )
        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    def test_bfd_with_rp_config_reload_ipv6(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv6"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source & destination dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(rp)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    def test_bfd_with_bad_fc_asic_ipv4(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv4"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
        for id in asic_ids:
            rp.shell("systemctl stop swss@{}".format(id))

        # Verify that BFD sessions are down
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Down"
            ),
        )

        # Config reload RP to bring up the swss containers
        config_reload(rp)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload RP
        config_reload(rp)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )

    def test_bfd_with_bad_fc_asic_ipv6(
        self,
        localhost,
        duthost,
        request,
        duthosts,
        tbinfo,
        get_src_dst_asic_and_duts,
        bfd_base_instance,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """

        version = "ipv6"

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
            request, get_src_dst_asic_and_duts, bfd_base_instance, version
        )

        # Creation of BFD
        logger.info("BFD addition on source dut")
        bfd_base_instance.add_bfd(src_asic.asic_index, src_prefix, src_dut)

        logger.info("BFD addition on destination dut")
        bfd_base_instance.add_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Verification of BFD session state.
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
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
        for id in asic_ids:
            rp.shell("systemctl stop swss@{}".format(id))

        # Verify that BFD sessions are down
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Down"
            ),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Down"
            ),
        )

        # Config reload RP to bring up the swss containers
        config_reload(rp)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "Up"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "Up"
            ),
        )

        logger.info("BFD deletion on source dut")
        bfd_base_instance.delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        bfd_base_instance.delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload RP
        config_reload(rp)

        # Waiting for all processes on Source & destination dut
        wait_critical_processes(src_dut)
        wait_critical_processes(dst_dut)

        assert wait_until(
            600,
            10,
            0,
            lambda: check_bgp_status(request),
        )

        # Verification of BFD session state.
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                dst_dut, dst_dut_nexthops.values(), dst_asic, "No BFD sessions found"
            ),
        )
        assert wait_until(
            300,
            20,
            0,
            lambda: bfd_base_instance.verify_bfd_state(
                src_dut, src_dut_nexthops.values(), src_asic, "No BFD sessions found"
            ),
        )
