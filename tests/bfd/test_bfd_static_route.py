import pytest
from bfd_base import BfdBase
import logging
import time
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot

pytestmark = [pytest.mark.topology("t2")]

logger = logging.getLogger(__name__)


class TestBfdStaticRoute(BfdBase):
    test_case_status = True
    total_iterations = 100

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
                # config_reload(dut)
                wait_critical_processes(dut)
            # Verification that all BFD sessions are deleted
            for dut in duts:
                asics = [
                    asic.split("asic")[1] for asic in dut.get_asic_namespace_list()
                ]
                for asic in asics:
                    assert wait_until(
                        300,
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
                        300,
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
        ) = self.select_src_dst_dut_with_asic(
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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
        ) = self.select_src_dst_dut_with_asic(
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Removal",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
        )

        assert self.test_case_status, "BFD deletion did not influence static routes"
        logger.info("test_bfd_static_route_deletion completed")

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
        ) = self.select_src_dst_dut_with_asic(
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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
        ) = self.select_src_dst_dut_with_asic(
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Removal",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
        )

        assert self.test_case_status, "BFD deletion did not influence static routes"
        logger.info("test_bfd_static_route_deletion completed")

    def verify_static_route(
        self,
        request,
        asic,
        prefix,
        dut,
        dut_nexthops,
        expected_prefix_state,
        bfd_base_instance,
        version,
    ):
        # Verification of static route
        if version == "ipv4":
            command = "show ip route static"
        elif version == "ipv6":
            command = "show ipv6 route static"
        static_route_output = (
            dut.shell(command, module_ignore_errors=True)["stdout"]
            .encode("utf-8")
            .strip()
            .split("\n")
        )
        asic_routes = bfd_base_instance.extract_routes(static_route_output, version)
        logger.info("Here are asic routes, {}".format(asic_routes))

        if expected_prefix_state == "Route Removal":
            if len(asic_routes) == 0 and request.config.interface_shutdown:
                logger.info("asic routes are empty post interface shutdown")
            else:
                assert len(asic_routes) > 0, "static routes on source dut are empty"
                assert (
                    prefix
                    not in asic_routes.get("asic{}".format(asic.asic_index), {}).keys()
                ), "Prefix removal is not successful. Prefix being validated: {}.".format(
                    prefix
                )
        elif expected_prefix_state == "Route Addition":
            assert (
                prefix in asic_routes.get("asic{}".format(asic.asic_index), {}).keys()
            ), "Prefix has not been added even though BFD is expected. Prefix: {}".format(
                prefix
            )

    def select_src_dst_dut_with_asic(
        self, request, get_src_dst_asic_and_duts, bfd_base_instance, version
    ):
        logger.debug("Selecting source and destination DUTs with ASICs...")
        # Random selection of dut & asic.
        src_asic = get_src_dst_asic_and_duts["src_asic"]
        dst_asic = get_src_dst_asic_and_duts["dst_asic"]
        src_dut = get_src_dst_asic_and_duts["src_dut"]
        dst_dut = get_src_dst_asic_and_duts["dst_dut"]

        logger.info("Source Asic: %s", src_asic)
        logger.info("Destination Asic: %s", dst_asic)
        logger.info("Source dut: %s", src_dut)
        logger.info("Destination dut: %s", dst_dut)

        request.config.src_asic = src_asic
        request.config.dst_asic = dst_asic
        request.config.src_dut = src_dut
        request.config.dst_dut = dst_dut

        # Extracting static routes
        if version == "ipv4":
            static_route_command = "show ip route static"
        elif version == "ipv6":
            static_route_command = "show ipv6 route static"
        src_dut_static_route_output = (
            src_dut.shell(static_route_command, module_ignore_errors=True)["stdout"]
            .encode("utf-8")
            .strip()
            .split("\n")
        )
        src_asic_routes = bfd_base_instance.extract_routes(
            src_dut_static_route_output, version
        )
        logger.info("Source asic routes, {}".format(src_asic_routes))
        assert len(src_asic_routes) > 0, "static routes on source dut are empty"

        dst_dut_static_route_output = (
            dst_dut.shell(static_route_command, module_ignore_errors=True)["stdout"]
            .encode("utf-8")
            .strip()
            .split("\n")
        )
        dst_asic_routes = bfd_base_instance.extract_routes(
            dst_dut_static_route_output, version
        )
        logger.info("Destination asic routes, {}".format(dst_asic_routes))
        assert len(dst_asic_routes) > 0, "static routes on destination dut are empty"

        # Extracting nexthops
        dst_dut_nexthops = (
            bfd_base_instance.extract_ip_addresses_for_backend_portchannels(
                src_dut, src_asic, version
            )
        )
        logger.info("Destination nexthops, {}".format(dst_dut_nexthops))
        assert len(dst_dut_nexthops) != 0, "Destination Nexthops are empty"

        src_dut_nexthops = (
            bfd_base_instance.extract_ip_addresses_for_backend_portchannels(
                dst_dut, dst_asic, version
            )
        )
        logger.info("Source nexthops, {}".format(src_dut_nexthops))
        assert len(src_dut_nexthops) != 0, "Source Nexthops are empty"

        # Picking a static route to delete correspinding BFD session
        src_prefix = bfd_base_instance.selecting_route_to_delete(
            src_asic_routes, src_dut_nexthops.values()
        )
        logger.info("Source prefix: %s", src_prefix)
        request.config.src_prefix = src_prefix
        assert src_prefix is not None and src_prefix != "", "Source prefix not found"

        dst_prefix = bfd_base_instance.selecting_route_to_delete(
            dst_asic_routes, dst_dut_nexthops.values()
        )
        logger.info("Destination prefix: %s", dst_prefix)
        request.config.dst_prefix = dst_prefix
        assert (
            dst_prefix is not None and dst_prefix != ""
        ), "Destination prefix not found"

        return (
            src_asic,
            dst_asic,
            src_dut,
            dst_dut,
            src_dut_nexthops,
            dst_dut_nexthops,
            src_prefix,
            dst_prefix,
        )

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
        ) = self.select_src_dst_dut_with_asic(
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

        for i in range(self.total_iterations):
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
            self.verify_static_route(
                request,
                dst_asic,
                dst_prefix,
                dst_dut,
                dst_dut_nexthops,
                "Route Removal",
                bfd_base_instance,
                version,
            )
            self.verify_static_route(
                request,
                src_asic,
                src_prefix,
                src_dut,
                src_dut_nexthops,
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
            self.verify_static_route(
                request,
                dst_asic,
                dst_prefix,
                dst_dut,
                dst_dut_nexthops,
                "Route Addition",
                bfd_base_instance,
                version,
            )
            self.verify_static_route(
                request,
                src_asic,
                src_prefix,
                src_dut,
                src_dut_nexthops,
                "Route Addition",
                bfd_base_instance,
                version,
            )

            # Check if both iterations were successful and increment the counter
            if self.test_case_status:
                successful_iterations += 1

        # Determine the success rate
        logger.info("successful_iterations: %d", successful_iterations)
        success_rate = (successful_iterations / self.total_iterations) * 100

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
        ) = self.select_src_dst_dut_with_asic(
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

        for i in range(self.total_iterations):
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
            self.verify_static_route(
                request,
                dst_asic,
                dst_prefix,
                dst_dut,
                dst_dut_nexthops,
                "Route Removal",
                bfd_base_instance,
                version,
            )
            self.verify_static_route(
                request,
                src_asic,
                src_prefix,
                src_dut,
                src_dut_nexthops,
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
            self.verify_static_route(
                request,
                dst_asic,
                dst_prefix,
                dst_dut,
                dst_dut_nexthops,
                "Route Addition",
                bfd_base_instance,
                version,
            )
            self.verify_static_route(
                request,
                src_asic,
                src_prefix,
                src_dut,
                src_dut_nexthops,
                "Route Addition",
                bfd_base_instance,
                version,
            )

            # Check if both iterations were successful and increment the counter
            if self.test_case_status:
                successful_iterations += 1

        # Determine the success rate
        logger.info("successful_iterations: %d", successful_iterations)
        success_rate = (successful_iterations / self.total_iterations) * 100

        logger.info("Current success rate: %.2f%%", success_rate)
        # Check if the success rate is above the threshold (e.g., 98%)
        assert (
            success_rate >= 98
        ), "BFD flap verification success rate is below 98% ({}%)".format(success_rate)

        logger.info("test_bfd_flap completed")

    def control_interface_state(self, dut, asic, bfd_base_instance, interface, action):
        int_status = dut.show_interface(
            command="status", include_internal_intfs=True, asic_index=asic.asic_index
        )["ansible_facts"]["int_status"][interface]
        oper_state = int_status["oper_state"]
        if action == "shutdown":
            target_state = "down"
        elif action == "startup":
            target_state = "up"

        if oper_state != target_state:
            command = "shutdown" if action == "shutdown" else "startup"
            exec_cmd = (
                "sudo ip netns exec asic{} config interface -n asic{} {} {}".format(
                    asic.asic_index, asic.asic_index, command, interface
                )
            )
            logger.info("Command: {}".format(exec_cmd))
            logger.info("Target state: {}".format(target_state))
            dut.shell(exec_cmd)
            assert wait_until(
                180,
                10,
                0,
                lambda: dut.show_interface(
                    command="status",
                    include_internal_intfs=True,
                    asic_index=asic.asic_index,
                )["ansible_facts"]["int_status"][interface]["oper_state"]
                == target_state,
            )
        else:
            raise ValueError("Invalid action specified")

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
        ) = self.select_src_dst_dut_with_asic(
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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
        ) = self.select_src_dst_dut_with_asic(
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
            self.control_interface_state(
                dst_dut, dst_asic, bfd_base_instance, interface, action
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
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
            "Route Removal",
            bfd_base_instance,
            version,
        )

        for interface in list_of_portchannels_on_dst:
            action = "startup"
            self.control_interface_state(
                dst_dut, dst_asic, bfd_base_instance, interface, action
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
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
        ) = self.select_src_dst_dut_with_asic(
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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
        ) = self.select_src_dst_dut_with_asic(
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
            self.control_interface_state(
                dst_dut, dst_asic, bfd_base_instance, interface, action
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
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
            "Route Removal",
            bfd_base_instance,
            version,
        )

        for interface in list_of_portchannels_on_dst:
            action = "startup"
            self.control_interface_state(
                dst_dut, dst_asic, bfd_base_instance, interface, action
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
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
        ) = self.select_src_dst_dut_with_asic(
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
            self.control_interface_state(
                src_dut, src_asic, bfd_base_instance, interface, action
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Removal",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
            "Route Removal",
            bfd_base_instance,
            version,
        )

        for interface in list_of_portchannels_on_src:
            action = "startup"
            self.control_interface_state(
                src_dut, src_asic, bfd_base_instance, interface, action
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
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
        ) = self.select_src_dst_dut_with_asic(
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
            self.control_interface_state(
                src_dut, src_asic, bfd_base_instance, interface, action
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Removal",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
            "Route Removal",
            bfd_base_instance,
            version,
        )

        for interface in list_of_portchannels_on_src:
            action = "startup"
            self.control_interface_state(
                src_dut, src_asic, bfd_base_instance, interface, action
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
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
        ) = self.select_src_dst_dut_with_asic(
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
                self.control_interface_state(
                    src_dut, src_asic, bfd_base_instance, each_member, action
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Removal",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
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
                self.control_interface_state(
                    src_dut, src_asic, bfd_base_instance, each_member, action
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
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
        ) = self.select_src_dst_dut_with_asic(
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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
        ) = self.select_src_dst_dut_with_asic(
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
                self.control_interface_state(
                    src_dut, src_asic, bfd_base_instance, each_member, action
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Removal",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
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
                self.control_interface_state(
                    src_dut, src_asic, bfd_base_instance, each_member, action
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
        self.verify_static_route(
            request,
            dst_asic,
            dst_prefix,
            dst_dut,
            dst_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
        )
        self.verify_static_route(
            request,
            src_asic,
            src_prefix,
            src_dut,
            src_dut_nexthops,
            "Route Addition",
            bfd_base_instance,
            version,
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
        ) = self.select_src_dst_dut_with_asic(
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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
        ) = self.select_src_dst_dut_with_asic(
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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
        ) = self.select_src_dst_dut_with_asic(
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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
        ) = self.select_src_dst_dut_with_asic(
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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
        ) = self.select_src_dst_dut_with_asic(
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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

        check_bgp = request.getfixturevalue("check_bgp")
        results = check_bgp()
        failed = [
            result for result in results if "failed" in result and result["failed"]
        ]
        if failed:
            pytest.fail(
                "BGP check failed, not all BGP sessions are up. Failed: {}".format(
                    failed
                )
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
