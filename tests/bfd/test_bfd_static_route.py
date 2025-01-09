import logging
import time

import pytest

from tests.bfd.bfd_base import BfdBase
from tests.bfd.bfd_helpers import check_bgp_status, add_bfd, delete_bfd, extract_backend_portchannels, \
    batch_control_interface_state, create_and_verify_bfd_state, verify_bfd_and_static_route, verify_bfd_only
from tests.common.config_reload import config_reload
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot

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

    def test_bfd_with_lc_reboot(self, localhost, request, select_src_dst_dut_with_asic, bfd_cleanup_db):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        src_asic = select_src_dst_dut_with_asic["src_asic"]
        dst_asic = select_src_dst_dut_with_asic["dst_asic"]
        src_dut = select_src_dst_dut_with_asic["src_dut"]
        dst_dut = select_src_dst_dut_with_asic["dst_dut"]
        src_dut_nexthops = select_src_dst_dut_with_asic["src_dut_nexthops"]
        dst_dut_nexthops = select_src_dst_dut_with_asic["dst_dut_nexthops"]
        src_prefix = select_src_dst_dut_with_asic["src_prefix"]
        dst_prefix = select_src_dst_dut_with_asic["dst_prefix"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_dut, src_dut_nexthops),
            ("dst", dst_asic, dst_prefix, dst_dut, dst_dut_nexthops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, dut_nexthops)

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Perform a cold reboot on source dut
        reboot(src_dut, localhost, safe_reboot=True)

        check_bgp_status(request)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "Up")

        logger.info("BFD deletion on source & destination dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Save the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        reboot(src_dut, localhost, safe_reboot=True)

        check_bgp_status(request)

        # Verification of BFD session state.
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "No BFD sessions found")

    def test_bfd_static_route_deletion(self, request, select_src_dst_dut_with_asic, bfd_cleanup_db):
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
        src_asic = select_src_dst_dut_with_asic["src_asic"]
        dst_asic = select_src_dst_dut_with_asic["dst_asic"]
        src_dut = select_src_dst_dut_with_asic["src_dut"]
        dst_dut = select_src_dst_dut_with_asic["dst_dut"]
        src_dut_nexthops = select_src_dst_dut_with_asic["src_dut_nexthops"]
        dst_dut_nexthops = select_src_dst_dut_with_asic["dst_dut_nexthops"]
        src_prefix = select_src_dst_dut_with_asic["src_prefix"]
        dst_prefix = select_src_dst_dut_with_asic["dst_prefix"]
        version = select_src_dst_dut_with_asic["version"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_dut, src_dut_nexthops),
            ("dst", dst_asic, dst_prefix, dst_dut, dst_dut_nexthops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, dut_nexthops)

        logger.info("BFD deletion on source dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for target, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(
                    verify_bfd_and_static_route,
                    dut,
                    dut_nexthops,
                    asic,
                    "No BFD sessions found" if target == "src" else "Down",
                    request,
                    prefix,
                    "Route Addition" if target == "src" else "Route Removal",
                    version,
                )

        logger.info("BFD deletion on destination dut")
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for target, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(
                    verify_bfd_and_static_route,
                    dut,
                    dut_nexthops,
                    asic,
                    "No BFD sessions found",
                    request,
                    prefix,
                    "Route Addition",
                    version,
                )

        logger.info("BFD deletion did not influence static routes and test completed successfully")

    def test_bfd_flap(
        self,
        request,
        select_src_dst_dut_with_asic,
        bfd_cleanup_db,
        get_function_completeness_level,
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
        src_asic = select_src_dst_dut_with_asic["src_asic"]
        dst_asic = select_src_dst_dut_with_asic["dst_asic"]
        src_dut = select_src_dst_dut_with_asic["src_dut"]
        dst_dut = select_src_dst_dut_with_asic["dst_dut"]
        src_dut_nexthops = select_src_dst_dut_with_asic["src_dut_nexthops"]
        dst_dut_nexthops = select_src_dst_dut_with_asic["dst_dut_nexthops"]
        src_prefix = select_src_dst_dut_with_asic["src_prefix"]
        dst_prefix = select_src_dst_dut_with_asic["dst_prefix"]
        version = select_src_dst_dut_with_asic["version"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_dut, src_dut_nexthops),
            ("dst", dst_asic, dst_prefix, dst_dut, dst_dut_nexthops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, dut_nexthops)

        completeness_level = get_function_completeness_level
        if completeness_level is None:
            completeness_level = "debug"

        total_iterations = self.COMPLETENESS_TO_ITERATIONS[completeness_level]
        successful_iterations = 0  # Counter for successful iterations
        for i in range(total_iterations):
            logger.info("Iteration {}".format(i))

            logger.info("BFD deletion on source dut")
            delete_bfd(src_asic.asic_index, src_prefix, src_dut)

            logger.info("Waiting for 5s post BFD shutdown")
            time.sleep(5)

            logger.info("BFD & Static route verifications")
            with SafeThreadPoolExecutor(max_workers=8) as executor:
                for target, asic, prefix, dut, dut_nexthops in src_dst_context:
                    executor.submit(
                        verify_bfd_and_static_route,
                        dut,
                        dut_nexthops,
                        asic,
                        "No BFD sessions found" if target == "src" else "Down",
                        request,
                        prefix,
                        "Route Addition" if target == "src" else "Route Removal",
                        version,
                    )

            logger.info("BFD addition on source dut")
            add_bfd(src_asic.asic_index, src_prefix, src_dut)

            with SafeThreadPoolExecutor(max_workers=8) as executor:
                for target, asic, prefix, dut, dut_nexthops in src_dst_context:
                    executor.submit(
                        verify_bfd_and_static_route,
                        dut,
                        dut_nexthops,
                        asic,
                        "Up",
                        request,
                        prefix,
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

    def test_bfd_with_rp_reboot(
        self,
        localhost,
        request,
        duthosts,
        enum_supervisor_dut_hostname,
        select_src_dst_dut_with_asic,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        rp = duthosts[enum_supervisor_dut_hostname]

        src_asic = select_src_dst_dut_with_asic["src_asic"]
        dst_asic = select_src_dst_dut_with_asic["dst_asic"]
        src_dut = select_src_dst_dut_with_asic["src_dut"]
        dst_dut = select_src_dst_dut_with_asic["dst_dut"]
        src_dut_nexthops = select_src_dst_dut_with_asic["src_dut_nexthops"]
        dst_dut_nexthops = select_src_dst_dut_with_asic["dst_dut_nexthops"]
        src_prefix = select_src_dst_dut_with_asic["src_prefix"]
        dst_prefix = select_src_dst_dut_with_asic["dst_prefix"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_dut, src_dut_nexthops),
            ("dst", dst_asic, dst_prefix, dst_dut, dst_dut_nexthops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, dut_nexthops)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Perform a cold reboot on RP
        reboot(rp, localhost, safe_reboot=True)

        # Waiting for all processes on Source & destination dut
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, _, _, dut, _ in src_dst_context:
                executor.submit(wait_critical_processes, dut)

        check_bgp_status(request)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "Up")

        logger.info("BFD deletion on source & destination dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Perform a cold reboot on RP
        reboot(rp, localhost, safe_reboot=True)

        # Waiting for all processes on Source & destination dut
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, _, _, dut, _ in src_dst_context:
                executor.submit(wait_critical_processes, dut)

        check_bgp_status(request)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "No BFD sessions found")

    def test_bfd_remote_link_flap(self, request, select_src_dst_dut_with_asic, bfd_cleanup_db):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        request.config.interface_shutdown = True

        src_asic = select_src_dst_dut_with_asic["src_asic"]
        dst_asic = select_src_dst_dut_with_asic["dst_asic"]
        src_dut = select_src_dst_dut_with_asic["src_dut"]
        dst_dut = select_src_dst_dut_with_asic["dst_dut"]
        src_dut_nexthops = select_src_dst_dut_with_asic["src_dut_nexthops"]
        dst_dut_nexthops = select_src_dst_dut_with_asic["dst_dut_nexthops"]
        src_prefix = select_src_dst_dut_with_asic["src_prefix"]
        dst_prefix = select_src_dst_dut_with_asic["dst_prefix"]
        version = select_src_dst_dut_with_asic["version"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_dut, src_dut_nexthops),
            ("dst", dst_asic, dst_prefix, dst_dut, dst_dut_nexthops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, dut_nexthops)

        # Extract portchannel interfaces on dst
        list_of_portchannels_on_dst = src_dut_nexthops.keys()
        request.config.portchannels_on_dut = "dst"
        request.config.selected_portchannels = list_of_portchannels_on_dst

        # Shutdown PortChannels on destination dut
        batch_control_interface_state(dst_dut, dst_asic, list_of_portchannels_on_dst, "shutdown")

        # Verification of BFD session state on src dut
        verify_bfd_and_static_route(
            src_dut,
            src_dut_nexthops,
            src_asic,
            "Down",
            request,
            src_prefix,
            "Route Removal",
            version,
        )

        batch_control_interface_state(dst_dut, dst_asic, list_of_portchannels_on_dst, "startup")
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(
                    verify_bfd_and_static_route,
                    dut,
                    dut_nexthops,
                    asic,
                    "Up",
                    request,
                    prefix,
                    "Route Addition",
                    version,
                )

    def test_bfd_lc_asic_shutdown(self, request, select_src_dst_dut_with_asic, bfd_cleanup_db):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        request.config.interface_shutdown = True

        src_asic = select_src_dst_dut_with_asic["src_asic"]
        dst_asic = select_src_dst_dut_with_asic["dst_asic"]
        src_dut = select_src_dst_dut_with_asic["src_dut"]
        dst_dut = select_src_dst_dut_with_asic["dst_dut"]
        src_dut_nexthops = select_src_dst_dut_with_asic["src_dut_nexthops"]
        dst_dut_nexthops = select_src_dst_dut_with_asic["dst_dut_nexthops"]
        src_prefix = select_src_dst_dut_with_asic["src_prefix"]
        dst_prefix = select_src_dst_dut_with_asic["dst_prefix"]
        version = select_src_dst_dut_with_asic["version"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_dut, src_dut_nexthops),
            ("dst", dst_asic, dst_prefix, dst_dut, dst_dut_nexthops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, dut_nexthops)

        # Extract portchannel interfaces on src
        list_of_portchannels_on_src = dst_dut_nexthops.keys()
        request.config.portchannels_on_dut = "src"
        request.config.selected_portchannels = list_of_portchannels_on_src

        # Shutdown PortChannels
        batch_control_interface_state(src_dut, src_asic, list_of_portchannels_on_src, "shutdown")

        # Verify BFD and static routes
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(
                    verify_bfd_and_static_route,
                    dut,
                    dut_nexthops,
                    asic,
                    "Down",
                    request,
                    prefix,
                    "Route Removal",
                    version,
                )

        batch_control_interface_state(src_dut, src_asic, list_of_portchannels_on_src, "startup")

        # Verify BFD and static routes.
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(
                    verify_bfd_and_static_route,
                    dut,
                    dut_nexthops,
                    asic,
                    "Up",
                    request,
                    prefix,
                    "Route Addition",
                    version,
                )

    def test_bfd_portchannel_member_flap(self, request, select_src_dst_dut_with_asic, bfd_cleanup_db):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        request.config.interface_shutdown = True

        src_asic = select_src_dst_dut_with_asic["src_asic"]
        dst_asic = select_src_dst_dut_with_asic["dst_asic"]
        src_dut = select_src_dst_dut_with_asic["src_dut"]
        dst_dut = select_src_dst_dut_with_asic["dst_dut"]
        src_dut_nexthops = select_src_dst_dut_with_asic["src_dut_nexthops"]
        dst_dut_nexthops = select_src_dst_dut_with_asic["dst_dut_nexthops"]
        src_prefix = select_src_dst_dut_with_asic["src_prefix"]
        dst_prefix = select_src_dst_dut_with_asic["dst_prefix"]
        version = select_src_dst_dut_with_asic["version"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_dut, src_dut_nexthops),
            ("dst", dst_asic, dst_prefix, dst_dut, dst_dut_nexthops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, dut_nexthops)

        # Extract portchannel interfaces on src
        list_of_portchannels_on_src = dst_dut_nexthops.keys()
        request.config.portchannels_on_dut = "src"
        request.config.selected_portchannels = list_of_portchannels_on_src

        # Shutdown PortChannel members
        port_channel_members_on_src = []
        for portchannel_interface in list_of_portchannels_on_src:
            list_of_portchannel_members_on_src = (
                extract_backend_portchannels(src_dut)[portchannel_interface]["members"]
            )

            port_channel_members_on_src.extend(list_of_portchannel_members_on_src)

        request.config.selected_portchannel_members = port_channel_members_on_src
        batch_control_interface_state(src_dut, src_asic, port_channel_members_on_src, "shutdown")

        # Verify BFD and static routes
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(
                    verify_bfd_and_static_route,
                    dut,
                    dut_nexthops,
                    asic,
                    "Down",
                    request,
                    prefix,
                    "Route Removal",
                    version,
                )

        # Bring up of PortChannel members
        batch_control_interface_state(src_dut, src_asic, port_channel_members_on_src, "startup")

        # Verify BFD and static routes
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(
                    verify_bfd_and_static_route,
                    dut,
                    dut_nexthops,
                    asic,
                    "Up",
                    request,
                    prefix,
                    "Route Addition",
                    version,
                )

    def test_bfd_config_reload(self, request, select_src_dst_dut_with_asic, bfd_cleanup_db):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        src_asic = select_src_dst_dut_with_asic["src_asic"]
        dst_asic = select_src_dst_dut_with_asic["dst_asic"]
        src_dut = select_src_dst_dut_with_asic["src_dut"]
        dst_dut = select_src_dst_dut_with_asic["dst_dut"]
        src_dut_nexthops = select_src_dst_dut_with_asic["src_dut_nexthops"]
        dst_dut_nexthops = select_src_dst_dut_with_asic["dst_dut_nexthops"]
        src_prefix = select_src_dst_dut_with_asic["src_prefix"]
        dst_prefix = select_src_dst_dut_with_asic["dst_prefix"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_dut, src_dut_nexthops),
            ("dst", dst_asic, dst_prefix, dst_dut, dst_dut_nexthops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, dut_nexthops)

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(src_dut, safe_reload=True)

        check_bgp_status(request)

        # Verification of BFD session state.
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "Up")

        logger.info("BFD deletion on source & destination dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")

        # Config reload of Source dut
        config_reload(src_dut, safe_reload=True)

        check_bgp_status(request)

        # Verification of BFD session state.
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "No BFD sessions found")

    def test_bfd_with_rp_config_reload(
        self,
        request,
        duthosts,
        select_src_dst_dut_with_asic,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        rp = duthosts[enum_supervisor_dut_hostname]

        src_asic = select_src_dst_dut_with_asic["src_asic"]
        dst_asic = select_src_dst_dut_with_asic["dst_asic"]
        src_dut = select_src_dst_dut_with_asic["src_dut"]
        dst_dut = select_src_dst_dut_with_asic["dst_dut"]
        src_dut_nexthops = select_src_dst_dut_with_asic["src_dut_nexthops"]
        dst_dut_nexthops = select_src_dst_dut_with_asic["dst_dut_nexthops"]
        src_prefix = select_src_dst_dut_with_asic["src_prefix"]
        dst_prefix = select_src_dst_dut_with_asic["dst_prefix"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_dut, src_dut_nexthops),
            ("dst", dst_asic, dst_prefix, dst_dut, dst_dut_nexthops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, dut_nexthops)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload of RP
        config_reload(rp, safe_reload=True)

        # Waiting for all processes on Source & destination dut
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, _, _, dut, _ in src_dst_context:
                executor.submit(wait_critical_processes, dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "Up")

        logger.info("BFD deletion on source & destination dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload of RP
        config_reload(rp, safe_reload=True)

        # Waiting for all processes on Source & destination dut
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, _, _, dut, _ in src_dst_context:
                executor.submit(wait_critical_processes, dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "No BFD sessions found")

    def test_bfd_with_bad_fc_asic(
        self,
        request,
        duthosts,
        select_src_dst_dut_with_asic,
        enum_supervisor_dut_hostname,
        bfd_cleanup_db,
    ):
        """
        Author:  Harsha Golla
        Email : harsgoll@cisco.com
        """
        rp = duthosts[enum_supervisor_dut_hostname]

        src_asic = select_src_dst_dut_with_asic["src_asic"]
        dst_asic = select_src_dst_dut_with_asic["dst_asic"]
        src_dut = select_src_dst_dut_with_asic["src_dut"]
        dst_dut = select_src_dst_dut_with_asic["dst_dut"]
        src_dut_nexthops = select_src_dst_dut_with_asic["src_dut_nexthops"]
        dst_dut_nexthops = select_src_dst_dut_with_asic["dst_dut_nexthops"]
        src_prefix = select_src_dst_dut_with_asic["src_prefix"]
        dst_prefix = select_src_dst_dut_with_asic["dst_prefix"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_dut, src_dut_nexthops),
            ("dst", dst_asic, dst_prefix, dst_dut, dst_dut_nexthops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, dut, dut_nexthops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, dut_nexthops)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Extract asic ids
        docker_output = rp.shell("docker ps | grep swss | awk '{print $NF}'")[
            "stdout"
        ].split("\n")
        asic_ids = [int(element.split("swss")[1]) for element in docker_output]

        # Shut down corresponding asic on supervisor to simulate bad asic
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for asic_id in asic_ids:
                executor.submit(rp.shell, "systemctl stop swss@{}".format(asic_id))

        # Verify that BFD sessions are down
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "Down")

        # Config reload RP to bring up the swss containers
        config_reload(rp, safe_reload=True)

        # Waiting for all processes on Source & destination dut
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, _, _, dut, _ in src_dst_context:
                executor.submit(wait_critical_processes, dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "Up")

        logger.info("BFD deletion on source dut")
        delete_bfd(src_asic.asic_index, src_prefix, src_dut)
        delete_bfd(dst_asic.asic_index, dst_prefix, dst_dut)

        # Savings the configs
        src_dut.shell("sudo config save -y")
        dst_dut.shell("sudo config save -y")

        # Config reload RP
        config_reload(rp, safe_reload=True)

        # Waiting for all processes on Source & destination dut
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, _, _, dut, _ in src_dst_context:
                executor.submit(wait_critical_processes, dut)

        check_bgp_status(request)

        # Verification of BFD session state.
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, dut, dut_nexthops in src_dst_context:
                executor.submit(verify_bfd_only, dut, dut_nexthops, asic, "No BFD sessions found")
