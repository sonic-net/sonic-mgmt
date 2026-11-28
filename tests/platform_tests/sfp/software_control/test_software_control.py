import pytest
import logging
import random
import tests.platform_tests.mellanox.software_control_helper as helpers
from tests.platform_tests.mellanox import software_control_constants as sc_const
from tests.platform_tests.sfp.util import get_sfp_type_per_interface, write_eeprom_by_page_and_byte, \
    DICT_WRITABLE_BYTE_FOR_PAGE_0, read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.platform.transceiver_utils import get_passive_cable_port_list
from tests.common.platform.interface_utils import get_lport_to_first_subport_mapping, get_xcvr_presence_data
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.mellanox_data import get_service_ports
from tests.platform_tests.conftest import check_pmon_uptime_minutes
import re


pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger()


class TestSoftwareControlFunctional:

    @pytest.fixture(autouse=True)
    def setup(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, conn_graph_facts):
        self.duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        # Check Software Control enabled in sai.profile. If not - whole test suite will be skipped
        if not helpers.check_sc_sai_attribute_value(self.duthost):
            pytest.skip("SW control feature is not enabled in sai.profile")
        self.enum_frontend_asic_index = enum_frontend_asic_index
        self.conn_graph_facts = conn_graph_facts
        self.sc_port_list = helpers.get_ports_supporting_sc(self.duthost, only_ports_index_up=True)

    @pytest.fixture(autouse=True)
    def verify_pmon_uptime(self):
        pytest_assert(wait_until(360, 10, 0, check_pmon_uptime_minutes, self.duthost),
                      "Pmon docker is not ready for test")

    def test_all_modules_in_software_control_mode(self):
        """
        @summary: When CMIS host management is enabled every physically-present
        module must be in software control (``control == 1``).

        Uses ``show interface transceiver presence`` (via ``get_xcvr_presence_data``)
        to determine which modules are physically present, and
        ``get_ports_supporting_sc`` to obtain the list of ports whose sysfs
        ``control`` file equals ``1``.
        """
        hostname = self.duthost.hostname
        ports_presence_status = get_xcvr_presence_data(self.duthost)
        sw_control_ports = set(helpers.get_ports_supporting_sc(self.duthost))
        present_ports = {port for port, is_present in ports_presence_status.items() if is_present}
        service_ports = set(get_service_ports(self.duthost.facts["platform"]))
        violations = sorted(present_ports - sw_control_ports - service_ports)

        assert not violations, (
            f"{len(violations)} present module(s) not in software control "
            f"on [{hostname}]: {', '.join(violations)}"
        )

    def test_sc_check_show_interfaces_transceiver_eeprom(self):
        """
        @summary: Check SFP transceiver info using 'show interface transceiver eeprom'
        """
        sfp_show_eeprom_all_interfaces = self.duthost.command(f"{sc_const.CMD_INTERFACE_TRANSCEIVER}")
        parsed_eeprom_output_all_interfaces = helpers.parse_all_interfaces_eeprom_output_to_dict(
            sfp_show_eeprom_all_interfaces["stdout"])
        for port in self.sc_port_list:
            parsed_eeprom = helpers.parse_sc_eeprom(parsed_eeprom_output_all_interfaces[port])
            helpers.cleanup_placeholder(parsed_eeprom, "Vendor Date Code(YYYY-MM-DD Lot)")
            redis_output = helpers.transform_redis_transceiver_data(
                self.duthost, "TRANSCEIVER_INFO", self.enum_frontend_asic_index, [port])

            # Compare information from eeprom and redis
            helpers.compare_data_from_cli_and_redis(parsed_eeprom, redis_output, port, sc_const.EEPROM_TO_REDIS_KEY_MAP)

    def test_check_sc_sfputil_eeprom_params(self):
        """
        @summary: Check sfputils eeprom output with  Independent Module enabled
        """
        present = set(helpers.get_platform_sfputil_ports(self.duthost))
        ports = [port for port in self.sc_port_list if port in present]
        sfp_show_eeprom_all_interfaces = self.duthost.command(f"{sc_const.CMD_SFPUTIL_EEPROM}")
        parsed_eeprom_output_all_interfaces = helpers.parse_all_interfaces_eeprom_output_to_dict(
            sfp_show_eeprom_all_interfaces["stdout"])
        for port in ports:
            parsed_eeprom = helpers.parse_sc_eeprom(parsed_eeprom_output_all_interfaces[port])
            helpers.cleanup_placeholder(parsed_eeprom, "Vendor Date Code(YYYY-MM-DD Lot)")
            redis_output = helpers.transform_redis_transceiver_data(
                self.duthost, "TRANSCEIVER_INFO", self.enum_frontend_asic_index, [port])

            # Compare information from eeprom and redis
            helpers.compare_data_from_cli_and_redis(parsed_eeprom, redis_output, port, sc_const.EEPROM_TO_REDIS_KEY_MAP)

    def test_sc_check_show_interfaces_transceiver_status(self):
        """
        @summary: Check SFP transceiver info using 'show interface transceiver status'
        """
        sff_cables = helpers.get_sff_cables(
            self.duthost, "TRANSCEIVER_INFO", self.enum_frontend_asic_index, self.sc_port_list)
        show_transceiver_status_all_interfaces = self.duthost.command(f"{sc_const.CMD_INTERFACE_TRANSCEIVER_STATUS}")
        parsed_transceiver_status_all_interfaces = helpers.parse_all_interfaces_eeprom_output_to_dict(
            show_transceiver_status_all_interfaces["stdout"])
        lport_to_first_subport_mapping = get_lport_to_first_subport_mapping(self.duthost, self.sc_port_list)
        for port in set(lport_to_first_subport_mapping.values()):
            redis_output = helpers.transform_redis_transceiver_data(
                self.duthost, "TRANSCEIVER_STATUS", self.enum_frontend_asic_index, [port])
            if port in sff_cables:
                logger.info(f"Port {port} has SFF cable connected, skip for this test")
                continue
            parsed_tranceiver_status = helpers.parse_sc_transceiver_status(
                parsed_transceiver_status_all_interfaces[port])
            # Compare information from cli and redis
            for cli_eeprom_key, redis_key in sc_const.TRANSCEIVER_STATUS_TO_REDIS_KEY_MAP.items():
                assert parsed_tranceiver_status[cli_eeprom_key] == redis_output[port][redis_key], \
                    f"Data from cli param {cli_eeprom_key} does not data from redis"

    def test_sc_ber(self):
        """
        @summary: Check that BER per Software Control module is not bigger than cable BER threshold
        """
        for port in list(self.sc_port_list):
            # These part numbers report bad BER while the module is in software control.
            redis_output = helpers.transform_redis_transceiver_data(
                self.duthost, "TRANSCEIVER_INFO", self.enum_frontend_asic_index, [port]
            )
            model = redis_output.get(port, {}).get(sc_const.SC_REDIS_VENDOR_PM_KEY, "").strip()
            if model in {"FCBN950QE2C06-MS", "FCBN950QE2C08-MS", "FCBN950QE2C10-MS"}:
                self.sc_port_list.remove(port)
                logger.warning("Exclude {} from BER check for part number {}".format(port, model))

        mlxlink_ber_all_interfaces = helpers.get_mlxlink_ber_all_interfaces(self.duthost, self.sc_port_list)
        for port in self.sc_port_list:
            mlxlink_output = mlxlink_ber_all_interfaces[port]
            assert int(mlxlink_output[sc_const.BER_EFFECTIVE_PHYSICAL_ERRORS]) == 0, \
                f"{sc_const.BER_EFFECTIVE_PHYSICAL_ERRORS} > 0 "
            assert mlxlink_output[sc_const.BER_EFFECTIVE_PHYSICAL_BER] == '15E-255', \
                f"{sc_const.BER_EFFECTIVE_PHYSICAL_BER} > 15E-255"

    def test_sc_mlxlink_serdes_tx(self):
        """
        @summary: Verify mlxlink --show_serdes_tx for all software-control ports.

        Coverage table: command must Pass (no SERDES lane transmit or register Errors). Also verify
        the SERDES TX section is present and each lane row matches the dynamic
        parameter header (names differ by SPC generation).
        """
        mlxlink_serdes_tx_all_interfaces = helpers.get_mlxlink_serdes_tx_all_interfaces(self.duthost, self.sc_port_list)
        for port in self.sc_port_list:
            with allure.step(f"Verify SERDES TX output for port {port}"):
                serdes_tx_output = mlxlink_serdes_tx_all_interfaces[port]
                assert serdes_tx_output, f"No SERDES TX output received for port {port}"
                helpers.assert_mlxlink_no_tool_errors(serdes_tx_output, port, "--show_serdes_tx")
                parsed = helpers.parse_mlxlink_serdes_tx(serdes_tx_output)
                assert parsed, (
                    f"SERDES TX section not found for port {port}. "
                    f"Expected '{sc_const.MLXLINK_SERDES_TX_SECTION}' and "
                    f"'Serdes TX parameters'"
                )
                parameters = parsed["parameters"]
                lanes = parsed["lanes"]
                assert parameters, f"No SERDES TX parameter names for port {port}"
                assert lanes, f"No SERDES TX lanes for port {port}"
                for lane_id, values in lanes.items():
                    assert len(values) == len(parameters), (
                        f"Port {port} lane {lane_id}: expected {len(parameters)} values "
                        f"for {parameters}, got {len(values)} ({values})"
                    )
                logger.info(
                    f"SERDES TX parameters successfully retrieved for port {port}: "
                    f"{len(parameters)} parameters, {len(lanes)} lane(s)"
                )

    def test_sc_mlxlink_rx_fec_histogram(self):
        """
        @summary: Verify mlxlink --rx_fec_histogram --show_histogram on SC ports
        that run a histogram-capable FEC.

        Coverage table: command must Pass (empty Errors section). Ports with
        active FEC "No FEC" are skipped. RS-FEC ports must return
        'Histogram of FEC Errors' with parseable bins (at least Bin 0 and
        Bin 1). Occurrence values are not used as a pass/fail threshold.
        """
        mlxlink_rx_fec_histogram_all_interfaces = helpers.get_mlxlink_rx_fec_histogram_all_interfaces(
            self.duthost, self.sc_port_list)
        histogram_checked = 0
        for port in self.sc_port_list:
            with allure.step(f"Verify RX FEC histogram output for port {port}"):
                rx_fec_histogram_output = mlxlink_rx_fec_histogram_all_interfaces[port]
                assert rx_fec_histogram_output, f"No RX FEC histogram output received for port {port}"
                if helpers.is_mlxlink_fec_histogram_unsupported(rx_fec_histogram_output):
                    fec = helpers.get_mlxlink_operational_fec(rx_fec_histogram_output)
                    logger.warning(
                        f"Skip RX FEC histogram check for port {port}: active FEC is '{fec}' "
                        "(mlxlink has no histogram for this FEC)"
                    )
                    continue
                helpers.assert_mlxlink_no_tool_errors(rx_fec_histogram_output, port, "RX FEC histogram")
                parsed = helpers.parse_mlxlink_rx_fec_histogram(rx_fec_histogram_output)
                assert parsed, (
                    f"FEC histogram section not found for port {port}. "
                    f"Expected '{sc_const.MLXLINK_RX_FEC_HISTOGRAM_SECTION}', "
                    f"'Header : Range Occurrences', and parseable Bin rows"
                )
                bins = parsed["bins"]
                bin_ids = sorted(bins)
                assert bin_ids[0] == 0 and len(bin_ids) >= 2, (
                    f"Port {port}: expected consecutive bins starting at 0 "
                    f"with at least Bin 0 and Bin 1, got {bin_ids}"
                )
                assert bin_ids == list(range(len(bin_ids))), (
                    f"Port {port}: histogram bins are not consecutive: {bin_ids}"
                )
                logger.info(
                    f"RX FEC histogram successfully retrieved for port {port}: "
                    f"{len(bins)} bin(s)"
                )
                histogram_checked += 1
        if not histogram_checked:
            pytest.skip("No software-control ports with histogram-capable FEC")

    def test_sc_mlxlink_cable_dump(self):
        """
        @summary: On software control, mlxlink --cable --dump is expected to Fail.

        Coverage table: Fail after Operational Info with PDDR / Register not
        supported. EEPROM-dump exceptions are the same SC block on some ASICs.
        'No plugged cable detected' counts only when the module is present.
        Empty cages are skipped. Page: 0x (successful dump) must Fail the test.
        """
        if not self.sc_port_list:
            pytest.skip("No software-control ports available for cable dump test")
        ports_presence_status = get_xcvr_presence_data(self.duthost)
        mlxlink_cable_dump_all_interfaces = helpers.get_mlxlink_cable_dump_all_interfaces(
            self.duthost, self.sc_port_list)
        dump_checked = 0
        for port in self.sc_port_list:
            with allure.step(f"Verify cable dump expected Fail for port {port}"):
                cable_dump_output = mlxlink_cable_dump_all_interfaces[port]
                assert cable_dump_output, f"No cable dump output received for port {port}"
                assert sc_const.MLXLINK_CABLE_DUMP_PAGE_MARKER not in cable_dump_output, (
                    f"SC mlxlink --cable --dump must not dump EEPROM pages for port {port}"
                )
                module_present = ports_presence_status.get(port, False)
                if helpers.is_mlxlink_sc_cable_dump_no_cable(cable_dump_output) and not module_present:
                    logger.warning(
                        f"Skip cable dump check for port {port}: cage is empty "
                        "(mlxlink 'No plugged cable detected' is not SC coverage)"
                    )
                    continue
                assert sc_const.MLXLINK_OPERATIONAL_INFO in cable_dump_output, (
                    f"Expected Operational Info before Errors for port {port}"
                )
                tool_errors = helpers.get_mlxlink_tool_errors(cable_dump_output)
                assert tool_errors, (
                    f"Expected mlxlink Errors section for SC --cable --dump on port {port}"
                )
                assert helpers.is_mlxlink_sc_cable_dump_expected_fail(
                    cable_dump_output, module_present=module_present
                ), (
                    f"Expected SC mlxlink --cable --dump to fail with PDDR/"
                    f"register-not-supported or EEPROM-dump exception for port {port}, "
                    f"got: {cable_dump_output}"
                )
                logger.info(f"SC cable dump failed as expected for port {port}")
                dump_checked += 1
        if not dump_checked:
            pytest.skip("No software-control ports with a present module for cable dump test")

    def test_sc_mlxlink_show_counters(self):
        """
        @summary: Verify mlxlink --show_counters for all software-control ports.

        Coverage table: command must Pass (empty Errors section). Require the
        Physical Counters and BER Info section and a Link Down Counter value.
        BER values are checked by test_sc_ber.
        """
        mlxlink_counters_all_interfaces = helpers.get_mlxlink_counters_all_interfaces(self.duthost, self.sc_port_list)
        for port in self.sc_port_list:
            with allure.step(f"Verify counters output for port {port}"):
                counters_output = mlxlink_counters_all_interfaces[port]
                assert counters_output, f"No counters output received for port {port}"
                helpers.assert_mlxlink_no_tool_errors(counters_output, port, "--show_counters")
                assert sc_const.MLXLINK_COUNTERS_SECTION in counters_output, (
                    f"Missing '{sc_const.MLXLINK_COUNTERS_SECTION}' in mlxlink --show_counters "
                    f"output for port {port}"
                )
                assert sc_const.MLXLINK_LINK_DOWN_COUNTER_RE.search(counters_output), (
                    f"Missing '{sc_const.MLXLINK_LINK_DOWN_COUNTER}' value in mlxlink "
                    f"--show_counters output for port {port}"
                )
                logger.info(f"Port counters successfully retrieved for port {port}")

    def test_sc_mlxlink_module_state(self):
        """
        @summary: On software control, mlxlink --module_state DN/UP is expected to Fail.

        FW refuses with 'No plugged cable detected' on SPC3-SPC6 (including CPO),
        A successful DN would unplug the module and violate that requirement.
        Only one port is used, chosen at random each run, so an unexpected
        success cannot unplug every software-control module. UP is always sent
        in finally to restore.
        """
        if not self.sc_port_list:
            pytest.skip("No software-control ports available for module state test")
        port = random.choice(self.sc_port_list)
        with allure.step(f"Verify module state expected Fail for port {port}"):
            try:
                for state, action in (('DN', 'plug out'), ('UP', 'plug in')):
                    with allure.step(f"Set module state to {state} ({action}) for port {port}"):
                        output = helpers.set_mlxlink_module_state_all_interfaces(self.duthost, [port], state)[port]
                        assert output, f"No output received for module state {state} on port {port}"
                        assert helpers.is_mlxlink_sc_module_state_expected_fail(output), (
                            f"Expected SC mlxlink --module_state {state} on port {port} to be refused with "
                            f"'{sc_const.MLXLINK_SC_NO_CABLE_ERROR}', got mlxlink errors: "
                            f"{helpers.get_mlxlink_tool_errors(output)}"
                        )
                        logger.info(f"SC module state {state} failed as expected for port {port}")
            finally:
                with allure.step(f"Restore module state UP for port {port}"):
                    helpers.set_mlxlink_module_state_all_interfaces(self.duthost, [port], 'UP')
                    logger.info(f"Restore module state UP completed for port {port}")

    def test_read_write_eeprom_by_page_and_byte(self, enum_rand_one_per_hwsku_frontend_hostname,
                                                enum_frontend_asic_index, xcvr_skip_list,
                                                ignore_loganalyzer_exceptions):
        """
        This test is verifying read and write eeprom by page and byte.
        1. Get all sfp type of all sfp types by reading the first byte of 0 page
        2. Verify write eeprom function for ports supporting FW module management
          2.1. Write the writable byte, verify there is no any error
          2.2  Write the writable byte with verify option, verify there is no any error,
               and verify the read value is equal to the written value
          2.4  Write the read-only byte with verify option, verify "Error: Write data failed!" is in the output
        3. Recover the written byte with the original value fot all tested ports
        """
        page = 0
        present = set(helpers.get_platform_sfputil_ports(self.duthost))
        ports = [port for port in self.sc_port_list if port in present]
        with allure.step("get passive port list"):
            passive_cable_port_list = get_passive_cable_port_list(self.duthost)
        with allure.step("Get sfp type from redis db"):
            sfp_type_per_interface = get_sfp_type_per_interface(self.duthost, ports, xcvr_skip_list)
        original_eeprom_per_interface = read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type(
            self.duthost, "READ_EEPROM", sfp_type_per_interface, ports, page,
            DICT_WRITABLE_BYTE_FOR_PAGE_0, size=1)
        sfp_type_not_support_write_on_passive_cable = ["cmis", "sff8636"]
        interfaces_not_support_write = self.interfaces_not_support_write_on_passive_cable(
            ports, passive_cable_port_list, sfp_type_not_support_write_on_passive_cable, sfp_type_per_interface)
        interfaces_support_write = [intf for intf in ports if intf not in interfaces_not_support_write]
        try:
            with allure.step(f"Verify Writing eeprom for {ports}"):
                logger.info(f"Skip test write function for cmis passive cable port: {interfaces_not_support_write}")
                data = "15"
                output_write_eeprom_all_interfaces = read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type(
                    self.duthost, "WRITE_EEPROM", sfp_type_per_interface, interfaces_support_write, page,
                    DICT_WRITABLE_BYTE_FOR_PAGE_0, data=data)
                output_write_eeprom_all_interfaces_verify = (
                    read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type(
                        self.duthost, "WRITE_EEPROM", sfp_type_per_interface, interfaces_support_write, page,
                        DICT_WRITABLE_BYTE_FOR_PAGE_0, data=data, is_verify=True))
                for intf in interfaces_support_write:
                    sfp_type = sfp_type_per_interface[intf]
                    offset = DICT_WRITABLE_BYTE_FOR_PAGE_0[sfp_type]
                    with allure.step(f"Verify writing writable byte {offset} for port {intf} with data {data} "):
                        output_write_eeprom = output_write_eeprom_all_interfaces[intf]
                        assert not output_write_eeprom, (
                            f"Failed to write eeprom for {intf}. output is: {output_write_eeprom}")
                        output_write_eeprom = output_write_eeprom_all_interfaces_verify[intf]
                        assert not output_write_eeprom, (
                            f"Failed to write eeprom for {intf} with verify option. output is {output_write_eeprom}")

                output_read_eeprom_all_interfaces = read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type(
                    self.duthost, "READ_EEPROM", sfp_type_per_interface, interfaces_support_write, page,
                    DICT_WRITABLE_BYTE_FOR_PAGE_0, size=1)
                for intf in interfaces_support_write:
                    output_read_eeprom = output_read_eeprom_all_interfaces[intf]
                    assert output_read_eeprom == data, (
                        "write data {data} doesn't match the read data {output_read_eeprom}")

                read_only_byte = 20
                output_write_eeprom_all_interfaces_verify = (
                    read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type(
                        self.duthost, "WRITE_EEPROM", sfp_type_per_interface, ports, page, read_only_byte,
                        data=data, is_verify=True))
                regex_error_write_eeprom = r".*Error: (?:Failed to write EEPROM!.*|Write data failed! Write.*)"
                for intf in ports:
                    with allure.step(
                            f"Verify writing read-only byte {read_only_byte} for port {intf} with data {data}"):
                        output_write_eeprom = output_write_eeprom_all_interfaces_verify[intf]
                        assert re.search(regex_error_write_eeprom, output_write_eeprom), (
                            f"Data should not be written to non-writable byte for {intf} "
                            f"for offset {read_only_byte}. output is {output_write_eeprom}")
        except Exception as err:
            logger.error(f"Failed to write eeprom: {err}")
            raise AssertionError(err)
        finally:
            for intf, data_info in original_eeprom_per_interface.items():
                sfp_type = sfp_type_per_interface[intf]
                offset = DICT_WRITABLE_BYTE_FOR_PAGE_0[sfp_type]
                if intf in interfaces_not_support_write:
                    logger.info(f"Skip recover eeprom for {intf} due to it is cmis passive port")
                    continue
                with allure.step(f"Recover original eeprom for {intf} with offset {offset} and data {data_info}"):
                    write_eeprom_by_page_and_byte(
                        self.duthost, intf, sfp_type, data_info, page, offset)

    def interfaces_not_support_write_on_passive_cable(
            self, interfaces, passive_cable_port_list, sfp_type_not_support_write_on_passive_cable,
            sfp_type_per_interface):
        interfaces_not_support_write = []
        for intf in interfaces:
            sfp_type = sfp_type_per_interface[intf]
            if intf in passive_cable_port_list and sfp_type in sfp_type_not_support_write_on_passive_cable:
                interfaces_not_support_write.append(intf)
        return interfaces_not_support_write

    @pytest.fixture(scope="function")
    def ignore_loganalyzer_exceptions(self, loganalyzer):
        if loganalyzer:
            ignoreRegex = [
                (r".*ERR sfputil:.*Failed to write EEPROM data sfp.* EEPROM page=\/sys\/module\/sx_core.*"
                 r"eeprom\/pages.*page_offset=\d+, size=\d+, offset=\d+, .*Errno.* Input\/output error.*"),
                r".*ERR kernel.*sxd_kernel:.*Fails to access.* module eeprom, status.*",
                r".*ERR kernel.*sxd_kernel.*Fails to write eeprom, status:.*\d+.*"]

            loganalyzer[self.duthost.hostname].ignore_regex.extend(ignoreRegex)

        yield
