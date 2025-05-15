import pytest
import logging
import tests.platform_tests.sfp.software_control.helpers as helpers
from tests.platform_tests.sfp.util import get_sfp_type, get_dev_conn, read_eeprom_by_page_and_byte, \
    write_eeprom_by_page_and_byte, DICT_WRITABLE_BYTE_FOR_PAGE_0
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.platform.transceiver_utils import get_passive_cable_port_list


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
        self.sff_cables = helpers.get_sff_cables(self.duthost, helpers.CMD_REDIS_TRANSCEIVER_INFO,
                                                 self.enum_frontend_asic_index, self.sc_port_list)

    def test_sc_check_show_interfaces_transceiver_eeprom(self):
        """
        @summary: Check SFP transceiver info using 'show interface transceiver eeprom'
        """
        for port in self.sc_port_list:
            sfp_show_eeprom = self.duthost.command(f"{helpers.CMD_INTERFACE_TRANSCEIVER} {port}")
            parsed_eeprom = helpers.parse_sc_eeprom(sfp_show_eeprom["stdout"])
            helpers.cleanup_placeholder(parsed_eeprom, "Vendor Date Code(YYYY-MM-DD Lot)")
            redis_output = helpers.parse_sfp_info_from_redis(self.duthost, helpers.CMD_REDIS_TRANSCEIVER_INFO,
                                                             self.enum_frontend_asic_index, [port])

            # Compare information from eeprom and redis
            helpers.compare_data_from_cli_and_redis(parsed_eeprom, redis_output, port, helpers.EEPROM_TO_REDIS_KEY_MAP)

    def test_check_sc_sfputil_eeprom_params(self):
        """
        @summary: Check sfputils eeprom output with Software Control enabled
        """

        for port in self.sc_port_list:
            sfp_show_eeprom = self.duthost.command(f"{helpers.CMD_SFPUTIL_EEPROM} -p {port}")
            parsed_eeprom = helpers.parse_sc_eeprom(sfp_show_eeprom["stdout"])
            helpers.cleanup_placeholder(parsed_eeprom, "Vendor Date Code(YYYY-MM-DD Lot)")
            redis_output = helpers.parse_sfp_info_from_redis(self.duthost, helpers.CMD_REDIS_TRANSCEIVER_INFO,
                                                             self.enum_frontend_asic_index, [port])

            # Compare information from eeprom and redis
            helpers.compare_data_from_cli_and_redis(parsed_eeprom, redis_output, port, helpers.EEPROM_TO_REDIS_KEY_MAP)

    def test_sc_check_show_interfaces_transceiver_status(self):
        """
        @summary: Check SFP transceiver info using 'show interface transceiver status'
        """
        for port in self.sc_port_list:
            show_transceiver_status = self.duthost.command(f"{helpers.CMD_INTERFACE_TRANSCEIVER_STATUS} {port}")
            redis_output = helpers.parse_sfp_info_from_redis(self.duthost, helpers.CMD_REDIS_TRANSCEIVER_STATUS,
                                                             self.enum_frontend_asic_index, [port])
            if port in self.sff_cables:
                logger.info(f"Port {port} has SFF cable connected, skip for this test")
                continue
            parsed_tranceiver_status = helpers.parse_sc_transceiver_status(show_transceiver_status["stdout"])
            # Compare information from cli and redis
            for cli_eeprom_key, redis_key in helpers.TRANSCEIVER_STATUS_TO_REDIS_KEY_MAP.items():
                assert parsed_tranceiver_status[cli_eeprom_key] == redis_output[port][redis_key], \
                    f"Data from cli param {cli_eeprom_key} does not data from redis"

    def test_sc_ber(self):
        """
        @summary: Check that BER per Software Control module is not bigger than cable BER threshold
        """
        for port in self.sc_port_list:
            mlxlink_output = helpers.get_mlxlink_ber(self.duthost, port)
            assert int(mlxlink_output[helpers.BER_EFFECTIVE_PHYSICAL_ERRORS]) == 0, \
                f"{helpers.BER_EFFECTIVE_PHYSICAL_ERRORS} > 0 "
            assert mlxlink_output[helpers.BER_EFFECTIVE_PHYSICAL_BER] == '15E-255', \
                f"{helpers.BER_EFFECTIVE_PHYSICAL_BER} > 15E-255"

    def test_read_write_eeprom_by_page_and_byte(self, enum_rand_one_per_hwsku_frontend_hostname,
                                                enum_frontend_asic_index, conn_graph_facts, xcvr_skip_list):
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

        portmap, dev_conn = get_dev_conn(self.duthost, conn_graph_facts, enum_frontend_asic_index)
        sfp_type_sc_port_dict = {}
        with allure.step("get passive port list"):
            passive_cable_port_list = get_passive_cable_port_list(self.duthost)

        with allure.step("Get sfp type by reading the first byte of 0 page in eeprom"):
            for intf in dev_conn:
                if intf not in xcvr_skip_list[self.duthost.hostname]:
                    sfp_type = get_sfp_type(self.duthost, intf)
                    assert sfp_type,  f"Failed to get sfp type {sfp_type} for port {intf}"
                    if intf in self.sc_port_list:
                        sfp_type_sc_port_dict.update({intf: sfp_type})

        original_port_to_eeprom_dict = {}
        try:
            with allure.step(f"Verify Writing eeprom for {self.sc_port_list}"):
                sfp_type_not_support_write_on_passive_cable = ["cmis", "sff8636"]
                for intf in self.sc_port_list:
                    page = 0
                    offset = DICT_WRITABLE_BYTE_FOR_PAGE_0[sfp_type_sc_port_dict[intf]]
                    data = "15"
                    sfp_type = sfp_type_sc_port_dict[intf]

                    original_eeprom = read_eeprom_by_page_and_byte(self.duthost, intf, sfp_type, page, offset)
                    original_port_to_eeprom_dict.update({intf: [offset, original_eeprom]})

                    if intf in passive_cable_port_list and sfp_type in sfp_type_not_support_write_on_passive_cable:
                        logger.info(f"Skip test write function for cmis passive cable port: {intf}")
                    else:
                        with allure.step(f"Verify writing writable byte {offset} for port {intf} with data {data} "):

                            output_write_eeprom = write_eeprom_by_page_and_byte(
                                self.duthost, intf, sfp_type, data, page, offset)
                            assert not output_write_eeprom, \
                                f"Failed to write eeprom for {intf}. output is: {output_write_eeprom}"

                            output_write_eeprom = write_eeprom_by_page_and_byte(
                                self.duthost, intf, sfp_type, data, page, offset, is_verify=True)
                            assert not output_write_eeprom, \
                                f"Failed to write eeprom for {intf} with verify option. output is {output_write_eeprom}"

                            output_read_eeprom = read_eeprom_by_page_and_byte(self.duthost, intf, sfp_type, page,
                                                                              offset)

                            assert output_read_eeprom == data, \
                                "write data {data} doesn't match the read data {output_read_eeprom}"

                    read_only_byte = 20
                    with allure.step(
                            f"Verify writing read-only byte {read_only_byte} for port {intf} with data {data}"):
                        output_write_eeprom = write_eeprom_by_page_and_byte(
                            self.duthost, intf, sfp_type, data, page, read_only_byte,
                            is_verify=True, module_ignore_errors=True)
                        assert "Error: Write data failed! " in output_write_eeprom, \
                            f"Data should not be written to non-writable byte for {intf} " \
                            f"for offset {read_only_byte}. output is {output_write_eeprom}"
        except Exception as err:
            logger.error(f"Failed to write eeprom: {err}")
            raise AssertionError(err)
        finally:
            for intf, offset_data_info in original_port_to_eeprom_dict.items():
                sfp_type = sfp_type_sc_port_dict[intf]
                if intf in passive_cable_port_list and sfp_type in ["cmis"]:
                    logger.info(f"Skip recover eeprom for {intf} due to it is cmis passive port")
                    continue
                with allure.step(f"Recover original eeprom for {intf} with {offset_data_info}"):
                    write_eeprom_by_page_and_byte(
                        self.duthost, intf, sfp_type, offset_data_info[1], page, offset_data_info[0])
