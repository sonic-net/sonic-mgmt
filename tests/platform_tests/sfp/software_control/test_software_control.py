import pytest
import logging
import tests.platform_tests.sfp.software_control.helpers as helpers
from tests.platform_tests.sfp.util import get_sfp_type_per_interface, write_eeprom_by_page_and_byte, \
    DICT_WRITABLE_BYTE_FOR_PAGE_0, read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.platform.transceiver_utils import get_passive_cable_port_list
from tests.common.platform.interface_utils import get_first_port_in_split


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

    def test_sc_check_show_interfaces_transceiver_eeprom(self):
        """
        @summary: Check SFP transceiver info using 'show interface transceiver eeprom'
        """
        sfp_show_eeprom_all_interfaces = self.duthost.command(f"{helpers.CMD_INTERFACE_TRANSCEIVER}")
        parsed_eeprom_output_all_interfaces = helpers.parse_all_interfaces_eeprom_output_to_dict(
            sfp_show_eeprom_all_interfaces["stdout"])
        for port in self.sc_port_list:
            parsed_eeprom = helpers.parse_sc_eeprom(parsed_eeprom_output_all_interfaces[port])
            helpers.cleanup_placeholder(parsed_eeprom, "Vendor Date Code(YYYY-MM-DD Lot)")
            redis_output = helpers.transform_redis_transceiver_data(
                self.duthost, "TRANSCEIVER_INFO", self.enum_frontend_asic_index, [port])

            # Compare information from eeprom and redis
            helpers.compare_data_from_cli_and_redis(parsed_eeprom, redis_output, port, helpers.EEPROM_TO_REDIS_KEY_MAP)

    def test_check_sc_sfputil_eeprom_params(self):
        """
        @summary: Check sfputils eeprom output with  Independent Module enabled
        """
        sfp_show_eeprom_all_interfaces = self.duthost.command(f"{helpers.CMD_SFPUTIL_EEPROM}")
        parsed_eeprom_output_all_interfaces = helpers.parse_all_interfaces_eeprom_output_to_dict(
            sfp_show_eeprom_all_interfaces["stdout"])
        for port in self.sc_port_list:
            parsed_eeprom = helpers.parse_sc_eeprom(parsed_eeprom_output_all_interfaces[port])
            helpers.cleanup_placeholder(parsed_eeprom, "Vendor Date Code(YYYY-MM-DD Lot)")
            redis_output = helpers.transform_redis_transceiver_data(
                self.duthost, "TRANSCEIVER_INFO", self.enum_frontend_asic_index, [port])

            # Compare information from eeprom and redis
            helpers.compare_data_from_cli_and_redis(parsed_eeprom, redis_output, port, helpers.EEPROM_TO_REDIS_KEY_MAP)

    def test_sc_check_show_interfaces_transceiver_status(self):
        """
        @summary: Check SFP transceiver info using 'show interface transceiver status'
        """
        sff_cables = helpers.get_sff_cables(self.duthost, "TRANSCEIVER_INFO", self.enum_frontend_asic_index,
                                            self.sc_port_list)
        show_transceiver_status_all_interfaces = self.duthost.command(f"{helpers.CMD_INTERFACE_TRANSCEIVER_STATUS}")
        parsed_transceiver_status_all_interfaces = helpers.parse_all_interfaces_eeprom_output_to_dict(
            show_transceiver_status_all_interfaces["stdout"])
        first_port_in_split = get_first_port_in_split(self.duthost)
        for port in self.sc_port_list:
            if port not in first_port_in_split:
                continue
            redis_output = helpers.transform_redis_transceiver_data(
                self.duthost, "TRANSCEIVER_STATUS", self.enum_frontend_asic_index, [port])
            if port in sff_cables:
                logger.info(f"Port {port} has SFF cable connected, skip for this test")
                continue
            parsed_tranceiver_status = helpers.parse_sc_transceiver_status(
                parsed_transceiver_status_all_interfaces[port])
            # Compare information from cli and redis
            for cli_eeprom_key, redis_key in helpers.TRANSCEIVER_STATUS_TO_REDIS_KEY_MAP.items():
                assert parsed_tranceiver_status[cli_eeprom_key] == redis_output[port][redis_key], \
                    f"Data from cli param {cli_eeprom_key} does not data from redis"

    def test_sc_ber(self):
        """
        @summary: Check that BER per Software Control module is not bigger than cable BER threshold
        """
        mlxlink_ber_all_interfaces = helpers.get_mlxlink_ber_all_interfaces(self.duthost, self.sc_port_list)
        for port in self.sc_port_list:
            mlxlink_output = mlxlink_ber_all_interfaces[port]
            assert int(mlxlink_output[helpers.BER_EFFECTIVE_PHYSICAL_ERRORS]) == 0, \
                f"{helpers.BER_EFFECTIVE_PHYSICAL_ERRORS} > 0 "
            assert mlxlink_output[helpers.BER_EFFECTIVE_PHYSICAL_BER] == '15E-255', \
                f"{helpers.BER_EFFECTIVE_PHYSICAL_BER} > 15E-255"

    def test_read_write_eeprom_by_page_and_byte(self, enum_rand_one_per_hwsku_frontend_hostname,
                                                enum_frontend_asic_index, xcvr_skip_list):
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
        with allure.step("get passive port list"):
            passive_cable_port_list = get_passive_cable_port_list(self.duthost)
        with allure.step("Get sfp type by reading the first byte of 0 page in eeprom"):
            sfp_type_per_interface = get_sfp_type_per_interface(self.duthost, self.sc_port_list, xcvr_skip_list)
        original_eeprom_per_interface = read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type(
                    self.duthost, "READ_EEPROM", sfp_type_per_interface, self.sc_port_list, page,
                    DICT_WRITABLE_BYTE_FOR_PAGE_0, size=1)
        sfp_type_not_support_write_on_passive_cable = ["cmis", "sff8636"]
        interfaces_not_support_write = self.interfaces_not_support_write_on_passive_cable(
            self.sc_port_list, passive_cable_port_list, sfp_type_not_support_write_on_passive_cable,
            sfp_type_per_interface)
        interfaces_support_write = [intf for intf in self.sc_port_list if intf not in interfaces_not_support_write]
        try:
            with allure.step(f"Verify Writing eeprom for {self.sc_port_list}"):
                logger.info(f"Skip test write function for cmis passive cable port: {interfaces_not_support_write}")
                data = "15"
                output_write_eeprom_all_interfaces = read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type(
                    self.duthost, "WRITE_EEPROM", sfp_type_per_interface, interfaces_support_write, page,
                    DICT_WRITABLE_BYTE_FOR_PAGE_0, data=data)
                output_write_eeprom_all_interfaces_verify = \
                    read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type(
                        self.duthost, "WRITE_EEPROM", sfp_type_per_interface, interfaces_support_write, page,
                        DICT_WRITABLE_BYTE_FOR_PAGE_0, data=data, is_verify=True)
                for intf in interfaces_support_write:
                    sfp_type = sfp_type_per_interface[intf]
                    offset = DICT_WRITABLE_BYTE_FOR_PAGE_0[sfp_type]
                    with allure.step(f"Verify writing writable byte {offset} for port {intf} with data {data} "):
                        output_write_eeprom = output_write_eeprom_all_interfaces[intf]
                        assert not output_write_eeprom, (f"Failed to write eeprom for {intf}. "
                                                         f"Output is: {output_write_eeprom}")
                        output_write_eeprom = output_write_eeprom_all_interfaces_verify[intf]
                        assert not output_write_eeprom, (f"Failed to write eeprom for {intf} with verify option. "
                                                         f"Output is {output_write_eeprom}")

                output_read_eeprom_all_interfaces = read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type(
                    self.duthost, "READ_EEPROM", sfp_type_per_interface, interfaces_support_write, page,
                    DICT_WRITABLE_BYTE_FOR_PAGE_0, size=1)
                for intf in interfaces_support_write:
                    output_read_eeprom = output_read_eeprom_all_interfaces[intf]
                    assert output_read_eeprom == data, (f"write data {data} doesn't match the read data "
                                                        f"{output_read_eeprom}")

                read_only_byte = 20
                output_write_eeprom_all_interfaces_verify = \
                    read_write_eeprom_by_page_and_byte_to_interfaes_list_by_sfp_type(
                        self.duthost, "WRITE_EEPROM", sfp_type_per_interface, self.sc_port_list, page,
                        read_only_byte, data=data, is_verify=True)
                for intf in self.sc_port_list:
                    with allure.step(f"Verify writing read-only byte {read_only_byte} for port {intf} with "
                                     f"data {data}"):
                        output_write_eeprom = output_write_eeprom_all_interfaces_verify[intf]
                        assert "Error: Write data failed! " in output_write_eeprom, \
                            f"Data should not be written to non-writable byte for {intf} " \
                            f"for offset {read_only_byte}. output is {output_write_eeprom}"
        except Exception as err:
            logger.error(f"Failed to write eeprom: {err}")
            raise AssertionError(err)
        finally:
            for intf, data_info in original_eeprom_per_interface.items():
                sfp_type = sfp_type_per_interface[intf]
                offset = DICT_WRITABLE_BYTE_FOR_PAGE_0[sfp_type]
                if intf in passive_cable_port_list and sfp_type in ["cmis"]:
                    logger.info(f"Skip recover eeprom for {intf} due to it is cmis passive port")
                    continue
                with allure.step(f"Recover original eeprom for {intf} with offset {offset} and data {data_info}"):
                    write_eeprom_by_page_and_byte(
                        self.duthost, intf, sfp_type, data_info, page, offset)

    def interfaces_not_support_write_on_passive_cable(self, interfaces, passive_cable_port_list,
                                                      sfp_type_not_support_write_on_passive_cable,
                                                      sfp_type_per_interface):
        interfaces_not_support_write = []
        for intf in interfaces:
            sfp_type = sfp_type_per_interface[intf]
            if intf in passive_cable_port_list and sfp_type in sfp_type_not_support_write_on_passive_cable:
                interfaces_not_support_write.append(intf)
        return interfaces_not_support_write
