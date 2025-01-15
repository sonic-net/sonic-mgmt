import ast
import pytest
import os
import logging
import copy
from jinja2 import Template
from tests.common.mellanox_data import is_mellanox_device

PORT_CABLE_LEN_JSON_TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files/mellanox")

logger = logging.getLogger(__name__)


class DutDbInfo:
    def __init__(self, duthost):
        self.duthost = duthost
        self.update_db_info()

    def get_asic_db(self):
        return ast.literal_eval(self.duthost.shell('sonic-db-dump -n ASIC_DB -y')['stdout'])

    def get_appl_db(self):
        return ast.literal_eval(self.duthost.shell('sonic-db-dump -n APPL_DB -y')['stdout'])

    def get_config_db(self):
        return ast.literal_eval(self.duthost.shell('sonic-db-dump -n CONFIG_DB -y ')['stdout'])

    def get_port_info_from_config_db(self, port):
        return self.config_db.get("PORT|{}".format(port)).get("value")

    def get_profile_name_from_appl_db(self, table, port, ids):
        return self.appl_db.get("{}:{}:{}".format(table, port, ids)).get("value").get("profile")

    def get_buffer_profile_oid_in_pg_from_asic_db(self, buffer_item_asic_key, asic_key_name):
        return self.asic_db.get(buffer_item_asic_key).get("value").get(asic_key_name)

    def get_profile_info_from_appl_db(self, expected_profile_key):
        return self.appl_db.get(expected_profile_key).get("value")

    def get_buffer_profile_key_from_asic_db(self, buffer_profile_oid):
        for key in list(self.asic_db.keys()):
            if buffer_profile_oid in key:
                return key
        raise Exception(
            "Not find the profile key for {}".format(buffer_profile_oid))

    def get_buffer_profile_info_from_asic_db(self, buffer_profile_key):
        return self.asic_db.get(buffer_profile_key).get("value")

    def update_db_info(self):
        self.config_db = self.get_config_db()
        self.appl_db = self.get_appl_db()
        self.asic_db = self.get_asic_db()


def get_ports_with_config_exceed_max_headroom(duthost):
    config_db_info = DutDbInfo(duthost).get_config_db()
    map_port_to_cable_len = config_db_info.get("CABLE_LENGTH|AZURE").get("value")
    ports_with_config_exceed_max_headroom_ports = {}
    speed_cable_len_exceed_max_headroom = {"speed": 400000, "cable_len": 200}

    for port, cable_len in map_port_to_cable_len.items():
        port_speed = config_db_info.get(f"PORT|{port}").get("value").get("speed")
        if port_speed and cable_len:
            if int(port_speed) >= speed_cable_len_exceed_max_headroom["speed"] and\
                    int(cable_len.split("m")[0]) >= speed_cable_len_exceed_max_headroom["cable_len"]:
                ports_with_config_exceed_max_headroom_ports.update({port: cable_len})
    return ports_with_config_exceed_max_headroom_ports, map_port_to_cable_len


def change_ports_cable_len(duthost, port_cable_info):
    ports_cable_len_j2_file_name = "ports_cable_len.j2"
    with open(os.path.join(PORT_CABLE_LEN_JSON_TEMPLATE_PATH, ports_cable_len_j2_file_name)) as template_file:
        t = Template(template_file.read())

    content = t.render(ports_cable_info=port_cable_info, ports_cable_info_len=len(port_cable_info))
    logger.info(f"port cable len json content is {port_cable_info}")
    ports_cable_len_config_json_file_name = "ports_cable_len_config.json"

    cmd_gen_port_cable_len_config = f"cat << EOF >  {ports_cable_len_config_json_file_name} \n {content}"

    duthost.shell(cmd_gen_port_cable_len_config)
    duthost.shell("sudo config load {} -y".format(ports_cable_len_config_json_file_name))


def gen_ports_cable_info(ports_with_config_exceed_max_headroom_ports, map_port_to_cable_len, updated_cable_len):
    ports_cable_info = copy.deepcopy(map_port_to_cable_len)
    if updated_cable_len:
        for port, cable_len in ports_cable_info.items():
            if port in ports_with_config_exceed_max_headroom_ports:
                ports_cable_info[port] = updated_cable_len

    return ports_cable_info


@pytest.fixture(scope="function")
def update_cable_len_for_all_ports(duthost):
    if is_mellanox_device(duthost):
        ports_cable_len_map_with_config_exceed_max_headroom, original_ports_cable_len_map = \
            get_ports_with_config_exceed_max_headroom(duthost)

        if ports_cable_len_map_with_config_exceed_max_headroom:
            # change cable length to a smaller one than 200m
            new_cable_len = "50m"
            ports_cable_info = gen_ports_cable_info(ports_cable_len_map_with_config_exceed_max_headroom,
                                                    original_ports_cable_len_map, new_cable_len)
            change_ports_cable_len(duthost, ports_cable_info)

    yield

    if is_mellanox_device(duthost):
        if ports_cable_len_map_with_config_exceed_max_headroom:
            # recover the cable length
            change_ports_cable_len(duthost, original_ports_cable_len_map)
