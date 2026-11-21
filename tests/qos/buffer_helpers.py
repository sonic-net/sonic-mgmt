import ast
import pytest
import os
import logging
import copy
from jinja2 import Template
from tests.common.mellanox_data import get_service_ports, is_mellanox_device, is_spectrum6_or_newer
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

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

    def get_state_db(self):
        return ast.literal_eval(self.duthost.shell('sonic-db-dump -n STATE_DB -y')['stdout'])

    def get_port_info_from_config_db(self, port):
        return self.config_db.get("PORT|{}".format(port)).get("value")

    def get_profile_name_from_appl_db(self, table, port, ids):
        return self.appl_db.get("{}:{}:{}".format(table, port, ids)).get("value").get("profile")

    def get_port_info_from_state_db(self, port):
        return self.state_db.get("PORT_TABLE|{}".format(port)).get("value")

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
        self.state_db = self.get_state_db()


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
    cmd_get_pool_size = 'redis-cli -n 0 hget "BUFFER_POOL_TABLE:ingress_lossless_pool" size'
    original_pool_size = duthost.shell(cmd_get_pool_size)['stdout']
    ports_cable_len_j2_file_name = "ports_cable_len.j2"
    with open(os.path.join(PORT_CABLE_LEN_JSON_TEMPLATE_PATH, ports_cable_len_j2_file_name)) as template_file:
        t = Template(template_file.read())

    content = t.render(ports_cable_info=port_cable_info, ports_cable_info_len=len(port_cable_info))
    logger.info(f"port cable len json content is {port_cable_info}")
    ports_cable_len_config_json_file_name = "ports_cable_len_config.json"

    cmd_gen_port_cable_len_config = f"cat << EOF >  {ports_cable_len_config_json_file_name} \n {content}"

    duthost.shell(cmd_gen_port_cable_len_config)
    duthost.shell("sudo config load {} -y".format(ports_cable_len_config_json_file_name))

    def _check_pool_size_is_updated(duthost, original_pool_size):
        logger.info(f"original_pool_size is {original_pool_size}")
        new_pool_size = duthost.shell(cmd_get_pool_size)['stdout']
        logger.info(f"new_pool_size is {new_pool_size}")
        return new_pool_size != original_pool_size

    pytest_assert(
        wait_until(20, 2, 0, _check_pool_size_is_updated, duthost, original_pool_size),
        "Failed to update the buffer pool size after changing the cable length")


def gen_ports_cable_info(ports_with_config_exceed_max_headroom_ports, map_port_to_cable_len, updated_cable_len):
    ports_cable_info = copy.deepcopy(map_port_to_cable_len)
    if updated_cable_len:
        for port, cable_len in ports_cable_info.items():
            if port in ports_with_config_exceed_max_headroom_ports:
                ports_cable_info[port] = updated_cable_len

    return ports_cable_info


@pytest.fixture(scope="function")
def update_cable_len_for_all_ports(duthost, skip_traditional_model):
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


SERVICE_PORT_PG_PROFILE = "sp_pg_lossy_profile"
SERVICE_PORT_INGRESS_PROFILE = "sp_ingress_port_profile"
LEGACY_SERVICE_PORT_PG_PROFILE = "ingress_lossy_profile"
SERVICE_PORT_INGRESS_PORT_DYNAMIC_TH = "4"
SERVICE_PORT_ALLOWED_POOLS = ("ingress_lossy_pool", "ingress_lossless_pool")


def get_reduced_shared_buffer_service_ports(duthost):
    if not is_spectrum6_or_newer(duthost):
        return set()
    return set(get_service_ports(duthost.facts.get("platform", "")))


def _buffer_profile_names_from_config_db(config_db):
    names = set()
    for key in config_db:
        if key.startswith("BUFFER_PROFILE|"):
            names.add(key.split("|", 1)[1])
    return names


def resolve_service_port_profile_names(config_db):
    profile_names = _buffer_profile_names_from_config_db(config_db)
    if SERVICE_PORT_PG_PROFILE in profile_names:
        return SERVICE_PORT_PG_PROFILE, SERVICE_PORT_INGRESS_PROFILE
    return LEGACY_SERVICE_PORT_PG_PROFILE, LEGACY_SERVICE_PORT_PG_PROFILE


def _get_buffer_profile_fields(config_db, profile_name):
    entry = config_db.get("BUFFER_PROFILE|{}".format(profile_name))
    if not entry:
        return {}
    return entry.get("value") or {}


def assert_service_ports_platform_completeness(duthost, service_ports):
    """Boundaries — platform service ports render complete SP CONFIG entries."""
    pytest_assert(service_ports, "No service ports defined for this platform")
    for port in sorted(service_ports):
        pytest_assert(
            duthost.shell('sonic-db-cli CONFIG_DB exists "PORT|{}"'.format(port))['stdout'].strip() == "1",
            "Service port {} missing from PORT table".format(port))
        pytest_assert(
            duthost.shell('sonic-db-cli CONFIG_DB exists "BUFFER_PG|{}|0"'.format(port))['stdout'].strip() == "1",
            "Service port {} missing BUFFER_PG|0".format(port))
        pytest_assert(
            duthost.shell(
                'sonic-db-cli CONFIG_DB exists "BUFFER_PORT_INGRESS_PROFILE_LIST|{}"'.format(port)
            )['stdout'].strip() == "1",
            "Service port {} missing BUFFER_PORT_INGRESS_PROFILE_LIST".format(port))


def _assert_service_port_profile_pool_and_size(profile_name, fields, config_db):
    pool = fields.get("pool", "")
    # CONFIG may store pool as bare name or "[BUFFER_POOL|name]"
    pool_name = pool.strip("[]").split("|")[-1] if pool else ""
    pytest_assert(
        pool_name in SERVICE_PORT_ALLOWED_POOLS,
        "{} pool {} expected one of {}".format(profile_name, pool, SERVICE_PORT_ALLOWED_POOLS))
    if "BUFFER_POOL|ingress_lossy_pool" in config_db:
        pytest_assert(
            pool_name == "ingress_lossy_pool",
            "{} must use ingress_lossy_pool when SKU defines it (got {})".format(profile_name, pool_name))
    pytest_assert(
        fields.get("size") == "0",
        "{} size {} expected 0".format(profile_name, fields.get("size")))


def assert_service_port_profile_fields(config_db, pg_profile_name, ingress_profile_name):
    """SP lossy profile pool / size=0 / dynamic_th rules."""
    pg_fields = _get_buffer_profile_fields(config_db, pg_profile_name)
    ingress_fields = _get_buffer_profile_fields(config_db, ingress_profile_name)
    ref_lossy = _get_buffer_profile_fields(config_db, LEGACY_SERVICE_PORT_PG_PROFILE)

    if pg_profile_name == SERVICE_PORT_PG_PROFILE:
        pytest_assert(pg_fields, "Missing BUFFER_PROFILE|{}".format(SERVICE_PORT_PG_PROFILE))
        _assert_service_port_profile_pool_and_size(pg_profile_name, pg_fields, config_db)
        if ref_lossy:
            pytest_assert(
                pg_fields.get("dynamic_th") == ref_lossy.get("dynamic_th"),
                "sp_pg_lossy_profile dynamic_th {} must match ingress_lossy_profile {}".format(
                    pg_fields.get("dynamic_th"), ref_lossy.get("dynamic_th")))

    if ingress_profile_name == SERVICE_PORT_INGRESS_PROFILE:
        pytest_assert(ingress_fields, "Missing BUFFER_PROFILE|{}".format(SERVICE_PORT_INGRESS_PROFILE))
        _assert_service_port_profile_pool_and_size(ingress_profile_name, ingress_fields, config_db)
        pytest_assert(
            ingress_fields.get("dynamic_th") == SERVICE_PORT_INGRESS_PORT_DYNAMIC_TH,
            "sp_ingress_port_profile dynamic_th {} expected {}".format(
                ingress_fields.get("dynamic_th"), SERVICE_PORT_INGRESS_PORT_DYNAMIC_TH))


def get_service_port_appl_buffer_items(profile_wrapper, pg_profile_name):
    q_lossy = profile_wrapper.format("q_lossy_profile")
    pg_profile = profile_wrapper.format(pg_profile_name)
    return [
        ("BUFFER_PG_TABLE", "0", pg_profile),
        ("BUFFER_QUEUE_TABLE", "0-2", q_lossy),
        ("BUFFER_QUEUE_TABLE", "3-4", q_lossy),
        ("BUFFER_QUEUE_TABLE", "5-6", q_lossy),
    ]


def assert_service_ports_no_lossless_pfc(duthost, service_ports):
    """Service ports must not expose lossless PFC priorities (empty or N/A).

    Accepted values from `show pfc priority <port>`:
      Ethernet512  N/A
    or
      Ethernet512
    """
    empty_values = {"", "n/a", "none", "-"}
    for port in sorted(service_ports):
        cmd = "show pfc priority {}".format(port)
        rows = duthost.show_and_parse(cmd)
        logger.info("{}: {}".format(cmd, rows))
        lossless = None
        for row in rows:
            if row.get("interface") == port:
                lossless = (row.get("lossless priorities") or "").strip()
                break
        pytest_assert(
            lossless is not None,
            "Failed to parse lossless priorities for service port {} from: {}".format(port, rows))
        pytest_assert(
            lossless.lower() in empty_values,
            "Service port {} expected empty/N/A lossless priorities, got {!r} from: {}".format(
                port, lossless, rows))


def verify_service_port_config_and_metadata(duthost, service_ports):
    """CONFIG checks for SPC6+ service ports."""
    dut_db_info = DutDbInfo(duthost)
    pg_profile, ingress_profile = resolve_service_port_profile_names(dut_db_info.config_db)
    assert_service_ports_platform_completeness(duthost, service_ports)
    assert_service_port_profile_fields(dut_db_info.config_db, pg_profile, ingress_profile)
    assert_service_ports_no_lossless_pfc(duthost, service_ports)
    return pg_profile, ingress_profile


def wait_buffer_pg_table_restored(duthost, timeout=120, interval=10):
    def _restored():
        return bool(duthost.shell('sonic-db-cli APPL_DB keys "BUFFER_PG_TABLE:*"')['stdout'].strip())
    pytest_assert(
        wait_until(timeout, interval, 0, _restored),
        "BUFFER_PG_TABLE not restored within {}s".format(timeout))


def assert_buffermgrd_and_syncd_alive(duthost):
    """qos reload / SP flap must not crash buffermgrd or syncd."""
    asic = duthost.asic_instance()
    for service in (asic.get_docker_name("swss"), asic.get_docker_name("syncd")):
        pytest_assert(duthost.critical_processes_running(service),
                      "{} critical processes not healthy".format(service))


def flap_service_port(duthost, port):
    """Shutdown then startup one service port and wait for admin up."""
    duthost.shutdown(port)
    try:
        duthost.no_shutdown(port)
        pytest_assert(wait_until(60, 5, 0, duthost.is_interface_status_up, port),
                      "Service port {} did not return to admin up after flap".format(port))
    finally:
        duthost.no_shutdown(port)
