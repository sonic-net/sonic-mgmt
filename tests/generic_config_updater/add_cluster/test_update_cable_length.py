import copy
import logging

import pytest

from tests.common.buffer_utils import load_lossless_info_from_pg_profile_lookup
from tests.common.gu_utils import apply_patch, delete_tmpfile, expect_op_success, generate_tmpfile
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.utilities import wait_until
from tests.generic_config_updater.add_cluster.helpers import change_interface_admin_state_for_namespace, \
    get_active_interfaces, get_cfg_info_from_dut, select_random_active_interface

pytestmark = [
    pytest.mark.topology("t2")
]

logger = logging.getLogger(__name__)


def _namespace_cli_prefix(namespace):
    return '' if namespace is None else '-n ' + namespace


def _namespace_json_prefix(namespace):
    return '' if namespace is None else '/' + namespace


def _profile_name(profile_ref):
    """Normalize CONFIG_DB profile refs such as '[BUFFER_PROFILE|name]' to 'name'."""
    if not profile_ref:
        return profile_ref
    return profile_ref.strip('[]').split('|')[-1]


def _rewrite_profile_ref(current_ref, new_profile_name):
    if current_ref and current_ref.startswith('['):
        return '[BUFFER_PROFILE|{}]'.format(new_profile_name)
    return new_profile_name


def find_nearest_cable_length(pg_profile_info_dict, speed, cable_length):
    """
    Finds a different supported cable length for the required port speed.

    Prefers the next-shorter supported length; if the current length is already
    the shortest, uses the next-longer length.
    """
    filtered_dict = {key: value for key, value in pg_profile_info_dict.items() if key[0] == speed}
    if not filtered_dict:
        pytest.skip("Speed {} is not present in pg_profile_lookup.ini".format(speed))
        return None

    sorted_cable_lengths_for_speed = sorted([int(key[1][:-1]) for key in filtered_dict.keys()])
    index = None
    try:
        current_length = int(cable_length[:-1])
        index = sorted_cable_lengths_for_speed.index(current_length)
    except (TypeError, ValueError):
        pytest.skip("Current cable length {} is not in pg_profile_lookup.ini for speed {}".format(
            cable_length, speed))
        return None

    if index > 0:
        return sorted_cable_lengths_for_speed[index - 1]
    if index < len(sorted_cable_lengths_for_speed) - 1:
        return sorted_cable_lengths_for_speed[index + 1]

    pytest.skip("Cannot change cable length; only one supported length for speed {}".format(speed))
    return None


def _apply_cable_length_patch(duthost, json_namespace, cable_length_config):
    json_patch = [
        {
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE".format(json_namespace),
            "value": cable_length_config
        }
    ]
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.disable_loganalyzer
def test_update_cable_length(duthosts,
                             rand_one_dut_front_end_hostname,
                             enum_rand_one_frontend_asic_index,
                             enum_rand_one_asic_namespace):
    """
    Verifies GCU cable-length update for interfaces in one random ASIC namespace.

    Interfaces are shut down, CABLE_LENGTH is patched, then interfaces are brought
    up so buffermgrd remaps lossless BUFFER_PROFILE / BUFFER_PG. CONFIG_DB and
    APPL_DB are checked. CABLE_LENGTH and interface admin state are restored.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]
    ns_cli = _namespace_cli_prefix(enum_rand_one_asic_namespace)
    json_namespace = _namespace_json_prefix(enum_rand_one_asic_namespace)

    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running", namespace=enum_rand_one_asic_namespace
    )['ansible_facts']
    active_interfaces = get_active_interfaces(config_facts, duthost=duthost)

    try:
        selected_intf = select_random_active_interface(duthost, enum_rand_one_asic_namespace)
    except IndexError:
        pytest.skip("No active Ethernet interfaces available for cable length update")
        return

    supported_pg_profile_info_dict = load_lossless_info_from_pg_profile_lookup(
        duthost, duthost.asic_instance(enum_rand_one_frontend_asic_index))

    initial_cable_length = duthost.shell(
        'sonic-db-cli {} CONFIG_DB hget "CABLE_LENGTH|AZURE" {}'.format(ns_cli, selected_intf)
    )['stdout']
    initial_port_speed = duthost.shell(
        'sonic-db-cli {} CONFIG_DB hget "PORT|{}" speed'.format(ns_cli, selected_intf)
    )['stdout']
    pytest_assert(initial_cable_length and initial_port_speed,
                  "Failed to read cable length or speed for {}".format(selected_intf))

    initial_pg_lossless_profile_name = 'pg_lossless_{}_{}_profile'.format(
        initial_port_speed, initial_cable_length)
    initial_buffer_profile_info = get_cfg_info_from_dut(
        duthost, 'BUFFER_PROFILE', enum_rand_one_asic_namespace) or {}
    initial_buffer_pg_info = get_cfg_info_from_dut(
        duthost, 'BUFFER_PG', enum_rand_one_asic_namespace) or {}
    initial_pg_lossless_profile_info = initial_buffer_profile_info.get(initial_pg_lossless_profile_name)
    if not initial_pg_lossless_profile_info:
        pytest.skip("Initial lossless profile {} not found in BUFFER_PROFILE".format(
            initial_pg_lossless_profile_name))

    target_cable_length_val = find_nearest_cable_length(
        supported_pg_profile_info_dict, initial_port_speed, initial_cable_length)
    target_cable_length = "{}m".format(target_cable_length_val)
    logger.info("Changing cable length from {} to {}.".format(initial_cable_length, target_cable_length))

    initial_cable_length_config = get_cfg_info_from_dut(
        duthost, 'CABLE_LENGTH', enum_rand_one_asic_namespace
    )
    pytest_assert(initial_cable_length_config and initial_cable_length_config.get('AZURE'),
                  "Failed to read CABLE_LENGTH|AZURE from CONFIG_DB")
    initial_cable_length_config = initial_cable_length_config.get('AZURE')

    target_cable_length_config = {}
    for interface, length in list(initial_cable_length_config.items()):
        if interface in active_interfaces:
            target_cable_length_config[interface] = target_cable_length
        else:
            target_cable_length_config[interface] = length

    expected_pg_lossless_profile_name = 'pg_lossless_{}_{}_profile'.format(
        initial_port_speed, target_cable_length)
    supported_pg_profile_info_for_speed = supported_pg_profile_info_dict.get(
        (initial_port_speed, target_cable_length))
    pytest_assert(supported_pg_profile_info_for_speed,
                  "No pg_profile_lookup.ini entry for speed {} cable {}".format(
                      initial_port_speed, target_cable_length))

    expected_pg_lossless_profile_info = copy.deepcopy(initial_pg_lossless_profile_info)
    expected_pg_lossless_profile_info['xon'] = supported_pg_profile_info_for_speed.get('xon')
    expected_pg_lossless_profile_info['xoff'] = supported_pg_profile_info_for_speed.get('xoff')
    if 'xon_offset' in supported_pg_profile_info_for_speed:
        expected_pg_lossless_profile_info['xon_offset'] = supported_pg_profile_info_for_speed.get('xon_offset')

    expected_buffer_pg_info = copy.deepcopy(initial_buffer_pg_info)
    for key, value in list(expected_buffer_pg_info.items()):
        if _profile_name(value.get('profile')) == initial_pg_lossless_profile_name:
            value['profile'] = _rewrite_profile_ref(value.get('profile'), expected_pg_lossless_profile_name)

    cable_length_changed = False
    interfaces_shutdown = False
    try:
        change_interface_admin_state_for_namespace(config_facts,
                                                   duthost,
                                                   enum_rand_one_asic_namespace,
                                                   status='down',
                                                   apply=True,
                                                   verify=True)
        interfaces_shutdown = True

        _apply_cable_length_patch(duthost, json_namespace, target_cable_length_config)
        cable_length_changed = True
        pytest_assert(get_cfg_info_from_dut(duthost, 'CABLE_LENGTH', enum_rand_one_asic_namespace).get(
            'AZURE') == target_cable_length_config, "Cable length value was not updated in CONFIG_DB.")

        change_interface_admin_state_for_namespace(config_facts,
                                                   duthost,
                                                   enum_rand_one_asic_namespace,
                                                   status='up',
                                                   apply=True,
                                                   verify=True)
        interfaces_shutdown = False
        pytest_assert(wait_until(300, 20, 0, check_interface_status_of_up_ports, duthost),
                      "Not all ports that are admin up are operationally up")

        updated_buffer_profile_info = get_cfg_info_from_dut(
            duthost, 'BUFFER_PROFILE', enum_rand_one_asic_namespace) or {}
        updated_buffer_pg_info = get_cfg_info_from_dut(
            duthost, 'BUFFER_PG', enum_rand_one_asic_namespace) or {}
        pytest_assert(expected_pg_lossless_profile_name in updated_buffer_profile_info,
                      "Expected buffer profile {} was not created in CONFIG_DB.".format(
                          expected_pg_lossless_profile_name))

        updated_profile = updated_buffer_profile_info[expected_pg_lossless_profile_name]
        for field in ('xon', 'xoff', 'xon_offset'):
            if field not in expected_pg_lossless_profile_info:
                continue
            pytest_assert(str(updated_profile.get(field)) == str(expected_pg_lossless_profile_info[field]),
                          "BUFFER_PROFILE {} field {} expected {} found {}".format(
                              expected_pg_lossless_profile_name, field,
                              expected_pg_lossless_profile_info[field], updated_profile.get(field)))

        pytest_assert(updated_buffer_pg_info == expected_buffer_pg_info,
                      "Didn't find expected BUFFER_PG info in CONFIG_DB.")

        cmd = "sonic-db-cli {} APPL_DB keys BUFFER_PROFILE_TABLE:*".format(ns_cli)
        updated_buffer_profile_info_appl_db = duthost.shell(cmd)["stdout"]
        pytest_assert(expected_pg_lossless_profile_name in updated_buffer_profile_info_appl_db,
                      "Expected buffer profile {} was not created in APPL_DB.".format(
                          expected_pg_lossless_profile_name))
    finally:
        try:
            if cable_length_changed or interfaces_shutdown:
                change_interface_admin_state_for_namespace(config_facts,
                                                           duthost,
                                                           enum_rand_one_asic_namespace,
                                                           status='down',
                                                           apply=True,
                                                           verify=True)
            if cable_length_changed:
                logger.info("Restoring CABLE_LENGTH to initial values via reverse patch.")
                _apply_cable_length_patch(duthost, json_namespace, initial_cable_length_config)
            change_interface_admin_state_for_namespace(config_facts,
                                                       duthost,
                                                       enum_rand_one_asic_namespace,
                                                       status='up',
                                                       apply=True,
                                                       verify=True)
        except Exception as restore_err:
            logger.warning("Failed to restore cable length or interface state: {}".format(restore_err))
