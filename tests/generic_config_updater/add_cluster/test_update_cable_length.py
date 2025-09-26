import logging
import pytest
from tests.common.gu_utils import apply_patch, delete_tmpfile, expect_op_success, generate_tmpfile
from tests.common.helpers.assertions import pytest_assert
from tests.common.buffer_utils import load_lossless_info_from_pg_profile_lookup
from tests.generic_config_updater.add_cluster.helpers import change_interface_admin_state_for_namespace, \
    get_active_interfaces, get_cfg_info_from_dut, select_random_active_interface

pytestmark = [
        pytest.mark.topology("t2")
        ]

logger = logging.getLogger(__name__)


def find_nearest_cable_length(pg_profile_info_dict, speed, cable_length):
    """
    Finds the nearest supported cable length for the required port speed based on the existing cable length value.
    """
    filtered_dict = {key: value for key, value in pg_profile_info_dict.items() if key[0] == speed}
    sorted_cable_lengths_for_speed = sorted([int(key[1][:-1]) for key in filtered_dict.keys()])
    index = sorted_cable_lengths_for_speed.index(int(cable_length[:-1]))
    if index > 0:
        # return the exact previous supported cable length for that speed
        return sorted_cable_lengths_for_speed[index - 1]
    elif index < len(sorted_cable_lengths_for_speed) - 1:
        # return the exact next supported cable length for that speed
        return sorted_cable_lengths_for_speed[index + 1]
    else:
        print("Cannot change cable length as found supported only one")


# -----------------------------
# Test Definitions
# -----------------------------

@pytest.mark.disable_loganalyzer
def test_update_cable_length(duthosts,
                             rand_one_dut_front_end_hostname,
                             enum_rand_one_frontend_asic_index,
                             enum_rand_one_asic_namespace,
                             verify=False):
    """
    Verifies the update of cable lengths for interfaces in one random ASIC namespace from a frontend host.
    The process involves shutting down the interfaces, updating the cable length, and then bringing the interfaces
    back up. All these operations are performed using apply-patch.

    Once the interfaces are up, the system should automatically detect the port speed and cable length of the active
    interfaces. It should then create or remove the relevant buffer PG lossless profiles and map the appropriate profile
    with the lossless queues of the active interfaces.
    This mapping happens automatically when the interfaces are brought up.

    The test verifies that CONFIG_DB has updated values for the paths CABLE_LENGTH, BUFFER_PROFILE, and BUFFER_PG.
    Additionally, APPL_DB is checked to confirm the correct BUFFER_PROFILE and BUFFER_PG information.

    Parameters:
    - `duthosts`: The DUT (Device Under Test) hosts participating in the test.
    - `rand_one_dut_front_end_hostname`: The randomly selected hostname of one front-end DUT.
    - `enum_rand_one_frontend_asic_index`: The randomly selected asic namespace.
    - `enum_rand_one_asic_namespace`: The randomly selected asic namespace.

    """

    duthost = duthosts[rand_one_dut_front_end_hostname]
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running", namespace=enum_rand_one_asic_namespace
        )['ansible_facts']
    active_interfaces = get_active_interfaces(config_facts)
    selected_intf = select_random_active_interface(duthost, enum_rand_one_asic_namespace)
    supported_pg_profile_info_dict = load_lossless_info_from_pg_profile_lookup(
        duthost, duthost.asic_instance(enum_rand_one_frontend_asic_index))
    initial_cable_length = duthost.shell('sonic-db-cli -n {} CONFIG_DB hget "CABLE_LENGTH|AZURE" {}'
                                         .format(enum_rand_one_asic_namespace, selected_intf))['stdout']
    initial_port_speed = duthost.shell('sonic-db-cli -n {} CONFIG_DB hget "PORT|{}" speed'
                                       .format(enum_rand_one_asic_namespace, selected_intf))['stdout']
    initial_pg_lossless_profile_name = 'pg_lossless_{}_{}_profile'.format(initial_port_speed, initial_cable_length)
    initial_buffer_profile_info = get_cfg_info_from_dut(duthost, 'BUFFER_PROFILE', enum_rand_one_asic_namespace)
    initial_buffer_pg_info = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)
    initial_pg_lossless_profile_info = initial_buffer_profile_info.get(initial_pg_lossless_profile_name)

    # shutdown interfaces for namespace
    change_interface_admin_state_for_namespace(config_facts,
                                               duthost,
                                               enum_rand_one_asic_namespace,
                                               status='down',
                                               apply=True,
                                               verify=True)

    # change cable lengths for neighbors in the namespace
    target_cable_length_val = find_nearest_cable_length(supported_pg_profile_info_dict,
                                                        initial_port_speed,
                                                        initial_cable_length)
    target_cable_length = "{}m".format(target_cable_length_val)
    logger.info("Changing cable length from {} to {}.".format(initial_cable_length, target_cable_length))
    json_namespace = '/' + enum_rand_one_asic_namespace
    initial_cable_length_config = get_cfg_info_from_dut(
        duthost, 'CABLE_LENGTH', enum_rand_one_asic_namespace
        ).get('AZURE')
    target_cable_length_config = {}
    for interface, length in list(initial_cable_length_config.items()):
        if interface in active_interfaces:
            target_cable_length_config[interface] = target_cable_length
        else:
            target_cable_length_config[interface] = length
    json_patch = [
         {
             "op": "add",
             "path": "{}/CABLE_LENGTH/AZURE".format(json_namespace),
             "value": target_cable_length_config
         }
     ]
    tmpfile = generate_tmpfile(duthost)
    # identify expected buffer pg profile information to be used later in verification
    expected_pg_lossless_profile_name = 'pg_lossless_{}_{}_profile'.format(initial_port_speed, target_cable_length)
    supported_pg_profile_info_for_speed = supported_pg_profile_info_dict.get((initial_port_speed, target_cable_length))
    expected_pg_lossless_profile_info = initial_pg_lossless_profile_info
    expected_pg_lossless_profile_info['xon'] = supported_pg_profile_info_for_speed.get('xon')
    expected_pg_lossless_profile_info['xoff'] = supported_pg_profile_info_for_speed.get('xoff')
    expected_pg_lossless_profile_info['xon_offset'] = supported_pg_profile_info_for_speed.get('xon_offset')
    expected_buffer_pg_info = {}
    for key, value in list(initial_buffer_pg_info.items()):
        if value['profile'] == initial_pg_lossless_profile_name:
            value['profile'] = expected_pg_lossless_profile_name
        expected_buffer_pg_info[key] = value

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        pytest_assert(get_cfg_info_from_dut(duthost, 'CABLE_LENGTH', enum_rand_one_asic_namespace).get(
            'AZURE') == target_cable_length_config, "Cable length value was not updated in CONFIG_DB.")

    finally:
        delete_tmpfile(duthost, tmpfile)

    # startup interfaces for namespace
    change_interface_admin_state_for_namespace(config_facts,
                                               duthost,
                                               enum_rand_one_asic_namespace,
                                               status='up',
                                               apply=True,
                                               verify=True)
    # verify that pg_lossless profiles automatically updated
    if verify:
        # verify CONFIG_DB:BUFFER_PROFILE:BUFFER_PG
        updated_buffer_profile_info = get_cfg_info_from_dut(duthost, 'BUFFER_PROFILE', enum_rand_one_asic_namespace)
        updated_buffer_pg_info = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)
        pytest_assert(expected_pg_lossless_profile_name in updated_buffer_profile_info,
                      "Expected buffer profile {} was not created in CONFIG_DB.".format(
                          expected_pg_lossless_profile_name))
        pytest_assert(updated_buffer_pg_info == expected_buffer_pg_info,
                      "Didn't find expected BUFFER_PG info in CONFIG_DB.")
        # verify APPL_DB:BUFFER_PROFILE_TABLE
        cmd = "sonic-db-cli -n {} APPL_DB keys BUFFER_PROFILE_TABLE:*".format(enum_rand_one_asic_namespace)
        updated_buffer_profile_info_appl_db = duthost.shell(cmd)["stdout"]
        pytest_assert(expected_pg_lossless_profile_name in updated_buffer_profile_info_appl_db,
                      "Expected buffer profile {} was not created in APPL_DB.".format(
                          expected_pg_lossless_profile_name))
