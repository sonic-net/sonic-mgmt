import logging
import os
import sys
import time
import re
import json

import pytest

from tests.common import config_reload
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

def load_lossless_info_from_pg_profile_lookup(duthost):
    """Load test parameters from the json file. Called only once when the module is initialized

    Args:
        duthost: the DUT host object
    """
    # Check the threshold mode
    threshold_mode = duthost.shell('redis-cli -n 4 hget "BUFFER_POOL|ingress_lossless_pool" mode')['stdout']
    threshold_field_name = 'dynamic_th' if threshold_mode == 'dynamic' else 'static_th'
    dut_hwsku = duthost.facts["hwsku"]
    dut_platform = duthost.facts["platform"]
    skudir = "/usr/share/sonic/device/{}/{}/".format(dut_platform, dut_hwsku)
    lines = duthost.shell('cat {}/pg_profile_lookup.ini'.format(skudir))["stdout"]
    default_lossless_profiles = {}
    for line in lines.split('\n'):
        if line[0] == '#':
            continue
        tokens = line.split()
        speed = tokens[0]
        cable_length = tokens[1]
        size = tokens[2]
        xon = tokens[3]
        xoff = tokens[4]
        threshold = tokens[5]
        profile_info = {
            'pool': '[BUFFER_POOL_TABLE:ingress_lossless_pool]',
            'size': size,
            'xon': xon,
            'xoff': xoff,
            threshold_field_name: threshold}
        if len(tokens) > 6:
            profile_info['xon_offset'] = tokens[6]
        default_lossless_profiles[(speed, cable_length)] = profile_info
    return default_lossless_profiles


def make_dict_from_output_lines(lines):
    if lines:
        return dict(zip(lines[::2], lines[1::2]))
    return None


def test_buffer_pg(duthosts, rand_one_dut_hostname, conn_graph_facts):
    """The testcase for (traditional) buffer manager

    1. For all ports in the config_db,
       - Check whether there is no lossless buffer PG configured on an admin-down port
       - Check whether the lossless PG aligns with the port's speed and cable length
       - If name to oid maps exist for port and PG, check whether the information in ASIC_DB aligns with that in CONFIG_DB
       - If a lossless profile hasn't been checked, check whether lossless profile in CONFIG_DB aligns with
         - pg_profile_lookup.ini according to speed and cable length
         - information in ASIC_DB
    2. Shutdown a port and check whether the lossless buffer PG has been remvoed
    3. Startup the port and check whether the lossless PG has been readded.
    """
    def _check_condition(condition, message, use_assert):
        """Check whether the condition is satisfied

        Args:
            condition: The condition to check
            message: The message to log or in pytest_assert
            use_assert: Whether to use assert or not. If this is called from wait_until(), it should be False.

        Return:
            The condition
        """
        if use_assert:
            pytest_assert(condition, message)
        elif not condition:
            logging.info("Port buffer check: {}".format(message))
            return False

        return True

    def _check_buffer_item_in_asic_db(duthost, port, buffer_item, buffer_name_map, buffer_profile_oid, asic_key_name, should_have_profile, use_assert):
        buffer_item_asic_oid = buffer_name_map['{}:{}'.format(port, buffer_item)]
        buffer_item_asic_key = duthost.shell('redis-cli -n 1 keys *{}*'.format(buffer_item_asic_oid))['stdout']
        buffer_profile_oid_in_pg = duthost.shell('redis-cli -n 1 hget {} {}'.format(buffer_item_asic_key, asic_key_name))['stdout']
        if should_have_profile:
            if buffer_profile_oid:
                if not _check_condition(buffer_profile_oid == buffer_profile_oid_in_pg,
                                        "Different OIDs in buffer items ({}) and ({}) in port {}".format(buffer_profile_oid, buffer_profile_oid_in_pg, port),
                                        use_assert):
                    return None, False
            else:
                buffer_profile_oid = buffer_profile_oid_in_pg
        else:
            if not _check_condition(not buffer_profile_oid_in_pg or buffer_profile_oid_in_pg == 'oid:0x0',
                                    "Buffer PG configured on admin down port in ASIC_DB {}".format(port),
                                    use_assert):
                return None, False

        return buffer_profile_oid, True

    def _ids_to_id_list(ids):
        pattern = "^([0-9])+(-[0-9]+)*$"
        m = re.match(pattern, ids)
        lower = m.group(1)
        upper = m.group(2)
        if not upper:
            upper = lower
        else:
            upper = upper[1:]
        return [str(x) for x in range(int(lower), int(upper) + 1)]

    def _check_port_buffer_info_and_get_profile_oid(duthost, table, ids, port, expected_profile, use_assert=True):
        """Check port's buffer information against CONFIG_DB and ASIC_DB

        Args:
            duthost: The duthost object
            port: The port to test in string
            expected_profile: The expected profile in string
            use_assert: Whether or not to use pytest_assert in case any conditional check isn't satisfied

        Return:
            A tuple consisting of the OID of buffer profile and whether there is any check failed
        """
        profile_in_pg = duthost.shell('redis-cli hget "{}:{}:{}" profile'.format(table, port, ids))['stdout']
        buffer_profile_oid = None
        if table == 'BUFFER_PG_TABLE':
            sai_field = 'SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE'
            buffer_name_map = pg_name_map
        elif table == 'BUFFER_QUEUE_TABLE':
            sai_field = 'SAI_QUEUE_ATTR_BUFFER_PROFILE_ID'
            buffer_name_map = queue_name_map

        id_list = _ids_to_id_list(ids)

        if expected_profile:
            if not _check_condition(profile_in_pg == expected_profile, "Buffer profile of lossless PG of port {} isn't the expected ({})".format(port, expected_profile), use_assert):
                return None, False

            if buffer_name_map:
                buffer_profile_oid = None
                for pg in id_list:
                    logging.info("Checking {}:{}:{} in ASIC_DB".format(table, port, pg))
                    buffer_profile_oid, success = _check_buffer_item_in_asic_db(duthost, port, pg, buffer_name_map, buffer_profile_oid, sai_field, True, use_assert)
                    if not success:
                        return None, False
        else:
            if not _check_condition(not profile_in_pg, "Buffer PG configured on admin down port {}".format(port), use_assert):
                return None, False
            if buffer_name_map:
                for pg in id_list:
                    logging.info("Checking {}:{}:{} in ASIC_DB".format(table, port, pg))
                    buffer_profile_oid, success = _check_buffer_item_in_asic_db(duthost, port, pg, buffer_name_map, None, sai_field, False, use_assert)

        return buffer_profile_oid, True

    def _check_port_buffer_info_and_return(duthost, table, ids, port, expected_profile):
        """Check port's buffer information against CONFIG_DB and ASIC_DB and return the result

        This is called from wait_until

        Args:
            duthost: The duthost object
            port: The port to test in string
            expected_profile: The expected profile in string

        Return:
            Whether all the checks passed
        """
        _, result = _check_port_buffer_info_and_get_profile_oid(duthost, table, ids, port, expected_profile, False)
        return result

    duthost = duthosts[rand_one_dut_hostname]

    default_lossless_profiles = load_lossless_info_from_pg_profile_lookup(duthost)

    # Check whether the COUNTERS_PG_NAME_MAP exists. Skip ASIC_DB checking if it isn't
    pg_name_map = make_dict_from_output_lines(duthost.shell('redis-cli -n 2 hgetall COUNTERS_PG_NAME_MAP')['stdout'].split())
    queue_name_map = make_dict_from_output_lines(duthost.shell('redis-cli -n 2 hgetall COUNTERS_QUEUE_NAME_MAP')['stdout'].split())
    cable_length_map = make_dict_from_output_lines(duthost.shell('redis-cli -n 4 hgetall "CABLE_LENGTH|AZURE"')['stdout'].split())

    configdb_ports = [x.split('|')[1] for x in duthost.shell('redis-cli -n 4 keys "PORT|*"')['stdout'].split()]
    profiles_checked = {}
    lossless_pool_oid = None
    admin_up_ports = set()
    for port in configdb_ports:
        logging.info("Checking port buffer information: {}".format(port))
        port_config = make_dict_from_output_lines(duthost.shell('redis-cli -n 4 hgetall "PORT|{}"'.format(port))['stdout'].split())

        if port_config.get('admin_status') == 'up':
            admin_up_ports.add(port)
            cable_length = cable_length_map[port]
            speed = port_config['speed']
            lossless_profile = '[BUFFER_PROFILE_TABLE:pg_lossless_{}_{}_profile]'.format(speed, cable_length)

            buffer_items_to_check = [('BUFFER_PG_TABLE', '3-4', lossless_profile),
                                     ('BUFFER_PG_TABLE', '0', '[BUFFER_PROFILE_TABLE:ingress_lossy_profile]'),
                                     ('BUFFER_QUEUE_TABLE', '0-2', '[BUFFER_PROFILE_TABLE:q_lossy_profile]'),
                                     ('BUFFER_QUEUE_TABLE', '3-4', '[BUFFER_PROFILE_TABLE:egress_lossless_profile]'),
                                     ('BUFFER_QUEUE_TABLE', '5-6', '[BUFFER_PROFILE_TABLE:q_lossy_profile]')
                                     ]
        else:
            buffer_items_to_check = [('BUFFER_PG_TABLE', '0', '[BUFFER_PROFILE_TABLE:ingress_lossy_pg_zero_profile]'),
                                     ('BUFFER_PG_TABLE', '3-4', None),
                                     ('BUFFER_QUEUE_TABLE', '0-2', '[BUFFER_PROFILE_TABLE:egress_lossy_zero_profile]'),
                                     ('BUFFER_QUEUE_TABLE', '3-4', '[BUFFER_PROFILE_TABLE:egress_lossless_zero_profile]'),
                                     ('BUFFER_QUEUE_TABLE', '5-6', '[BUFFER_PROFILE_TABLE:egress_lossy_zero_profile]')
                                     ]

        for table, ids, expected_profile in buffer_items_to_check:
            logging.info("Checking buffer item {}:{}:{}".format(table, port, ids))
            buffer_profile_oid, _ = _check_port_buffer_info_and_get_profile_oid(duthost, table, ids, port, expected_profile)

            if not expected_profile:
                continue

            if expected_profile not in profiles_checked:
                profile_info = make_dict_from_output_lines(duthost.shell('redis-cli hgetall "{}"'.format(expected_profile[1:-1]))['stdout'].split())
                is_ingress_lossless = expected_profile[:12] == 'pg_lossless_'
                if is_ingress_lossless:
                    pytest_assert(profile_info == default_lossless_profiles[(speed, cable_length)], "Buffer profile {} {} doesn't match default {}".format(expected_profile, profile_info, default_lossless_profiles[(speed, cable_length)]))

                if buffer_profile_oid:
                    # Further check the buffer profile in ASIC_DB
                    logging.info("Checking profile {} oid {}".format(expected_profile, buffer_profile_oid))
                    buffer_profile_key = duthost.shell('redis-cli -n 1 keys *{}*'.format(buffer_profile_oid))['stdout']
                    buffer_profile_asic_info = make_dict_from_output_lines(duthost.shell('redis-cli -n 1 hgetall {}'.format(buffer_profile_key))['stdout'].split())
                    pytest_assert(buffer_profile_asic_info.get('SAI_BUFFER_PROFILE_ATTR_XON_TH') == profile_info.get('xon') and
                                  buffer_profile_asic_info.get('SAI_BUFFER_PROFILE_ATTR_XOFF_TH') == profile_info.get('xoff') and
                                  buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE'] == profile_info['size'] and
                                  (buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE'] == 'SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC' and
                                   buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH'] == profile_info['dynamic_th'] or
                                   buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE'] == 'SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC' and
                                   buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH'] == profile_info['static_th']),
                                  "Buffer profile {} {} doesn't align with ASIC_TABLE {}".format(expected_profile, profile_info, buffer_profile_asic_info))

                profiles_checked[expected_profile] = buffer_profile_oid
                if is_ingress_lossless:
                    if not lossless_pool_oid:
                        lossless_pool_oid = buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_POOL_ID']
                    else:
                        pytest_assert(lossless_pool_oid == buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_POOL_ID'],
                                      "Buffer profile {} has different buffer pool id {} from others {}".format(expected_profile, buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_POOL_ID'], lossless_pool_oid))
            else:
                pytest_assert(profiles_checked[expected_profile] == buffer_profile_oid,
                              "PG {}:3-4 has different OID of profile from other PGs sharing the same profile {}".format(port, expected_profile))

    port_to_shutdown = admin_up_ports.pop()
    expected_profile = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port))['stdout']
    try:
        # Shutdown the port and check whether the lossless PG has been remvoed
        logging.info("Shut down an admin-up port {} and check its buffer information".format(port_to_shutdown))
        duthost.shell('config interface shutdown {}'.format(port_to_shutdown))
        wait_until(60, 5, _check_port_buffer_info_and_return, duthost, 'BUFFER_PG_TABLE', '3-4', port_to_shutdown, None)

        # Startup the port and check whether the lossless PG has been reconfigured
        logging.info("Re-startup the port {} and check its buffer information".format(port_to_shutdown))
        duthost.shell('config interface startup {}'.format(port_to_shutdown))
        wait_until(60, 5, _check_port_buffer_info_and_return, duthost, 'BUFFER_PG_TABLE', '3-4', port_to_shutdown, expected_profile)
    finally:
        duthost.shell('config interface startup {}'.format(port_to_shutdown), module_ignore_errors=True)
