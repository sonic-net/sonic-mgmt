import logging

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

DEFAULT_LOSSLESS_PROFILES = None
RECLAIM_BUFFER_ON_ADMIN_DOWN = None

@pytest.fixture(scope="module", autouse=True)
def setup_module(duthosts, rand_one_dut_hostname):
    """Setup module. Called only once when the module is initialized

    Args:
        duthosts: The duthosts object
        rand_one_dut_hostname:
    """
    global RECLAIM_BUFFER_ON_ADMIN_DOWN

    duthost = duthosts[rand_one_dut_hostname]
    if duthost.facts["asic_type"] in ["mellanox"]:
        RECLAIM_BUFFER_ON_ADMIN_DOWN = True
    else:
        RECLAIM_BUFFER_ON_ADMIN_DOWN = False

    load_lossless_info_from_pg_profile_lookup(duthost)


def load_lossless_info_from_pg_profile_lookup(duthost):
    """Load pg_profile_lookup.ini to a dictionary. Called only once when the module is initialized

    Args:
        duthost: the DUT host object

    Return:
        The dictionary containing the information in pg_profile_lookup.ini
    """
    global DEFAULT_LOSSLESS_PROFILES

    # Check the threshold mode
    threshold_mode = duthost.shell('redis-cli -n 4 hget "BUFFER_POOL|ingress_lossless_pool" mode')['stdout']
    threshold_field_name = 'dynamic_th' if threshold_mode == 'dynamic' else 'static_th'
    dut_hwsku = duthost.facts["hwsku"]
    dut_platform = duthost.facts["platform"]
    skudir = "/usr/share/sonic/device/{}/{}/".format(dut_platform, dut_hwsku)
    pg_profile_lookup_file = os.path.join(skudir, 'pg_profile_lookup.ini')
    duthost.file(path=pg_profile_lookup_file, state="file")
    lines = duthost.shell('cat {}'.format(pg_profile_lookup_file))["stdout_lines"]
    DEFAULT_LOSSLESS_PROFILES = {}
    for line in lines:
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
            'pool': '[BUFFER_POOL|ingress_lossless_pool]',
            'size': size,
            'xon': xon,
            'xoff': xoff,
            threshold_field_name: threshold}
        if len(tokens) > 6:
            profile_info['xon_offset'] = tokens[6]
        DEFAULT_LOSSLESS_PROFILES[(speed, cable_length)] = profile_info


def make_dict_from_output_lines(lines):
    if lines:
        return dict(zip(lines[::2], lines[1::2]))
    return None


def test_buffer_pg(duthosts, rand_one_dut_hostname, conn_graph_facts):
    """The testcase for (traditional) buffer manager

    1. For all ports in the config_db,
       - Check whether there is no lossless buffer PG configured on an admin-down port
         - on all paltforms, there is no lossless PG configured on inactive ports which are admin-down
           which is guaranteed by buffer template
       - Check whether the lossless PG aligns with the port's speed and cable length
       - If name to oid maps exist for port and PG, check whether the information in ASIC_DB aligns with that in CONFIG_DB
       - If a lossless profile hasn't been checked, check whether lossless profile in CONFIG_DB aligns with
         - pg_profile_lookup.ini according to speed and cable length
         - information in ASIC_DB
    2. Shutdown a port and check whether the lossless buffer PGs
       - has been removed on Mellanox platforms
       - will not be changed on other platforms
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

    def _check_port_buffer_info_and_get_profile_oid(duthost, port, expected_profile, use_assert=True):
        """Check port's buffer information against CONFIG_DB and ASIC_DB

        Args:
            duthost: The duthost object
            port: The port to test in string
            expected_profile: The expected profile in string
            use_assert: Whether or not to use pytest_assert in case any conditional check isn't satisfied

        Return:
            A tuple consisting of the OID of buffer profile and whether there is any check failed
        """
        profile_in_pg = duthost.shell('redis-cli -n 4 hget "BUFFER_PG|{}|3-4" profile'.format(port))['stdout']
        buffer_profile_oid = None
        default_lossless_pgs = ['3', '4']

        if expected_profile:
            if not _check_condition(profile_in_pg == expected_profile, "Buffer profile of lossless PG of port {} isn't the expected ({})".format(port, expected_profile), use_assert):
                return None, False

            if pg_name_map:
                for pg in default_lossless_pgs:
                    buffer_pg_asic_oid = pg_name_map['{}:{}'.format(port, pg)]
                    buffer_pg_asic_key = duthost.shell('redis-cli -n 1 keys *{}*'.format(buffer_pg_asic_oid))['stdout']
                    buffer_profile_oid_in_pg = duthost.shell('redis-cli -n 1 hget {} SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE'.format(buffer_pg_asic_key))['stdout']
                    logging.info("Checking admin-up port {} lossless PG {} in ASIC_DB ({})".format(port, pg, buffer_profile_oid_in_pg))
                    if buffer_profile_oid:
                        if not _check_condition(buffer_profile_oid == buffer_profile_oid_in_pg,
                                                "Different OIDs in PG 3 ({}) and 4 ({}) in port {}".format(buffer_profile_oid, buffer_profile_oid_in_pg, port),
                                                use_assert):
                            return None, False
                    else:
                        buffer_profile_oid = buffer_profile_oid_in_pg
        else:
            if not _check_condition(not profile_in_pg, "Buffer PG configured on admin down port {}".format(port), use_assert):
                return None, False
            if pg_name_map:
                for pg in default_lossless_pgs:
                    buffer_pg_asic_oid = pg_name_map['{}:{}'.format(port, pg)]
                    buffer_pg_asic_key = duthost.shell('redis-cli -n 1 keys *{}*'.format(buffer_pg_asic_oid))['stdout']
                    buffer_profile_oid_in_pg = duthost.shell('redis-cli -n 1 hget {} SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE'.format(buffer_pg_asic_key))['stdout']
                    logging.info("Checking admin-down port {} lossless PG {}".format(port, pg))
                    if not _check_condition(not buffer_profile_oid_in_pg or buffer_profile_oid_in_pg == 'oid:0x0',
                                            "Buffer PG configured on admin down port in ASIC_DB {}".format(port),
                                            use_assert):
                        return None, False

        return buffer_profile_oid, True

    def _check_port_buffer_info_and_return(duthost, port, expected_profile):
        """Check port's buffer information against CONFIG_DB and ASIC_DB and return the result

        This is called from wait_until

        Args:
            duthost: The duthost object
            port: The port to test in string
            expected_profile: The expected profile in string

        Return:
            Whether all the checks passed
        """
        _, result = _check_port_buffer_info_and_get_profile_oid(duthost, port, expected_profile, False)
        return result

    global DEFAULT_LOSSLESS_PROFILES

    duthost = duthosts[rand_one_dut_hostname]

    # Check whether the COUNTERS_PG_NAME_MAP exists. Skip ASIC_DB checking if it isn't
    pg_name_map = make_dict_from_output_lines(duthost.shell('redis-cli -n 2 hgetall COUNTERS_PG_NAME_MAP')['stdout'].split())
    cable_length_map = make_dict_from_output_lines(duthost.shell('redis-cli -n 4 hgetall "CABLE_LENGTH|AZURE"')['stdout'].split())

    configdb_ports = [x.split('|')[1] for x in duthost.shell('redis-cli -n 4 keys "PORT|*"')['stdout'].split()]
    profiles_checked = {}
    lossless_pool_oid = None
    buffer_profile_asic_info = None
    admin_up_ports = set()
    for port in configdb_ports:
        port_config = make_dict_from_output_lines(duthost.shell('redis-cli -n 4 hgetall "PORT|{}"'.format(port))['stdout'].split())

        is_port_up = port_config.get('admin_status') == 'up'
        if is_port_up or not RECLAIM_BUFFER_ON_ADMIN_DOWN:
            if is_port_up:
                admin_up_ports.add(port)

            cable_length = cable_length_map[port]
            speed = port_config['speed']
            expected_profile = '[BUFFER_PROFILE|pg_lossless_{}_{}_profile]'.format(speed, cable_length)

            logging.info("Checking admin-{} port {} buffer information: profile {}".format('up' if is_port_up else 'down', port, expected_profile))

            buffer_profile_oid, _ = _check_port_buffer_info_and_get_profile_oid(duthost, port, expected_profile)

            if expected_profile not in profiles_checked:
                profile_info = make_dict_from_output_lines(duthost.shell('redis-cli -n 4 hgetall "{}"'.format(expected_profile[1:-1]))['stdout'].split())
                pytest_assert(profile_info == DEFAULT_LOSSLESS_PROFILES[(speed, cable_length)], "Buffer profile {} {} doesn't match default {}".format(expected_profile, profile_info, DEFAULT_LOSSLESS_PROFILES[(speed, cable_length)]))

                logging.info("Checking buffer profile {}: OID: {}".format(expected_profile, buffer_profile_oid))
                if buffer_profile_oid:
                    # Further check the buffer profile in ASIC_DB
                    buffer_profile_key = duthost.shell('redis-cli -n 1 keys *{}*'.format(buffer_profile_oid))['stdout']
                    buffer_profile_asic_info = make_dict_from_output_lines(duthost.shell('redis-cli -n 1 hgetall {}'.format(buffer_profile_key))['stdout'].split())
                    pytest_assert(buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_XON_TH'] == profile_info['xon'] and
                                  buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_XOFF_TH'] == profile_info['xoff'] and
                                  buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE'] == profile_info['size'] and
                                  (buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE'] == 'SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC' and
                                   buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH'] == profile_info['dynamic_th'] or
                                   buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE'] == 'SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC' and
                                   buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH'] == profile_info['static_th']),
                                  "Buffer profile {} {} doesn't align with ASIC_TABLE {}".format(expected_profile, profile_info, buffer_profile_asic_info))

                profiles_checked[expected_profile] = buffer_profile_oid
                if not lossless_pool_oid:
                    if buffer_profile_asic_info:
                        lossless_pool_oid = buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_POOL_ID']
                else:
                    pytest_assert(lossless_pool_oid == buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_POOL_ID'],
                                  "Buffer profile {} has different buffer pool id {} from others {}".format(expected_profile, buffer_profile_asic_info['SAI_BUFFER_PROFILE_ATTR_POOL_ID'], lossless_pool_oid))
            else:
                pytest_assert(profiles_checked[expected_profile] == buffer_profile_oid,
                              "PG {}|3-4 has different OID of profile from other PGs sharing the same profile {}".format(port, expected_profile))
        else:
            # Port admin down. Make sure no lossless PG configured.
            # After deployment, there should not be lossless PG configured on any platforms
            # This is guaranteed by buffers_config.j2: no lossless PG will be configured on inactive ports
            logging.info("Checking admin-down port buffer information: {}".format(port))
            _, _ = _check_port_buffer_info_and_get_profile_oid(duthost, port, None)

    port_to_shutdown = admin_up_ports.pop()
    expected_profile = duthost.shell('redis-cli -n 4 hget "BUFFER_PG|{}|3-4" profile'.format(port_to_shutdown))['stdout']
    try:
        # Shutdown the port and check whether the lossless PGs
        # - have been removed on Mellanox platforms
        # - will not be affected on other platforms
        logging.info("Shut down an admin-up port {} and check its buffer information".format(port_to_shutdown))
        duthost.shell('config interface shutdown {}'.format(port_to_shutdown))
        if RECLAIM_BUFFER_ON_ADMIN_DOWN:
            expected_profile_admin_down = None
        else:
            expected_profile_admin_down = expected_profile
        wait_until(60, 5, _check_port_buffer_info_and_return, duthost, port_to_shutdown, expected_profile_admin_down)

        # Startup the port and check whether the lossless PG has been reconfigured
        logging.info("Re-startup the port {} and check its buffer information".format(port_to_shutdown))
        duthost.shell('config interface startup {}'.format(port_to_shutdown))
        wait_until(60, 5, _check_port_buffer_info_and_return, duthost, port_to_shutdown, expected_profile)
    finally:
        duthost.shell('config interface startup {}'.format(port_to_shutdown), module_ignore_errors=True)
