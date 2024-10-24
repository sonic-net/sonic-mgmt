import pytest
import logging
import re

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import AsicDbCli, AppDbCli, VoqDbCli

TMP_PC = 'PortChannel999'


def get_lag_ids_from_chassis_db(duthosts):
    """
    Get all LAG IDs from CHASSIS_DB

    Args:
        duthosts: duthosts to probe

    Returns:
        lag_ids: List of LAG ids in CHASSIS_DB
    """
    lag_ids = list()
    for sup in duthosts.supervisor_nodes:
        voqdb = VoqDbCli(sup)
        lag_list = voqdb.get_lag_list()
        for lag in lag_list:
            lag_ids.append(voqdb.hget_key_value(lag, "lag_id"))

    logging.info("LAG IDs present in CHASSIS_DB are {}".format(lag_ids))
    return lag_ids


def get_lag_id_from_chassis_db(duthosts, pc=TMP_PC):
    """
    Get LAG ID for a LAG from CHASSIS_DB

    Args:
        duthosts: duthosts to probe

    Returns:
        lag_id: LAG ID of LAG
    """
    for sup in duthosts.supervisor_nodes:
        voqdb = VoqDbCli(sup)
        lag_list = voqdb.get_lag_list()
        for lag in lag_list:
            if pc in lag:
                lag_id = voqdb.hget_key_value(lag, "lag_id")
                logging.info("LAG ID for LAG {} is {}".format(pc, lag_id))
                return lag_id

        pytest.fail("LAG ID for LAG {} is not present in CHASSIS_DB".format(pc))


def verify_lag_interface(duthost, asic, portchannel, expected=True):
    """Verify lag interface status"""
    if duthost.interface_facts(namespace=asic.namespace)['ansible_facts'][
            'ansible_interface_facts'][portchannel]['link'] == expected:
        return True
    return False


def add_lag(duthost, asic, portchannel=TMP_PC):
    """Creates a LAG on given ASIC"""
    logging.info("Adding LAG {} to {} asic{}".format(portchannel, duthost, asic.asic_index))
    duthost.shell("config portchannel {} add {}".format(asic.cli_ns_option, portchannel))


def delete_lag(duthost, asic, portchannel=TMP_PC):
    """Deletes a LAG on given ASIC"""
    logging.info("Deleting lag from {}".format(duthost.hostname))
    duthost.shell("config portchannel {} del {}".format(asic.cli_ns_option, portchannel))


def add_members_ip_to_lag(duthost, asic, portchannel_members=None, portchannel_ip=None, portchannel=TMP_PC):
    """Add members and IP to LAG"""
    if portchannel_members:
        logging.info("Adding members {} to LAG {}".format(portchannel_members, portchannel))
        for member in portchannel_members:
            duthost.shell("config portchannel {} member add {} {}".format(asic.cli_ns_option, portchannel, member))

    if portchannel_ip:
        logging.info("Assigning IP {} to LAG {}".format(portchannel_ip, portchannel))
        duthost.shell("config interface {} ip add {} {}".format(asic.cli_ns_option, portchannel, portchannel_ip))
        int_facts = duthost.interface_facts(namespace=asic.namespace)['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts']
                      [portchannel]['ipv4']['address'] == portchannel_ip.split('/')[0])

        pytest_assert(wait_until(30, 5, 0, verify_lag_interface, duthost, asic, portchannel),
                      'For added Portchannel {} link is not up'.format(portchannel))


def delete_members_ip_from_lag(duthost, asic, portchannel_members=None, portchannel_ip=None, portchannel=TMP_PC):
    """Deletes members and IP from LAG"""
    if portchannel_members:
        logging.info("Deleting members {} from LAG {}".format(portchannel_members, portchannel))
        for member in portchannel_members:
            duthost.shell("config portchannel {} member del {} {}".format(asic.cli_ns_option, portchannel, member))

    if portchannel_ip:
        logging.info("Dismissing IP {} from LAG {}".format(portchannel_ip, portchannel))
        duthost.shell("config interface {} ip remove {} {}"
                      .format(asic.cli_ns_option, portchannel, portchannel_ip))
        pytest_assert(wait_until(30, 5, 0, verify_lag_interface, duthost, asic, portchannel, expected=False),
                      'For deleted Portchannel {} ip link is not down'.format(portchannel))


def is_lag_in_app_db(asic, pc=TMP_PC):
    """Returns True if LAG in given ASIC APP DB else False"""
    appdb = AppDbCli(asic)
    app_db_lag_list = appdb.get_app_db_lag_list()
    for lag in app_db_lag_list:
        if pc in lag:
            return True

    return False


def verify_lag_in_app_db(asic, pc=TMP_PC, expected=True):
    """Verifies if LAG exists or not in given ASIC APP DB"""
    exists = is_lag_in_app_db(asic, pc)
    lag_exists_msg = "LAG {} exists in {} asic{} APPL_DB".format(pc, asic.sonichost.hostname, asic.asic_index)
    lag_missing_msg = "LAG {} doesn't exist in {} asic{} APPL_DB".format(pc, asic.sonichost.hostname, asic.asic_index)
    lag_msg = lag_exists_msg if exists else lag_missing_msg
    if exists == expected:
        logging.info(lag_msg)
    else:
        pytest.fail(lag_msg)


def verify_lag_in_chassis_db(duthosts, pc=TMP_PC, expected=True):
    """Verifies if LAG exists or not in CHASSIS DB"""
    for sup in duthosts.supervisor_nodes:
        voqdb = VoqDbCli(sup)
        lag_list = voqdb.get_lag_list()
        exists = False
        for lag in lag_list:
            if pc in lag:
                exists = True
                break

        lag_exists_msg = "LAG {} exists CHASSIS_APP_DB on {}".format(pc, sup)
        lag_missing_msg = "LAG {} doesn't exist in CHASSIS_APP_DB on {}".format(pc, sup)
        lag_msg = lag_exists_msg if exists else lag_missing_msg
        if exists == expected:
            logging.info(lag_msg)
        else:
            pytest.fail(lag_msg)


def verify_lag_id_in_asic_dbs(asics, lag_id, expected=True):
    """Verifies if LAG exists or not in given ASIC DBs"""
    for asic in asics:
        asicdb = AsicDbCli(asic)
        asic_db_lag_list = asicdb.get_asic_db_lag_list()
        exists = False
        for lag in asic_db_lag_list:
            if asicdb.hget_key_value(lag, "SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID") == lag_id:
                exists = True
                break

        lag_id_exists_msg = "LAG ID {} exists in {} asic{} ASIC_DB"\
                            .format(lag_id, asic.sonichost.hostname, asic.asic_index)
        lag_id_missing_msg = "LAG ID {} doesn't exist in {} asic{} ASIC_DB"\
                             .format(lag_id, asic.sonichost.hostname, asic.asic_index)
        lag_msg = lag_id_exists_msg if exists else lag_id_missing_msg
        if exists == expected:
            logging.info(lag_msg)
        else:
            pytest.fail(lag_msg)


def verify_lag_member_in_app_db(asic, pc_member, pc=TMP_PC, expected=True):
    """"Verifies if LAG member exists or not in given ASICs APP DB"""
    appdb = AppDbCli(asic)
    app_db_lag_member_list = appdb.get_app_db_lag_member_list()
    exists = False
    pattern = "{}:{}".format(pc, pc_member)
    for lag_member in app_db_lag_member_list:
        if pattern in lag_member:
            exists = True
            break

    lag_member_exists_msg = "LAG {} member {} exists in {} asic{} APPL_DB".\
                            format(pc, pc_member, asic.sonichost.hostname, asic.asic_index)
    lag_member_missing_msg = "LAG {} member {} doesn't exist in {} asic{} APPL_DB".\
                             format(pc, pc_member, asic.sonichost.hostname, asic.asic_index)
    lag_member_msg = lag_member_exists_msg if exists else lag_member_missing_msg
    if exists == expected:
        logging.info(lag_member_msg)
    else:
        pytest.fail(lag_member_msg)


def verify_lag_member_in_chassis_db(duthosts, pc_member, pc=TMP_PC, expected=True):
    """Verifies if LAG member exists or not in CHASSIS DB"""
    for sup in duthosts.supervisor_nodes:
        voqdb = VoqDbCli(sup)
        lag_member_list = voqdb.get_lag_member_list()
        exists = False
        pattern = "{}.*{}".format(pc, pc_member)
        for lag_member in lag_member_list:
            if re.search(pattern, lag_member):
                exists = True
                break

        lag_member_exists_msg = "LAG {} member {} exists in {} CHASSIS_APP_DB".format(pc, pc_member, sup)
        lag_member_missing_msg = "LAG {} member {} doesn't exist in {} CHASSIS_APP_DB".format(pc, pc_member, sup)
        lag_member_msg = lag_member_exists_msg if exists else lag_member_missing_msg
        if exists == expected:
            logging.info(lag_member_msg)
        else:
            pytest.fail(lag_member_msg)


def verify_lag_member_in_asic_db(asics, lag_id, expected=0):
    """Verifies if expected amount of LAG members exist in given ASIC DBs"""
    for asic in asics:
        asicdb = AsicDbCli(asic)
        asic_lag_list = asicdb.get_asic_db_lag_list()
        asic_db_lag_member_list = asicdb.get_asic_db_lag_member_list()
        lag_oid = None

        for lag in asic_lag_list:
            if asicdb.hget_key_value(lag, "SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID") == lag_id:
                lag_oid = ":".join(lag for lag in lag.split(':')[-2::1])

        count = 0
        for lag_member in asic_db_lag_member_list:
            if asicdb.hget_key_value(lag_member, "SAI_LAG_MEMBER_ATTR_LAG_ID") == lag_oid:
                count += 1

        pytest_assert(count == expected, "Found {} LAG members in {} asic{} ASIC_DB, expected {}"
                                         .format(count, asic.sonichost.hostname, asic.asic_index, expected))


def verify_lag_member_status_in_app_db(asic, pc_member, enabled=True):
    """Verifies if the status of a LAG member is enabled or disabled in given ASIC APP DB"""
    appdb = AppDbCli(asic)
    app_db_lag_member_list = appdb.get_app_db_lag_member_list()

    pattern = "{}:{}".format(TMP_PC, pc_member)
    for lag in app_db_lag_member_list:
        if pattern in lag:
            status = appdb.hget_key_value(lag, "status")
            logging.info("LAG member {} is {} in ASIC APPL_DB".format(pc_member, status))
            fail_msg = "LAG member {} is {} in ASIC APPL_DB when it shouldn't be".format(pc_member, status)
            status = True if status == "enabled" else False
            pytest_assert(status == enabled, fail_msg)
            return

    pytest.fail('LAG member {} does not exist in ASIC APPL_DB'.format(TMP_PC))


def verify_lag_member_status_in_chassis_db(duthosts, pc_member, enabled=False):
    """Verifies if the status of a LAG member is enabled or disabled in CHASSIS DB"""
    for sup in duthosts.supervisor_nodes:
        voqdb = VoqDbCli(sup)
        lag_member_list = voqdb.get_lag_member_list()
        pattern = "{}.*{}".format(TMP_PC, pc_member)
        for lag_member in lag_member_list:
            if re.search(pattern, lag_member):
                status = voqdb.hget_key_value(lag_member, "status")
                logging.info("LAG member {} is {} in CHASSIS_APP_DB".format(pc_member, status))
                fail_msg = "LAG member {} is {} in CHASSIS_APP_DB when it shouldn't be".format(pc_member, status)
                status = True if status == "enabled" else False
                pytest_assert(status == enabled, fail_msg)
                return

        pytest.fail('LAG member {} does not exist in CHASSIS_APP_DB'.format(TMP_PC))


def verify_lag_member_status_in_asic_db(asics, lag_id, exp_disabled=0):
    """Verifies if expected amount of LAG members are disabled in given ASIC DBs"""
    for asic in asics:
        asicdb = AsicDbCli(asic)
        asic_lag_list = asicdb.get_asic_db_lag_list()
        asic_db_lag_member_list = asicdb.get_asic_db_lag_member_list()
        lag_oid = None
        count = 0
        disabled = 0
        # Find LAG members OIDs from lag id
        for lag in asic_lag_list:
            if asicdb.hget_key_value(lag, "SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID") == lag_id:
                lag_oid = ":".join(lag for lag in lag.split(':')[-2::1])
                break

        # Find LAG members of LAG by OID, one should have disabled status
        for lag_member in asic_db_lag_member_list:
            if asicdb.hget_key_value(lag_member, "SAI_LAG_MEMBER_ATTR_LAG_ID") == lag_oid:
                status = asicdb.hget_key_value(lag_member, "SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE")
                count += 1
                if status == "true":
                    disabled += 1

        logging.info("Found {} members of LAG in {} asic {} ASIC_DB, {} are disabled"
                     .format(count, asic.sonichost.hostname, asic.asic_index, disabled))
        pytest_assert(count != 0, "No members matching LAG exist in {} asic {} ASIC_DB"
                                  .format(asic.sonichost.hostname, asic.asic_index))
        pytest_assert(disabled == exp_disabled,
                      "Found {} disabled members of LAG in {} asic {} ASIC_DB, expected {}"
                      .format(disabled, asic.sonichost.hostname, asic.asic_index, exp_disabled))
