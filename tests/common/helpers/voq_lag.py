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

        lag_id_exists_msg = "LAG ID {} exists in {} asic{} ASIC_DB".format(lag_id, asic.sonichost.hostname, asic.asic_index)
        lag_id_missing_msg = "LAG ID {} doesn't exist in {} asic{} ASIC_DB".format(lag_id, asic.sonichost.hostname, asic.asic_index)
        lag_msg = lag_id_exists_msg if exists else lag_id_missing_msg
        if exists == expected:
            logging.info(lag_msg)
        else:
            pytest.fail(lag_msg)


def verify_lag_member_in_app_db(asic, pc_members, deleted=False):
    """"
    Verifies lag member in asic app db
    cmd = sonic-db-cli APPL_DB KEYS "*LAG_MEMBER_TABLE*"
    """
    appdb = AppDbCli(asic)
    app_db_lag_member_list = appdb.get_app_db_lag_member_list()
    if deleted:
        for member in pc_members:
            pattern = "{}:{}".format(TMP_PC, member)
            exist = False
            for lag_member in app_db_lag_member_list:
                if pattern in lag_member:
                    exist = True
                    break

            if exist:
                pytest.fail('LAG {} still exist in ASIC app db, '
                            'Expected was should be deleted from asic app db.'.format(TMP_PC))

        logging.info('For lag {} lag members {} are deleted in ASIC app db'.format(TMP_PC, pc_members))
    else:
        for member in pc_members:
            pattern = "{}:{}".format(TMP_PC, member)
            exist = False
            for lag in app_db_lag_member_list:
                if pattern in lag:
                    exist = True
                    break

            if not exist:
                pytest.fail('LAG {} does not exist in ASIC app db,'
                            ' Expected was should should exist in asic app db. '.format(TMP_PC))

        logging.info('For lag {} lag members {} are present in ASIC app db'.format(TMP_PC, pc_members))


def verify_lag_member_in_asic_db(asics, lag_id, pc_members, deleted=False):
    """
       Verifies lag member in ASIC DB
       It runs the command e.g.
    """
    for asic in asics:
        asicdb = AsicDbCli(asic)
        asic_lag_list = asicdb.get_asic_db_lag_list()
        asic_db_lag_member_list = asicdb.get_asic_db_lag_member_list()
        lag_oid = None
        if deleted:
            for lag in asic_lag_list:
                if asicdb.hget_key_value(lag,
                                         "SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID") == lag_id:
                    lag_oid = ":".join(lag for lag in lag.split(':')[-1:-3:-1])

            for lag_member in asic_db_lag_member_list:
                if asicdb.hget_key_value(lag_member, "SAI_LAG_MEMBER_ATTR_LAG_ID") == lag_oid:
                    pytest.fail("lag members {} still exist in lag member table on {},"
                                " Expected was should be deleted"
                                .format(pc_members, asic.sonichost.hostname))
            logging.info('Lag members are deleted from {} on {}'.format(asic.asic_index,
                                                                        asic.sonichost.hostname))

        else:
            for lag in asic_lag_list:
                if asicdb.hget_key_value(lag, "SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID") == lag_id:
                    lag_oid = ":".join(lag for lag in lag.split(':')[-2::1])
                    break

            for lag_member in asic_db_lag_member_list:
                if asicdb.hget_key_value(lag_member, "SAI_LAG_MEMBER_ATTR_LAG_ID") == lag_oid:
                    logging.info('Lag members exist in {} on {}'
                                 .format(asic.asic_index, asic.sonichost.hostname))
                    return

            pytest.fail('Lag members {} does not exist in {} on {}'
                        .format(pc_members, asic.asic_index, asic.sonichost.hostname))


def verify_lag_member_in_remote_asic_db(remote_dut, lag_id, pc_members, deleted=False):
    """
      Verifies lag member in remote ASIC DB

    """
    for dut in remote_dut:
        logging.info('Verifying lag members {} on dut {}'.format(pc_members, dut.hostname))
        verify_lag_member_in_asic_db(dut.asics, lag_id, pc_members, deleted)


def verify_lag_member_in_chassis_db(duthosts, members, deleted=False):
    """
    verifies lag members for a lag exist in chassis db
    cmd = 'sonic-db-cli CHASSIS_APP_DB KEYS "*SYSTEM_LAG_MEMBER_TABLE*|PortChannel0051*|Ethernet*"'
    """
    for sup in duthosts.supervisor_nodes:
        voqdb = VoqDbCli(sup)
        lag_member_list = voqdb.get_lag_member_list()
        if deleted:
            for member in members:
                exist = False
                pattern = "{}.*{}".format(TMP_PC, member)
                for lag_member in lag_member_list:
                    if re.search(pattern, lag_member):
                        exist = True
                        break
                if exist:
                    pytest.fail('lag member {} not found in system lag member table {}'
                                .format(member, lag_member_list))

            logging.info('lag members {} found in system lag member table {}'
                         .format(members, lag_member_list))

        else:
            for member in members:
                exist = False
                pattern = "{}.*{}".format(TMP_PC, member)
                for lag_member in lag_member_list:
                    if re.search(pattern, lag_member):
                        exist = True
                        logging.info('lag member {} found in system lag member table {}'
                                     .format(member, lag_member))
                        break

                if not exist:
                    pytest.fail('lag member {} not found in system lag member table {}'
                                .format(member, lag_member_list))


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

        logging.info("Found {} members of LAG in {} asic {} ASIC_DB, {} are disabled".format(count, asic.sonichost.hostname, asic.asic_index, disabled))
        pytest_assert(count != 0, "No members matching LAG exist in {} asic {} ASIC_DB".format(asic.sonichost.hostname, asic.asic_index))
        pytest_assert(disabled == exp_disabled, "Found {} disabled members of LAG in {} asic {} ASIC_DB, expected {}"
                                                .format(disabled, asic.sonichost.hostname, asic.asic_index, exp_disabled))
