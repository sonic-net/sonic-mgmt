import pytest
import logging
import re

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.redis import AsicDbCli, AppDbCli, VoqDbCli

TMP_PC = 'PortChannel999'


def get_lag_ids_from_chassis_db(duthosts):
    """
    Get lag_ids from CHASSIS_DB
    cmd = 'redis-dump -H 10.0.5.16 -p 6380 -d 12 -y -k "*SYSTEM_LAG_TABLE*PortChannel0016"'
      Args:
          duthosts: The duthost fixture.

      Returns:
          lag_ids<list>: lag id

    """
    lag_ids = list()
    for sup in duthosts.supervisor_nodes:
        voqdb = VoqDbCli(sup)
        lag_list = voqdb.get_lag_list()
        for lag in lag_list:
            lag_ids.append(voqdb.hget_key_value(lag, "lag_id"))

    logging.info("LAG id's preset in CHASSIS_DB are {}".format(lag_ids))
    return lag_ids


def get_lag_id_from_chassis_db(duthosts):
    """
    Get LAG id for a lag form CHASSIS_DB
    Args:
        duthosts: The duthost fixture.

    Returns:
        lag_ids <int>: lag id
    """
    for sup in duthosts.supervisor_nodes:
        voqdb = VoqDbCli(sup)
        lag_list = voqdb.get_lag_list()
        for lag in lag_list:
            if TMP_PC in lag:
                lag_id = voqdb.hget_key_value(lag, "lag_id")
                logging.info("LAG id for lag {} is {}".format(TMP_PC, lag_id))
                return lag_id

        pytest.fail("LAG id for lag {} is not preset in CHASSIS_DB".format(TMP_PC))


def verify_lag_interface(duthost, asic, portchannel, expected=True):
    """Verify lag interface status"""
    if duthost.interface_facts(namespace=asic.namespace)['ansible_facts']['ansible_interface_facts'][portchannel]['link'] == expected:
        return True
    return False


def add_lag(duthost, asic, portchannel_members=None, portchannel_ip=None,
            portchannel=TMP_PC, add=True):
    """
    Add LAG to an ASIC
    runs command e.g. 'sudo config portchannel -n asic0 add PortChannel99'
    Args:
        duthost<object>: duthost
        asic<object>: asic object
        portchannel_members<list> : portchannel members
        portchannel_ip<str>: portchannel ip
        portchannel<str> : portchannel
        add<bool> : True adds portchannel
    """
    if add:
        config_cmd = "config portchannel {}"\
            .format(asic.cli_ns_option if asic.cli_ns_option else "")
        duthost.shell("{} add {}".format(config_cmd, portchannel))
        int_facts = duthost.interface_facts(namespace=asic.namespace)['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][portchannel])

    if portchannel_members:
        for member in portchannel_members:
            duthost.shell("config portchannel {} member add {} {}"
                          .format(asic.cli_ns_option, portchannel, member))

    if portchannel_ip:
        duthost.shell("config interface {} ip add {} {}"
                      .format(asic.cli_ns_option, portchannel, portchannel_ip))
        int_facts = duthost.interface_facts(namespace=asic.namespace)['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts']
                      [portchannel]['ipv4']['address'] == portchannel_ip.split('/')[0])

        pytest_assert(wait_until(30,5, verify_lag_interface, duthost, asic, portchannel),
                      'For added Portchannel {} link is not up'.format(portchannel))


def verify_lag_id_is_unique_in_chassis_db(duthosts, duthost, asic):
    """
    Verifies lag id is unique for a newly added LAG in CHASSIS_DB
    args:
        duthosts <list>: duthost
        duthost <obj>: duthost
        asic <obje>: asic

    """
    logging.info("Verifying on duthost {} asic {} that lag id is unique"
                 .format(duthost.hostname, asic.asic_index))
    lag_id_list = get_lag_ids_from_chassis_db(duthosts)
    add_lag(duthost, asic)
    added_pc_lag_id = get_lag_id_from_chassis_db(duthosts)
    if added_pc_lag_id in lag_id_list:
        pytest.fail('LAG id {} for newly added LAG {} already exist in lag_id_list {}'
                    .format(added_pc_lag_id, TMP_PC, lag_id_list))

    logging.info('LAG id {} for newly added LAG {} is unique.'
                 .format(added_pc_lag_id, TMP_PC))


def verify_lag_in_app_db(asic, deleted=False):
    """
    Verifies lag in ASIC APP DB.
    It runs the command e.g. 'redis-cli -n 0 --raw keys "*LAG_TABLE*"'
    Args:
        asic<obj>: asic
        deleted<bool>: False if lag is not deleted
    """
    appdb = AppDbCli(asic)
    app_db_lag_list = appdb.get_app_db_lag_list()
    if deleted:
        for lag in app_db_lag_list:
            if TMP_PC in lag:
                pytest.fail('LAG {} still exist in ASIC app db,'
                            ' Expected was should be deleted from asic app db.'.format(TMP_PC))

        logging.info('LAG {} is deleted in ASIC app db'.format(TMP_PC))
        return

    else:
        for lag in app_db_lag_list:
            if TMP_PC in lag:
                logging.info('LAG {} exist in ASIC app db'.format(TMP_PC))
                return
        pytest.fail('LAG {} does not exist in ASIC app db,'
                    ' Expected was should should exist in asic app db. '.format(TMP_PC))


def verify_lag_in_asic_db(asics, lag_id, deleted=False):
    """
    Verifies LAG in ASIC DB
    Args:
        asics<list>: asic
        lag_id<int>: lag id
        deleted<bool>: True if lag is deleted
    """
    for asic in asics:
        asicdb = AsicDbCli(asic)
        asic_db_lag_list = asicdb.get_asic_db_lag_list()
        if deleted:
            for lag in asic_db_lag_list:
                if asicdb.hget_key_value(lag, "SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID") == lag_id:
                    pytest.fail('LAG id {} for LAG {} exist in ASIC DB,'
                                ' Expected was should not be present'.format(lag_id, TMP_PC))

            logging.info('LAG id {} for LAG {} does not exist in ASIC DB'.format(lag_id, TMP_PC))

        else:
            for lag in asic_db_lag_list:
                if asicdb.hget_key_value(lag, "SAI_LAG_ATTR_SYSTEM_PORT_AGGREGATE_ID") == lag_id:
                    logging.info('LAG id {} for LAG {} exist in ASIC DB'.format(lag_id, TMP_PC))
                    return
            pytest.fail('LAG id {} for LAG {} does not exist in ASIC DB'.format(lag_id, TMP_PC))


def verify_lag_in_remote_asic_db(remote_duthosts, lag_id, deleted=False):
    """
    Verifies lag in remote asic db
    Args:
        remote_duthosts<list>: list of remote dut
        lag_id<int>: lag id of added/deleted lag
        deleted<bool>: True if lag is deleted
    """
    for dut in remote_duthosts:
        logging.info("Verifing lag in remote {} asic db ".format(dut.hostname))
        verify_lag_in_asic_db(dut.asics, lag_id, deleted)


def delete_lag(duthost, asic, portchannel=TMP_PC):
    """
    Deletes a LAG

    """
    logging.info("Deleting lag from {}".format(duthost.hostname))
    duthost.shell("config portchannel {} del {}".format(asic.cli_ns_option, portchannel))


def delete_lag_members_ip(duthost, asic, portchannel_members,
                          portchannel_ip=None, portchannel=TMP_PC):
    """
    deletes lag members and ip
    """
    logging.info('Deleting lag members {} from lag {} on dut {}'
                 .format(portchannel_members, portchannel, duthost.hostname))
    for member in portchannel_members:
        duthost.shell("config portchannel {} member del {} {}"
                      .format(asic.cli_ns_option, portchannel, member))

    if portchannel_ip:
        duthost.shell("config interface {} ip remove {} {}"
                      .format(asic.cli_ns_option, portchannel, portchannel_ip))

        pytest_assert(wait_until(30,5, verify_lag_interface, duthost, asic, portchannel, expected=False),
                      'For deleted Portchannel {} ip link is not down'.format(portchannel))



def verify_lag_id_deleted_in_chassis_db(duthosts, duthost, asic, lag_id):
    """
    Verifies lag id is deletes in CHASSIS_DB
    """
    delete_lag(duthost, asic)
    lag_id_list = get_lag_ids_from_chassis_db(duthosts)
    if lag_id in lag_id_list:
        pytest.fail('LAG id {} for lag {} still exist in chassis db lag_id_list {}, '
                    'Expected was should be deleted. '.format(lag_id, TMP_PC, lag_id_list))

    logging.info('LAG id {} for lag {} is deleted in chassis db.'.format(lag_id, TMP_PC))


def verify_lag_member_in_app_db(asic, pc_members, deleted=False):
    """"
    Verifies lag member in asic app db
    cmd = redis-cli -d 0 KEYS "*LAG_MEMBER_TABLE*"
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
    cmd = 'redis-cli -h 10.0.5.16 -p 6380 -n 12 KEYS
     "*SYSTEM_LAG_MEMBER_TABLE*|PortChannel0051*|Ethernet*"'
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

def is_lag_in_app_db(asic):
    """
    Returnes True if lag in app db else False
    It runs the command e.g. 'redis-cli -n 0 --raw keys "*LAG_TABLE*"'
    Args:
        asic<obj>: asic
    """
    appdb = AppDbCli(asic)
    app_db_lag_list = appdb.get_app_db_lag_list()
    for lag in app_db_lag_list:
        if TMP_PC in lag:
            return True

    return False
