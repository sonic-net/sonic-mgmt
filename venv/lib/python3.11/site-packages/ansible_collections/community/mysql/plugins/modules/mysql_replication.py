#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2013, Balazs Pocze <banyek@gawker.com>
# Copyright: (c) 2019, Andrew Klychkov (@Andersson007) <andrew.a.klychkov@gmail.com>
# Certain parts are taken from Mark Theunissen's mysqldb module
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: mysql_replication
short_description: Manage MySQL or MariaDB replication
description:
- Manages MySQL or MariaDB server replication, replica, primary status, get and change primary host.
author:
- Balazs Pocze (@banyek)
- Andrew Klychkov (@Andersson007)
- Dennis Urtubia (@dennisurtubia)
- Laurent Indermühle (@laurent-indermuehle)
options:
  mode:
    description:
    - Module operating mode. Could be
      C(changeprimary) (CHANGE MASTER TO) - also works for MySQL 8.0.23 and later since community.mysql 3.10.0,
      C(changereplication) (CHANGE REPLICATION SOURCE TO) - only supported in MySQL 8.0.23 and later,
      C(getprimary) (SHOW MASTER STATUS),
      C(getreplica) (SHOW REPLICA STATUS),
      C(startreplica) (START REPLICA),
      C(stopreplica) (STOP REPLICA),
      C(resetprimary) (RESET MASTER) - supported since community.mysql 0.1.0,
      C(resetreplica) (RESET REPLICA),
      C(resetreplicaall) (RESET REPLICA ALL).
    type: str
    choices:
    - changeprimary
    - changereplication
    - getprimary
    - getreplica
    - startreplica
    - stopreplica
    - resetprimary
    - resetreplica
    - resetreplicaall
    default: getreplica
  primary_host:
    description:
    - Same as the C(MASTER_HOST) mysql variable.
    type: str
    aliases: [master_host]
  primary_user:
    description:
    - Same as the C(MASTER_USER) mysql variable.
    type: str
    aliases: [master_user]
  primary_password:
    description:
    - Same as the C(MASTER_PASSWORD) mysql variable.
    type: str
    aliases: [master_password]
  primary_port:
    description:
    - Same as the C(MASTER_PORT) mysql variable.
    type: int
    aliases: [master_port]
  primary_connect_retry:
    description:
    - Same as the C(MASTER_CONNECT_RETRY) mysql variable.
    type: int
    aliases: [master_connect_retry]
  primary_log_file:
    description:
    - Same as the C(MASTER_LOG_FILE) mysql variable.
    type: str
    aliases: [master_log_file]
  primary_log_pos:
    description:
    - Same as the C(MASTER_LOG_POS) mysql variable.
    type: int
    aliases: [master_log_pos]
  relay_log_file:
    description:
    - Same as mysql variable.
    type: str
  relay_log_pos:
    description:
    - Same as mysql variable.
    type: int
  primary_ssl:
    description:
    - Same as the C(MASTER_SSL) mysql variable.
    - When setting it to C(yes), the connection attempt only succeeds
      if an encrypted connection can be established.
    - For details, refer to
      L(MySQL encrypted replication documentation,https://dev.mysql.com/doc/refman/8.0/en/replication-solutions-encrypted-connections.html).
    - The default is C(false).
    type: bool
    aliases: [master_ssl]
  primary_ssl_ca:
    description:
    - Same as the C(MASTER_SSL_CA) mysql variable.
    - For details, refer to
      L(MySQL encrypted replication documentation,https://dev.mysql.com/doc/refman/8.0/en/replication-solutions-encrypted-connections.html).
    type: str
    aliases: [master_ssl_ca]
  primary_ssl_capath:
    description:
    - Same as the C(MASTER_SSL_CAPATH) mysql variable.
    - For details, refer to
      L(MySQL encrypted replication documentation,https://dev.mysql.com/doc/refman/8.0/en/replication-solutions-encrypted-connections.html).
    type: str
    aliases: [master_ssl_capath]
  primary_ssl_cert:
    description:
    - Same as the C(MASTER_SSL_CERT) mysql variable.
    - For details, refer to
      L(MySQL encrypted replication documentation,https://dev.mysql.com/doc/refman/8.0/en/replication-solutions-encrypted-connections.html).
    type: str
    aliases: [master_ssl_cert]
  primary_ssl_key:
    description:
    - Same as the C(MASTER_SSL_KEY) mysql variable.
    - For details, refer to
      L(MySQL encrypted replication documentation,https://dev.mysql.com/doc/refman/8.0/en/replication-solutions-encrypted-connections.html).
    type: str
    aliases: [master_ssl_key]
  primary_ssl_cipher:
    description:
    - Same as the C(MASTER_SSL_CIPHER) mysql variable.
    - Specifies a colon-separated list of one or more ciphers permitted by the replica for the replication connection.
    - For details, refer to
      L(MySQL encrypted replication documentation,https://dev.mysql.com/doc/refman/8.0/en/replication-solutions-encrypted-connections.html).
    type: str
    aliases: [master_ssl_cipher]
  primary_ssl_verify_server_cert:
    description:
    - Same as C(MASTER_SSL_VERIFY_SERVER_CERT) MySQL/MariaDB variable.
    - The module switch automatically to C(SOURCE_SSL_VERIFY_SERVER_CERT) for MySQL 8.0.23 and later.
    - Prior to community.mysql 3.14.0 C(false) had no effect.
    type: bool
    version_added: '3.5.0'
  primary_auto_position:
    description:
    - Whether the host uses GTID based replication or not.
    - Same as the C(MASTER_AUTO_POSITION) mysql variable.
    type: bool
    default: false
    aliases: [master_auto_position]
  primary_use_gtid:
    description:
    - Configures the replica to use the MariaDB Global Transaction ID.
    - C(disabled) equals MASTER_USE_GTID=no command.
    - To find information about available values see
      U(https://mariadb.com/kb/en/library/change-master-to/#master_use_gtid).
    - Available since MariaDB 10.0.2.
    choices: [current_pos, replica_pos, disabled]
    type: str
    version_added: '0.1.0'
    aliases: [master_use_gtid]
  primary_delay:
    description:
    - Time lag behind the primary's state (in seconds).
    - Same as the C(MASTER_DELAY) mysql variable.
    - Available from MySQL 5.6.
    - For more information see U(https://dev.mysql.com/doc/refman/8.0/en/replication-delayed.html).
    type: int
    version_added: '0.1.0'
    aliases: [master_delay]
  connection_name:
    description:
    - Name of the primary connection.
    - Supported from MariaDB 10.0.1.
    - Mutually exclusive with I(channel).
    - For more information see U(https://mariadb.com/kb/en/library/multi-source-replication/).
    type: str
    version_added: '0.1.0'
  channel:
    description:
    - Name of replication channel.
    - Multi-source replication is supported from MySQL 5.7.
    - Mutually exclusive with I(connection_name).
    - For more information see U(https://dev.mysql.com/doc/refman/8.0/en/replication-multi-source.html).
    type: str
    version_added: '0.1.0'
  fail_on_error:
    description:
    - Fails on error when calling mysql.
    type: bool
    default: false
    version_added: '0.1.0'

notes:
   - Compatible with MariaDB or MySQL.
   - If an empty value for the parameter of string type is needed, use an empty string.

attributes:
  check_mode:
    support: none

extends_documentation_fragment:
- community.mysql.mysql

seealso:
- module: community.mysql.mysql_info
- name: MySQL replication reference
  description: Complete reference of the MySQL replication documentation.
  link: https://dev.mysql.com/doc/refman/8.0/en/replication.html
- name: MySQL encrypted replication reference.
  description: Setting up MySQL replication to use encrypted connection.
  link: https://dev.mysql.com/doc/refman/8.0/en/replication-solutions-encrypted-connections.html
- name: MariaDB replication reference
  description: Complete reference of the MariaDB replication documentation.
  link: https://mariadb.com/kb/en/library/setting-up-replication/
'''

EXAMPLES = r'''
# If you encounter the "Please explicitly state intended protocol" error,
# use the login_unix_socket argument
- name: Stop mysql replica thread
  community.mysql.mysql_replication:
    mode: stopreplica
    login_unix_socket: /run/mysqld/mysqld.sock

- name: Get primary binlog file name and binlog position
  community.mysql.mysql_replication:
    mode: getprimary

- name: Change primary to primary server 192.0.2.1 and use binary log 'mysql-bin.000009' with position 4578
  community.mysql.mysql_replication:
    mode: changeprimary
    primary_host: 192.0.2.1
    primary_log_file: mysql-bin.000009
    primary_log_pos: 4578

- name: Change replication source to replica server 192.0.2.1 and use binary log 'mysql-bin.000009' with position 4578
  community.mysql.mysql_replication:
    mode: changereplication
    primary_host: 192.0.2.1
    primary_log_file: mysql-bin.000009
    primary_log_pos: 4578

- name: Check replica status using port 3308
  community.mysql.mysql_replication:
    mode: getreplica
    login_host: ansible.example.com
    login_port: 3308

- name: On MariaDB change primary to use GTID current_pos
  community.mysql.mysql_replication:
    mode: changeprimary
    primary_use_gtid: current_pos

- name: Change primary to use replication delay 3600 seconds
  community.mysql.mysql_replication:
    mode: changeprimary
    primary_host: 192.0.2.1
    primary_delay: 3600

- name: Start MariaDB replica with connection name primary-1
  community.mysql.mysql_replication:
    mode: startreplica
    connection_name: primary-1

- name: Stop replication in channel primary-1
  community.mysql.mysql_replication:
    mode: stopreplica
    channel: primary-1

- name: >
    Run RESET MASTER command which will delete all existing binary log files
    and reset the binary log index file on the primary
  community.mysql.mysql_replication:
    mode: resetprimary

- name: Run start replica and fail the task on errors
  community.mysql.mysql_replication:
    mode: startreplica
    connection_name: primary-1
    fail_on_error: true

- name: Change primary and fail on error (like when replica thread is running)
  community.mysql.mysql_replication:
    mode: changeprimary
    fail_on_error: true
'''

RETURN = r'''
queries:
  description: List of executed queries which modified DB's state.
  returned: always
  type: list
  sample: ["CHANGE MASTER TO MASTER_HOST='primary2.example.com',MASTER_PORT=3306"]
  version_added: '0.1.0'
'''

import os
import warnings

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.mysql.plugins.module_utils.command_resolver import (
    CommandResolver
)
from ansible_collections.community.mysql.plugins.module_utils.mysql import (
    get_server_version,
    get_server_implementation,
    mysql_connect,
    mysql_driver,
    mysql_driver_fail_msg,
    mysql_common_argument_spec,
)
from ansible.module_utils._text import to_native

executed_queries = []


def get_primary_status(cursor, command_resolver):
    query = command_resolver.resolve_command("SHOW MASTER STATUS")
    cursor.execute(query)

    primarystatus = cursor.fetchone()
    return primarystatus


def get_replica_status(cursor, connection_name='', channel='', term='REPLICA'):
    if connection_name:
        query = "SHOW %s '%s' STATUS" % (term, connection_name)
    else:
        query = "SHOW %s STATUS" % term

    if channel:
        query += " FOR CHANNEL '%s'" % channel

    cursor.execute(query)
    replica_status = cursor.fetchone()
    return replica_status


def stop_replica(module, cursor, connection_name='', channel='', fail_on_error=False, term='REPLICA'):
    if connection_name:
        query = "STOP %s '%s'" % (term, connection_name)
    else:
        query = 'STOP %s' % term

    if channel:
        query += " FOR CHANNEL '%s'" % channel

    try:
        executed_queries.append(query)
        cursor.execute(query)
        stopped = True
    except mysql_driver.Warning as e:
        stopped = False
    except Exception as e:
        if fail_on_error:
            module.fail_json(msg="STOP REPLICA failed: %s" % to_native(e))
        stopped = False
    return stopped


def reset_replica(module, cursor, connection_name='', channel='', fail_on_error=False, term='REPLICA'):
    if connection_name:
        query = "RESET %s '%s'" % (term, connection_name)
    else:
        query = 'RESET %s' % term

    if channel:
        query += " FOR CHANNEL '%s'" % channel

    try:
        executed_queries.append(query)
        cursor.execute(query)
        reset = True
    except mysql_driver.Warning as e:
        reset = False
    except Exception as e:
        if fail_on_error:
            module.fail_json(msg="RESET REPLICA failed: %s" % to_native(e))
        reset = False
    return reset


def reset_replica_all(module, cursor, connection_name='', channel='', fail_on_error=False, term='REPLICA'):
    if connection_name:
        query = "RESET %s '%s' ALL" % (term, connection_name)
    else:
        query = 'RESET %s ALL' % term

    if channel:
        query += " FOR CHANNEL '%s'" % channel

    try:
        executed_queries.append(query)
        cursor.execute(query)
        reset = True
    except mysql_driver.Warning as e:
        reset = False
    except Exception as e:
        if fail_on_error:
            module.fail_json(msg="RESET REPLICA ALL failed: %s" % to_native(e))
        reset = False
    return reset


def reset_primary(module, cursor, command_resolver, fail_on_error=False):
    query = command_resolver.resolve_command('RESET MASTER')
    try:
        executed_queries.append(query)
        cursor.execute(query)
        reset = True
    except mysql_driver.Warning as e:
        reset = False
    except Exception as e:
        if fail_on_error:
            module.fail_json(msg="%s failed: %s" % (command_resolver.resolve_command('RESET MASTER'), to_native(e)))
        reset = False
    return reset


def start_replica(module, cursor, connection_name='', channel='', fail_on_error=False, term='REPLICA'):
    if connection_name:
        query = "START %s '%s'" % (term, connection_name)
    else:
        query = 'START %s' % term

    if channel:
        query += " FOR CHANNEL '%s'" % channel

    try:
        executed_queries.append(query)
        cursor.execute(query)
        started = True
    except mysql_driver.Warning as e:
        started = False
    except Exception as e:
        if fail_on_error:
            module.fail_json(msg="START REPLICA failed: %s" % to_native(e))
        started = False
    return started


def changeprimary(cursor, command_resolver, chm, connection_name='', channel=''):
    query_head = command_resolver.resolve_command("CHANGE MASTER")
    if connection_name:
        query = "%s '%s' TO %s" % (query_head, connection_name, ','.join(chm))
    else:
        query = '%s TO %s' % (query_head, ','.join(chm))

    if channel:
        query += " FOR CHANNEL '%s'" % channel

    executed_queries.append(query)
    cursor.execute(query)


def changereplication(cursor, chm, channel=''):
    query = 'CHANGE REPLICATION SOURCE TO %s' % ','.join(chm)

    if channel:
        query += " FOR CHANNEL '%s'" % channel

    executed_queries.append(query)
    cursor.execute(query)


def main():
    argument_spec = mysql_common_argument_spec()
    argument_spec.update(
        mode=dict(type='str', default='getreplica', choices=[
            'getprimary',
            'getreplica',
            'changeprimary',
            'stopreplica',
            'startreplica',
            'resetprimary',
            'resetreplica',
            'resetreplicaall',
            'changereplication']),
        primary_auto_position=dict(type='bool', default=False, aliases=['master_auto_position']),
        primary_host=dict(type='str', aliases=['master_host']),
        primary_user=dict(type='str', aliases=['master_user']),
        primary_password=dict(type='str', no_log=True, aliases=['master_password']),
        primary_port=dict(type='int', aliases=['master_port']),
        primary_connect_retry=dict(type='int', aliases=['master_connect_retry']),
        primary_log_file=dict(type='str', aliases=['master_log_file']),
        primary_log_pos=dict(type='int', aliases=['master_log_pos']),
        relay_log_file=dict(type='str'),
        relay_log_pos=dict(type='int'),
        primary_ssl=dict(type='bool', aliases=['master_ssl']),
        primary_ssl_ca=dict(type='str', aliases=['master_ssl_ca']),
        primary_ssl_capath=dict(type='str', aliases=['master_ssl_capath']),
        primary_ssl_cert=dict(type='str', aliases=['master_ssl_cert']),
        primary_ssl_key=dict(type='str', no_log=False, aliases=['master_ssl_key']),
        primary_ssl_cipher=dict(type='str', aliases=['master_ssl_cipher']),
        primary_ssl_verify_server_cert=dict(type='bool'),
        primary_use_gtid=dict(type='str', choices=[
            'current_pos', 'replica_pos', 'disabled'], aliases=['master_use_gtid']),
        primary_delay=dict(type='int', aliases=['master_delay']),
        connection_name=dict(type='str'),
        channel=dict(type='str'),
        fail_on_error=dict(type='bool', default=False),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[
            ['connection_name', 'channel']
        ],
    )
    mode = module.params["mode"]
    primary_host = module.params["primary_host"]
    primary_user = module.params["primary_user"]
    primary_password = module.params["primary_password"]
    primary_port = module.params["primary_port"]
    primary_connect_retry = module.params["primary_connect_retry"]
    primary_log_file = module.params["primary_log_file"]
    primary_log_pos = module.params["primary_log_pos"]
    relay_log_file = module.params["relay_log_file"]
    relay_log_pos = module.params["relay_log_pos"]
    primary_ssl = module.params["primary_ssl"]
    primary_ssl_ca = module.params["primary_ssl_ca"]
    primary_ssl_capath = module.params["primary_ssl_capath"]
    primary_ssl_cert = module.params["primary_ssl_cert"]
    primary_ssl_key = module.params["primary_ssl_key"]
    primary_ssl_cipher = module.params["primary_ssl_cipher"]
    primary_ssl_verify_server_cert = module.params["primary_ssl_verify_server_cert"]
    primary_auto_position = module.params["primary_auto_position"]
    ssl_cert = module.params["client_cert"]
    ssl_key = module.params["client_key"]
    ssl_ca = module.params["ca_cert"]
    check_hostname = module.params["check_hostname"]
    connect_timeout = module.params['connect_timeout']
    config_file = module.params['config_file']
    primary_delay = module.params['primary_delay']
    if module.params.get("primary_use_gtid") == 'disabled':
        primary_use_gtid = 'no'
    else:
        primary_use_gtid = module.params["primary_use_gtid"]
    connection_name = module.params["connection_name"]
    channel = module.params['channel']
    fail_on_error = module.params['fail_on_error']

    if mysql_driver is None:
        module.fail_json(msg=mysql_driver_fail_msg)
    else:
        warnings.filterwarnings('error', category=mysql_driver.Warning)

    login_password = module.params["login_password"]
    login_user = module.params["login_user"]

    try:
        cursor, db_conn = mysql_connect(module, login_user, login_password, config_file,
                                        ssl_cert, ssl_key, ssl_ca, None, cursor_class='DictCursor',
                                        connect_timeout=connect_timeout, check_hostname=check_hostname)
    except Exception as e:
        if os.path.exists(config_file):
            module.fail_json(msg="unable to connect to database, check login_user and "
                                 "login_password are correct or %s has the credentials. "
                                 "Exception message: %s" % (config_file, to_native(e)))
        else:
            module.fail_json(msg="unable to find %s. Exception message: %s" % (config_file, to_native(e)))

    server_version = get_server_version(cursor)
    server_implementation = get_server_implementation(cursor)
    command_resolver = CommandResolver(server_implementation, server_version)
    cursor.execute("SELECT VERSION()")
    if server_implementation == 'mariadb':
        from ansible_collections.community.mysql.plugins.module_utils.implementations.mariadb import replication as impl
    else:
        from ansible_collections.community.mysql.plugins.module_utils.implementations.mysql import replication as impl

    # Since MySQL 8.0.22 and MariaDB 10.5.1,
    # "REPLICA" must be used instead of "SLAVE"
    if impl.uses_replica_terminology(cursor):
        replica_term = 'REPLICA'
    else:
        replica_term = 'SLAVE'
        if primary_use_gtid == 'replica_pos':
            primary_use_gtid = 'slave_pos'

    if mode == 'getprimary':
        status = get_primary_status(cursor, command_resolver)
        if status and "File" in status and "Position" in status:
            status['Is_Primary'] = True
        else:
            status = dict(
                Is_Primary=False,
                msg="Server is not configured as mysql primary. "
                    "Meaning: Binary logs are disabled")

        module.exit_json(queries=executed_queries, **status)

    elif mode == "getreplica":
        status = get_replica_status(cursor, connection_name, channel, replica_term)
        # MySQL 8.0 uses Replica_...
        # MariaDB 10.6 uses Slave_...
        if status and (
                "Slave_IO_Running" in status or
                "Replica_IO_Running" in status):
            status['Is_Replica'] = True
        else:
            status = dict(Is_Replica=False, msg="Server is not configured as mysql replica")

        module.exit_json(queries=executed_queries, **status)

    elif mode == 'changeprimary':
        chm = []
        result = {}
        if primary_host is not None:
            chm.append("%s='%s'" % (command_resolver.resolve_command('MASTER_HOST'), primary_host))
        if primary_user is not None:
            chm.append("%s='%s'" % (command_resolver.resolve_command('MASTER_USER'), primary_user))
        if primary_password is not None:
            chm.append("%s='%s'" % (command_resolver.resolve_command('MASTER_PASSWORD'), primary_password))
        if primary_port is not None:
            chm.append("%s=%s" % (command_resolver.resolve_command('MASTER_PORT'), primary_port))
        if primary_connect_retry is not None:
            chm.append("%s=%s" % (command_resolver.resolve_command('MASTER_CONNECT_RETRY'), primary_connect_retry))
        if primary_log_file is not None:
            chm.append("%s='%s'" % (command_resolver.resolve_command('MASTER_LOG_FILE'), primary_log_file))
        if primary_log_pos is not None:
            chm.append("%s=%s" % (command_resolver.resolve_command('MASTER_LOG_POS'), primary_log_pos))
        if primary_delay is not None:
            chm.append("%s=%s" % (command_resolver.resolve_command('MASTER_DELAY'), primary_delay))
        if relay_log_file is not None:
            chm.append("RELAY_LOG_FILE='%s'" % relay_log_file)
        if relay_log_pos is not None:
            chm.append("RELAY_LOG_POS=%s" % relay_log_pos)
        if primary_ssl is not None:
            if primary_ssl:
                chm.append("%s=1" % command_resolver.resolve_command('MASTER_SSL'))
            else:
                chm.append("%s=0" % command_resolver.resolve_command('MASTER_SSL'))
        if primary_ssl_ca is not None:
            chm.append("%s='%s'" % (command_resolver.resolve_command('MASTER_SSL_CA'), primary_ssl_ca))
        if primary_ssl_capath is not None:
            chm.append("%s='%s'" % (command_resolver.resolve_command('MASTER_SSL_CAPATH'), primary_ssl_capath))
        if primary_ssl_cert is not None:
            chm.append("%s='%s'" % (command_resolver.resolve_command('MASTER_SSL_CERT'), primary_ssl_cert))
        if primary_ssl_key is not None:
            chm.append("%s='%s'" % (command_resolver.resolve_command('MASTER_SSL_KEY'), primary_ssl_key))
        if primary_ssl_cipher is not None:
            chm.append("%s='%s'" % (command_resolver.resolve_command('MASTER_SSL_CIPHER'), primary_ssl_cipher))
        if primary_ssl_verify_server_cert is not None:
            if primary_ssl_verify_server_cert:
                chm.append("%s=1" % command_resolver.resolve_command('MASTER_SSL_VERIFY_SERVER_CERT'))
            else:
                chm.append("%s=0" % command_resolver.resolve_command('MASTER_SSL_VERIFY_SERVER_CERT'))
        if primary_auto_position:
            chm.append("%s=1" % command_resolver.resolve_command('MASTER_AUTO_POSITION'))
        if primary_use_gtid is not None:
            chm.append("MASTER_USE_GTID=%s" % primary_use_gtid)  # MariaDB only
        try:
            changeprimary(cursor, command_resolver, chm, connection_name, channel)
        except mysql_driver.Warning as e:
            result['warning'] = to_native(e)
        except Exception as e:
            module.fail_json(msg='%s. Query == %s TO %s' % (to_native(e), command_resolver.resolve_command('CHANGE MASTER'), chm))
        result['changed'] = True
        module.exit_json(queries=executed_queries, **result)
    elif mode == "startreplica":
        started = start_replica(module, cursor, connection_name, channel, fail_on_error, replica_term)
        if started is True:
            module.exit_json(msg="Replica started ", changed=True, queries=executed_queries)
        else:
            module.exit_json(msg="Replica already started (Or cannot be started)", changed=False, queries=executed_queries)
    elif mode == "stopreplica":
        stopped = stop_replica(module, cursor, connection_name, channel, fail_on_error, replica_term)
        if stopped is True:
            module.exit_json(msg="Replica stopped", changed=True, queries=executed_queries)
        else:
            module.exit_json(msg="Replica already stopped", changed=False, queries=executed_queries)
    elif mode == 'resetprimary':
        reset = reset_primary(module, cursor, command_resolver, fail_on_error)
        if reset is True:
            module.exit_json(msg="Primary reset", changed=True, queries=executed_queries)
        else:
            module.exit_json(msg="Primary already reset", changed=False, queries=executed_queries)
    elif mode == "resetreplica":
        reset = reset_replica(module, cursor, connection_name, channel, fail_on_error, replica_term)
        if reset is True:
            module.exit_json(msg="Replica reset", changed=True, queries=executed_queries)
        else:
            module.exit_json(msg="Replica already reset", changed=False, queries=executed_queries)
    elif mode == "resetreplicaall":
        reset = reset_replica_all(module, cursor, connection_name, channel, fail_on_error, replica_term)
        if reset is True:
            module.exit_json(msg="Replica reset", changed=True, queries=executed_queries)
        else:
            module.exit_json(msg="Replica already reset", changed=False, queries=executed_queries)
    elif mode == 'changereplication':
        chm = []
        result = {}
        if primary_host is not None:
            chm.append("SOURCE_HOST='%s'" % primary_host)
        if primary_user is not None:
            chm.append("SOURCE_USER='%s'" % primary_user)
        if primary_password is not None:
            chm.append("SOURCE_PASSWORD='%s'" % primary_password)
        if primary_port is not None:
            chm.append("SOURCE_PORT=%s" % primary_port)
        if primary_connect_retry is not None:
            chm.append("SOURCE_CONNECT_RETRY=%s" % primary_connect_retry)
        if primary_log_file is not None:
            chm.append("SOURCE_LOG_FILE='%s'" % primary_log_file)
        if primary_log_pos is not None:
            chm.append("SOURCE_LOG_POS=%s" % primary_log_pos)
        if primary_delay is not None:
            chm.append("SOURCE_DELAY=%s" % primary_delay)
        if relay_log_file is not None:
            chm.append("RELAY_LOG_FILE='%s'" % relay_log_file)
        if relay_log_pos is not None:
            chm.append("RELAY_LOG_POS=%s" % relay_log_pos)
        if primary_ssl is not None:
            if primary_ssl:
                chm.append("SOURCE_SSL=1")
            else:
                chm.append("SOURCE_SSL=0")
        if primary_ssl_ca is not None:
            chm.append("SOURCE_SSL_CA='%s'" % primary_ssl_ca)
        if primary_ssl_capath is not None:
            chm.append("SOURCE_SSL_CAPATH='%s'" % primary_ssl_capath)
        if primary_ssl_cert is not None:
            chm.append("SOURCE_SSL_CERT='%s'" % primary_ssl_cert)
        if primary_ssl_key is not None:
            chm.append("SOURCE_SSL_KEY='%s'" % primary_ssl_key)
        if primary_ssl_cipher is not None:
            chm.append("SOURCE_SSL_CIPHER='%s'" % primary_ssl_cipher)
        if primary_ssl_verify_server_cert is not None:
            if primary_ssl_verify_server_cert:
                chm.append("%s=1" % command_resolver.resolve_command('MASTER_SSL_VERIFY_SERVER_CERT'))
            else:
                chm.append("%s=0" % command_resolver.resolve_command('MASTER_SSL_VERIFY_SERVER_CERT'))
        if primary_auto_position:
            chm.append("SOURCE_AUTO_POSITION=1")
        try:
            changereplication(cursor, chm, channel)
        except mysql_driver.Warning as e:
            result['warning'] = to_native(e)
        except Exception as e:
            module.fail_json(msg='%s. Query == CHANGE REPLICATION SOURCE TO %s' % (to_native(e), chm))
        result['changed'] = True
        module.exit_json(queries=executed_queries, **result)

    warnings.simplefilter("ignore")


if __name__ == '__main__':
    main()
