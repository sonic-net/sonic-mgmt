from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible.module_utils.basic import missing_required_lib  # pylint: disable=unused-import:
from ansible.module_utils.six.moves import configparser
from ansible.module_utils._text import to_native
import traceback
import os
import ssl as ssl_lib


try:
    from bson.timestamp import Timestamp
    from bson import ObjectId
except ImportError:
    pass  # TODO Should we do something here or are we covered by pymongo?

MongoClient = None
PYMONGO_IMP_ERR = None
pymongo_found = None
PyMongoVersion = None
ConnectionFailure = None
OperationFailure = None
TYPES_NEED_TO_CONVERT = None

try:
    from pymongo.errors import ConnectionFailure  # pylint: disable=unused-import:
    from pymongo.errors import OperationFailure  # pylint: disable=unused-import:
    from pymongo import version as PyMongoVersion
    from pymongo import MongoClient
    pymongo_found = True
except ImportError:
    PYMONGO_IMP_ERR = traceback.format_exc()
    pymongo_found = False

try:
    TYPES_NEED_TO_CONVERT = (Timestamp, ObjectId)
except NameError:
    pass  # sanity tests


def check_compatibility(module, srv_version, driver_version):
    if int(driver_version[0]) >= 4:
        if int(srv_version[0]) < 4:
            if module.params['strict_compatibility']:
                module.fail_json(msg="This version of MongoDB is pretty old and these modules are no longer tested against this version.")
            else:
                module.warn("This version of MongoDB is pretty old and these modules are no longer tested against this version.")
    else:
        if module.params['strict_compatibility']:
            module.fail_json(msg="You must use pymongo 4+.")
        else:
            module.warn("You must use pymongo 4+.")


def load_mongocnf():
    config = configparser.RawConfigParser()
    mongocnf = os.path.expanduser('~/.mongodb.cnf')

    try:
        config.read_file(open(mongocnf))
    except (configparser.NoOptionError, IOError):
        return False

    creds = dict(
        user=config.get('client', 'user'),
        password=config.get('client', 'pass')
    )

    return creds


def index_exists(client, database, collection, index_name):
    """
    Returns true if an index on the collection exists with the given name
    @client: MongoDB connection.
    @database: MongoDB Database.
    @collection: MongoDB collection.
    @index_name: The index name.
    """
    exists = False
    indexes = client[database][collection].list_indexes()
    for index in indexes:
        if index["name"] == index_name:
            exists = True
    return exists


def create_index(client, database, collection, keys, options):
    """
    Creates an index on the given collection
    @client: MongoDB connection.
    @database: MongoDB Database - str.
    @collection: MongoDB collection - str.
    @keys: Specification of index - dict.
    """
    client[database][collection].create_index(list(keys.items()),
                                              **options)


def drop_index(client, database, collection, index_name):
    client[database][collection].drop_index(index_name)


def member_state(client):
    """Check if a replicaset exists.

    Args:
        client (cursor): Mongodb cursor on admin database.

    Returns:
        str: member state i.e. PRIMARY, SECONDARY
    """
    state = None
    doc = client['admin'].command('replSetGetStatus')
    for member in doc["members"]:
        if "self" in member.keys():
            state = str(member['stateStr'])
    return state


def mongodb_common_argument_spec(ssl_options=True):
    """
    Returns a dict containing common options shared across the MongoDB modules.
    """
    options = dict(
        login_user=dict(type='str', required=False),
        login_password=dict(type='str', required=False, no_log=True),
        login_database=dict(type='str', required=False, default='admin'),
        login_host=dict(type='str', required=False, default='localhost'),
        login_port=dict(type='int', required=False, default=27017),
        strict_compatibility=dict(type='bool', default=True),
        atlas_auth=dict(type='bool', default=False),
    )
    ssl_options_dict = dict(
        ssl=dict(type='bool', required=False, default=False, aliases=['tls']),
        ssl_cert_reqs=dict(type='str',
                           required=False,
                           default='CERT_REQUIRED',
                           choices=['CERT_NONE',
                                    'CERT_OPTIONAL',
                                    'CERT_REQUIRED'],
                           aliases=['tlsAllowInvalidCertificates']),
        ssl_ca_certs=dict(type='str', default=None, aliases=['tlsCAFile']),
        ssl_crlfile=dict(type='str', default=None),
        ssl_certfile=dict(type='str', default=None, aliases=['tlsCertificateKeyFile']),
        ssl_keyfile=dict(type='str', default=None, no_log=True),
        ssl_pem_passphrase=dict(type='str', default=None, no_log=True, aliases=['tlsCertificateKeyFilePassword']),
        auth_mechanism=dict(type='str',
                            required=False,
                            default=None,
                            choices=['SCRAM-SHA-256',
                                     'SCRAM-SHA-1',
                                     'MONGODB-X509',
                                     'GSSAPI',
                                     'PLAIN']),
        connection_options=dict(type='list',
                                elements='raw',
                                default=None)
    )
    if ssl_options:
        options.update(ssl_options_dict)
    return options


def rename_ssl_option_for_pymongo4(connection_options):
    """
    This function renames the old ssl parameter, and sorts the data out,
    when the driver use is >= PyMongo 4
    """
    if int(PyMongoVersion[0]) >= 4:
        if connection_options.get('ssl_cert_reqs', None) in ('CERT_NONE', ssl_lib.CERT_NONE):
            connection_options['tlsAllowInvalidCertificates'] = True
        elif connection_options.get('ssl_cert_reqs', None) in ('CERT_REQUIRED', ssl_lib.CERT_REQUIRED):
            connection_options['tlsAllowInvalidCertificates'] = False
        connection_options.pop('ssl_cert_reqs', None)
        if connection_options.get('ssl_ca_certs', None) is not None:
            connection_options['tlsCAFile'] = connection_options['ssl_ca_certs']
        connection_options.pop('ssl_ca_certs', None)
        connection_options.pop('ssl_crlfile', None)
        if connection_options.get('ssl_certfile', None) is not None:
            connection_options['tlsCertificateKeyFile'] = connection_options['ssl_certfile']
        elif connection_options.get('ssl_keyfile', None) is not None:
            connection_options['tlsCertificateKeyFile'] = connection_options['ssl_keyfile']
        connection_options.pop('ssl_certfile', None)
        connection_options.pop('ssl_keyfile', None)
        if connection_options.get('ssl_pem_passphrase', None) is not None:
            connection_options['tlsCertificateKeyFilePassword'] = connection_options['ssl_pem_passphrase']
        connection_options.pop('ssl_pem_passphrase', None)
    return connection_options


def add_option_if_not_none(param_name, module, connection_params):
    '''
    @param_name - The parameter name to check
    @module - The ansible module object
    @connection_params - Dict containing the connection params
    '''
    if module.params[param_name] is not None:
        connection_params[param_name] = module.params[param_name]
    return connection_params


def ssl_connection_options(connection_params, module):
    connection_params['ssl'] = True
    if module.params['ssl_cert_reqs'] is not None:
        connection_params['ssl_cert_reqs'] = getattr(ssl_lib, module.params['ssl_cert_reqs'])
    connection_params = add_option_if_not_none('ssl_ca_certs', module, connection_params)
    connection_params = add_option_if_not_none('ssl_crlfile', module, connection_params)
    connection_params = add_option_if_not_none('ssl_certfile', module, connection_params)
    connection_params = add_option_if_not_none('ssl_keyfile', module, connection_params)
    connection_params = add_option_if_not_none('ssl_pem_passphrase', module, connection_params)
    if module.params['auth_mechanism'] is not None:
        connection_params['authMechanism'] = module.params['auth_mechanism']
    if module.params['connection_options'] is not None:
        for item in module.params['connection_options']:
            if isinstance(item, dict):
                for key, value in item.items():
                    connection_params[key] = value
            elif isinstance(item, str) and "=" in item:
                connection_params[item.split('=')[0]] = item.split('=')[1]
            else:
                raise ValueError("Invalid value supplied in connection_options: {0} .".format(str(item)))
    return connection_params


def check_srv_version(module, client):
    srv_version = None
    try:
        srv_version = client.server_info()['version']
    except Exception as excep:
        module.fail_json(msg='Unable to get MongoDB server version: %s' % to_native(excep))
    return srv_version


def check_driver_compatibility(module, client, srv_version):
    try:
        # Get driver version::
        driver_version = PyMongoVersion
        # Check driver and server version compatibility:
        check_compatibility(module, srv_version, driver_version)
    except Exception as excep:
        module.fail_json(msg='Unable to check driver compatibility: %s' % to_native(excep))


def get_mongodb_client(module, login_user=None, login_password=None, login_database=None, directConnection=False):
    """
    Build the connection params dict and returns a MongoDB Client object
    """
    connection_params = {
        'host': module.params['login_host'],
        'port': module.params['login_port'],
    }

    if directConnection:
        connection_params['directConnection'] = True
    if module.params['ssl']:
        connection_params = ssl_connection_options(connection_params, module)
        connection_params = rename_ssl_option_for_pymongo4(connection_params)
    # param exists only in some modules
    if 'replica_set' in module.params and 'reconfigure' not in module.params:
        connection_params["replicaset"] = module.params['replica_set']
    elif 'replica_set' in module.params and 'reconfigure' in module.params \
            and module.params['reconfigure']:
        connection_params["replicaset"] = module.params['replica_set']
    if login_user:
        connection_params['username'] = login_user
        connection_params['password'] = login_password
        connection_params['authSource'] = login_database
    client = MongoClient(**connection_params)
    return client


def is_auth_enabled(module):
    """
    Returns True if auth is enabled on the mongo instance
    For PyMongo 4+ we have to connect directly to the instance
    rather than the replicaset
    """
    auth_is_enabled = None
    connection_params = {}
    connection_params['host'] = module.params['login_host']
    connection_params['port'] = module.params['login_port']
    connection_params['directConnection'] = True  # Need to do this for 3.12.* as well
    if int(PyMongoVersion[0]) >= 4:  # we need to connect directly to the instance
        connection_params['directConnection'] = True
    else:
        if 'replica_set' in module.params and module.params['replica_set'] is not None:
            connection_params['replicaset'] = module.params['replica_set']
    if module.params['ssl']:
        connection_params = ssl_connection_options(connection_params, module)
        connection_params = rename_ssl_option_for_pymongo4(connection_params)
    try:
        myclient = MongoClient(**connection_params)
        hello_response = myclient.admin.command('hello')
        if 'arbiterOnly' in hello_response and hello_response['arbiterOnly']:
            auth_is_enabled = False  # Arbiters cannot login with a user
        else:
            myclient['admin'].command('listDatabases', 1.0)
            auth_is_enabled = False
    except Exception as excep:
        if hasattr(excep, 'code') and excep.code in [13]:
            auth_is_enabled = True
        if auth_is_enabled is None:  # if this is still none we have a problem
            module.fail_json(msg='Unable to determine if auth is enabled: {0}'.format(traceback.format_exc()))
    finally:
        myclient.close()
    return auth_is_enabled


def mongo_auth(module, client, directConnection=False):
    """
    TODO: This function was extracted from code from the mongodb_replicaset module.
    We should refactor other modules to use this where appropriate. - DONE?
    @module - The calling Ansible module
    @client - The MongoDB connection object
    """
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    login_database = module.params['login_database']

    atlas_auth = module.params['atlas_auth']

    fail_msg = None  # Our test code had issues with multiple exit points with fail_json

    crypt_flag = 'ssl'
    if 'tls' in module.params:
        crypt_flag = 'tls'

    if not atlas_auth:

        if login_user is None and login_password is None:
            mongocnf_creds = load_mongocnf()
            if mongocnf_creds is not False:
                login_user = mongocnf_creds['user']
                login_password = mongocnf_creds['password']
        elif not all([login_user, login_password]) and module.params[crypt_flag] is False:
            fail_msg = "When supplying login arguments, both 'login_user' and 'login_password' must be provided"

        if 'create_for_localhost_exception' not in module.params and fail_msg is None:
            try:
                if is_auth_enabled(module):
                    if login_user is not None and login_password is not None:
                        client = get_mongodb_client(module, login_user, login_password, login_database, directConnection=directConnection)
                    else:
                        fail_msg = 'No credentials to authenticate'
            except Exception as excep:
                fail_msg = 'unable to connect to database: %s' % to_native(excep)
            # Get server version:
            if fail_msg is None:
                srv_version = check_srv_version(module, client)
                check_driver_compatibility(module, client, srv_version)
        elif fail_msg is None:  # this is the mongodb_user module
            if login_user is not None and login_password is not None:
                client = get_mongodb_client(module, login_user, login_password, login_database, directConnection=directConnection)
                # Get server version:
                srv_version = check_srv_version(module, client)
                check_driver_compatibility(module, client, srv_version)
            elif module.params['strict_compatibility'] is False:
                if module.params['database'] not in ["admin", "$external"]:
                    fail_msg = 'The localhost login exception only allows the first admin account to be created'
                # else: this has to be the first admin user added
        if fail_msg:
            module.fail_json(msg=fail_msg)
    else:  # Atlas auth path
        if 'create_for_localhost_exception' not in module.params and fail_msg is None:
            try:
                if login_user is not None and login_password is not None:
                    # pymongo >= 4. There's no authenticate method in pymongo 4.0. Recreate the connection object
                    client = get_mongodb_client(module, login_user, login_password, login_database)
                else:
                    fail_msg = 'No credentials to authenticate'
            except Exception as excep:
                fail_msg = 'unable to connect to database: %s' % to_native(excep)
        elif fail_msg is None:  # this is the mongodb_user module
            if login_user is not None and login_password is not None:
                client = get_mongodb_client(module, login_user, login_password, login_database, directConnection=False)
                # Get server version:
                srv_version = check_srv_version(module, client)
                check_driver_compatibility(module, client, srv_version)
            elif module.params['strict_compatibility'] is False:
                if module.params['database'] not in ["admin", "$external"]:
                    fail_msg = 'The localhost login exception only allows the first admin account to be created'
                # else: this has to be the first admin user added
        if fail_msg:
            module.fail_json(msg=fail_msg)
    return client


def member_dicts_different(conf, member_config):
    '''
    Returns if there is a difference in the replicaset configuration that we care about
    @con - The current MongoDB Replicaset configure document
    @member_config - The member dict config provided by the module. List of dicts
    '''
    current_member_config = conf['members']
    member_config_defaults = {
        "arbiterOnly": False,
        "buildIndexes": True,
        "hidden": False,
        "priority": {"nonarbiter": 1.0, "arbiter": 0},
        "tags": {},
        "horizons": {},
        "secondardDelaySecs": 0,
        "votes": 1
    }
    different = False
    msg = "None"
    current_member_hosts = []
    for member in current_member_config:
        current_member_hosts.append(member['host'])
    member_config_hosts = []
    for member in member_config:
        if ':' not in member['host']:  # no port supplied
            member_config_hosts.append(member['host'] + ":27017")
        else:
            member_config_hosts.append(member['host'])
    if sorted(current_member_hosts) != sorted(member_config_hosts):  # compare if members are the same
        different = True
        msg = "hosts different"
    else:  # Compare dict key to see if votes, tags etc have changed. We also default value if key is not specified
        for host in current_member_hosts:
            member_index = next((index for (index, d) in enumerate(current_member_config) if d["host"] == host), None)
            new_member_index = next((index for (index, d) in enumerate(member_config) if d["host"] == host), None)
            for config_item in member_config_defaults:
                if config_item != "priority":
                    if current_member_config[member_index].get(config_item, member_config_defaults[config_item]) != \
                            member_config[new_member_index].get(config_item, member_config_defaults[config_item]):
                        different = True
                        msg = "var different {0} {1} {2}".format(config_item,
                                                                 current_member_config[member_index].get(config_item, member_config_defaults[config_item]),
                                                                 member_config[new_member_index].get(config_item, member_config_defaults[config_item]))
                        break
                else:  # priority a special case
                    role = "nonarbiter"
                    if current_member_config[member_index]["arbiterOnly"]:
                        role = "arbiter"
                        if current_member_config[member_index][config_item] != \
                                member_config[new_member_index].get(config_item, member_config_defaults[config_item][role]):
                            different = True
                            msg = "var different {0}".format(config_item)
                            break
                    else:  # for case when the member is not an arbiter
                        if current_member_config[member_index]["priority"] != \
                                member_config[new_member_index].get(config_item, 1.0):
                            different = True
                            msg = "var different {0}".format(config_item)
                            break
    return different  # , msg


def lists_are_different(list1, list2):
    diff = False
    if sorted(list1) != sorted(list2):
        diff = True
    return diff


# Taken from https://github.com/ansible-collections/community.postgresql/blob/main/plugins/module_utils/postgres.py#L420
def convert_to_supported(val):
    """Convert unsupported type to appropriate.
    Args:
        val (any) -- Any value fetched from database.
    Returns value of appropriate type.
    """
    if isinstance(val, Timestamp):
        return str(val)
    elif isinstance(val, ObjectId):
        return str(val)

    return val  # By default returns the same value


def convert_bson_values_recur(mydict):
    """
    Converts values that Ansible doesn't like
    # https://github.com/ansible-collections/community.mongodb/issues/462
    """
    if isinstance(mydict, dict):
        for key, value in mydict.items():
            if isinstance(value, dict):
                mydict[key] = convert_bson_values_recur(value)
            else:
                if isinstance(value, TYPES_NEED_TO_CONVERT):
                    mydict[key] = convert_to_supported(value)
                else:
                    mydict[key] = value
    return mydict
