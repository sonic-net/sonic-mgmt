from __future__ import (absolute_import, division, print_function)


__metaclass__ = type

# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Simplified BSD License (see simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

import string
import json
import re

from ansible.module_utils.six import iteritems

from ansible_collections.community.mysql.plugins.module_utils.mysql import (
    mysql_driver,
    get_server_implementation,
)
from ansible_collections.community.mysql.plugins.module_utils.implementations.mysql.hash import (
    mysql_sha256_password_hash,
    mysql_sha256_password_hash_hex,
)


class InvalidPrivsError(Exception):
    pass


def get_mode(cursor):
    cursor.execute('SELECT @@sql_mode')
    result = cursor.fetchone()
    mode_str = result[0]
    if 'ANSI' in mode_str:
        mode = 'ANSI'
    else:
        mode = 'NOTANSI'
    return mode


def user_exists(cursor, user, host, host_all):
    if host_all:
        cursor.execute("SELECT count(*) FROM mysql.user WHERE user = %s", (user,))
    else:
        cursor.execute("SELECT count(*) FROM mysql.user WHERE user = %s AND host = %s", (user, host))

    count = cursor.fetchone()
    return count[0] > 0


def user_is_locked(cursor, user, host):
    cursor.execute("SHOW CREATE USER %s@%s", (user, host))

    # Per discussions on irc:libera.chat:#maria the query may return up to 2 rows but "ACCOUNT LOCK" should always be in the first row.
    result = cursor.fetchone()

    # ACCOUNT LOCK does not have to be the last option in the CREATE USER query.
    # Need to handle both DictCursor and non-DictCursor
    if isinstance(result, tuple):
        if result[0].find('ACCOUNT LOCK') > 0:
            return True
    elif isinstance(result, dict):
        for res in result.values():
            if res.find('ACCOUNT LOCK') > 0:
                return True

    return False


def sanitize_requires(tls_requires):
    sanitized_requires = {}
    if tls_requires:
        for key in tls_requires.keys():
            sanitized_requires[key.upper()] = tls_requires[key]
        if any(key in ["CIPHER", "ISSUER", "SUBJECT"] for key in sanitized_requires.keys()):
            sanitized_requires.pop("SSL", None)
            sanitized_requires.pop("X509", None)
            return sanitized_requires

        if "X509" in sanitized_requires.keys():
            sanitized_requires = "X509"
        else:
            sanitized_requires = "SSL"

        return sanitized_requires
    return None


def mogrify_requires(query, params, tls_requires):
    if tls_requires:
        if isinstance(tls_requires, dict):
            k, v = zip(*tls_requires.items())
            requires_query = " AND ".join(("%s %%s" % key for key in k))
            params += v
        else:
            requires_query = tls_requires
        query = " REQUIRE ".join((query, requires_query))
    return query, params


def do_not_mogrify_requires(query, params, tls_requires):
    return query, params


def get_grants(cursor, user, host):
    cursor.execute("SHOW GRANTS FOR %s@%s", (user, host))
    grants_line = list(filter(lambda x: "ON *.*" in x[0], cursor.fetchall()))[0]
    pattern = r"(?<=\bGRANT\b)(.*?)(?=(?:\bON\b))"
    grants = re.search(pattern, grants_line[0]).group().strip()
    return grants.split(", ")


def get_existing_authentication(cursor, user, host=None):
    """ Return a list of dict containing the plugin and auth_string for the
    specified username.
    If hostname is provided, return only the information about this particular
    account.
    """
    cursor.execute("SELECT VERSION()")
    srv_type = cursor.fetchone()
    # Mysql_info use a DictCursor so we must convert back to a list
    # otherwise we get KeyError 0
    if isinstance(srv_type, dict):
        srv_type = list(srv_type.values())

    if 'mariadb' in srv_type[0].lower():
        # before MariaDB 10.2.19 and 10.3.11, "password" and "authentication_string" can differ
        # when using mysql_native_password
        if host:
            cursor.execute("""select plugin, auth from (
                select plugin, password as auth from mysql.user where user=%(user)s
                and host=%(host)s
                union select plugin, authentication_string as auth from mysql.user where user=%(user)s
                and host=%(host)s) x group by plugin, auth
            """, {'user': user, 'host': host})
        else:
            cursor.execute("""select plugin, auth from (
                select plugin, password as auth from mysql.user where user=%(user)s
                union select plugin, authentication_string as auth from mysql.user where user=%(user)s
                ) x group by plugin, auth
            """, {'user': user})
    else:
        if host:
            cursor.execute("""select plugin, authentication_string as auth
                from mysql.user where user=%(user)s and host=%(host)s
                group by plugin, authentication_string""", {'user': user, 'host': host})
        else:
            cursor.execute("""select plugin, authentication_string as auth
                from mysql.user where user=%(user)s
                group by plugin, authentication_string""", {'user': user})

    rows = cursor.fetchall()

    if len(rows) == 0:
        return []

    # Mysql_info use a DictCursor so we must convert list(dict)
    # to list(tuple) otherwise we get KeyError 0
    if isinstance(rows[0], dict):
        rows = [tuple(row.values()) for row in rows]

    existing_auth_list = []

    # 'plugin_auth_string' contains the hash string. Must be removed in c.mysql 4.0
    # See https://github.com/ansible-collections/community.mysql/pull/629
    for r in rows:
        existing_auth_list.append({
            'plugin': r[0],
            'plugin_auth_string': r[1],
            'plugin_hash_string': r[1]})

    return existing_auth_list


def user_add(cursor, user, host, host_all, password, encrypted,
             plugin, plugin_hash_string, plugin_auth_string, salt, new_priv,
             attributes, tls_requires, reuse_existing_password, module,
             password_expire, password_expire_interval, locked=False):
    # If attributes are set, perform a sanity check to ensure server supports user attributes before creating user
    if attributes and not get_attribute_support(cursor):
        module.fail_json(msg="user attributes were specified but the server does not support user attributes")

    # we cannot create users without a proper hostname
    if host_all:
        return {'changed': False, 'password_changed': False, 'attributes': attributes}

    if module.check_mode:
        return {'changed': True, 'password_changed': None, 'attributes': attributes}

    # Determine what user management method server uses
    impl = get_user_implementation(cursor)
    old_user_mgmt = impl.use_old_user_mgmt(cursor)

    mogrify = do_not_mogrify_requires if old_user_mgmt else mogrify_requires

    # This is for update_password: on_new_username
    used_existing_password = False
    if reuse_existing_password:
        existing_auth = get_existing_authentication(cursor, user)
        if existing_auth:
            if len(existing_auth) != 1:
                module.warn("An account with the username %s has a different "
                            "password than the others existing accounts. Thus "
                            "on_new_username can't decide which password to "
                            "reuse so it will use your provided password "
                            "instead. If no password is provided, the account "
                            "will have an empty password!" % user)
                used_existing_password = False
            else:
                plugin_hash_string = existing_auth[0]['plugin_hash_string']
                password = None
                used_existing_password = True
                plugin = existing_auth[0]['plugin']  # What if plugin differ?
    if password and encrypted:
        if impl.supports_identified_by_password(cursor):
            query_with_args = "CREATE USER %s@%s IDENTIFIED BY PASSWORD %s", (user, host, password)
        else:
            query_with_args = "CREATE USER %s@%s IDENTIFIED WITH mysql_native_password AS %s", (user, host, password)
    elif password and not encrypted:
        if old_user_mgmt:
            query_with_args = "CREATE USER %s@%s IDENTIFIED BY %s", (user, host, password)
        else:
            cursor.execute("SELECT CONCAT('*', UCASE(SHA1(UNHEX(SHA1(%s)))))", (password,))
            encrypted_password = cursor.fetchone()[0]
            query_with_args = "CREATE USER %s@%s IDENTIFIED WITH mysql_native_password AS %s", (user, host, encrypted_password)
    elif plugin and plugin_hash_string:
        query_with_args = "CREATE USER %s@%s IDENTIFIED WITH %s AS %s", (user, host, plugin, plugin_hash_string)
    elif plugin and plugin_auth_string:
        # Mysql and MariaDB differ in naming pam plugin and Syntax to set it
        if plugin == 'pam':  # Used by MariaDB which requires the USING keyword, not BY
            query_with_args = "CREATE USER %s@%s IDENTIFIED WITH %s USING %s", (user, host, plugin, plugin_auth_string)
        elif plugin == 'ed25519':  # Used by MariaDB which requires the USING keyword, not BY
            query_with_args = "CREATE USER %s@%s IDENTIFIED WITH %s USING PASSWORD(%s)", (user, host, plugin, plugin_auth_string)
        elif salt:
            if plugin in ['caching_sha2_password', 'sha256_password']:
                generated_hash_string = mysql_sha256_password_hash_hex(password=plugin_auth_string, salt=salt)
            else:
                module.fail_json(msg="salt not handled for %s authentication plugin" % plugin)
            query_with_args = ("CREATE USER %s@%s IDENTIFIED WITH %s AS 0x" + generated_hash_string), (user, host, plugin)
        else:
            query_with_args = "CREATE USER %s@%s IDENTIFIED WITH %s BY %s", (user, host, plugin, plugin_auth_string)
    elif plugin:
        query_with_args = "CREATE USER %s@%s IDENTIFIED WITH %s", (user, host, plugin)
    else:
        query_with_args = "CREATE USER %s@%s", (user, host)

    query_with_args_and_tls_requires = query_with_args + (tls_requires,)
    cursor.execute(*mogrify(*query_with_args_and_tls_requires))

    if password_expire:
        if not impl.server_supports_password_expire(cursor):
            module.fail_json(msg="The server version does not match the requirements "
                             "for password_expire parameter. See module's documentation.")
        set_password_expire(cursor, user, host, password_expire, password_expire_interval)

    if new_priv is not None:
        for db_table, priv in iteritems(new_priv):
            privileges_grant(cursor, user, host, db_table, priv, tls_requires)
    if tls_requires is not None:
        privileges_grant(cursor, user, host, "*.*", get_grants(cursor, user, host), tls_requires)

    final_attributes = None

    if attributes:
        cursor.execute("ALTER USER %s@%s ATTRIBUTE %s", (user, host, json.dumps(attributes)))
        final_attributes = attributes_get(cursor, user, host)

    if locked:
        cursor.execute("ALTER USER %s@%s ACCOUNT LOCK", (user, host))

    return {'changed': True, 'password_changed': not used_existing_password, 'attributes': final_attributes}


def is_hash(password):
    ishash = False
    if len(password) == 41 and password[0] == '*':
        if frozenset(password[1:]).issubset(string.hexdigits):
            ishash = True
    return ishash


def user_mod(cursor, user, host, host_all, password, encrypted,
             plugin, plugin_hash_string, plugin_auth_string, salt, new_priv,
             append_privs, subtract_privs, attributes, tls_requires, module,
             password_expire, password_expire_interval, locked=None, role=False, maria_role=False):
    changed = False
    msg = "User unchanged"
    grant_option = False

    # Determine what user management method server uses
    impl = get_user_implementation(cursor)
    old_user_mgmt = impl.use_old_user_mgmt(cursor)

    if host_all and not role:
        hostnames = user_get_hostnames(cursor, user)
    else:
        hostnames = [host]

    password_changed = False
    for host in hostnames:
        # Handle clear text and hashed passwords.
        if not role:
            if bool(password):

                # Get a list of valid columns in mysql.user table to check if Password and/or authentication_string exist
                cursor.execute("""
                    SELECT COLUMN_NAME FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = 'mysql' AND TABLE_NAME = 'user' AND COLUMN_NAME IN ('Password', 'authentication_string')
                    ORDER BY COLUMN_NAME DESC LIMIT 1
                """)
                colA = cursor.fetchone()

                cursor.execute("""
                    SELECT COLUMN_NAME FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = 'mysql' AND TABLE_NAME = 'user' AND COLUMN_NAME IN ('Password', 'authentication_string')
                    ORDER BY COLUMN_NAME ASC  LIMIT 1
                """)
                colB = cursor.fetchone()

                # Select hash from either Password or authentication_string, depending which one exists and/or is filled
                cursor.execute("""
                    SELECT COALESCE(
                            CASE WHEN %s = '' THEN NULL ELSE %s END,
                            CASE WHEN %s = '' THEN NULL ELSE %s END
                        )
                    FROM mysql.user WHERE user = %%s AND host = %%s
                    """ % (colA[0], colA[0], colB[0], colB[0]), (user, host))
                current_pass_hash = cursor.fetchone()[0]
                if isinstance(current_pass_hash, bytes):
                    current_pass_hash = current_pass_hash.decode('ascii')

                if encrypted:
                    encrypted_password = password
                    if not is_hash(encrypted_password):
                        module.fail_json(msg="encrypted was specified however it does not appear to be a valid hash expecting: *SHA1(SHA1(your_password))")
                else:
                    if old_user_mgmt:
                        cursor.execute("SELECT PASSWORD(%s)", (password,))
                    else:
                        cursor.execute("SELECT CONCAT('*', UCASE(SHA1(UNHEX(SHA1(%s)))))", (password,))
                    encrypted_password = cursor.fetchone()[0]

                if current_pass_hash != encrypted_password:
                    password_changed = True
                    msg = "Password updated"
                    if not module.check_mode:
                        if old_user_mgmt:
                            cursor.execute("SET PASSWORD FOR %s@%s = %s", (user, host, encrypted_password))
                            msg = "Password updated (old style)"
                        else:
                            try:
                                cursor.execute("ALTER USER %s@%s IDENTIFIED WITH mysql_native_password AS %s", (user, host, encrypted_password))
                                msg = "Password updated (new style)"
                            except (mysql_driver.Error) as e:
                                # https://stackoverflow.com/questions/51600000/authentication-string-of-root-user-on-mysql
                                # Replacing empty root password with new authentication mechanisms fails with error 1396
                                if e.args[0] == 1396:
                                    cursor.execute(
                                        "UPDATE mysql.user SET plugin = %s, authentication_string = %s, Password = '' WHERE User = %s AND Host = %s",
                                        ('mysql_native_password', encrypted_password, user, host)
                                    )
                                    cursor.execute("FLUSH PRIVILEGES")
                                    msg = "Password forced update"
                                else:
                                    raise e
                    changed = True

        # Handle password expiration
        if bool(password_expire):
            if not impl.server_supports_password_expire(cursor):
                module.fail_json(msg="The server version does not match the requirements "
                                     "for password_expire parameter. See module's documentation.")
            update = False
            mariadb_role = True if "mariadb" in str(impl.__name__) else False
            current_password_policy = get_password_expiration_policy(cursor, user, host, maria_role=mariadb_role)
            password_expired = is_password_expired(cursor, user, host)
            # Check if changes needed to be applied.
            if not ((current_password_policy == -1 and password_expire == "default") or
                    (current_password_policy == 0 and password_expire == "never") or
                    (current_password_policy == password_expire_interval and password_expire == "interval") or
                    (password_expire == 'now' and password_expired)):

                update = True

                if not module.check_mode:
                    set_password_expire(cursor, user, host, password_expire, password_expire_interval)
                    password_changed = True
                    changed = True

        # Handle plugin authentication
        if plugin and not role:
            cursor.execute("SELECT plugin, authentication_string FROM mysql.user "
                           "WHERE user = %s AND host = %s", (user, host))
            current_plugin = cursor.fetchone()

            update = False

            if current_plugin[0] != plugin:
                update = True

            if plugin_hash_string and current_plugin[1] != plugin_hash_string:
                update = True

            if salt:
                if plugin in ['caching_sha2_password', 'sha256_password']:
                    if current_plugin[1] != mysql_sha256_password_hash(password=plugin_auth_string, salt=salt):
                        update = True
            elif plugin_auth_string and current_plugin[1] != plugin_auth_string:
                # this case can cause more updates than expected,
                # as plugin can hash auth_string in any way it wants
                # and there's no way to figure it out for
                # a check, so I prefer to update more often than never
                update = True

            if update:
                query_with_args = None
                if plugin_hash_string:
                    query_with_args = "ALTER USER %s@%s IDENTIFIED WITH %s AS %s", (user, host, plugin, plugin_hash_string)
                elif plugin_auth_string:
                    # Mysql and MariaDB differ in naming pam plugin and syntax to set it
                    if plugin == 'pam':
                        query_with_args = "ALTER USER %s@%s IDENTIFIED WITH %s USING %s", (user, host, plugin, plugin_auth_string)
                    elif plugin == 'ed25519':
                        query_with_args = "ALTER USER %s@%s IDENTIFIED WITH %s USING PASSWORD(%s)", (user, host, plugin, plugin_auth_string)
                    elif salt:
                        if plugin in ['caching_sha2_password', 'sha256_password']:
                            generated_hash_string = mysql_sha256_password_hash_hex(password=plugin_auth_string, salt=salt)
                        else:
                            module.fail_json(msg="salt not handled for %s authentication plugin" % plugin)
                        query_with_args = ("ALTER USER %s@%s IDENTIFIED WITH %s AS 0x" + generated_hash_string), (user, host, plugin)
                    else:
                        query_with_args = "ALTER USER %s@%s IDENTIFIED WITH %s BY %s", (user, host, plugin, plugin_auth_string)
                else:
                    query_with_args = "ALTER USER %s@%s IDENTIFIED WITH %s", (user, host, plugin)

                if not module.check_mode:
                    cursor.execute(*query_with_args)
                password_changed = True
                changed = True

        # Handle privileges
        if new_priv is not None:
            curr_priv = privileges_get(cursor, user, host, maria_role)

            # If the user has privileges on a db.table that doesn't appear at all in
            # the new specification, then revoke all privileges on it.
            if not append_privs and not subtract_privs:
                for db_table, priv in iteritems(curr_priv):
                    # If the user has the GRANT OPTION on a db.table, revoke it first.
                    if "GRANT" in priv:
                        grant_option = True
                    if db_table not in new_priv:
                        if user != "root" and "PROXY" not in priv:
                            msg = "Privileges updated"
                            if not module.check_mode:
                                privileges_revoke(cursor, user, host, db_table, priv, grant_option, maria_role)
                            changed = True

            # If the user doesn't currently have any privileges on a db.table, then
            # we can perform a straight grant operation.
            if not subtract_privs:
                for db_table, priv in iteritems(new_priv):
                    if db_table not in curr_priv:
                        msg = "New privileges granted"
                        if not module.check_mode:
                            privileges_grant(cursor, user, host, db_table, priv, tls_requires, maria_role)
                        changed = True

            # If the db.table specification exists in both the user's current privileges
            # and in the new privileges, then we need to see if there's a difference.
            db_table_intersect = set(new_priv.keys()) & set(curr_priv.keys())
            for db_table in db_table_intersect:

                grant_privs = []
                revoke_privs = []
                if append_privs:
                    # When appending privileges, only missing privileges need to be granted. Nothing is revoked.
                    grant_privs = list(set(new_priv[db_table]) - set(curr_priv[db_table]))
                elif subtract_privs:
                    # When subtracting privileges, revoke only the intersection of requested and current privileges.
                    # No privileges are granted.
                    revoke_privs = list(set(new_priv[db_table]) & set(curr_priv[db_table]))
                else:
                    # When replacing (neither append_privs nor subtract_privs), grant all missing privileges
                    # and revoke existing privileges that were not requested...
                    grant_privs = list(set(new_priv[db_table]) - set(curr_priv[db_table]))
                    revoke_privs = list(set(curr_priv[db_table]) - set(new_priv[db_table]))

                    # ... avoiding pointless revocations when ALL are granted
                    if 'ALL' in grant_privs or 'ALL PRIVILEGES' in grant_privs:
                        revoke_privs = list(set(['GRANT', 'PROXY']).intersection(set(revoke_privs)))

                    # Only revoke grant option if it exists and absence is requested
                    #
                    # For more details
                    # https://github.com/ansible-collections/community.mysql/issues/77#issuecomment-1209693807
                    grant_option = 'GRANT' in revoke_privs and 'GRANT' not in grant_privs

                if grant_privs == ['GRANT']:
                    # USAGE grants no privileges, it is only needed because 'WITH GRANT OPTION' cannot stand alone
                    grant_privs.append('USAGE')

                if len(grant_privs) + len(revoke_privs) > 0:
                    msg = "Privileges updated: granted %s, revoked %s" % (grant_privs, revoke_privs)
                    if not module.check_mode:
                        if len(revoke_privs) > 0:
                            privileges_revoke(cursor, user, host, db_table, revoke_privs, grant_option, maria_role)
                        if len(grant_privs) > 0:
                            privileges_grant(cursor, user, host, db_table, grant_privs, tls_requires, maria_role)
                    else:
                        changed = True

            # after privilege manipulation, compare privileges from before and now
            after_priv = privileges_get(cursor, user, host, maria_role)
            changed = changed or (curr_priv != after_priv)

        # Handle attributes
        attribute_support = get_attribute_support(cursor)
        final_attributes = {}

        if attributes:
            if not attribute_support:
                module.fail_json(msg="user attributes were specified but the server does not support user attributes")
            else:
                current_attributes = attributes_get(cursor, user, host)

                if current_attributes is None:
                    current_attributes = {}

                attributes_to_change = {}

                for key, value in attributes.items():
                    if key not in current_attributes or current_attributes[key] != value:
                        attributes_to_change[key] = value

                if attributes_to_change:
                    msg = "Attributes updated: %s" % (", ".join(["%s: %s" % (key, value) for key, value in attributes_to_change.items()]))

                    # Calculate final attributes by re-running attributes_get when not in check mode, and merge dictionaries when in check mode
                    if not module.check_mode:
                        cursor.execute("ALTER USER %s@%s ATTRIBUTE %s", (user, host, json.dumps(attributes_to_change)))
                        final_attributes = attributes_get(cursor, user, host)
                    else:
                        # Final if statements excludes items whose values are None in attributes_to_change, i.e. attributes that will be deleted
                        final_attributes = {k: v for d in (current_attributes, attributes_to_change) for k, v in d.items() if k not in attributes_to_change or
                                            attributes_to_change[k] is not None}

                        # Convert empty dict to None per return value requirements
                        final_attributes = final_attributes if final_attributes else None
                    changed = True
                else:
                    final_attributes = current_attributes
        else:
            if attribute_support:
                final_attributes = attributes_get(cursor, user, host)

        if not role and locked is not None and user_is_locked(cursor, user, host) != locked:
            if not module.check_mode:
                if locked:
                    cursor.execute("ALTER USER %s@%s ACCOUNT LOCK", (user, host))
                    msg = 'User locked'
                else:
                    cursor.execute("ALTER USER %s@%s ACCOUNT UNLOCK", (user, host))
                    msg = 'User unlocked'
            else:
                if locked:
                    msg = 'User will be locked'
                else:
                    msg = 'User will be unlocked'

            changed = True

        if role:
            continue

        # Handle TLS requirements
        current_requires = sanitize_requires(impl.get_tls_requires(cursor, user, host))
        if current_requires != tls_requires:
            msg = "TLS requires updated"
            if not module.check_mode:
                if not old_user_mgmt:
                    pre_query = "ALTER USER"
                else:
                    pre_query = "GRANT %s ON *.* TO" % ",".join(get_grants(cursor, user, host))

                if tls_requires is not None:
                    query = " ".join((pre_query, "%s@%s"))
                    query_with_args = mogrify_requires(query, (user, host), tls_requires)
                else:
                    query = " ".join((pre_query, "%s@%s REQUIRE NONE"))
                    query_with_args = query, (user, host)

                cursor.execute(*query_with_args)
            changed = True

    return {'changed': changed, 'msg': msg, 'password_changed': password_changed, 'attributes': final_attributes}


def user_delete(cursor, user, host, host_all, check_mode):
    if check_mode:
        return True

    if host_all:
        hostnames = user_get_hostnames(cursor, user)
    else:
        hostnames = [host]

    for hostname in hostnames:
        try:
            cursor.execute("DROP USER IF EXISTS %s@%s", (user, hostname))
        except Exception:
            cursor.execute("DROP USER %s@%s", (user, hostname))

    return True


def user_get_hostnames(cursor, user):
    cursor.execute("SELECT Host FROM mysql.user WHERE user = %s", (user,))
    hostnames_raw = cursor.fetchall()
    hostnames = []

    for hostname_raw in hostnames_raw:
        hostnames.append(hostname_raw[0])

    return hostnames


def privileges_get(cursor, user, host, maria_role=False):
    """ MySQL doesn't have a better method of getting privileges aside from the
    SHOW GRANTS query syntax, which requires us to then parse the returned string.
    Here's an example of the string that is returned from MySQL:

     GRANT USAGE ON *.* TO 'user'@'localhost' IDENTIFIED BY 'pass';

    This function makes the query and returns a dictionary containing the results.
    The dictionary format is the same as that returned by privileges_unpack() below.
    """
    output = {}
    if not maria_role:
        cursor.execute("SHOW GRANTS FOR %s@%s", (user, host))
    else:
        cursor.execute("SHOW GRANTS FOR %s", (user,))
    grants = cursor.fetchall()

    def pick(x):
        if x == 'ALL PRIVILEGES':
            return 'ALL'
        else:
            return x

    for grant in grants:

        # Mysql_info use a DictCursor so we must convert back to a list
        # otherwise we get KeyError 0
        if isinstance(grant, dict):
            grant = list(grant.values())

        if not maria_role:
            res = re.match("""GRANT (.+) ON (.+) TO (['`"]).*\\3@(['`"]).*\\4( IDENTIFIED BY PASSWORD (['`"]).+\\6)? ?(.*)""", grant[0])
        else:
            res = re.match("""GRANT (.+) ON (.+) TO .*""", grant[0])

        if res is None:
            # If a user has roles or a default role assigned,
            # we'll have some of the priv tuples looking either like
            # GRANT `admin`@`%` TO `user1`@`localhost`
            # or
            # SET DEFAULT ROLE `admin`@`%` FOR `user1`@`localhost`
            # which will result None as res value.
            # As we use the mysql_role module to manipulate roles
            # we just ignore such privs below:
            res = re.match(
                """GRANT (.+) TO (['`"]).*|SET DEFAULT ROLE (.+) FOR (['`"]).*""",
                grant[0]
            )

            if not maria_role and res:
                continue

            raise InvalidPrivsError('unable to parse the MySQL grant string: %s' % grant[0])

        privileges = res.group(1).split(",")
        privileges = [pick(x.strip()) for x in privileges]

        # Handle cases when there's privs like GRANT SELECT (colA, ...) in privs.
        # To this point, the privileges list can look like
        # ['SELECT (`A`', '`B`)', 'INSERT'] that is incorrect (SELECT statement is splitted).
        # Columns should also be sorted to compare it with desired privileges later.
        # Determine if there's a case similar to the above:
        privileges = normalize_col_grants(privileges)

        if not maria_role:
            if "WITH GRANT OPTION" in res.group(7):
                privileges.append('GRANT')
        db = res.group(2)
        output.setdefault(db, []).extend(privileges)
    return output


def normalize_col_grants(privileges):
    """Fix and sort grants on columns in privileges list

    Make ['SELECT (A, B)', 'INSERT (A, B)', 'DETELE']
    from ['SELECT (A', 'B)', 'INSERT (B', 'A)', 'DELETE'].
    See unit tests in tests/unit/plugins/modules/test_mysql_user.py
    """
    for grant in ('SELECT', 'UPDATE', 'INSERT', 'REFERENCES'):
        start, end = has_grant_on_col(privileges, grant)
        # If not, either start and end will be None
        if start is not None:
            privileges = handle_grant_on_col(privileges, start, end)

    return privileges


def has_grant_on_col(privileges, grant):
    """Check if there is a statement like SELECT (colA, colB)
    in the privilege list.

    Return (start index, end index).
    """
    # Determine elements of privileges where
    # columns are listed
    start = None
    end = None
    for n, priv in enumerate(privileges):
        if '%s (' % grant in priv:
            # We found the start element
            start = n

        if start is not None and ')' in priv:
            # We found the end element
            end = n
            break

    if start is not None and end is not None:
        # if the privileges list consist of, for example,
        # ['SELECT (A', 'B), 'INSERT'], return indexes of related elements
        return start, end
    else:
        # If start and end position is the same element,
        # it means there's expression like 'SELECT (A)',
        # so no need to handle it
        return None, None


def handle_grant_on_col(privileges, start, end):
    """Handle cases when the privs like SELECT (colA, ...) is in the privileges list."""
    # When the privileges list look like ['SELECT (colA,', 'colB)']
    # (Notice that the statement is splitted)
    if start != end:
        output = list(privileges[:start])

        select_on_col = ', '.join(privileges[start:end + 1])

        select_on_col = sort_column_order(select_on_col)

        output.append(select_on_col)

        output.extend(privileges[end + 1:])

    # When it look like it should be, e.g. ['SELECT (colA, colB)'],
    # we need to be sure, the columns is sorted
    else:
        output = list(privileges)
        output[start] = sort_column_order(output[start])

    return output


def sort_column_order(statement):
    """Sort column order in grants like SELECT (colA, colB, ...).

    MySQL changes columns order like below:
    ---------------------------------------
    mysql> GRANT SELECT (testColA, testColB), INSERT ON `testDb`.`testTable` TO 'testUser'@'localhost';
    Query OK, 0 rows affected (0.04 sec)

    mysql> flush privileges;
    Query OK, 0 rows affected (0.00 sec)

    mysql> SHOW GRANTS FOR testUser@localhost;
    +---------------------------------------------------------------------------------------------+
    | Grants for testUser@localhost                                                               |
    +---------------------------------------------------------------------------------------------+
    | GRANT USAGE ON *.* TO 'testUser'@'localhost'                                                |
    | GRANT SELECT (testColB, testColA), INSERT ON `testDb`.`testTable` TO 'testUser'@'localhost' |
    +---------------------------------------------------------------------------------------------+

    We should sort columns in our statement, otherwise the module always will return
    that the state has changed.
    """
    # 1. Extract stuff inside ()
    # 2. Split
    # 3. Sort
    # 4. Put between () and return

    # "SELECT/UPDATE/.. (colA, colB) => "colA, colB"
    tmp = statement.split('(')
    priv_name = tmp[0]
    columns = tmp[1].rstrip(')')

    # "colA, colB" => ["colA", "colB"]
    columns = columns.split(',')

    for i, col in enumerate(columns):
        col = col.strip()
        columns[i] = col.strip('`')

    columns.sort()
    return '%s(%s)' % (priv_name, ', '.join(columns))


def privileges_unpack(priv, mode, column_case_sensitive, ensure_usage=True):
    """ Take a privileges string, typically passed as a parameter, and unserialize
    it into a dictionary, the same format as privileges_get() above. We have this
    custom format to avoid using YAML/JSON strings inside YAML playbooks. Example
    of a privileges string:

     mydb.*:INSERT,UPDATE/anotherdb.*:SELECT/yetanother.*:ALL

    The privilege USAGE stands for no privileges, so we add that in on *.* if it's
    not specified in the string, as MySQL will always provide this by default.
    """
    if mode == 'ANSI':
        quote = '"'
    else:
        quote = '`'
    output = {}
    privs = []
    for item in priv.strip().split('/'):
        pieces = item.strip().rsplit(':', 1)
        dbpriv = pieces[0].rsplit(".", 1)

        # Check for FUNCTION or PROCEDURE object types
        parts = dbpriv[0].split(" ", 1)
        object_type = ''
        if len(parts) > 1 and (parts[0] == 'FUNCTION' or parts[0] == 'PROCEDURE'):
            object_type = parts[0] + ' '
            dbpriv[0] = parts[1]

        # Do not escape if privilege is for database or table, i.e.
        # neither quote *. nor .*
        for i, side in enumerate(dbpriv):
            if side.strip('`') != '*':
                dbpriv[i] = '%s%s%s' % (quote, side.strip('`'), quote)
        pieces[0] = object_type + '.'.join(dbpriv)

        if '(' in pieces[1]:
            if column_case_sensitive is True:
                output[pieces[0]] = re.split(r',\s*(?=[^)]*(?:\(|$))', pieces[1])
                for i in output[pieces[0]]:
                    privs.append(re.sub(r'\s*\(.*\)', '', i))
            else:
                output[pieces[0]] = re.split(r',\s*(?=[^)]*(?:\(|$))', pieces[1].upper())
                for i in output[pieces[0]]:
                    privs.append(re.sub(r'\s*\(.*\)', '', i))
        else:
            output[pieces[0]] = pieces[1].upper().split(',')
            privs = output[pieces[0]]

        # Handle cases when there's privs like GRANT SELECT (colA, ...) in privs.
        output[pieces[0]] = normalize_col_grants(output[pieces[0]])

    if ensure_usage and '*.*' not in output:
        output['*.*'] = ['USAGE']

    return output


def privileges_revoke(cursor, user, host, db_table, priv, grant_option, maria_role=False):
    # Escape '%' since mysql db.execute() uses a format string
    db_table = db_table.replace('%', '%%')
    if grant_option:
        query = ["REVOKE GRANT OPTION ON %s" % db_table]
        if not maria_role:
            query.append("FROM %s@%s")
        else:
            query.append("FROM %s")

        query = ' '.join(query)
        cursor.execute(query, (user, host))
    priv_string = ",".join([p for p in priv if p not in ('GRANT', )])

    if priv_string != "" and not (grant_option and priv_string == "USAGE"):
        query = ["REVOKE %s ON %s" % (priv_string, db_table)]

        if not maria_role:
            query.append("FROM %s@%s")
            params = (user, host)
        else:
            query.append("FROM %s")
            params = (user,)

        query = ' '.join(query)
        cursor.execute(query, params)
    cursor.execute("FLUSH PRIVILEGES")


def privileges_grant(cursor, user, host, db_table, priv, tls_requires, maria_role=False):
    # Escape '%' since mysql db.execute uses a format string and the
    # specification of db and table often use a % (SQL wildcard)
    db_table = db_table.replace('%', '%%')
    priv_string = ",".join([p for p in priv if p not in ('GRANT', )])
    query = ["GRANT %s ON %s" % (priv_string, db_table)]

    # MySQL and MariaDB don't store roles in the user table the same manner:
    # select user, host from mysql.user;
    # +------------------+-----------+
    # | user             | host      |
    # +------------------+-----------+
    # | role_foo         | %         | <- MySQL
    # | role_foo         |           | <- MariaDB
    # +------------------+-----------+
    if not maria_role:
        query.append("TO %s@%s")
        params = (user, host)
    else:
        query.append("TO %s")
        params = (user)

    impl = get_user_implementation(cursor)
    if tls_requires and impl.use_old_user_mgmt(cursor):
        query, params = mogrify_requires(" ".join(query), params, tls_requires)
        query = [query]
    if 'GRANT' in priv:
        query.append("WITH GRANT OPTION")
    query = ' '.join(query)

    if isinstance(params, str):
        params = (params,)

    try:
        cursor.execute(query, params)
    except (mysql_driver.ProgrammingError, mysql_driver.OperationalError, mysql_driver.InternalError) as e:
        raise InvalidPrivsError("Error granting privileges, invalid priv string: %s , params: %s, query: %s ,"
                                " exception: %s." % (priv_string, str(params), query, str(e)))


def convert_priv_dict_to_str(priv):
    """Converts privs dictionary to string of certain format.

    Args:
        priv (dict): Dict of privileges that needs to be converted to string.

    Returns:
        priv (str): String representation of input argument.
    """
    priv_list = ['%s:%s' % (key, val) for key, val in iteritems(priv)]

    return '/'.join(priv_list)


def get_resource_limits(cursor, user, host):
    """Get user resource limits.

    Args:
        cursor (cursor): DB driver cursor object.
        user (str): User name.
        host (str): User host name.

    Returns: Dictionary containing current resource limits.
    """

    query = ('SELECT max_questions AS MAX_QUERIES_PER_HOUR, '
             'max_updates AS MAX_UPDATES_PER_HOUR, '
             'max_connections AS MAX_CONNECTIONS_PER_HOUR, '
             'max_user_connections AS MAX_USER_CONNECTIONS '
             'FROM mysql.user WHERE User = %s AND Host = %s')
    cursor.execute(query, (user, host))
    res = cursor.fetchone()

    # Mysql_info use a DictCursor so we must convert back to a list
    # otherwise we get KeyError 0
    if isinstance(res, dict):
        res = list(res.values())

    if not res:
        return None

    current_limits = {
        'MAX_QUERIES_PER_HOUR': res[0],
        'MAX_UPDATES_PER_HOUR': res[1],
        'MAX_CONNECTIONS_PER_HOUR': res[2],
        'MAX_USER_CONNECTIONS': res[3],
    }

    cursor.execute("SELECT VERSION()")
    srv_type = cursor.fetchone()
    # Mysql_info use a DictCursor so we must convert back to a list
    # otherwise we get KeyError 0
    if isinstance(srv_type, dict):
        srv_type = list(srv_type.values())

    if 'mariadb' in srv_type[0].lower():
        query = ('SELECT max_statement_time AS MAX_STATEMENT_TIME '
                 'FROM mysql.user WHERE User = %s AND Host = %s')
        cursor.execute(query, (user, host))
        res_max_statement_time = cursor.fetchone()

        # Mysql_info use a DictCursor so we must convert back to a list
        # otherwise we get KeyError 0
        if isinstance(res_max_statement_time, dict):
            res_max_statement_time = list(res_max_statement_time.values())
        current_limits['MAX_STATEMENT_TIME'] = res_max_statement_time[0]

    return current_limits


def match_resource_limits(module, current, desired):
    """Check and match limits.

    Args:
        module (AnsibleModule): Ansible module object.
        current (dict): Dictionary with current limits.
        desired (dict): Dictionary with desired limits.

    Returns: Dictionary containing parameters that need to change.
    """

    if not current:
        # It means the user does not exists, so we need
        # to set all limits after its creation
        return desired

    needs_to_change = {}

    for key, val in iteritems(desired):
        if key not in current:
            # Supported keys are listed in the documentation
            # and must be determined in the get_resource_limits function
            # (follow 'AS' keyword)
            module.fail_json(msg="resource_limits: key '%s' is unsupported." % key)

        try:
            val = int(val)
        except Exception:
            module.fail_json(msg="Can't convert value '%s' to integer." % val)

        if val != current.get(key):
            needs_to_change[key] = val

    return needs_to_change


def limit_resources(module, cursor, user, host, resource_limits, check_mode):
    """Limit user resources.

    Args:
        module (AnsibleModule): Ansible module object.
        cursor (cursor): DB driver cursor object.
        user (str): User name.
        host (str): User host name.
        resource_limit (dict): Dictionary with desired limits.
        check_mode (bool): Run the function in check mode or not.

    Returns: True, if changed, False otherwise.
    """
    impl = get_user_implementation(cursor)
    if not impl.server_supports_alter_user(cursor):
        module.fail_json(msg="The server version does not match the requirements "
                             "for resource_limits parameter. See module's documentation.")

    cursor.execute("SELECT VERSION()")
    if 'mariadb' not in cursor.fetchone()[0].lower():
        if 'MAX_STATEMENT_TIME' in resource_limits:
            module.fail_json(msg="MAX_STATEMENT_TIME resource limit is only supported by MariaDB.")

    current_limits = get_resource_limits(cursor, user, host)

    needs_to_change = match_resource_limits(module, current_limits, resource_limits)

    if not needs_to_change:
        return False

    if needs_to_change and check_mode:
        return True

    # If not check_mode
    tmp = []
    for key, val in iteritems(needs_to_change):
        tmp.append('%s %s' % (key, val))

    query = "ALTER USER %s@%s"
    query += ' WITH %s' % ' '.join(tmp)
    cursor.execute(query, (user, host))
    return True


def set_password_expire(cursor, user, host, password_expire, password_expire_interval):
    """Fuction to set passowrd expiration for user.

    Args:
        cursor (cursor): DB driver cursor object.
        user (str): User name.
        host (str): User hostname.
        password_expire (str): Password expiration mode.
        password_expire_days (int): Invterval of days password expires.
    """
    if password_expire.lower() == "never":
        statement = "PASSWORD EXPIRE NEVER"
    elif password_expire.lower() == "default":
        statement = "PASSWORD EXPIRE DEFAULT"
    elif password_expire.lower() == "interval":
        statement = "PASSWORD EXPIRE INTERVAL %d DAY" % (password_expire_interval)
    elif password_expire.lower() == "now":
        statement = "PASSWORD EXPIRE"

    cursor.execute("ALTER USER %s@%s " + statement, (user, host))


def get_password_expiration_policy(cursor, user, host, maria_role=False):
    """Function to get password policy for user.

    Args:
        cursor (cursor): DB driver cursor object.
        user (str): User name.
        host (str): User hostname.
        maria_role (bool, optional): mariadb or mysql. Defaults to False.

    Returns:
        policy (int): Current users password policy.
    """
    if not maria_role:
        statement = "SELECT IFNULL(password_lifetime, -1) FROM mysql.user \
            WHERE User = %s AND Host = %s", (user, host)
    else:
        statement = "SELECT JSON_EXTRACT(Priv, '$.password_lifetime') AS password_lifetime \
            FROM mysql.global_priv \
            WHERE User = %s AND Host = %s", (user, host)
    cursor.execute(*statement)
    policy = cursor.fetchone()[0]
    return int(policy)


def is_password_expired(cursor, user, host):
    """Function to check if password is expired

    Args:
        cursor (cursor): DB driver cursor object.
        user (str): User name.
        host (str): User hostname.

    Returns:
        expired (bool): True if expired, else False.
    """
    statement = "SELECT password_expired FROM mysql.user \
            WHERE User = %s AND Host = %s", (user, host)
    cursor.execute(*statement)
    expired = cursor.fetchone()[0]
    if str(expired) == "Y":
        return True
    return False


def get_attribute_support(cursor):
    """Checks if the MySQL server supports user attributes.

    Args:
        cursor (cursor): DB driver cursor object.
    Returns:
        True if attributes are supported, False if they are not.
    """
    try:
        # information_schema.tables does not hold the tables within information_schema itself
        cursor.execute("SELECT attribute FROM INFORMATION_SCHEMA.USER_ATTRIBUTES LIMIT 0")
        cursor.fetchone()
    except mysql_driver.Error:
        return False

    return True


def attributes_get(cursor, user, host):
    """Get attributes for a given user.

    Args:
        cursor (cursor): DB driver cursor object.
        user (str): User name.
        host (str): User host name.

    Returns:
        None if the user does not exist or the user has no attributes set, otherwise a dict of attributes set on the user
    """
    cursor.execute("SELECT attribute FROM INFORMATION_SCHEMA.USER_ATTRIBUTES WHERE user = %s AND host = %s", (user, host))

    r = cursor.fetchone()
    # convert JSON string stored in row into a dict - mysql enforces that user_attributes entires are in JSON format
    j = json.loads(r[0]) if r and r[0] else None

    # if the attributes dict is empty, return None instead
    return j if j else None


def get_user_implementation(cursor):
    db_engine = get_server_implementation(cursor)
    if db_engine == 'mariadb':
        from ansible_collections.community.mysql.plugins.module_utils.implementations.mariadb import user as mariauser
        return mariauser
    else:
        from ansible_collections.community.mysql.plugins.module_utils.implementations.mysql import user as mysqluser
        return mysqluser
