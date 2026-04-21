#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: postgresql_ext
short_description: Add or remove PostgreSQL extensions from a database
description:
- Add or remove PostgreSQL extensions from a database.
options:
  name:
    description:
    - Name of the extension to add or remove.
    required: true
    type: str
    aliases:
    - ext
  login_db:
    description:
    - Name of the database to add or remove the extension to/from.
    - The V(db) alias is deprecated and will be removed in version 5.0.0.
    required: true
    type: str
    aliases:
    - db
  schema:
    description:
    - Name of the schema to add the extension to.
    type: str
  session_role:
    description:
    - Switch to session_role after connecting.
    - The specified session_role must be a role that the current login_user is a member of.
    - Permissions checking for SQL commands is carried out as though the session_role were the one that had logged in originally.
    type: str
  state:
    description:
    - The database extension state.
    default: present
    choices: [ absent, present ]
    type: str
  cascade:
    description:
    - Automatically install/remove any extensions that this extension depends on
      that are not already installed/removed (supported since PostgreSQL 9.6).
    type: bool
    default: false
  login_unix_socket:
    description:
      - Path to a Unix domain socket for local connections.
    type: str
  ssl_mode:
    description:
      - Determines whether or with what priority a secure SSL TCP/IP connection will be negotiated with the server.
      - See U(https://www.postgresql.org/docs/current/static/libpq-ssl.html) for more information on the modes.
      - Default of C(prefer) matches libpq default.
    type: str
    default: prefer
    choices: [ allow, disable, prefer, require, verify-ca, verify-full ]
  ca_cert:
    description:
      - Specifies the name of a file containing SSL certificate authority (CA) certificate(s).
      - If the file exists, the server's certificate will be verified to be signed by one of these authorities.
    type: str
    aliases: [ ssl_rootcert ]
  version:
    description:
      - Extension version to add or update to. Has effect with I(state=present) only.
      - If not specified and extension is not installed in the database,
        the latest version available will be created.
      - If extension is already installed, will update to the given version if a valid update
        path exists.
      - Downgrading is only supported if the extension provides a downgrade path otherwise
        the extension must be removed and a lower version of the extension must be made available.
      - Set I(version=latest) to update the extension to the latest available version.
    type: str
  trust_input:
    description:
    - If C(false), check whether values of parameters I(ext), I(schema),
      I(version), I(session_role) are potentially dangerous.
    - It makes sense to use C(false) only when SQL injections via the parameters are possible.
    type: bool
    default: true
    version_added: '0.2.0'
  comment:
    description:
    - Sets a comment on the extension.
    - To reset the comment, pass an empty string.
    type: str
    version_added: '3.3.0'

seealso:
- name: PostgreSQL extensions
  description: General information about PostgreSQL extensions.
  link: https://www.postgresql.org/docs/current/external-extensions.html
- name: CREATE EXTENSION reference
  description: Complete reference of the CREATE EXTENSION command documentation.
  link: https://www.postgresql.org/docs/current/sql-createextension.html
- name: ALTER EXTENSION reference
  description: Complete reference of the ALTER EXTENSION command documentation.
  link: https://www.postgresql.org/docs/current/sql-alterextension.html
- name: DROP EXTENSION reference
  description: Complete reference of the DROP EXTENSION command documentation.
  link: https://www.postgresql.org/docs/current/sql-droppublication.html

notes:
- Incomparable versions, for example PostGIS ``unpackaged``, cannot be installed.

attributes:
  check_mode:
    support: full

author:
- Daniel Schep (@dschep)
- Thomas O'Donnell (@andytom)
- Sandro Santilli (@strk)
- Andrew Klychkov (@Andersson007)
- Keith Fiske (@keithf4)
- Daniele Giudice (@RealGreenDragon)

extends_documentation_fragment:
- community.postgresql.postgres
'''

EXAMPLES = r'''
- name: Adds postgis extension to the database acme in the schema foo
  community.postgresql.postgresql_ext:
    name: postgis
    login_db: acme
    schema: foo
    comment: Test extension

- name: Removes postgis extension to the database acme
  community.postgresql.postgresql_ext:
    name: postgis
    login_db: acme
    state: absent

- name: Adds earthdistance extension to the database template1 cascade
  community.postgresql.postgresql_ext:
    name: earthdistance
    login_db: template1
    cascade: true

# In the example below, if earthdistance extension is installed,
# it will be removed too because it depends on cube:
- name: Removes cube extension from the database acme cascade
  community.postgresql.postgresql_ext:
    name: cube
    login_db: acme
    cascade: true
    state: absent

- name: Create extension foo of version 1.2 or update it to that version if it's already created and a valid update path exists
  community.postgresql.postgresql_ext:
    login_db: acme
    name: foo
    version: 1.2

- name: Create the latest available version of extension foo. If already installed, update it to the latest version
  community.postgresql.postgresql_ext:
    login_db: acme
    name: foo
    version: latest
'''

RETURN = r'''
queries:
  description: List of executed queries.
  returned: success
  type: list
  sample: ["DROP EXTENSION \"acme\""]
prev_version:
  description: Previous installed extension version or empty string if the extension was not installed.
  returned: success
  type: str
  sample: '1.0'
  version_added: '3.1.0'
version:
  description: Current installed extension version or empty string if the extension is not installed.
  returned: success
  type: str
  sample: '2.0'
  version_added: '3.1.0'
'''

import traceback

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.postgresql.plugins.module_utils.database import \
    check_input
from ansible_collections.community.postgresql.plugins.module_utils.postgres import (
    connect_to_db,
    ensure_required_libs,
    get_comment,
    get_conn_params,
    pg_cursor_args,
    postgres_common_argument_spec,
    set_comment,
)

executed_queries = []


# ===========================================
# PostgreSQL module specific support methods.
#


def ext_delete(check_mode, cursor, ext, cascade):
    """Remove the extension from the database.

    Return True if success.

    Args:
      cursor (cursor) -- cursor object of psycopg library
      ext (str) -- extension name
      cascade (boolean) -- Pass the CASCADE flag to the DROP command
    """
    query = "DROP EXTENSION \"%s\"" % ext

    if cascade:
        query += " CASCADE"

    if not check_mode:
        cursor.execute(query)
    executed_queries.append(cursor.mogrify(query))

    return True


def ext_update_version(check_mode, cursor, ext, version):
    """Update extension version.

    Return True if success.

    Args:
      cursor (cursor) -- cursor object of psycopg library
      ext (str) -- extension name
      version (str) -- extension version
    """
    query = "ALTER EXTENSION \"%s\" UPDATE" % ext
    params = {}

    if version != 'latest':
        query += " TO %(ver)s"
        params['ver'] = version

    if not check_mode:
        cursor.execute(query, params)
    executed_queries.append(cursor.mogrify(query, params))

    return True


def ext_create(check_mode, cursor, ext, schema, cascade, version):
    """
    Create the extension objects inside the database.

    Return True if success.

    Args:
      cursor (cursor) -- cursor object of psycopg library
      ext (str) -- extension name
      schema (str) -- target schema for extension objects
      cascade (boolean) -- Pass the CASCADE flag to the CREATE command
      version (str) -- extension version
    """
    query = "CREATE EXTENSION \"%s\"" % ext
    params = {}

    if schema:
        query += " WITH SCHEMA \"%s\"" % schema
    if version != 'latest':
        query += " VERSION %(ver)s"
        params['ver'] = version
    if cascade:
        query += " CASCADE"

    if not check_mode:
        cursor.execute(query, params)
    executed_queries.append(cursor.mogrify(query, params))

    return True


def ext_get_versions(cursor, ext):
    """
    Get the currently created extension version if it is installed
    in the database, its default version (used to update to 'latest'),
    and versions that are available if it is installed on the system.

    Return tuple (current_version, default_version, [list of available versions]).

    Note: the list of available versions contains only versions
          that higher than the current created version.
          If the extension is not created, this list will contain all
          available versions.

    Args:
      cursor (cursor) -- cursor object of psycopg library
      ext (str) -- extension name
    """

    current_version = None
    default_version = None
    params = {}
    params['ext'] = ext

    # 1. Get the current extension version:
    query = ("SELECT extversion FROM pg_catalog.pg_extension "
             "WHERE extname = %(ext)s")

    cursor.execute(query, params)

    res = cursor.fetchone()
    if res:
        current_version = res["extversion"]

    # 2. Get the extension default version:
    query = ("SELECT default_version FROM pg_catalog.pg_available_extensions "
             "WHERE name = %(ext)s")

    cursor.execute(query, params)

    res = cursor.fetchone()
    if res:
        default_version = res["default_version"]

    # 3. Get extension available versions:
    query = ("SELECT version FROM pg_catalog.pg_available_extension_versions "
             "WHERE name = %(ext)s")

    cursor.execute(query, params)

    available_versions = set(r["version"] for r in cursor.fetchall())

    if current_version is None:
        current_version = False
    if default_version is None:
        default_version = False

    return (current_version, default_version, available_versions)


def ext_valid_update_path(cursor, ext, current_version, version):
    """
    Check to see if the installed extension version has a valid update
    path to the given version.

    Return True if a valid path exists. Otherwise return False.

    Note: 'latest' is not a valid value for version here as it can be
          replaced with default_version specified in extension control file.

    Args:
      cursor (cursor) -- cursor object of psycopg library
      ext (str) -- extension name
      current_version (str) -- installed version of the extension.
      version (str) -- target extension version to update to.
    """

    valid_path = False
    params = {}
    query = ("SELECT path FROM pg_extension_update_paths(%(ext)s) "
             "WHERE source = %(cv)s "
             "AND target = %(ver)s")

    params['ext'] = ext
    params['cv'] = current_version
    params['ver'] = version

    cursor.execute(query, params)
    res = cursor.fetchone()
    if res is not None:
        valid_path = True

    return (valid_path)


# ===========================================
# Module execution.
#


def main():
    argument_spec = postgres_common_argument_spec()
    argument_spec.update(
        login_db=dict(type='str', aliases=['db'], required=True, deprecated_aliases=[
            {
                'name': 'db',
                'version': '5.0.0',
                'collection_name': 'community.postgresql',
            }],
        ),
        ext=dict(type="str", required=True, aliases=["name"]),
        schema=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present"]),
        cascade=dict(type="bool", default=False),
        session_role=dict(type="str"),
        version=dict(type="str"),
        trust_input=dict(type="bool", default=True),
        comment=dict(type="str", default=None),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    ext = module.params["ext"]
    schema = module.params["schema"]
    state = module.params["state"]
    cascade = module.params["cascade"]
    version = module.params["version"]
    session_role = module.params["session_role"]
    trust_input = module.params["trust_input"]
    comment = module.params["comment"]

    changed = False

    if not trust_input:
        check_input(module, ext, schema, version, session_role, comment)

    if version and state == 'absent':
        module.warn("Parameter version is ignored when state=absent")

    # Ensure psycopg libraries are available before connecting to DB:
    ensure_required_libs(module)
    conn_params = get_conn_params(module, module.params)
    db_connection, dummy = connect_to_db(module, conn_params, autocommit=True)
    cursor = db_connection.cursor(**pg_cursor_args)

    try:
        # Get extension info and available versions:
        curr_version, default_version, available_versions = ext_get_versions(cursor, ext)

        # Decode version 'latest' when passed (if version is not passed 'latest' is assumed)
        # Note: real_version used for checks but not in CREATE/DROP/ALTER EXTENSION commands,
        #       as the correct way to obtain 'latest' version is not specify the version
        if not version or version == 'latest':
            # If there are not available versions the extension is not available
            if not available_versions:
                module.fail_json(msg="Extension %s is not available" % ext)
            # Check default_version is available
            if default_version:
                # 'latest' version matches default_version specified in extension control file
                real_version = default_version
            else:
                # Passed version is 'latest', versions are available, but no default_version is specified
                # in extension control file. In this situation CREATE/ALTER EXTENSION commands fail if
                # a specific version is not passed ('latest' cannot be determined).
                module.fail_json(msg="Passed version 'latest' but no default_version available "
                                     "in extension control file")
        else:
            real_version = version

        if state == "present":

            # If version passed:
            if version:
                # If extension is installed, update to passed version if a valid path exists
                if curr_version:
                    # Given/Latest version already installed
                    if curr_version == real_version:
                        changed = False
                    # Attempt to update to given/latest version
                    else:
                        valid_update_path = ext_valid_update_path(cursor, ext, curr_version, real_version)
                        if valid_update_path:
                            # Reconnect (required by some extensions like timescaledb)
                            if not module.check_mode:
                                db_connection.close()
                                db_connection, dummy = connect_to_db(module, conn_params, autocommit=True)
                                cursor = db_connection.cursor(**pg_cursor_args)
                            changed = ext_update_version(module.check_mode, cursor, ext, version)
                        else:
                            if version == 'latest':
                                # No valid update path from curr_version to latest extension version
                                # (extension is buggy or no direct update supported)
                                module.fail_json(msg="Latest version '%s' has no valid update path from "
                                                     "the currently installed version '%s'" % (real_version, curr_version))
                            else:
                                module.fail_json(msg="Passed version '%s' has no valid update path from "
                                                     "the currently installed version '%s' or "
                                                     "the passed version is not available" % (version, curr_version))
                # If extension is not installed, install passed version
                else:
                    # If passed version not available fail
                    if real_version not in available_versions:
                        if version == 'latest':
                            # Latest version not available (extension is buggy)
                            module.fail_json(msg="Latest version '%s' is not available" % real_version)
                        else:
                            module.fail_json(msg="Passed version '%s' is not available" % real_version)
                    # Else install the passed version
                    else:
                        changed = ext_create(module.check_mode, cursor, ext, schema, cascade, version)

            # If version is not passed:
            else:
                # Extension exists, no request to update so no change
                if curr_version:
                    changed = False
                else:
                    # If the ext doesn't exist and is available:
                    if available_versions:
                        # 'latest' version installed by default if version not passed
                        changed = ext_create(module.check_mode, cursor, ext, schema, cascade, 'latest')
                    # If the ext doesn't exist and is not available:
                    else:
                        module.fail_json(msg="Extension %s is not available" % ext)

            if comment is not None:
                current_comment = get_comment(cursor, 'extension', ext)
                # For the resetting comment feature (comment: '') to work correctly
                current_comment = current_comment if current_comment is not None else ''
                if comment != current_comment:
                    changed = set_comment(cursor, comment, 'extension', ext, module.check_mode, executed_queries)

        elif state == "absent":
            if curr_version:
                changed = ext_delete(module.check_mode, cursor, ext, cascade)
            else:
                changed = False

        # Get extension info again:
        new_version, new_default_version, new_available_versions = ext_get_versions(cursor, ext)

        # Parse previous and current version for module output
        out_prev_version = curr_version if curr_version else ''
        if module.check_mode and changed:
            if state == "present":
                out_version = real_version
            elif state == "absent":
                out_version = ''
        else:
            out_version = new_version if new_version else ''

    except Exception as e:
        db_connection.close()
        module.fail_json(msg="Management of PostgreSQL extension failed: %s" % to_native(e), exception=traceback.format_exc())

    db_connection.close()
    module.exit_json(
        changed=changed,
        db=module.params["login_db"],
        ext=ext,
        prev_version=out_prev_version,
        version=out_version,
        queries=executed_queries,
    )


if __name__ == '__main__':
    main()
