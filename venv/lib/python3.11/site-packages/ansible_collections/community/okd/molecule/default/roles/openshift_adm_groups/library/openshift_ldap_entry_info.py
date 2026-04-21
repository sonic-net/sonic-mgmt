# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''

module: openshift_ldap_entry_info

short_description: Validate entry from LDAP server.

author:
  - Aubin Bikouo (@abikouo)

description:
  - This module connect to a ldap server and search for entry.
  - This module is not supported outside of testing this collection.

options:
  bind_dn:
    description:
      - A DN to bind with. If this is omitted, we'll try a SASL bind with the EXTERNAL mechanism as default.
      - If this is blank, we'll use an anonymous bind.
    type: str
    required: true
  bind_pw:
    description:
      - The password to use with I(bind_dn).
    type: str
    required: True
  dn:
    description:
      - The DN of the entry to test.
    type: str
    required: True
  server_uri:
    description:
      - A URI to the LDAP server.
      - The default value lets the underlying LDAP client library look for a UNIX domain socket in its default location.
    type: str
    default: ldapi:///
    required: True

requirements:
  - python-ldap
'''

EXAMPLES = r'''
'''


RETURN = r'''
# Default return values
'''

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

LDAP_IMP_ERR = None
try:
    import ldap
    import ldap.modlist
    HAS_LDAP = True
except ImportError:
    LDAP_IMP_ERR = traceback.format_exc()
    HAS_LDAP = False


def argument_spec():
    args = {}
    args['bind_dn'] = dict(required=True)
    args['bind_pw'] = dict(required=True, no_log=True)
    args['dn'] = dict(required=True)
    args['server_uri'] = dict(required=True)
    return args


def execute():
    module = AnsibleModule(
        argument_spec=argument_spec(),
        supports_check_mode=True
    )

    if not HAS_LDAP:
        module.fail_json(msg=missing_required_lib("python-ldap"), exception=LDAP_IMP_ERR)

    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    connection = ldap.initialize(module.params['server_uri'])
    connection.set_option(ldap.OPT_REFERRALS, 0)
    try:
        connection.simple_bind_s(module.params['bind_dn'], module.params['bind_pw'])
    except ldap.LDAPError as e:
        module.fail_json(msg="Cannot bind to the server due to: %s" % e)

    try:
        connection.search_s(module.params['dn'], ldap.SCOPE_BASE)
        module.exit_json(changed=False, found=True)
    except ldap.NO_SUCH_OBJECT:
        module.exit_json(changed=False, found=False)


def main():
    execute()


if __name__ == '__main__':
    main()
