# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''

module: openshift_ldap_entry

short_description: add/remove entry to LDAP Server.

author:
  - Aubin Bikouo (@abikouo)

description:
  - This module perform basic operations on the LDAP Server (add/remove entries).
  - Similar to `community.general.ldap_entry` this has been created to avoid dependency with this collection for the test.
  - This module is not supported outside of testing this collection.

options:
  attributes:
    description:
      - If I(state=present), attributes necessary to create an entry. Existing
        entries are never modified. To assert specific attribute values on an
        existing entry, use M(community.general.ldap_attrs) module instead.
    type: dict
  objectClass:
    description:
      - If I(state=present), value or list of values to use when creating
        the entry. It can either be a string or an actual list of
        strings.
    type: list
    elements: str
  state:
    description:
      - The target state of the entry.
    choices: [present, absent]
    default: present
    type: str
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
  dn:
    required: true
    description:
      - The DN of the entry to add or remove.
    type: str
  server_uri:
    description:
      - A URI to the LDAP server.
      - The default value lets the underlying LDAP client library look for a UNIX domain socket in its default location.
    type: str
    default: ldapi:///

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
from ansible.module_utils.common.text.converters import to_native, to_bytes

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
    args['attributes'] = dict(default={}, type='dict')
    args['objectClass'] = dict(type='list', elements='str')
    args['state'] = dict(default='present', choices=['present', 'absent'])
    args['bind_dn'] = dict(required=True)
    args['bind_pw'] = dict(default='', no_log=True)
    args['dn'] = dict(required=True)
    args['server_uri'] = dict(default='ldapi:///')
    return args


class LdapEntry(AnsibleModule):
    def __init__(self):

        AnsibleModule.__init__(
            self,
            argument_spec=argument_spec(),
            required_if=[('state', 'present', ['objectClass'])],
        )

        if not HAS_LDAP:
            self.fail_json(msg=missing_required_lib('python-ldap'), exception=LDAP_IMP_ERR)

        self.__connection = None
        # Add the objectClass into the list of attributes
        self.params['attributes']['objectClass'] = (self.params['objectClass'])

        # Load attributes
        if self.params['state'] == 'present':
            self.attrs = {}
            for name, value in self.params['attributes'].items():
                if isinstance(value, list):
                    self.attrs[name] = list(map(to_bytes, value))
                else:
                    self.attrs[name] = [to_bytes(value)]

    @property
    def connection(self):
        if not self.__connection:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            self.__connection = ldap.initialize(self.params['server_uri'])
            try:
                self.__connection.simple_bind_s(self.params['bind_dn'], self.params['bind_pw'])
            except ldap.LDAPError as e:
                self.fail_json(msg="Cannot bind to the server due to: %s" % e)
        return self.__connection

    def add(self):
        """ If self.dn does not exist, returns a callable that will add it. """
        changed = False
        msg = "LDAP Entry '%s' already exist." % self.params["dn"]
        if not self._is_entry_present():
            modlist = ldap.modlist.addModlist(self.attrs)
            self.connection.add_s(self.params['dn'], modlist)
            changed = True
            msg = "LDAP Entry '%s' successfully created." % self.params["dn"]
        self.exit_json(changed=changed, msg=msg)

    def delete(self):
        """ If self.dn exists, returns a callable that will delete it. """
        changed = False
        msg = "LDAP Entry '%s' does not exist." % self.params["dn"]
        if self._is_entry_present():
            self.connection.delete_s(self.params['dn'])
            changed = True
            msg = "LDAP Entry '%s' successfully deleted." % self.params["dn"]
        self.exit_json(changed=changed, msg=msg)

    def _is_entry_present(self):
        try:
            self.connection.search_s(self.params['dn'], ldap.SCOPE_BASE)
        except ldap.NO_SUCH_OBJECT:
            is_present = False
        else:
            is_present = True

        return is_present

    def execute(self):
        try:
            if self.params['state'] == 'present':
                self.add()
            else:
                self.delete()
        except Exception as e:
            self.fail_json(msg="Entry action failed.", details=to_native(e), exception=traceback.format_exc())


def main():
    module = LdapEntry()
    module.execute()


if __name__ == '__main__':
    main()
