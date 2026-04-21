# (c) 2013, Michael DeHaan <michael.dehaan@gmail.com>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    name: license_hopper
    author: Tim Rupp (@caphrim007)
    version_added: "1.0.0"
    short_description: Return random license from list
    description:
      - Select a random license key from a file and remove it from future lookups.
      - Can optionally remove the key if C(remove=True) is specified.
"""

EXAMPLES = """
- name: Get a regkey license from a stash without deleting it
  bigiq_regkey_license:
    key: "{{ lookup('license_hopper', 'filename=/path/to/licenses.txt') }}"
    state: present
    pool: regkey1

- name: Get a regkey license from a stash and delete the key from the file
  bigiq_regkey_license:
    key: "{{ lookup('license_hopper', 'filename=/path/to/licenses.txt', remove=True) }}"
    state: present
    pool: regkey1
"""

RETURN = """
  _raw:
    description:
      - random item
"""

import random

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native
from ansible.plugins.lookup import LookupBase

BOOLEANS_TRUE = frozenset(('y', 'yes', 'on', '1', 'true', 'True', 't', 1, 1.0, True))


class LookupModule(LookupBase):
    def __init__(self, loader=None, templar=None, **kwargs):

        super(LookupModule, self).__init__(loader, templar, **kwargs)

        self.filename = None
        self.remove = False

    def run(self, terms, variables=None, **kwargs):
        self.filename = kwargs.pop('filename', None)
        self.remove = kwargs.pop('remove', False)
        if self.filename is None:
            raise AnsibleError("No 'filename' was specified")
        lookupfile = self.find_file_in_search_path(variables, 'files', self.filename)
        if lookupfile is None:
            raise AnsibleError("Could not find the specified 'filename'")
        fh = open(lookupfile, 'r')
        lines = [x.strip() for x in fh.readlines()]
        fh.close()
        try:
            ret = [random.choice(lines)]
        except Exception as e:
            raise AnsibleError("Unable to choose random license: %s" % to_native(e))
        if self.remove:
            to_write = [x + "\n" for x in lines if x != ret[0]]
            fh = open(lookupfile, 'w')
            fh.writelines(to_write)
        return ret
