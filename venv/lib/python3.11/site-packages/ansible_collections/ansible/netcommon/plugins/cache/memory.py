#
# (c) 2020 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    short_description: RAM backed, non persistent cache.
    description:
        - RAM backed cache that is not persistent.
        - Tailored for networking use case.
    version_added: 2.0.0
    author:
        - Ansible Networking Team (@ansible-network)
    name: memory
"""

from ansible.plugins import AnsiblePlugin


class CacheModule(AnsiblePlugin):
    def __init__(self, *args, **kwargs):
        super(CacheModule, self).__init__(*args, **kwargs)
        self._cache = {}

    def get(self, key):
        return self._cache.get(key)

    def set(self, key, value):
        self._cache[key] = value

    def keys(self):
        return self._cache.keys()

    def flush(self):
        self._cache = {}

    def lookup(self, key):
        return self.get(key)

    def populate(self, key, value):
        self.set(key, value)

    def invalidate(self):
        self.flush()
