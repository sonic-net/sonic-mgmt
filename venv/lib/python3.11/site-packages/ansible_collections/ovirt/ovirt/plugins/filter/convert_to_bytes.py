from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.ovirt.ovirt.plugins.module_utils.ovirt import convert_to_bytes


class FilterModule(object):

    def filters(self):
        'Define filters'
        return {
            'convert_to_bytes': self.convert_to_bytes,
        }

    def convert_to_bytes(self, param):
        """
        Filter to convert units to bytes, which follow IEC standard.

        :param param: value to be converted
        """
        return convert_to_bytes(param)
