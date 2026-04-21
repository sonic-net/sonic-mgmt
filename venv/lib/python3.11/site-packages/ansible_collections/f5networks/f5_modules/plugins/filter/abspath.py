from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os


def abspath(file):
    return os.path.abspath(file)


class FilterModule(object):
    def filters(self):
        return {
            'abspath': abspath
        }
