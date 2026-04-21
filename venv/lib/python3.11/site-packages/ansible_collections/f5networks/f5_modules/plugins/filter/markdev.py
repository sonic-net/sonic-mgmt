from __future__ import absolute_import, division, print_function
__metaclass__ = type


class FilterModule(object):
    def filters(self):
        return {
            'markdev': self.mark_devel
        }

    def mark_devel(self, var):
        result = var.split('-')[0] + '-devel'
        return result
