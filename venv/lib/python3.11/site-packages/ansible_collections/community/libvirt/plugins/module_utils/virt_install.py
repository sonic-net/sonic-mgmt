# (c) 2025, Joey Zhang <thinkdoggie@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from ansible_collections.community.libvirt.plugins.module_utils.libvirt import LibvirtConnection


class LibvirtWrapper(object):

    def __init__(self, module):
        self.module = module
        self.uri = module.params.get('uri')

    def __get_conn(self):
        self.conn = LibvirtConnection(self.uri, self.module)
        return self.conn

    def find_vm(self, vmid):
        self.__get_conn()
        return self.conn.find_vm(vmid)

    def shutdown(self, vmid):
        if not self.module.check_mode:
            self.__get_conn()
            return self.conn.shutdown(vmid)

    def destroy(self, vmid):
        if not self.module.check_mode:
            self.__get_conn()
            return self.conn.destroy(vmid)

    def undefine(self, vmid):
        if not self.module.check_mode:
            self.__get_conn()
            self.conn.delete_domain_volumes(vmid)
            return self.conn.undefine(vmid, 0)
