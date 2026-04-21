# Copyright: (c) 2007, 2012 Red Hat, Inc
# Michael DeHaan <michael.dehaan@gmail.com>
# Seth Vidal <skvidal@fedoraproject.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


try:
    import libvirt
except ImportError:
    HAS_VIRT = False
else:
    HAS_VIRT = True

try:
    from lxml import etree
except ImportError:
    HAS_XML = False
else:
    HAS_XML = True


VIRT_STATE_NAME_MAP = {
    0: 'running',
    1: 'running',
    2: 'running',
    3: 'paused',
    4: 'shutdown',
    5: 'shutdown',
    6: 'crashed',
}


class VMNotFound(Exception):
    pass


class LibvirtConnection(object):

    def __init__(self, uri, module):

        self.module = module

        cmd = "uname -r"
        rc, stdout, stderr = self.module.run_command(cmd)

        if "xen" in stdout:
            conn = libvirt.open(None)
        elif "esx" in uri:
            auth = [[libvirt.VIR_CRED_AUTHNAME,
                     libvirt.VIR_CRED_NOECHOPROMPT], [], None]
            conn = libvirt.openAuth(uri, auth)
        else:
            conn = libvirt.open(uri)

        if not conn:
            raise Exception("hypervisor connection failure")

        self.conn = conn

    def find_vm(self, vmid):
        """
        Extra bonus feature: vmid = -1 returns a list of everything
        """

        vms = self.conn.listAllDomains()

        if vmid == -1:
            return vms

        for vm in vms:
            if vm.name() == vmid:
                return vm

        raise VMNotFound("virtual machine %s not found" % vmid)

    def shutdown(self, vmid):
        return self.find_vm(vmid).shutdown()

    def pause(self, vmid):
        return self.suspend(vmid)

    def unpause(self, vmid):
        return self.resume(vmid)

    def suspend(self, vmid):
        return self.find_vm(vmid).suspend()

    def resume(self, vmid):
        return self.find_vm(vmid).resume()

    def create(self, vmid):
        return self.find_vm(vmid).create()

    def destroy(self, vmid):
        return self.find_vm(vmid).destroy()

    def undefine(self, vmid, flag):
        vm = self.find_vm(vmid)
        if flag & 32:
            self.delete_domain_volumes(vmid)
        return vm.undefineFlags(flag)

    def get_status2(self, vm):
        state = vm.info()[0]
        return VIRT_STATE_NAME_MAP.get(state, "unknown")

    def get_status(self, vmid):
        state = self.find_vm(vmid).info()[0]
        return VIRT_STATE_NAME_MAP.get(state, "unknown")

    def nodeinfo(self):
        return self.conn.getInfo()

    def get_type(self):
        return self.conn.getType()

    def get_xml(self, vmid):
        vm = self.conn.lookupByName(vmid)
        return vm.XMLDesc(0)

    def get_maxVcpus(self, vmid):
        vm = self.conn.lookupByName(vmid)
        return vm.maxVcpus()

    def get_maxMemory(self, vmid):
        vm = self.conn.lookupByName(vmid)
        return vm.maxMemory()

    def getFreeMemory(self):
        return self.conn.getFreeMemory()

    def get_autostart(self, vmid):
        vm = self.conn.lookupByName(vmid)
        return vm.autostart()

    def set_autostart(self, vmid, val):
        vm = self.conn.lookupByName(vmid)
        return vm.setAutostart(val)

    def define_from_xml(self, xml):
        return self.conn.defineXML(xml)

    def get_uuid(self, vmid):
        vm = self.conn.lookupByName(vmid)
        return vm.UUIDString()

    def get_interfaces(self, vmid):
        dom_xml = self.get_xml(vmid)
        root = etree.fromstring(dom_xml)
        interfaces = root.findall("./devices/interface")
        interface_type_map = {
            'network': 'NAT',
            'direct': 'macvtap',
            'bridge': 'bridge'
        }
        interface_counter = 0
        interfaces_dict = {}
        interfaces_dict['network_interfaces'] = {}
        for interface in interfaces:
            interface_counter += 1
            interface_type = interface.get('type')
            source = interface.find("source").get({
                'bridge': 'bridge',
                'direct': 'dev',
                'network': 'network'
            }.get(interface_type))
            mac_address = interface.find("mac").get("address")
            pci_bus = interface.find("address").get("bus")
            interface_info = {
                "type": interface_type_map.get(interface_type, interface_type),
                "mac": mac_address,
                "pci_bus": pci_bus,
                "source": source
            }
            interfaces_dict['network_interfaces'].update(
                {"interface_{0}".format(interface_counter): interface_info})
        return interfaces_dict

    def delete_domain_volumes(self, vmid):
        dom_xml = self.get_xml(vmid)
        root = etree.fromstring(dom_xml)
        disk_objects = root.findall(".//disk[@type='file']/source")
        for disk in disk_objects:
            disk_path = disk.get('file')
            disk_volumes = self.conn.storageVolLookupByPath(disk_path)
            if disk_volumes:
                disk_volumes.delete()
