#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2007, 2012 Red Hat, Inc
# Michael DeHaan <michael.dehaan@gmail.com>
# Seth Vidal <skvidal@fedoraproject.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: virt
short_description: Manages virtual machines supported by libvirt
description:
     - Manages virtual machines supported by I(libvirt).
options:
    flags:
        choices: [ 'managed_save', 'snapshots_metadata', 'nvram', 'keep_nvram', 'checkpoints_metadata', 'delete_volumes']
        description:
            - Pass additional parameters.
            - Currently only implemented with command C(undefine).
              Specify which metadata should be removed with C(undefine).
              Useful option to be able to C(undefine) guests with UEFI nvram.
              C(nvram) and C(keep_nvram) are conflicting and mutually exclusive.
              Consider option C(force) if all related metadata should be removed.
        type: list
        elements: str
    force:
        description:
            - Enforce an action.
            - Currently only implemented with command C(undefine).
              This option can be used instead of providing all C(flags).
              If C(true), C(undefine) removes also any related nvram or other metadata, if existing.
              If C(false) or not set, C(undefine) executes only if there is no nvram or other metadata existing.
              Otherwise the task fails and the guest is kept defined without change.
              C(true) and option C(flags) should not be provided together. In this case
              C(undefine) ignores C(true), considers only C(flags) and issues a warning.
        type: bool
extends_documentation_fragment:
    - community.libvirt.virt.options_uri
    - community.libvirt.virt.options_xml
    - community.libvirt.virt.options_guest
    - community.libvirt.virt.options_autostart
    - community.libvirt.virt.options_state
    - community.libvirt.virt.options_command
    - community.libvirt.virt.options_mutate_flags
    - community.libvirt.requirements
attributes:
    check_mode:
        description: Supports check_mode.
        support: full
author:
    - Ansible Core Team
    - Michael DeHaan
    - Seth Vidal (@skvidal)
'''

EXAMPLES = '''
# a playbook task line:
- name: Start a VM
  community.libvirt.virt:
    name: alpha
    state: running

# /usr/bin/ansible invocations
# ansible host -m virt -a "name=alpha command=status"
# ansible host -m virt -a "name=alpha command=get_xml"
# ansible host -m virt -a "name=alpha command=create uri=lxc:///"

# defining and launching an LXC guest
- name: Define a VM
  community.libvirt.virt:
    command: define
    xml: "{{ lookup('template', 'container-template.xml.j2') }}"
    uri: 'lxc:///'
- name: start vm
  community.libvirt.virt:
    name: foo
    state: running
    uri: 'lxc:///'

# setting autostart on a qemu VM (default uri)
- name: Set autostart for a VM
  community.libvirt.virt:
    name: foo
    autostart: true

# Defining a VM and making is autostart with host. VM will be off after this task
- name: Define vm from xml and set autostart
  community.libvirt.virt:
    command: define
    xml: "{{ lookup('template', 'vm_template.xml.j2') }}"
    autostart: true

# Undefine VM only, if it has no existing nvram or other metadata
- name: Undefine qemu VM
  community.libvirt.virt:
    command: undefine
    name: foo

# Undefine VM and force remove all of its related metadata (nvram, snapshots, etc.)
- name: "Undefine qemu VM with force"
  community.libvirt.virt:
    command: undefine
    name: foo
    force: true

# Undefine VM and remove all of its specified metadata specified
# Result would the same as with force=true
- name: Undefine qemu VM with list of flags
  community.libvirt.virt:
    command: undefine
    name: foo
    flags: managed_save, snapshots_metadata, nvram, checkpoints_metadata

# Undefine VM, but keep its nvram
- name: Undefine qemu VM and keep its nvram
  community.libvirt.virt:
    command: undefine
    name: foo
    flags: keep_nvram

# Listing VMs
- name: List all VMs
  community.libvirt.virt:
    command: list_vms
  register: all_vms

- name: List only running VMs
  community.libvirt.virt:
    command: list_vms
    state: running
  register: running_vms
'''

RETURN = '''
# for list_vms command
list_vms:
    description: The list of vms defined on the remote system.
    type: list
    returned: success
    sample: [
        "build.example.org",
        "dev.example.org"
    ]
# for status command
status:
    description: The status of the VM, among running, crashed, paused and shutdown.
    type: str
    sample: "success"
    returned: success
'''

import traceback

try:
    import libvirt
    from libvirt import libvirtError
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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native


VIRT_FAILED = 1
VIRT_SUCCESS = 0
VIRT_UNAVAILABLE = 2

ALL_COMMANDS = []
VM_COMMANDS = ['create', 'define', 'destroy', 'get_xml', 'get_interfaces', 'pause', 'shutdown', 'status', 'start', 'stop', 'undefine', 'unpause', 'uuid']
HOST_COMMANDS = ['freemem', 'info', 'list_vms', 'nodeinfo', 'virttype']
ALL_COMMANDS.extend(VM_COMMANDS)
ALL_COMMANDS.extend(HOST_COMMANDS)

VIRT_STATE_NAME_MAP = {
    0: 'running',
    1: 'running',
    2: 'running',
    3: 'paused',
    4: 'shutdown',
    5: 'shutdown',
    6: 'crashed',
}

ENTRY_UNDEFINE_FLAGS_MAP = {
    'managed_save': 1,
    'snapshots_metadata': 2,
    'nvram': 4,
    'keep_nvram': 8,
    'checkpoints_metadata': 16,
    'delete_volumes': 32,
}

MUTATE_FLAGS = ['ADD_UUID', 'ADD_MAC_ADDRESSES', 'ADD_MAC_ADDRESSES_FUZZY']

ALL_FLAGS = []
ALL_FLAGS.extend(ENTRY_UNDEFINE_FLAGS_MAP.keys())


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
            auth = [[libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_NOECHOPROMPT], [], None]
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
            interfaces_dict['network_interfaces'].update({"interface_{0}".format(interface_counter): interface_info})
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


class Virt(object):

    def __init__(self, uri, module):
        self.module = module
        self.uri = uri

    def __get_conn(self):
        self.conn = LibvirtConnection(self.uri, self.module)
        return self.conn

    def get_vm(self, vmid):
        self.__get_conn()
        return self.conn.find_vm(vmid)

    def state(self):
        vms = self.list_vms()
        state = []
        for vm in vms:
            state_blurb = self.conn.get_status(vm)
            state.append("%s %s" % (vm, state_blurb))
        return state

    def info(self):
        vms = self.list_vms()
        info = dict()
        for vm in vms:
            data = self.conn.find_vm(vm).info()
            # libvirt returns maxMem, memory, and cpuTime as long()'s, which
            # xmlrpclib tries to convert to regular int's during serialization.
            # This throws exceptions, so convert them to strings here and
            # assume the other end of the xmlrpc connection can figure things
            # out or doesn't care.
            info[vm] = dict(
                state=VIRT_STATE_NAME_MAP.get(data[0], "unknown"),
                maxMem=str(data[1]),
                memory=str(data[2]),
                nrVirtCpu=data[3],
                cpuTime=str(data[4]),
                autostart=self.conn.get_autostart(vm),
            )

        return info

    def nodeinfo(self):
        self.__get_conn()
        data = self.conn.nodeinfo()
        info = dict(
            cpumodel=str(data[0]),
            phymemory=str(data[1]),
            cpus=str(data[2]),
            cpumhz=str(data[3]),
            numanodes=str(data[4]),
            sockets=str(data[5]),
            cpucores=str(data[6]),
            cputhreads=str(data[7])
        )
        return info

    def list_vms(self, state=None):
        self.conn = self.__get_conn()
        vms = self.conn.find_vm(-1)
        results = []
        for x in vms:
            try:
                if state:
                    vmstate = self.conn.get_status2(x)
                    if vmstate == state:
                        results.append(x.name())
                else:
                    results.append(x.name())
            except Exception:
                pass
        return results

    def virttype(self):
        return self.__get_conn().get_type()

    def autostart(self, vmid, as_flag):
        self.conn = self.__get_conn()
        if self.module.check_mode:
            return self.conn.get_autostart(vmid) != as_flag

        # Change autostart flag only if needed
        if self.conn.get_autostart(vmid) != as_flag:
            self.conn.set_autostart(vmid, as_flag)
            return True

        return False

    def freemem(self):
        self.conn = self.__get_conn()
        return self.conn.getFreeMemory()

    def shutdown(self, vmid):
        """ Make the machine with the given vmid stop running.  Whatever that takes.  """
        if self.module.check_mode:
            return 0
        self.__get_conn()
        self.conn.shutdown(vmid)
        return 0

    def pause(self, vmid):
        """ Pause the machine with the given vmid.  """
        if self.module.check_mode:
            return 0
        self.__get_conn()
        return self.conn.suspend(vmid)

    def unpause(self, vmid):
        """ Unpause the machine with the given vmid.  """
        if self.module.check_mode:
            return 0
        self.__get_conn()
        return self.conn.resume(vmid)

    def create(self, vmid):
        """ Start the machine via the given vmid """
        if self.module.check_mode:
            return 0
        self.__get_conn()
        return self.conn.create(vmid)

    def start(self, vmid):
        """ Start the machine via the given id/name """
        if self.module.check_mode:
            return 0
        self.__get_conn()
        return self.conn.create(vmid)

    def destroy(self, vmid):
        """ Pull the virtual power from the virtual domain, giving it virtually no time to virtually shut down.  """
        if self.module.check_mode:
            return 0
        self.__get_conn()
        return self.conn.destroy(vmid)

    def undefine(self, vmid, flag):
        """ Stop a domain, and then wipe it from the face of the earth.  (delete disk/config file) """
        if self.module.check_mode:
            return {
                'changed': vmid in self.list_vms(),
                'command': 0,
            }
        self.__get_conn()
        res = self.conn.undefine(vmid, flag)
        return {
            'changed': res == 0,
            'command': res,
        }

    def status(self, vmid):
        """
        Return a state suitable for server consumption.  Aka, codes.py values, not XM output.
        """
        self.__get_conn()
        return self.conn.get_status(vmid)

    def get_xml(self, vmid):
        """
        Receive a Vm id as input
        Return an xml describing vm config returned by a libvirt call
        """

        self.__get_conn()
        return self.conn.get_xml(vmid)

    def get_maxVcpus(self, vmid):
        """
        Gets the max number of VCPUs on a guest
        """

        self.__get_conn()
        return self.conn.get_maxVcpus(vmid)

    def get_max_memory(self, vmid):
        """
        Gets the max memory on a guest
        """

        self.__get_conn()
        return self.conn.get_MaxMemory(vmid)

    def define(self, xml):
        """
        Define a guest with the given xml
        """
        if self.module.check_mode:
            return 0
        self.__get_conn()
        return self.conn.define_from_xml(xml)

    def get_uuid(self, vmid):
        self.__get_conn()
        return self.conn.get_uuid(vmid)

    def get_interfaces(self, vmid):
        """
        Get Interface Name and Mac Address from xml
        """
        self.__get_conn()
        return self.conn.get_interfaces(vmid)

    def delete_domain_volumes(self, vmid):
        self.__get_conn()
        return self.conn.delete_domain_volumes(vmid)


# A dict of interface types (found in their `type` attribute) to the
# corresponding "source" attribute name of their  <source> elements
# user networks don't have a <source> element
#
# We do not support fuzzy matching against any interface types
# not defined here
INTERFACE_SOURCE_ATTRS = {
    'network': 'network',
    'bridge': 'bridge',
    'direct': 'dev',
    'user': None,
}


def handle_define(module, v):
    ''' handle `command: define` '''
    xml = module.params.get('xml', None)
    guest = module.params.get('name', None)
    autostart = module.params.get('autostart', None)
    mutate_flags = module.params.get('mutate_flags', [])
    parser = etree.XMLParser(remove_blank_text=True)

    if not xml:
        module.fail_json(msg="define requires 'xml' argument")
    try:
        incoming_xml = etree.fromstring(xml, parser)
    except etree.XMLSyntaxError:
        # TODO: provide info from parser
        module.fail_json(msg="given XML is invalid")

    # We'll support supplying the domain's name either from 'name' parameter or xml
    #
    # But we will fail if both are defined and not equal.
    domain_name = incoming_xml.findtext("./name")
    if domain_name is not None:
        if guest is not None and domain_name != guest:
            module.fail_json("given 'name' parameter does not match name in XML")
    else:
        if guest is None:
            module.fail_json("missing 'name' parameter and no name provided in XML")
        domain_name = guest
        # since there's no <name> in the xml, we'll add it
        etree.SubElement(incoming_xml, 'name').text = domain_name

    if domain_name == '':
        module.fail_json(msg="domain name cannot be an empty string")

    res = dict()

    # From libvirt docs (https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainDefineXML):
    # -- A previous definition for this domain with the same UUID and name would
    # be overridden if it already exists.
    #
    # If a domain is defined without a <uuid>, libvirt will generate one for it.
    # If an attempt is made to re-define the same xml (with the same <name> and
    # no <uuid>), libvirt will complain with the following error:
    #
    # operation failed: domain '<name>' already exists with <uuid>
    #
    # If a domain with a similiar <name> but different <uuid> is defined,
    # libvirt complains with the same error. However, if a domain is defined
    # with the same <name> and <uuid> as an existing domain, then libvirt will
    # update the domain with the new definition (automatically handling
    # addition/removal of devices. some changes may require a boot).
    try:
        existing_domain = v.get_vm(domain_name)
        existing_xml_raw = existing_domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
        existing_xml = etree.fromstring(existing_xml_raw, parser)
    except VMNotFound:
        existing_domain = None
        existing_xml_raw = None
        existing_xml = None

    if existing_domain is not None:
        # we are updating a domain's definition

        incoming_uuid = incoming_xml.findtext('./uuid')
        existing_uuid = existing_domain.UUIDString()

        if incoming_uuid is not None and incoming_uuid != existing_uuid:
            # A user should not try defining a domain with the same name but
            # different UUID
            module.fail_json(msg="attempting to re-define domain %s/%s with a different UUID: %s" % (
                domain_name, existing_uuid, incoming_uuid
            ))
        else:
            if 'ADD_UUID' in mutate_flags and incoming_uuid is None:
                # Users will often want to define their domains without an explicit
                # UUID, instead giving them a unique name - so we support bringing
                # over the UUID from the existing domain
                etree.SubElement(incoming_xml, 'uuid').text = existing_uuid

            existing_devices = existing_xml.find('./devices')

            if 'ADD_MAC_ADDRESSES' in mutate_flags:
                for interface in incoming_xml.xpath('./devices/interface[not(mac) and alias]'):
                    search_alias = interface.find('alias').get('name')
                    xpath = "./interface[alias[@name='%s']]" % search_alias
                    try:
                        matched_interface = existing_devices.xpath(xpath)[0]
                        existing_devices.remove(matched_interface)
                        etree.SubElement(interface, 'mac', {
                            'address': matched_interface.find('mac').get('address')
                        })
                    except IndexError:
                        module.warn("Could not match interface %i of incoming XML by alias %s." % (
                            interface.getparent().index(interface) + 1, search_alias
                        ))

            if 'ADD_MAC_ADDRESSES_FUZZY' in mutate_flags:
                # the counts of interfaces of a similar type/source
                # key'd with tuple of (type, source)
                similar_interface_counts = {}

                def get_interface_count(_type, source=None):
                    key = (_type, source if _type != "user" else None)
                    if key not in similar_interface_counts:
                        similar_interface_counts[key] = 1
                    else:
                        similar_interface_counts[key] += 1
                    return similar_interface_counts[key]

                # iterate user-defined interfaces
                for interface in incoming_xml.xpath('./devices/interface'):
                    _type = interface.get('type')

                    if interface.find('mac') is not None and interface.find('alias') is not None:
                        continue

                    if _type not in INTERFACE_SOURCE_ATTRS:
                        module.warn("Skipping fuzzy MAC matching for interface %i of incoming XML: unsupported interface type '%s'." % (
                            interface.getparent().index(interface) + 1, _type
                        ))
                        continue

                    source_attr = INTERFACE_SOURCE_ATTRS[_type]
                    source = interface.find('source').get(source_attr) if source_attr else None
                    similar_count = get_interface_count(_type, source)

                    if interface.find('mac') is not None:
                        # we want to count these, but not try to change their MAC address
                        continue

                    if source:
                        xpath = "./interface[@type='%s' and source[@%s='%s']]" % (
                            _type, source_attr, source)
                    else:
                        xpath = "./interface[@type = '%s']" % source_attr

                    matching_interfaces = existing_devices.xpath(xpath)
                    try:
                        matched_interface = matching_interfaces[similar_count - 1]
                        etree.SubElement(interface, 'mac', {
                            'address': matched_interface.find('./mac').get('address'),
                        })
                    except IndexError:
                        module.warn("Could not fuzzy match interface %i of incoming XML." % (
                            interface.getparent().index(interface) + 1
                        ))

    try:
        domain_xml = etree.tostring(incoming_xml, pretty_print=True).decode()

        if module.check_mode:
            before = etree.tostring(existing_xml, pretty_print=True).decode() if existing_xml else ''
            res.update({
                'changed': before != domain_xml,
                'diff': {
                    'before': before,
                    'after': domain_xml
                },
            })
            return res

        domain = v.define(domain_xml)

        if existing_domain is not None:
            # In this case, we may have updated the definition or it might be the same.
            # We compare the domain's previous xml with its new state and diff
            # the changes. This allows users to fix their xml if it results in
            # non-idempotent behaviour (e.g. libvirt mutates it each time)
            new_xml = domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE)
            if existing_xml_raw != new_xml:
                res.update({
                    'changed': True,
                    'change_reason': 'domain definition changed',
                    'diff': {
                        'before': existing_xml_raw,
                        'after': new_xml
                    }
                })
        else:
            # there was no existing XML, so this is a newly created domain
            res.update({'changed': True, 'created': domain.name()})

    except libvirtError as e:
        module.fail_json(msg='libvirtError: %s' % e.get_error_message())
    except Exception as e:
        module.fail_json(msg='an unknown error occured: %s' % e)

    if autostart is not None and v.autostart(domain_name, autostart):
        res.update({'changed': True, 'change_reason': 'autostart'})

    return res


def core(module):

    state = module.params.get('state', None)
    autostart = module.params.get('autostart', None)
    guest = module.params.get('name', None)
    command = module.params.get('command', None)
    force = module.params.get('force', None)
    flags = module.params.get('flags', None)
    uri = module.params.get('uri', None)

    v = Virt(uri, module)
    res = dict()

    if state and command == 'list_vms':
        res = v.list_vms(state=state)
        if not isinstance(res, dict):
            res = {command: res}
        return VIRT_SUCCESS, res

    if autostart is not None and command != 'define':
        if not guest:
            module.fail_json(msg="autostart requires 1 argument: name")
        try:
            v.get_vm(guest)
        except VMNotFound:
            module.fail_json(msg="domain %s not found" % guest)
        res['changed'] = v.autostart(guest, autostart)
        if not command and not state:
            return VIRT_SUCCESS, res

    if state:
        if not guest:
            module.fail_json(msg="state change requires a guest specified")

        if state == 'running':
            if v.status(guest) == 'paused':
                res['changed'] = True
                res['msg'] = v.unpause(guest)
            elif v.status(guest) != 'running':
                res['changed'] = True
                res['msg'] = v.start(guest)
        elif state == 'shutdown':
            if v.status(guest) != 'shutdown':
                res['changed'] = True
                res['msg'] = v.shutdown(guest)
        elif state == 'destroyed':
            if v.status(guest) != 'shutdown':
                res['changed'] = True
                res['msg'] = v.destroy(guest)
        elif state == 'paused':
            if v.status(guest) == 'running':
                res['changed'] = True
                res['msg'] = v.pause(guest)
        else:
            module.fail_json(msg="unexpected state")

        return VIRT_SUCCESS, res

    if command:
        def exec_virt(*args):
            res = getattr(v, command)(*args)
            if not isinstance(res, dict):
                res = {command: res}
            return res

        if command in VM_COMMANDS:
            if command == 'define':
                res.update(handle_define(module, v))

            elif not guest:
                module.fail_json(msg="%s requires 1 argument: guest" % command)

            elif command == 'undefine':
                # Use the undefine function with flag to also handle various metadata.
                # This is especially important for UEFI enabled guests with nvram.
                # Provide flag as an integer of all desired bits, see 'ENTRY_UNDEFINE_FLAGS_MAP'.
                # Integer 55 takes care of all cases (55 = 1 + 2 + 4 + 16 + 32).                flag = 0
                flag = 0
                if flags is not None:
                    if force is True:
                        module.warn("Ignoring 'force', because 'flags' are provided.")
                    nv = ['nvram', 'keep_nvram']
                    # Check mutually exclusive flags
                    if set(nv) <= set(flags):
                        raise ValueError("Flags '%s' are mutually exclusive" % "' and '".join(nv))
                    for item in flags:
                        # Get and add flag integer from mapping, otherwise 0.
                        flag += ENTRY_UNDEFINE_FLAGS_MAP.get(item, 0)
                elif force is True:
                    flag = 55
                # Finally, execute with flag
                res = exec_virt(guest, flag)

            elif command == 'uuid':
                res = {'uuid': v.get_uuid(guest)}

            else:
                res = exec_virt(guest)

            return VIRT_SUCCESS, res

        elif hasattr(v, command):
            res = exec_virt()
            return VIRT_SUCCESS, res

        else:
            module.fail_json(msg="Command %s not recognized" % command)

    module.fail_json(msg="expected state or command parameter to be specified")


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', aliases=['guest']),
            state=dict(type='str', choices=['destroyed', 'paused', 'running', 'shutdown']),
            autostart=dict(type='bool'),
            command=dict(type='str', choices=ALL_COMMANDS),
            flags=dict(type='list', elements='str', choices=ALL_FLAGS),
            force=dict(type='bool'),
            uri=dict(type='str', default='qemu:///system'),
            xml=dict(type='str'),
            mutate_flags=dict(type='list', elements='str', choices=MUTATE_FLAGS, default=['ADD_UUID']),
        ),
        supports_check_mode=True
    )

    if not HAS_VIRT:
        module.fail_json(
            msg='The `libvirt` module is not importable. Check the requirements.'
        )

    if not HAS_XML:
        module.fail_json(
            msg='The `lxml` module is not importable. Check the requirements.'
        )

    rc = VIRT_SUCCESS
    try:
        rc, result = core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    if rc != 0:  # something went wrong emit the msg
        module.fail_json(rc=rc, msg=result)
    else:
        module.exit_json(**result)


if __name__ == '__main__':
    main()
