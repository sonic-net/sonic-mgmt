#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Maciej Delmanowski <drybjed@gmail.com>
# (c) 2025, Dougal Seeley <git@dougalseeley.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: virt_volume
version_added: '1.4.0'
author:
  - Leonardo Galli (@galli-leo)
  - Niclas Kretschmer (@NK308)
  - Dougal Seeley (@dseeley)
short_description: Manage libvirt volumes inside a storage pool
description:
  - Manage I(libvirt) volumes inside a storage pool.
options:
  name:
    aliases: [ "volume" ]
    description:
      - Name of the volume being managed. Note that the volume must be previously defined with xml.
    type: str
  pool:
    required: true
    description:
      - Name of the storage pool, where the volume is located.
    type: str
  state:
    choices: [ "present", "absent" ]
    description:
      - If C(present), Creates a new volume with the XML provided, optionally cloning from the image in C(clone_source). The name of the volume is specified
        in the XML (if a C(name) parameter is provided, it is ignored). C(xml) must be provided.
      - If C(absent), Deletes the volume specified by C(name) from the storage pool.  If C(wipe) is set to C(true), the volume will be wiped before deletion.
      - Mutually exclusive with C(command).
    type: str
  command:
    choices: [ "create", "delete", "wipe", "list_volumes", "get_xml", "create_cidata_cdrom" ]
    description:
      - C(create) - Analagous to C(state) / C(present)
      - C(delete) - Analagous to C(state) / C(absent)
      - C(wipe) - Performs a wipe *only* of the volume specified by C(name) - *does not delete* the volume.
      - C(list_volumes) - Lists all volumes in the storage pool.
      - C(get_xml) - Retrieves the XML of the volume specified by C(name).
      - C(create_cidata_cdrom) - Creates a CIDATA CDROM with the provided C(cloudinit_config) data. Enables bootstrapping of cloud-init enabled VMs.
      - Mutually exclusive with C(state).
    type: str
  xml:
    description:
      - XML definition of the volume to be created.
      - This is required if C(command) is C(create)
    type: str
  cloudinit_config:
    description:
      - Ansible dict of cloud-init data to create a CIDATA CDROM.
      - The data should contain the keys C(METADATA), C(USERDATA), and/or C(NETWORK_CONFIG).
      - This is required if C(command) is C(create_cidata_cdrom).
    type: dict
  clone_source:
    description:
      - Name of the volume to clone from.
      - Optionally provided with C(state) C(present) or C(command) C(create).
    type: str
  wipe:
    description: Whether to wipe the volume before deleting it.
    default: False
    type: bool
extends_documentation_fragment:
  - community.libvirt.virt.options_uri
  - community.libvirt.virt.options_xml
  - community.libvirt.requirements
requirements:
  - "libvirt"
  - "lxml"
  - "pycdlib"
'''

EXAMPLES = '''
- name: Create volume in existing default pool
  community.libvirt.virt_volume:
    state: present
    pool: default
    xml: |
      <volume>
      <name>testing-volume</name>
      <allocation>0</allocation>
      <capacity unit="M">10</capacity>
      <target>
        <permissions>
          <mode>0644</mode>
          <label>virt_image_t</label>
        </permissions>
      </target>
      </volume>

- name: List volumes in default pool
  community.libvirt.virt_volume:
    pool: default
    command: list_volumes

- name: Get volume XML
  community.libvirt.virt_volume:
    pool: default
    command: get_xml
    name: testing-volume
  register: r__virt_volume__get_xml

- name: Wipe a volume
  community.libvirt.virt_volume:
    pool: default
    command: wipe
    name: testing-volume

- name: Delete volume from default pool, wiping it first (using state parameter)
  community.libvirt.virt_volume:
    pool: default
    state: absent
    name: testing-volume
    wipe: true

- name: Delete volume from default pool (using command parameter)
  community.libvirt.virt_volume:
    pool: default
    command: delete
    name: testing-volume

- name: Create a volume from an existing image (clone)
  community.libvirt.virt_volume:
    pool: default
    command: create
    clone_source: gold-ubuntu2404-base-image
    xml: |
      <volume type='file'>
        <name>testing_volume--boot</name>
        <capacity unit='G'>10</capacity>
        <target><format type='qcow2'/></target>
      </volume>

- name: Create CIDATA (cloud-init) cdrom
  community.libvirt.virt_volume:
    pool: default
    command: create_cidata_cdrom
    name: testing_cidata.iso
    cloudinit_config:
      NETWORK_CONFIG: {version: 2, ethernets: {eth0: {dhcp4: true}}}
      USERDATA: {users: [{name: testuser, lock_passwd: false, shell: /bin/bash, ssh_authorized_keys: ["ssh-rsa xxxxxxxxxxxxxxxxxxxxx=="]}]}
      METADATA: {local-hostname: my_host}
  register: r__virt_volume__create_cidata_cdrom
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
import traceback

try:
    import libvirt
    LIBVIRT_IMPORT_ERR = None
except ImportError as libvirt_import_exception:
    LIBVIRT_IMPORT_ERR = libvirt_import_exception

try:
    from lxml import etree
    LXML_IMPORT_ERR = None
except ImportError as lxml_import_exception:
    LXML_IMPORT_ERR = lxml_import_exception


class LibvirtConnection(object):
    def __init__(self, uri, check_mode, pool):
        conn = libvirt.open(uri)
        if not conn:
            raise Exception("hypervisor connection failure")
        self.conn = conn

        self.check_mode = check_mode

        self.pool_ptr = self.conn.storagePoolLookupByName(pool) if pool is not None else None

    def create(self, xml, clone_source=None, name=None, **kwargs):
        """
        Creates a new volume with the XML provided, with the name specified in the XML, optionally cloning the image from the clone_source
        (https://libvirt.org/html/libvirt-libvirt-storage.html#virStorageVolCreateXMLFrom)
        """
        isChanged = False
        xml_etree = etree.fromstring(xml)
        xml_vol_name = xml_etree.xpath("/volume/name")[0].text

        warnings_list = []
        if name:
            warnings_list.append("The 'name' parameter is ignored; the volume name is taken from the XML definition ('%s')." % xml_vol_name)

        try:
            createdStorageVolPtr = self.pool_ptr.storageVolLookupByName(xml_vol_name)
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_STORAGE_VOL:
                if clone_source:
                    # Ensure clone_source is valid
                    if not self.pool_ptr.storageVolLookupByName(clone_source):
                        raise libvirt.libvirtError("Clone source volume '%s' does not exist." % clone_source)

                    clone_source_vol_ptr = self.pool_ptr.storageVolLookupByName(clone_source)
                    createdStorageVolPtr = self.pool_ptr.createXMLFrom(xml, clone_source_vol_ptr, 0)

                    if xml_etree.xpath("/volume/capacity"):
                        capacity_elem = xml_etree.xpath("/volume/capacity")[0]
                        unit = capacity_elem.get("unit", "bytes").lower()

                        # Conversion factors to bytes
                        unit_factors = {"bytes": 1, "b": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}

                        # Convert size to bytes
                        try:
                            size_bytes = int(float(capacity_elem.text) * unit_factors.get(unit, 1))
                        except (ValueError, KeyError):
                            raise Exception(f"Unknown or invalid unit for capacity: {unit}")

                        createdStorageVolPtr.resize(size_bytes)

                    isChanged = True
                else:
                    # If no clone_source is provided, just create an empty volume
                    createdStorageVolPtr = self.pool_ptr.createXML(xml)

                    isChanged = True
            else:
                raise e

        result = {'changed': isChanged, 'res': {'XMLDesc': createdStorageVolPtr.XMLDesc(0),
                                                'name': createdStorageVolPtr.name(),
                                                'path': createdStorageVolPtr.path(),
                                                'key': createdStorageVolPtr.key()}}
        if warnings_list:
            result['warnings'] = warnings_list

        return result

    def create_cidata_cdrom(self, name, cloudinit_config, **kwargs):
        """ Create a properly formatted CD image containing cloud-init files, then upload it to the host """
        import yaml

        try:
            import pycdlib
        except ImportError as pycdlib_import_exception:
            raise pycdlib_import_exception

        # StringIO as BytesIO for python2/3 compatibility
        try:
            from cStringIO import StringIO as BytesIO
        except ImportError:
            from io import BytesIO

        # Ensure we actually have some CIDATA before creating the CIDATA cdrom
        if cloudinit_config and ('METADATA' in cloudinit_config or 'USERDATA' in cloudinit_config or 'NETWORK_CONFIG' in cloudinit_config):
            iso = pycdlib.PyCdlib()
            iso.new(interchange_level=3, joliet=True, sys_ident='LINUX', rock_ridge='1.09', vol_ident='cidata')

            if 'NETWORK_CONFIG' in cloudinit_config:
                cidata_network = yaml.safe_dump(cloudinit_config['NETWORK_CONFIG'], width=4096, encoding='utf-8')
                iso.add_fp(BytesIO(cidata_network), len(cidata_network), '/NETWORK_CONFIG.;1', rr_name="network-config", joliet_path='/network-config')

            if 'METADATA' in cloudinit_config:
                cidata_metadata = yaml.safe_dump(cloudinit_config['METADATA'], width=4096, encoding='utf-8')
            else:
                cidata_metadata = "# Note: The user-data and meta-data must both be present for this to be considered a valid seed ISO.".encode('utf-8')

            if 'USERDATA' in cloudinit_config:
                cidata_userdata = "#cloud-config\n".encode('utf-8') + yaml.safe_dump(cloudinit_config['USERDATA'], width=4096, encoding='utf-8')
            else:
                cidata_metadata = "# Note: The user-data and meta-data must both be present for this to be considered a valid seed ISO.".encode('utf-8')

            iso.add_fp(BytesIO(cidata_metadata), len(cidata_metadata), '/METADATA.;1', rr_name="meta-data", joliet_path='/meta-data')
            iso.add_fp(BytesIO(cidata_userdata), len(cidata_userdata), '/USERDATA.;1', rr_name="user-data", joliet_path='/user-data')

            outiso = BytesIO()
            iso.write_fp(outiso)
            outiso_len = outiso.getbuffer().nbytes

            # Remote iso XML
            vol_xml = """
              <volume type='file'>
                <name>{}</name>
                <capacity unit='bytes'>{}</capacity>
                <target><format type='iso'/></target>
              </volume>""".format(name, outiso_len)

            try:
                createdStorageVolPtr = self.pool_ptr.storageVolLookupByName(name)
            except libvirt.libvirtError as e:
                if e.get_error_code() == libvirt.VIR_ERR_NO_STORAGE_VOL:
                    createdStorageVolPtr = self.pool_ptr.createXML(vol_xml)

                    virStreamPtr = self.conn.newStream(0)
                    createdStorageVolPtr.upload(virStreamPtr, 0, outiso_len, 0)
                    virStreamPtr.send(outiso.getvalue())

                    virStreamPtr.finish()
                else:
                    raise e

            iso.close()
            return {'changed': True, 'res': {'XMLDesc': createdStorageVolPtr.XMLDesc(0),
                                             'name': createdStorageVolPtr.name(),
                                             'path': createdStorageVolPtr.path(),
                                             'key': createdStorageVolPtr.key()}}
        else:
            return {'changed': False, 'res': {'Error': 'No CIDATA to create'}}

    def delete(self, name, wipe=False, **kwargs):
        """ Delete a storage volume (https://libvirt.org/html/libvirt-libvirt-storage.html#virStorageVolDelete) """
        try:
            if wipe:
                self.pool_ptr.storageVolLookupByName(name).wipe(0)
            self.pool_ptr.storageVolLookupByName(name).delete()
            return {'changed': True, 'res': 'Deleted %s' % name}
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_STORAGE_VOL:
                return {'changed': False, 'res': e.get_error_message()}
            else:
                raise e

    def wipe(self, name, **kwargs):
        """ Wipe a storage volume (doesn't delete) (https://libvirt.org/html/libvirt-libvirt-storage.html#virStorageVolWipe)"""
        try:
            self.pool_ptr.storageVolLookupByName(name).wipe(0)
            return {'changed': True, 'res': 'Wiped and deleted %s' % name}
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_STORAGE_VOL:
                return {'changed': False, 'res': e.get_error_message()}
            else:
                raise e

    def get_xml(self, name, **kwargs):
        """ Return the XMLDesc for a given storage volume (https://libvirt.org/html/libvirt-libvirt-storage.html#virStorageVolGetXMLDesc) """
        try:
            res_XMLDesc = self.pool_ptr.storageVolLookupByName(name).XMLDesc(0)
            return {'changed': False, 'res': res_XMLDesc}
        except libvirt.libvirtError as e:
            if e.get_error_code() == libvirt.VIR_ERR_NO_STORAGE_VOL:
                return {'changed': False, 'res': {'Error': 'libvirt.VIR_ERR_NO_STORAGE_VOL: %s' % (e.get_error_message())}}
            else:
                raise e

    def list_volumes(self, **kwargs):
        """ List all volumes in the storage pool (https://libvirt.org/html/libvirt-libvirt-storage.html#virStoragePoolListAllVolumes) """
        results = []
        for entry in self.pool_ptr.listAllVolumes():
            results.append({'name': entry.name(), 'path': entry.path(), 'key': entry.key(), 'XMLDesc': entry.XMLDesc(0), 'info': entry.info()})
        return {'changed': False, 'res': results}


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(aliases=['volume']),
            pool=dict(required=True),
            state=dict(choices=['present', 'absent']),
            command=dict(choices=['create', 'delete', 'wipe', 'list_volumes', 'get_xml', 'create_cidata_cdrom']),
            uri=dict(default='qemu:///system'),
            xml=dict(),
            clone_source=dict(type='str'),
            cloudinit_config=dict(type='dict'),
            wipe=dict(type='bool', default=False)
        ),
        mutually_exclusive=[['state', 'command']],
        supports_check_mode=False
    )

    if LIBVIRT_IMPORT_ERR:
        module.fail_json(msg=missing_required_lib("libvirt"), exception=LIBVIRT_IMPORT_ERR)

    if LXML_IMPORT_ERR:
        module.fail_json(msg=missing_required_lib("lxml"), exception=LXML_IMPORT_ERR)

    state = module.params.get('state', None)
    command = module.params.get('command', None)
    uri = module.params.get('uri', None)

    if not command and not state:
        module.fail_json(msg="expected 'command' or 'state' parameter to be specified")

    if state:
        if state in ['present']:
            command = 'create'
        elif state in ['absent']:
            command = 'delete'
        else:
            module.fail_json(msg="unexpected state, %s" % state)

    if command:
        v = LibvirtConnection(uri, module.check_mode, module.params.get('pool', None))
        kwargs = {k: module.params.get(k) for k in module.argument_spec if module.params.get(k) is not None}

        if hasattr(v, command):
            try:
                res = getattr(v, command)(**kwargs)
            except Exception as e:
                module.fail_json(msg=repr(e), exception=traceback.format_exc())
            else:
                if not isinstance(res, dict):
                    res = {command: res}

                if 'res' in res:
                    res[command] = res.pop('res')

                module.exit_json(**res)
        else:
            module.fail_json(msg="Command %s not recognized" % command)
    else:
        module.fail_json(msg="expected command parameter to be specified")


if __name__ == '__main__':
    main()
