#!/usr/bin/python

# (c) 2019-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Update ONTAP service-prosessor firmware
  - The recommend procedure is to
    1. download the firmware package from the NetApp Support site
    2. copy the package to a web server
    3. download the package from the web server using this module
  - Once a disk qualification, disk, shelf, or ACP firmware package is downloaded, ONTAP will automatically update the related resources in background.
  - It may take some time to complete.
  - For service processor, the update requires a node reboot to take effect.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_firmware_upgrade
options:
  state:
    description:
      - Whether the specified ONTAP firmware should be upgraded or not.
    default: present
    type: str
  node:
    description:
      - Node on which the device is located.
      - Not required if package_url is present and force_disruptive_update is False.
      - If this option is not given, the firmware will be downloaded on all nodes in the cluster,
      - and the resources will be updated in background on all nodes, except for service processor.
      - For service processor, the upgrade will happen automatically when each node is rebooted.
    type: str
  clear_logs:
    description:
      - Clear logs on the device after update. Default value is true.
      - Not used if force_disruptive_update is False.
      - Not supported with REST when set to false.
    type: bool
    default: true
  package:
    description:
      - Name of the package file containing the firmware to be installed. Not required when -baseline is true.
      - Not used if force_disruptive_update is False.
      - Not supported with REST.
    type: str
  package_url:
    description:
      - URL of the package file containing the firmware to be downloaded.
      - Once the package file is downloaded to a node, the firmware update will happen automatically in background.
      - For SP, the upgrade will happen automatically when a node is rebooted.
      - For SP, the upgrade will happen automatically if autoupdate is enabled (which is the recommended setting).
    version_added: "20.5.0"
    type: str
  force_disruptive_update:
    description:
      - If set to C(False), and URL is given, the upgrade is non disruptive. If URL is not given, no operation is performed.
      - Do not set this to C(True), unless directed by NetApp Tech Support.
      - It will force an update even if the resource is not ready for it, and can be disruptive.
      - Not supported with REST when set to true.
    type: bool
    version_added: "20.5.0"
    default: false
  shelf_module_fw:
    description:
      - Shelf module firmware to be updated to.
      - Not used if force_disruptive_update is False (ONTAP will automatically select the firmware)
      - Not supported with REST.
    type: str
  disk_fw:
    description:
      - disk firmware to be updated to.
      - Not used if force_disruptive_update is False (ONTAP will automatically select the firmware)
      - Not supported with REST.
    type: str
  update_type:
    description:
      - Type of firmware update to be performed. Options include serial_full, serial_differential, network_full.
      - Not used if force_disruptive_update is False (ONTAP will automatically select the firmware)
      - Not supported with REST.
    type: str
  install_baseline_image:
    description:
      - Install the version packaged with ONTAP if this parameter is set to true. Otherwise, package must be used to specify the package to install.
      - Not used if force_disruptive_update is False (ONTAP will automatically select the firmware)
      - Not supported with REST when set to true.
    type: bool
    default: false
  firmware_type:
    description:
      - Type of firmware to be upgraded. Options include shelf, ACP, service-processor, and disk.
      - For shelf firmware upgrade the operation is asynchronous, and therefore returns no errors that might occur during the download process.
      - Shelf firmware upgrade is idempotent if shelf_module_fw is provided .
      - disk firmware upgrade is idempotent if disk_fw is provided .
      - With check mode, SP, ACP, disk, and shelf firmware upgrade is not idempotent.
      - This operation will only update firmware on shelves/disk that do not have the latest firmware-revision.
      - For normal operations, choose one of storage or service-processor.
      - Type storage includes acp, shelf and disk and ONTAP will automatically determine what to do.
      - With REST, the module does not validate that the package matches the firmware type.  ONTAP determines the type automatically.
      - With REST, C(storage) downloads any firmware, including service-processor firmware.
      - With REST, C(service-processor) unlocks SP reboot options.
    choices: ['storage', 'service-processor', 'shelf', 'acp', 'disk']
    type: str
    default: storage
  fail_on_502_error:
    description:
      - The firmware download may take time if the web server is slow and if there are many nodes in the cluster.
      - ONTAP will break the ZAPI connection after 5 minutes with a 502 Bad Gateway error, even though the download
        is still happening.
      - By default, this module ignores this error and assumes the download is progressing as ONTAP does not
        provide a way to check the status.
      - When setting this option to true, the module will report 502 as an error.
      - Not supported with REST when set to true.
    type: bool
    default: false
    version_added: "20.6.0"
  rename_package:
    description:
      - Rename the package.
      - Only available if 'firmware_type' is 'service-processor'.
      - Not supported with REST.
    type: str
    version_added: "20.7.0"
  replace_package:
    description:
      - Replace the local package.
      - Only available if 'firmware_type' is 'service-processor'.
      - Not supported with REST when set to false.
    type: bool
    version_added: "20.7.0"
  reboot_sp:
    description:
      - Reboot service processor before downloading package.
      - Only available if 'firmware_type' is 'service-processor'.
      - Defaults to True if not set when 'firmware_type' is 'service-processor'.
      - Set this explictly to true to avoid a warning, and to false to not reboot the SP.
      - Rebooting the SP before download is strongly recommended.
    type: bool
    version_added: "20.7.0"
  reboot_sp_after_download:
    description:
      - Reboot service processor after downloading package.
      - Only available if 'firmware_type' is 'service-processor'.
    type: bool
    version_added: "21.15.0"
  server_username:
    description:
      - username to authenticate with the firmware package server.
      - Ignored with ZAPI.
    type: str
    version_added: "21.15.0"
  server_password:
    description:
      - password to authenticate with the firmware package server.
      - Ignored with ZAPI.
    type: str
    version_added: "21.15.0"
short_description:  NetApp ONTAP firmware upgrade for SP, shelf, ACP, and disk.
version_added: 2.9.0
'''

EXAMPLES = """
- name: Any firmware upgrade - REST
  netapp.ontap.na_ontap_firmware_upgrade:
    state: present
    package_url: "{{ web_link }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Firmware upgrade, confirm successful download
  netapp.ontap.na_ontap_firmware_upgrade:
    state: present
    package_url: "{{ web_link }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    fail_on_502_error: true

- name: SP firmware upgrade
  netapp.ontap.na_ontap_firmware_upgrade:
    state: present
    node: vsim1
    package: "{{ file name }}"
    package_url: "{{ web_link }}"
    clear_logs: true
    install_baseline_image: false
    update_type: serial_full
    force_disruptive_update: false
    firmware_type: service-processor
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: SP firmware download replace package
  netapp.ontap.na_ontap_firmware_upgrade:
    state: present
    node: vsim1
    package_url: "{{ web_link }}"
    firmware_type: service-processor
    replace_package: true
    reboot_sp: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false

- name: SP firmware download rename package
  netapp.ontap.na_ontap_firmware_upgrade:
    state: present
    node: vsim1
    package_url: "{{ web_link }}"
    firmware_type: service-processor
    rename_package: SP_FW.zip
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    https: true
    validate_certs: false

- name: ACP firmware download and upgrade
  netapp.ontap.na_ontap_firmware_upgrade:
    state: present
    node: vsim1
    firmware_type: acp
    package_url: "{{ web_link }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Shelf firmware upgrade
  netapp.ontap.na_ontap_firmware_upgrade:
    state: present
    firmware_type: shelf
    package_url: "{{ web_link }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Disk firmware upgrade
  netapp.ontap.na_ontap_firmware_upgrade:
    state: present
    firmware_type: disk
    package_url: "{{ web_link }}"
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: SP firmware upgrade with reboots (REST)
  netapp.ontap.na_ontap_firmware_upgrade:
    state: present
    package_url: "{{ web_link }}"
    firmware_type: service-processor
    reboot_sp: true
    reboot_sp_after_download: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
msg:
    description: Returns additional information in case of success.
    returned: always
    type: str
"""

import time
import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


MSGS = dict(
    no_action='No action taken.',
    dl_completed='Firmware download completed.',
    dl_completed_slowly='Firmware download completed, slowly.',
    dl_in_progress='Firmware download still in progress.'
)


class NetAppONTAPFirmwareUpgrade:
    """
    Class with ONTAP firmware upgrade methods
    """

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', default='present'),
            node=dict(required=False, type='str'),
            firmware_type=dict(type='str', choices=['storage', 'service-processor', 'shelf', 'acp', 'disk'], default='storage'),
            clear_logs=dict(required=False, type='bool', default=True),
            package=dict(required=False, type='str'),
            install_baseline_image=dict(required=False, type='bool', default=False),
            update_type=dict(required=False, type='str'),
            shelf_module_fw=dict(required=False, type='str'),
            disk_fw=dict(required=False, type='str'),
            package_url=dict(required=False, type='str'),
            force_disruptive_update=dict(required=False, type='bool', default=False),
            fail_on_502_error=dict(required=False, type='bool', default=False),
            rename_package=dict(required=False, type='str'),
            replace_package=dict(required=False, type='bool'),
            reboot_sp=dict(required=False, type='bool'),
            reboot_sp_after_download=dict(required=False, type='bool'),
            server_username=dict(required=False, type='str'),
            server_password=dict(required=False, type='str', no_log=True),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('firmware_type', 'acp', ['node']),
                ('firmware_type', 'disk', ['node']),
                ('firmware_type', 'service-processor', ['node']),
                ('force_disruptive_update', True, ['firmware_type']),
                ('reboot_sp', True, ['node']),
                ('reboot_sp_after_download', True, ['node']),
            ],
            required_together=[['server_username', 'server_password']],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self._node_uuid = None       # to cache calls to get_node_uuid

        self.rest_api = OntapRestAPI(self.module)
        unsupported_rest_properties = ['package', 'update_type', 'rename_package', 'shelf_module_fw', 'disk_fw']
        # only accept default value for these 5 options (2 True and 3 False)
        # accept the default value (for replace_package, this is implicit for REST) but switch to ZAPI or error out if set to False
        unsupported_rest_properties.extend(option for option in ('clear_logs', 'replace_package') if self.parameters.get(option) is False)
        # accept the default value of False, but switch to ZAPI or error out if set to True
        unsupported_rest_properties.extend(option for option in ('install_baseline_image', 'force_disruptive_update', 'fail_on_502_error')
                                           if self.parameters[option])

        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties)

        if self.parameters.get('firmware_type') == 'storage' and self.parameters.get('force_disruptive_update'):
            self.module.fail_json(msg='Do not set force_disruptive_update to True, unless directed by NetApp Tech Support')

        for option in ('reboot_sp', 'reboot_sp_after_download'):
            if self.parameters.get('firmware_type') != 'service-processor' and self.parameters.get(option):
                self.module.warn('%s is ignored when firmware_type is not set to service-processor' % option)
        if self.parameters.get('firmware_type') == 'service-processor' and self.parameters.get('reboot_sp') is None:
            self.module.warn('Forcing a reboot of SP before download - set reboot_sp: true to disable this warning.')
            self.parameters['reboot_sp'] = True
        if not self.use_rest and self.parameters.get('firmware_type') == 'service-processor':
            msg = 'With ZAPI and firmware_type set to service-processor: '
            if 'node' not in self.parameters:
                self.module.fail_json(msg=msg + 'parameter node should be present.')
            if self.parameters.get('install_baseline_image') and self.parameters.get('package') is not None:
                self.module.fail_json(msg=msg + 'do not specify both package and install_baseline_image: true.')
            if self.parameters.get('force_disruptive_update') \
                    and self.parameters.get('install_baseline_image') is False \
                    and self.parameters.get('package') is None:
                self.module.fail_json(msg=msg + 'specify at least one of package or install_baseline_image: true.')

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, wrap_zapi=True)

    def firmware_image_get_iter(self):
        """
        Compose NaElement object to query current firmware version
        :return: NaElement object for firmware_image_get_iter with query
        """
        firmware_image_get = netapp_utils.zapi.NaElement('service-processor-get-iter')
        query = netapp_utils.zapi.NaElement('query')
        firmware_image_info = netapp_utils.zapi.NaElement('service-processor-info')
        firmware_image_info.add_new_child('node', self.parameters['node'])
        query.add_child_elem(firmware_image_info)
        firmware_image_get.add_child_elem(query)
        return firmware_image_get

    def firmware_image_get(self, node_name):
        """
        Get current firmware image info
        :return: True if query successful, else return None
        """
        firmware_image_get_iter = self.firmware_image_get_iter()
        try:
            result = self.server.invoke_successfully(firmware_image_get_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching firmware image details: %s: %s'
                                      % (self.parameters['node'], to_native(error)),
                                  exception=traceback.format_exc())
        # return firmware image details
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
            sp_info = result.get_child_by_name('attributes-list').get_child_by_name('service-processor-info')
            return sp_info.get_child_content('firmware-version')
        return None

    def acp_firmware_update_required(self):
        """
        where acp firmware upgrade is required
        :return:  True is firmware upgrade is required else return None
        """
        acp_firmware_get_iter = netapp_utils.zapi.NaElement('storage-shelf-acp-module-get-iter')
        query = netapp_utils.zapi.NaElement('query')
        acp_info = netapp_utils.zapi.NaElement('storage-shelf-acp-module')
        query.add_child_elem(acp_info)
        acp_firmware_get_iter.add_child_elem(query)
        try:
            result = self.server.invoke_successfully(acp_firmware_get_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching acp firmware details details: %s'
                                  % (to_native(error)), exception=traceback.format_exc())
        acp_module_info = self.na_helper.safe_get(result, ['attributes-list', 'storage-shelf-acp-module'])
        if acp_module_info:
            state = acp_module_info.get_child_content('state')
            if state == 'firmware_update_required':
                # acp firmware version upgrade required
                return True
        return False

    def sp_firmware_image_update_progress_get(self, node_name):
        """
        Get current firmware image update progress info
        :return: Dictionary of firmware image update progress if query successful, else return None
        """
        firmware_update_progress_get = netapp_utils.zapi.NaElement('service-processor-image-update-progress-get')
        firmware_update_progress_get.add_new_child('node', self.parameters['node'])

        firmware_update_progress_info = {}
        try:
            result = self.server.invoke_successfully(firmware_update_progress_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching firmware image upgrade progress details: %s'
                                      % (to_native(error)), exception=traceback.format_exc())
        # return firmware image update progress details
        if result.get_child_by_name('attributes').get_child_by_name('service-processor-image-update-progress-info'):
            update_progress_info = result.get_child_by_name('attributes').get_child_by_name('service-processor-image-update-progress-info')
            firmware_update_progress_info['is-in-progress'] = update_progress_info.get_child_content('is-in-progress')
            firmware_update_progress_info['node'] = update_progress_info.get_child_content('node')
        return firmware_update_progress_info

    def shelf_firmware_info_get(self):
        """
        Get the current firmware of shelf module
        :return:dict with module id and firmware info
        """
        shelf_id_fw_info = {}
        shelf_firmware_info_get = netapp_utils.zapi.NaElement('storage-shelf-info-get-iter')
        desired_attributes = netapp_utils.zapi.NaElement('desired-attributes')
        storage_shelf_info = netapp_utils.zapi.NaElement('storage-shelf-info')
        shelf_module = netapp_utils.zapi.NaElement('shelf-modules')
        shelf_module_info = netapp_utils.zapi.NaElement('storage-shelf-module-info')
        shelf_module.add_child_elem(shelf_module_info)
        storage_shelf_info.add_child_elem(shelf_module)
        desired_attributes.add_child_elem(storage_shelf_info)
        shelf_firmware_info_get.add_child_elem(desired_attributes)

        try:
            result = self.server.invoke_successfully(shelf_firmware_info_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching shelf module firmware  details: %s'
                                      % (to_native(error)), exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
            shelf_info = result.get_child_by_name('attributes-list').get_child_by_name('storage-shelf-info')
            if (shelf_info.get_child_by_name('shelf-modules') and
                    shelf_info.get_child_by_name('shelf-modules').get_child_by_name('storage-shelf-module-info')):
                shelves = shelf_info['shelf-modules'].get_children()
                for shelf in shelves:
                    shelf_id_fw_info[shelf.get_child_content('module-id')] = shelf.get_child_content('module-fw-revision')
        return shelf_id_fw_info

    def disk_firmware_info_get(self):
        """
        Get the current firmware of disks module
        :return:
        """
        disk_id_fw_info = {}
        disk_firmware_info_get = netapp_utils.zapi.NaElement('storage-disk-get-iter')
        desired_attributes = netapp_utils.zapi.NaElement('desired-attributes')
        storage_disk_info = netapp_utils.zapi.NaElement('storage-disk-info')
        disk_inv = netapp_utils.zapi.NaElement('disk-inventory-info')
        storage_disk_info.add_child_elem(disk_inv)
        desired_attributes.add_child_elem(storage_disk_info)
        disk_firmware_info_get.add_child_elem(desired_attributes)
        try:
            result = self.server.invoke_successfully(disk_firmware_info_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching disk module firmware  details: %s'
                                      % (to_native(error)), exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
            disk_info = result.get_child_by_name('attributes-list')
            disks = disk_info.get_children()
            for disk in disks:
                disk_id_fw_info[disk.get_child_content('disk-uid')] = disk.get_child_by_name('disk-inventory-info').get_child_content('firmware-revision')
        return disk_id_fw_info

    def disk_firmware_update_required(self):
        """
        Check weather disk firmware upgrade is required or not
        :return: True if the firmware upgrade is required
        """
        disk_firmware_info = self.disk_firmware_info_get()
        return any(
            disk_firmware_info[disk] != self.parameters['disk_fw']
            for disk in disk_firmware_info
        )

    def shelf_firmware_update_required(self):
        """
        Check weather shelf firmware upgrade is required or not
        :return: True if the firmware upgrade is required
        """
        shelf_firmware_info = self.shelf_firmware_info_get()
        return any(
            shelf_firmware_info[module] != self.parameters['shelf_module_fw']
            for module in shelf_firmware_info
        )

    def sp_firmware_image_update(self):
        """
        Update current firmware image
        """
        firmware_update_info = netapp_utils.zapi.NaElement('service-processor-image-update')
        if self.parameters.get('package') is not None:
            firmware_update_info.add_new_child('package', self.parameters['package'])
        if self.parameters.get('clear_logs') is not None:
            firmware_update_info.add_new_child('clear-logs', str(self.parameters['clear_logs']))
        if self.parameters.get('install_baseline_image') is not None:
            firmware_update_info.add_new_child('install-baseline-image', str(self.parameters['install_baseline_image']))
        firmware_update_info.add_new_child('node', self.parameters['node'])
        firmware_update_info.add_new_child('update-type', self.parameters['update_type'])

        try:
            self.server.invoke_successfully(firmware_update_info, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            # Current firmware version matches the version to be installed
            if to_native(error.code) == '13001' and (error.message.startswith('Service Processor update skipped')):
                return False
            self.module.fail_json(msg='Error updating firmware image for %s: %s'
                                      % (self.parameters['node'], to_native(error)),
                                  exception=traceback.format_exc())
        return True

    def shelf_firmware_upgrade(self):
        """
        Upgrade shelf firmware image
        """
        shelf_firmware_update_info = netapp_utils.zapi.NaElement('storage-shelf-firmware-update')
        try:
            self.server.invoke_successfully(shelf_firmware_update_info, enable_tunneling=True)
            return True
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error updating shelf firmware image : %s'
                                      % (to_native(error)), exception=traceback.format_exc())

    def acp_firmware_upgrade(self):

        """
        Upgrade shelf firmware image
        """
        acp_firmware_update_info = netapp_utils.zapi.NaElement('storage-shelf-acp-firmware-update')
        acp_firmware_update_info.add_new_child('node-name', self.parameters['node'])
        try:
            self.server.invoke_successfully(acp_firmware_update_info, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error updating acp firmware image : %s'
                                  % (to_native(error)), exception=traceback.format_exc())

    def disk_firmware_upgrade(self):

        """
        Upgrade disk firmware
        """
        disk_firmware_update_info = netapp_utils.zapi.NaElement('disk-update-disk-fw')
        disk_firmware_update_info.add_new_child('node-name', self.parameters['node'])
        try:
            self.server.invoke_successfully(disk_firmware_update_info, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error updating disk firmware image : %s'
                                  % (to_native(error)), exception=traceback.format_exc())
        return True

    def download_firmware(self):
        if self.use_rest:
            return self.download_software_rest()

        ''' calls the system-cli ZAPI as there is no ZAPI for this feature '''
        msg = MSGS['dl_completed']
        command = ['storage', 'firmware', 'download', '-node', self.parameters['node'] if self.parameters.get('node') else '*',
                   '-package-url', self.parameters['package_url']]
        command_obj = netapp_utils.zapi.NaElement("system-cli")

        args_obj = netapp_utils.zapi.NaElement("args")
        for arg in command:
            args_obj.add_new_child('arg', arg)
        command_obj.add_child_elem(args_obj)
        command_obj.add_new_child('priv', 'advanced')

        output = None
        try:
            output = self.server.invoke_successfully(command_obj, True)

        except netapp_utils.zapi.NaApiError as error:
            # with netapp_lib, error.code may be a number or a string
            try:
                err_num = int(error.code)
            except ValueError:
                err_num = -1
            if err_num == 60:                                                   # API did not finish on time
                # even if the ZAPI reports a timeout error, it does it after the command completed
                msg = MSGS['dl_completed_slowly']
            elif err_num == 502 and not self.parameters['fail_on_502_error']:   # Bad Gateway
                # ONTAP proxy breaks the connection after 5 minutes, we can assume the download is progressing slowly
                msg = MSGS['dl_in_progress']
            else:
                self.module.fail_json(msg='Error running command %s: %s' % (command, to_native(error)),
                                      exception=traceback.format_exc())
        except netapp_utils.zapi.etree.XMLSyntaxError as error:
            self.module.fail_json(msg='Error decoding output from command %s: %s' % (command, to_native(error)),
                                  exception=traceback.format_exc())

        if output is not None:
            # command completed, check for success
            status = output.get_attr('status')
            cli_output = output.get_child_content('cli-output')
            if status is None or status != 'passed' or cli_output is None or cli_output == "":
                if status is None:
                    extra_info = "'status' attribute missing"
                elif status != 'passed':
                    extra_info = "check 'status' value"
                else:
                    extra_info = 'check console permissions'
                self.module.fail_json(msg='unable to download package from %s: %s.  Received: %s' %
                                      (self.parameters['package_url'], extra_info, output.to_string()))

            if cli_output is not None:
                if cli_output.startswith('Error:') or \
                        'Failed to download package from' in cli_output:
                    self.module.fail_json(msg='failed to download package from %s: %s' % (self.parameters['package_url'], cli_output))
                msg += "  Extra info: %s" % cli_output

        return msg

    def download_sp_image(self):
        fetch_package = netapp_utils.zapi.NaElement('system-image-fetch-package')
        fetch_package.add_new_child('node', self.parameters['node'])
        fetch_package.add_new_child('package', self.parameters['package_url'])
        if self.parameters.get('rename_package'):
            fetch_package.add_new_child('rename-package', self.parameters['rename_package'])
        if self.parameters.get('replace_package'):
            fetch_package.add_new_child('replace-package', str(self.parameters['replace_package']))
        try:
            self.server.invoke_successfully(fetch_package, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching system image package from %s: %s'
                                      % (self.parameters['package_url'], to_native(error)),
                                  exception=traceback.format_exc())

    def download_sp_image_progress(self):
        progress = netapp_utils.zapi.NaElement('system-image-update-progress-get')
        progress.add_new_child('node', self.parameters['node'])
        progress_info = {}
        try:
            result = self.server.invoke_successfully(progress, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching system image package download progress: %s'
                                      % (to_native(error)), exception=traceback.format_exc())
        if result.get_child_by_name('phase'):
            progress_info['phase'] = result.get_child_content('phase')
        else:
            progress_info['phase'] = None
        if result.get_child_by_name('exit-message'):
            progress_info['exit_message'] = result.get_child_content('exit-message')
        else:
            progress_info['exit_message'] = None
        if result.get_child_by_name('exit-status'):
            progress_info['exit_status'] = result.get_child_content('exit-status')
        else:
            progress_info['exit_status'] = None
        if result.get_child_by_name('last-message'):
            progress_info['last_message'] = result.get_child_content('last-message')
        else:
            progress_info['last_message'] = None
        if result.get_child_by_name('run-status'):
            progress_info['run_status'] = result.get_child_content('run-status')
        else:
            progress_info['run_status'] = None
        return progress_info

    def reboot_sp(self):
        if self.use_rest:
            return self.reboot_sp_rest()
        reboot = netapp_utils.zapi.NaElement('service-processor-reboot')
        reboot.add_new_child('node', self.parameters['node'])
        try:
            self.server.invoke_successfully(reboot, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error rebooting service processor: %s'
                                      % (to_native(error)),
                                  exception=traceback.format_exc())

    def get_node_uuid(self):
        if self._node_uuid is not None:
            return self._node_uuid
        api = 'cluster/nodes'
        query = {'name': self.parameters['node']}
        node, error = rest_generic.get_one_record(self.rest_api, api, query, fields='uuid')
        if error:
            self.module.fail_json(msg='Error reading node UUID: %s' % error)
        if not node:
            self.module.fail_json(msg='Error: node not found %s, current nodes: %s.' % (self.parameters['node'], ', '.join(self.get_node_names())))
        self._node_uuid = node['uuid']
        return node['uuid']

    def get_node_names(self):
        api = 'cluster/nodes'
        nodes, error = rest_generic.get_0_or_more_records(self.rest_api, api, fields='name')
        if error:
            self.module.fail_json(msg='Error reading nodes: %s' % error)
        return [node['name'] for node in nodes]

    def reboot_sp_rest_cli(self):
        """ for older versions of ONTAP, use the REST CLI passthrough """
        api = 'private/cli/sp/reboot-sp'
        query = {'node': self.parameters['node']}
        dummy, error = rest_generic.patch_async(self.rest_api, api, None, None, query)
        return error

    def get_sp_state(self):
        api = 'cluster/nodes/%s' % self.get_node_uuid()
        node, error = rest_generic.get_one_record(self.rest_api, api, fields='service_processor.state')
        if error:
            self.module.fail_json(msg='Error getting node SP state: %s' % error)
        if node:
            return self.na_helper.safe_get(node, ['service_processor', 'state'])

    def wait_for_sp_reboot(self):
        for dummy in range(20):
            time.sleep(15)
            state = self.get_sp_state()
            if state != 'rebooting':
                break
        else:
            self.module.warn('node did not finish up booting in 5 minutes!')

    def reboot_sp_rest(self):
        uuid = self.get_node_uuid()
        api = 'cluster/nodes'
        body = {'service_processor.action': 'reboot'}
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid, body)
        if error and 'Unexpected argument "service_processor.action"' in error:
            error = self.reboot_sp_rest_cli()
            if error:
                error = 'reboot_sp requires ONTAP 9.10.1 or newer, falling back to CLI passthrough failed: ' + error
        if error:
            self.module.fail_json(msg='Error rebooting node SP: %s' % error)

    def download_sp_firmware(self):
        if self.parameters.get('reboot_sp'):
            self.reboot_sp()
        if self.use_rest:
            return self.download_software_rest()
        self.download_sp_image()
        progress = self.download_sp_image_progress()
        # progress only show the current or most recent update/install operation.
        if progress['phase'] == 'Download':
            while progress['run_status'] is not None and progress['run_status'] != 'Exited':
                time.sleep(10)
                progress = self.download_sp_image_progress()
            if progress['exit_status'] != 'Success':
                self.module.fail_json(msg=progress['exit_message'], exception=traceback.format_exc())
            return MSGS['dl_completed']
        return MSGS['no_action']

    def download_software_rest(self):
        body = {'url': self.parameters['package_url']}
        for attr in ('username', 'password'):
            value = self.parameters.get('server_%s' % attr)
            if value:
                body[attr] = value
        api = 'cluster/software/download'
        # burt 1442080 - when timeout is 30, the API may return a 500 error, though the job says download completed!
        message, error = rest_generic.post_async(self.rest_api, api, body, job_timeout=self.parameters.get('time_out', 180), timeout=0)
        if error:
            self.module.fail_json(msg='Error downloading software: %s' % error)
        return message

    def apply(self):
        """
        Apply action to upgrade firmware
        """
        changed = False
        msg = MSGS['no_action']
        if self.parameters.get('package_url'):
            if not self.module.check_mode:
                if self.parameters.get('firmware_type') == 'service-processor':
                    msg = self.download_sp_firmware()
                    if self.parameters.get('reboot_sp') and self.use_rest:
                        self.wait_for_sp_reboot()
                else:
                    msg = self.download_firmware()
            changed = True
        if not self.parameters['force_disruptive_update'] and not self.parameters.get('reboot_sp_after update'):
            # disk_qual, disk, shelf, and ACP are automatically updated in background
            # The SP firmware is automatically updated on reboot
            self.module.exit_json(changed=changed, msg=msg)
        if msg == MSGS['dl_in_progress']:
            # can't force an update if the software is still downloading
            self.module.fail_json(msg="Cannot force update: %s" % msg)
        self.disruptive_update(changed)

    def disruptive_update(self, changed):
        if self.parameters.get('firmware_type') == 'service-processor':
            if self.parameters.get('reboot_sp_after update'):
                self.reboot_sp()
            if not self.parameters['force_disruptive_update']:
                return
            # service-processor firmware upgrade
            current = self.firmware_image_get(self.parameters['node'])

            if self.parameters.get('state') == 'present' and current:
                if not self.module.check_mode:
                    if self.sp_firmware_image_update():
                        changed = True
                    firmware_update_progress = self.sp_firmware_image_update_progress_get(self.parameters['node'])
                    while firmware_update_progress.get('is-in-progress') == 'true':
                        time.sleep(25)
                        firmware_update_progress = self.sp_firmware_image_update_progress_get(self.parameters['node'])
                else:
                    # we don't know until we try the upgrade
                    changed = True

        elif self.parameters.get('firmware_type') == 'shelf':
            # shelf firmware upgrade
            if self.parameters.get('shelf_module_fw'):
                if self.shelf_firmware_update_required():
                    changed = True if self.module.check_mode else self.shelf_firmware_upgrade()
            else:
                # with check_mode, we don't know until we try the upgrade -- assuming the worst
                changed = True if self.module.check_mode else self.shelf_firmware_upgrade()
        elif self.parameters.get('firmware_type') == 'acp' and self.acp_firmware_update_required():
            # acp firmware upgrade
            if not self.module.check_mode:
                self.acp_firmware_upgrade()
            changed = True
        elif self.parameters.get('firmware_type') == 'disk':
            # Disk firmware upgrade
            if self.parameters.get('disk_fw'):
                if self.disk_firmware_update_required():
                    changed = True if self.module.check_mode else self.disk_firmware_upgrade()
            else:
                # with check_mode, we don't know until we try the upgrade -- assuming the worst
                changed = True if self.module.check_mode else self.disk_firmware_upgrade()
        self.module.exit_json(changed=changed, msg='forced update for %s' % self.parameters.get('firmware_type'))


def main():
    """Execute action"""
    fwupgrade_obj = NetAppONTAPFirmwareUpgrade()
    fwupgrade_obj.apply()


if __name__ == '__main__':
    main()
