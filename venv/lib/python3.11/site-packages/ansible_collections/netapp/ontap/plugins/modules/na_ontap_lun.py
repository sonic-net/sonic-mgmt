#!/usr/bin/python

# (c) 2017-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_lun

short_description: NetApp ONTAP manage LUNs
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Create, destroy, resize LUNs on NetApp ONTAP.

options:

  state:
    description:
      - Whether the specified LUN should exist or not.
    choices: ['present', 'absent']
    type: str
    default: present

  name:
    description:
      - The name of the LUN to manage.
      - Or LUN group name (volume name) when san_application_template is used.
    required: true
    type: str

  from_name:
    description:
      - The name of the LUN to be renamed.
    type: str
    version_added: 20.12.0

  flexvol_name:
    description:
      - The name of the FlexVol the LUN should exist on.
      - Required if san_application_template is not present.
      - Not allowed if san_application_template is present.
      - Not supported for ASA r2 system.
    type: str

  qtree_name:
    description:
      - Specifies the name of the Qtree that contains the new LUN.
      - Not allowed if san_application_template is present.
      - Only supported with REST.
      - Qtrees are not supported with ASA r2 system.
    version_added: 22.8.0
    type: str

  size:
    description:
      - The size of the LUN in C(size_unit).
      - Required when creating a single LUN if application template is not used.
    type: int

  size_unit:
    description:
      - The unit used to interpret the size parameter.
    choices: ['bytes', 'b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb']
    default: 'gb'
    type: str

  comment:
    description:
      - Optional descriptive comment for the LUN.
    type: str
    version_added: 21.2.0

  force_resize:
    description:
      - Forcibly reduce the size. This is required for reducing the size of the LUN to avoid accidentally
        reducing the LUN size.
    type: bool

  force_remove:
    description:
      - If "true", override checks that prevent a LUN from being destroyed if it is online and mapped.
      - If "false", destroying an online and mapped LUN will fail.
    type: bool
    default: false

  force_remove_fenced:
    description:
      - If "true", override checks that prevent a LUN from being destroyed while it is fenced.
      - If "false", attempting to destroy a fenced LUN will fail.
      - The default if not specified is "false". This field is available in Data ONTAP 8.2 and later.
    type: bool

  vserver:
    required: true
    description:
      - The name of the vserver to use.
    type: str

  os_type:
    description:
      - The os type for the LUN.
    type: str
    aliases: ['ostype']

  qos_policy_group:
    description:
      - The QoS policy group to be set on the LUN.
      - With REST, qos_policy_group and qos_adaptive_policy_group are handled as QOS policy.
    type: str
    version_added: 20.12.0

  qos_adaptive_policy_group:
    description:
      - The adaptive QoS policy group to be set on the LUN.
      - Defines measurable service level objectives (SLOs) and service level agreements (SLAs) that adjust based on the LUN's allocated space or used space.
      - Requires ONTAP 9.4 or later.
      - With REST, qos_policy_group and qos_adaptive_policy_group are handled as QOS policy.
    type: str
    version_added: 21.2.0

  space_reserve:
    description:
      - This can be set to "false" which will create a LUN without any space being reserved.
      - Not supported for ASA r2 system. All LUNs are provisioned without a space reservation.
    type: bool
    default: true

  space_allocation:
    description:
      - This enables support for the SCSI Thin Provisioning features.  If the Host and file system do
        not support this do not enable it.
      - Not supported for ASA r2 system. All LUNs are provisioned with SCSI thin provisioning enabled.
    type: bool
    version_added: 2.7.0

  use_exact_size:
    description:
    - This can be set to "false" which will round the LUN >= 450g.
    type: bool
    default: true
    version_added: 20.11.0

  san_application_template:
    description:
        - additional options when using the application/applications REST API to create LUNs.
        - the module is using ZAPI by default, and switches to REST if san_application_template is present.
        - create one or more LUNs (and the associated volume as needed).
        - operations at the LUN level are supported, they require to know the LUN short name.
        - this requires ONTAP 9.8 or higher.
        - The module partially supports ONTAP 9.7 for create and delete operations, but not for modify (API limitations).
        - Not supported with ASA r2 system.
    type: dict
    version_added: 20.12.0
    suboptions:
      name:
        description: name of the SAN application.
        type: str
        required: true
      igroup_name:
        description: name of the initiator group through which the contents of this application will be accessed.
        type: str
      lun_count:
        description: number of LUNs in the application component (1 to 32).
        type: int
      protection_type:
        description:
          - The snasphot policy for the volume supporting the LUNs.
        type: dict
        suboptions:
          local_policy:
            description:
              - The snapshot copy policy for the volume.
            type: str
      storage_service:
        description:
          - The performance service level (PSL) for this volume
        type: str
        choices: ['value', 'performance', 'extreme']
      tiering:
        description:
          - Cloud tiering policy.
        type: dict
        suboptions:
          control:
            description: Storage tiering placement rules for the container.
            choices: ['required', 'best_effort', 'disallowed']
            type: str
          policy:
            description:
              - Cloud tiering policy.
            choices: ['all', 'auto', 'none', 'snapshot-only']
            type: str
          object_stores:
            description: list of object store names for tiering.
            type: list
            elements: str
      total_size:
        description:
          - The total size of the application component, split across the member LUNs in C(total_size_unit).
          - Recommended when C(lun_count) is present.
          - Required when C(lun_count) is present and greater than 1.
          - Note - if lun_count is equal to 1, and total_size is not present, size is used to maintain backward compatibility.
        type: int
        version_added: 21.1.0
      total_size_unit:
        description:
          - The unit used to interpret the total_size parameter.
          - Defaults to size_unit if not present.
        choices: ['bytes', 'b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb']
        type: str
        version_added: 21.1.0
      use_san_application:
        description:
          - Whether to use the application/applications REST/API to create LUNs.
          - This will default to true if any other suboption is present.
        type: bool
        default: true
      scope:
        description:
          - whether the top level name identifies a single LUN or a LUN group (application).
          - By default, the module will try to make the right choice, but can report extra warnings.
          - Setting scope to 'application' is required to convert an existing volume to a smart container.
          - The module reports an error when 'lun' or 'application' is used and the desired action cannot be completed.
          - The module issues warnings when the default 'auto' is used, and there is ambiguity regarding the desired actions.
        type: str
        choices: ['application', 'auto', 'lun']
        default: auto
        version_added: 21.2.0
      exclude_aggregates:
        description:
          - The list of aggregate names to exclude when creating a volume.
          - Requires ONTAP 9.9.1 GA or better.
        type: list
        elements: str
        version_added: 21.7.0

  provisioning_options:
    description:
        - Options that are applied to create operation.
        - Only supported with REST, requires ONTAP 9.16.1 or later.
    type: dict
    version_added: 23.2.0
    suboptions:
      count:
        description:
          - The number of LUNs to provision with these properties.
          - When provided, the name is considered a prefix, and a suffix of the form _<N> is generated
            where N is the next available numeric index, starting with 1.
        type: int
      auto:
        description:
          - If the volume specified in the request does not exist, automatically provision one of appropriate size.
          - If the volume does exist, resize it to accommodate the new LUN.
          - Only supported on Unified ONTAP.
        type: bool

notes:
  - ASA r2 is only supported with ONTAP releases 9.16.0x onwards.
  - Module is not idempotent when C(provisioning_options) is set.
'''

EXAMPLES = """
- name: Create LUN
  netapp.ontap.na_ontap_lun:
    state: present
    name: ansibleLUN
    flexvol_name: ansibleVolume
    vserver: ansibleVServer
    size: 5
    size_unit: mb
    os_type: linux
    space_reserve: true
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Resize LUN
  netapp.ontap.na_ontap_lun:
    state: present
    name: ansibleLUN
    force_resize: true
    flexvol_name: ansibleVolume
    vserver: ansibleVServer
    size: 5
    size_unit: gb
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create LUNs using SAN application
  netapp.ontap.na_ontap_lun:
    state: present
    name: ansibleLUN
    size: 15
    size_unit: mb
    os_type: linux
    space_reserve: false
    san_application_template:
      name: san-ansibleLUN
      igroup_name: testme_igroup
      lun_count: 3
      protection_type:
      local_policy: default
      exclude_aggregates: aggr0
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Convert existing volume to SAN application
  netapp.ontap.na_ontap_lun:
    state: present
    name: someVolume
    size: 22
    size_unit: mb
    os_type: linux
    space_reserve: false
    san_application_template:
      name: san-ansibleLUN
      igroup_name: testme_igroup
      lun_count: 3
      protection_type:
      local_policy: default
      scope: application
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create LUNs
  netapp.ontap.na_ontap_lun:
    state: present
    name: ansibleLUN
    flexvol_name: ansibleVolume
    vserver: ansibleVServer
    size: 5
    size_unit: mb
    os_type: linux
    provisioning_options:
      count: 2
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
"""

import copy
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.rest_application import RestApplication
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_volume
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic
from ansible_collections.netapp.ontap.plugins.module_utils import rest_ontap_personality

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapLUN:
    ''' create, modify, delete LUN '''

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            from_name=dict(required=False, type='str'),
            size=dict(type='int'),
            size_unit=dict(default='gb',
                           choices=['bytes', 'b', 'kb', 'mb', 'gb', 'tb',
                                    'pb', 'eb', 'zb', 'yb'], type='str'),
            comment=dict(required=False, type='str'),
            force_resize=dict(type='bool'),
            force_remove=dict(required=False, type='bool', default=False),
            force_remove_fenced=dict(type='bool'),
            flexvol_name=dict(type='str'),
            qtree_name=dict(type='str'),
            vserver=dict(required=True, type='str'),
            os_type=dict(required=False, type='str', aliases=['ostype']),
            qos_policy_group=dict(required=False, type='str'),
            qos_adaptive_policy_group=dict(required=False, type='str'),
            space_reserve=dict(required=False, type='bool', default=True),
            space_allocation=dict(required=False, type='bool'),
            use_exact_size=dict(required=False, type='bool', default=True),
            san_application_template=dict(type='dict', options=dict(
                use_san_application=dict(type='bool', default=True),
                exclude_aggregates=dict(type='list', elements='str'),
                name=dict(required=True, type='str'),
                igroup_name=dict(type='str'),
                lun_count=dict(type='int'),
                protection_type=dict(type='dict', options=dict(
                    local_policy=dict(type='str'),
                )),
                storage_service=dict(type='str', choices=['value', 'performance', 'extreme']),
                tiering=dict(type='dict', options=dict(
                    control=dict(type='str', choices=['required', 'best_effort', 'disallowed']),
                    policy=dict(type='str', choices=['all', 'auto', 'none', 'snapshot-only']),
                    object_stores=dict(type='list', elements='str')  # create only
                )),
                total_size=dict(type='int'),
                total_size_unit=dict(choices=['bytes', 'b', 'kb', 'mb', 'gb', 'tb',
                                              'pb', 'eb', 'zb', 'yb'], type='str'),
                scope=dict(type='str', choices=['application', 'auto', 'lun'], default='auto'),
            )),
            provisioning_options=dict(type='dict', options=dict(
                count=dict(required=False, type='int'),
                auto=dict(required=False, type='bool'),
            )),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            mutually_exclusive=[('qos_policy_group', 'qos_adaptive_policy_group')]
        )

        # set up state variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        if self.parameters.get('size') is not None:
            self.parameters['size'] *= netapp_utils.POW2_BYTE_MAP[self.parameters['size_unit']]
        if self.na_helper.safe_get(self.parameters, ['san_application_template', 'total_size']) is not None:
            unit = self.na_helper.safe_get(self.parameters, ['san_application_template', 'total_size_unit'])
            if unit is None:
                unit = self.parameters['size_unit']
            self.parameters['san_application_template']['total_size'] *= netapp_utils.POW2_BYTE_MAP[unit]

        self.debug = {}
        self.uuid = None
        # self.debug['got'] = 'empty'     # uncomment to enable collecting data
        self.asa_r2_system = False

        self.rest_api = OntapRestAPI(self.module)
        # use_exact_size is defaulted to true, but not supported with REST. To get around this we will ignore the variable in rest.
        unsupported_rest_properties = ['force_resize', 'force_remove_fenced']
        partially_supported_rest_properties = [['san_application_template', (9, 7)],
                                               ['space_allocation', (9, 10)],
                                               ['provisioning_options', (9, 16, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties,
                                                                   partially_supported_rest_properties)
        if self.use_rest:
            if self.rest_api.meets_rest_minimum_version(True, 9, 16, 0):
                # ASA r2 is only supported from ONTAP releases 9.16.0x onwards
                self.is_asa_r2_system()
                if self.asa_r2_system:
                    self.validate_params_asa_r2()

            self.parameters.pop('use_exact_size')
            if self.parameters.get('qos_adaptive_policy_group') is not None:
                self.parameters['qos_policy_group'] = self.parameters.pop('qos_adaptive_policy_group')
        else:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])
            # set default value for ZAPI only supported options.
            if self.parameters.get('force_resize') is None:
                self.parameters['force_resize'] = False
            if self.parameters.get('force_remove_fenced') is None:
                self.parameters['force_remove_fenced'] = False

        # REST API for application/applications if needed
        self.rest_app = self.setup_rest_application()

    def is_asa_r2_system(self):
        ''' checks if the given host is a ASA r2 system or not '''
        self.asa_r2_system = rest_ontap_personality.is_asa_r2_system(self.rest_api, self.module)

    def validate_params_asa_r2(self):
        if self.parameters.get('space_reserve') is not None:
            if not self.parameters['space_reserve']:
                self.module.warn("Ignoring 'space_reserve' as all LUNs are provisioned without a space reservation for ASA r2 system.")
            self.parameters.pop('space_reserve')
        if self.parameters.get('space_allocation') is not None:
            self.module.warn("Ignoring 'space_allocation' as all LUNs are provisioned with SCSI thin provisioning enabled for ASA r2 system.")
            self.parameters.pop('space_allocation')
        if self.parameters.get('flexvol_name') is not None:
            self.module.warn("Ignoring 'flexvol_name' as volumes are managed internally for ASA r2 system.")
            self.parameters.pop('flexvol_name')
        if self.parameters.get('san_application_template') is not None:
            self.module.warn("Ignoring 'san_application_template' for ASA r2 system.")
            self.parameters.pop('san_application_template')

    def setup_rest_application(self):
        use_application_template = self.na_helper.safe_get(self.parameters, ['san_application_template', 'use_san_application'])
        rest_app = None
        if self.use_rest:
            if use_application_template:
                if self.parameters.get('flexvol_name') is not None:
                    self.module.fail_json(msg="'flexvol_name' option is not supported when san_application_template is present")
                if self.parameters.get('qtree_name') is not None:
                    self.module.fail_json(msg="'qtree_name' option is not supported when san_application_template is present")
                name = self.na_helper.safe_get(self.parameters, ['san_application_template', 'name'], allow_sparse_dict=False)
                rest_app = RestApplication(self.rest_api, self.parameters['vserver'], name)
            elif self.parameters.get('flexvol_name') is None:
                if not self.asa_r2_system:
                    self.module.fail_json(msg="flexvol_name option is required when san_application_template is not present")
        else:
            if use_application_template:
                self.module.fail_json(msg="Error: using san_application_template requires ONTAP 9.7 or later and REST must be enabled.")
            if self.parameters.get('flexvol_name') is None:
                self.module.fail_json(msg="Error: 'flexvol_name' option is required when using ZAPI.")
        return rest_app

    def get_luns(self, lun_path=None):
        """
        Return list of LUNs matching vserver and volume names.

        :return: list of LUNs in XML format.
        :rtype: list
        """
        if self.use_rest:
            return self.get_luns_rest(lun_path)
        luns = []
        tag = None

        query_details = netapp_utils.zapi.NaElement('lun-info')
        query_details.add_new_child('vserver', self.parameters['vserver'])
        if lun_path is not None:
            query_details.add_new_child('lun_path', lun_path)
        else:
            query_details.add_new_child('volume', self.parameters['flexvol_name'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(query_details)

        while True:
            lun_info = netapp_utils.zapi.NaElement('lun-get-iter')
            lun_info.add_child_elem(query)
            if tag:
                lun_info.add_new_child('tag', tag, True)

            try:
                result = self.server.invoke_successfully(lun_info, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as exc:
                self.module.fail_json(msg="Error fetching luns for %s: %s" %
                                      (self.parameters['flexvol_name'] if lun_path is None else lun_path, to_native(exc)),
                                      exception=traceback.format_exc())

            if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
                attr_list = result.get_child_by_name('attributes-list')
                luns.extend(attr_list.get_children())
            tag = result.get_child_content('next-tag')
            if tag is None:
                break
        return luns

    def get_lun_details(self, lun):
        """
        Extract LUN details, from XML to python dict

        :return: Details about the lun
        :rtype: dict
        """
        if self.use_rest:
            return lun
        return_value = {'size': int(lun.get_child_content('size'))}
        bool_attr_map = {
            'is-space-alloc-enabled': 'space_allocation',
            'is-space-reservation-enabled': 'space_reserve'
        }
        for attr in bool_attr_map:
            value = lun.get_child_content(attr)
            if value is not None:
                return_value[bool_attr_map[attr]] = self.na_helper.get_value_for_bool(True, value)
        str_attr_map = {
            'comment': 'comment',
            'multiprotocol-type': 'os_type',
            'name': 'name',
            'path': 'path',
            'qos-policy-group': 'qos_policy_group',
            'qos-adaptive-policy-group': 'qos_adaptive_policy_group',
        }
        for attr in str_attr_map:
            value = lun.get_child_content(attr)
            if value is None and attr in ('comment', 'qos-policy-group', 'qos-adaptive-policy-group'):
                value = ''
            if value is not None:
                return_value[str_attr_map[attr]] = value

        return return_value

    def find_lun(self, luns, name, lun_path=None):
        """
        Return lun record matching name or path

        :return: lun record
        :rtype: XML for ZAPI, dict for REST, or None if not found
        """
        if luns:
            for lun in luns:
                path = lun['path']
                if lun_path is None:
                    if name == path:
                        return lun
                    _rest, _splitter, found_name = path.rpartition('/')
                    if found_name == name:
                        return lun
                elif lun_path == path:
                    return lun
        return None

    def get_lun_by_name(self, name):
        """
        Return details about the LUN by name for ASA r2 systems

        :return: Details about the lun
        :rtype: dict
        """
        api = 'storage/luns'
        query = {
            'name': name,
            'svm.name': self.parameters['vserver'],
            'fields': "comment,lun_maps,name,os_type,qos_policy.name,space,enabled"}
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        if error:
            self.module.fail_json(msg="Error getting lun %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if record:
            return {
                'uuid': self.na_helper.safe_get(record, ['uuid']),
                'name': self.na_helper.safe_get(record, ['name']),
                'path': self.na_helper.safe_get(record, ['name']),
                'size': self.na_helper.safe_get(record, ['space', 'size']),
                'comment': self.na_helper.safe_get(record, ['comment']),
                'os_type': self.na_helper.safe_get(record, ['os_type']),
                'qos_policy_group': self.na_helper.safe_get(record, ['qos_policy', 'name']),
                'space_reserve': self.na_helper.safe_get(record, ['space', 'guarantee', 'requested']),
                'space_allocation': self.na_helper.safe_get(record, ['space', 'scsi_thin_provisioning_support_enabled']),
            }
        return None

    def get_lun(self, name, lun_path=None):
        """
        Return details about the LUN

        :return: Details about the lun
        :rtype: dict
        """
        if self.asa_r2_system:
            return self.get_lun_by_name(name)
        luns = self.get_luns(lun_path)
        lun = self.find_lun(luns, name, lun_path)
        if lun is not None:
            return self.get_lun_details(lun)
        return None

    def get_luns_from_app(self):
        app_details, error = self.rest_app.get_application_details()
        self.fail_on_error(error)
        if app_details is not None:
            app_details['paths'] = self.get_lun_paths_from_app()
        return app_details

    def get_lun_paths_from_app(self):
        """Get luns path for SAN application"""
        backing_storage, error = self.rest_app.get_application_component_backing_storage()
        self.fail_on_error(error)
        # {'luns': [{'path': '/vol/ansibleLUN/ansibleLUN_1', ...
        if backing_storage is not None:
            return [lun['path'] for lun in backing_storage.get('luns', [])]
        return None

    def get_lun_path_from_backend(self, name):
        """returns lun path matching name if found in backing_storage
           retruns None if not found
        """
        lun_paths = self.get_lun_paths_from_app()
        match = "/%s" % name
        return next((path for path in lun_paths if path.endswith(match)), None)

    def create_san_app_component(self, modify):
        '''Create SAN application component'''
        if modify:
            required_options = ['name']
            action = 'modify'
            if 'lun_count' in modify:
                required_options.append('total_size')
        else:
            required_options = ('name', 'total_size')
            action = 'create'
        for option in required_options:
            if self.parameters.get(option) is None:
                self.module.fail_json(msg="Error: '%s' is required to %s a san application." % (option, action))

        application_component = dict(name=self.parameters['name'])
        if not modify:
            application_component['lun_count'] = 1  # default value for create, may be overriden below

        for attr in ('igroup_name', 'lun_count', 'storage_service'):
            if not modify or attr in modify:
                value = self.na_helper.safe_get(self.parameters, ['san_application_template', attr])
                if value is not None:
                    application_component[attr] = value
        for attr in ('os_type', 'qos_policy_group', 'qos_adaptive_policy_group', 'total_size'):
            if not self.rest_api.meets_rest_minimum_version(True, 9, 8, 0) and attr in (
                    'os_type',
                    'qos_policy_group',
                    'qos_adaptive_policy_group',
            ):
                # os_type and qos are not supported in 9.7 for the SAN application_component
                continue
            if not modify or attr in modify:
                value = self.na_helper.safe_get(self.parameters, [attr])
                if value is not None:
                    # only one of them can be present at most
                    if attr in ('qos_policy_group', 'qos_adaptive_policy_group'):
                        attr = 'qos'
                        value = dict(policy=dict(name=value))
                    application_component[attr] = value
        tiering = self.na_helper.safe_get(self.parameters, ['san_application_template', 'tiering'])
        if tiering is not None and not modify:
            application_component['tiering'] = {}
            for attr in ('control', 'policy', 'object_stores'):
                value = tiering.get(attr)
                if attr == 'object_stores' and value is not None:
                    value = [dict(name=x) for x in value]
                if value is not None:
                    application_component['tiering'][attr] = value
        return application_component

    def create_san_app_body(self, modify=None):
        '''Create body for san template'''
        # TODO:
        # Should we support new_igroups?
        # It may raise idempotency issues if the REST call fails if the igroup already exists.
        # And we already have na_ontap_igroups.
        san = {
            'application_components': [self.create_san_app_component(modify)],
        }
        for attr in ('protection_type',):
            if not modify or attr in modify:
                value = self.na_helper.safe_get(self.parameters, ['san_application_template', attr])
                if value is not None:
                    # we expect value to be a dict, but maybe an empty dict
                    value = self.na_helper.filter_out_none_entries(value)
                    if value:
                        san[attr] = value
        for attr in ('exclude_aggregates',):
            if modify is None:  # only used for create
                values = self.na_helper.safe_get(self.parameters, ['san_application_template', attr])
                if values:
                    san[attr] = [dict(name=name) for name in values]
        for attr in ('os_type',):
            if not modify:  # not supported for modify operation, but required at application component level for create
                value = self.na_helper.safe_get(self.parameters, [attr])
                if value is not None:
                    san[attr] = value
        body, error = self.rest_app.create_application_body('san', san)
        return body, error

    def create_san_application(self):
        '''Use REST application/applications san template to create one or more LUNs'''
        body, error = self.create_san_app_body()
        self.fail_on_error(error)
        dummy, error = self.rest_app.create_application(body)
        self.fail_on_error(error)

    def modify_san_application(self, modify):
        '''Use REST application/applications san template to add one or more LUNs'''
        body, error = self.create_san_app_body(modify)
        self.fail_on_error(error)
        # these cannot be present when using PATCH
        body.pop('name')
        body.pop('svm')
        body.pop('smart_container')
        dummy, error = self.rest_app.patch_application(body)
        self.fail_on_error(error)

    def convert_to_san_application(self, scope):
        '''First convert volume to smart container using POST
           Second modify app to add new luns using PATCH
        '''
        # dummy modify, so that we don't fill in the body
        modify = dict(dummy='dummy')
        body, error = self.create_san_app_body(modify)
        self.fail_on_error(error)
        dummy, error = self.rest_app.create_application(body)
        self.fail_on_error(error)
        app_current, error = self.rest_app.get_application_uuid()
        self.fail_on_error(error)
        if app_current is None:
            self.module.fail_json(msg='Error: failed to create smart container for %s' % self.parameters['name'])
        app_modify, app_modify_warning = self.app_changes(scope)
        if app_modify_warning is not None:
            self.module.warn(app_modify_warning)
        if app_modify:
            self.modify_san_application(app_modify)

    def delete_san_application(self):
        '''Use REST application/applications san template to delete one or more LUNs'''
        dummy, error = self.rest_app.delete_application()
        self.fail_on_error(error)

    def create_lun(self):
        """
        Create LUN with requested name and size
        """
        if self.use_rest:
            return self.create_lun_rest()
        path = '/vol/%s/%s' % (self.parameters['flexvol_name'], self.parameters['name'])
        options = {'path': path,
                   'size': str(self.parameters['size']),
                   'space-reservation-enabled': self.na_helper.get_value_for_bool(False, self.parameters['space_reserve']),
                   'use-exact-size': str(self.parameters['use_exact_size'])}
        if self.parameters.get('space_allocation') is not None:
            options['space-allocation-enabled'] = self.na_helper.get_value_for_bool(False, self.parameters['space_allocation'])
        if self.parameters.get('comment') is not None:
            options['comment'] = self.parameters['comment']
        if self.parameters.get('os_type') is not None:
            options['ostype'] = self.parameters['os_type']
        if self.parameters.get('qos_policy_group') is not None:
            options['qos-policy-group'] = self.parameters['qos_policy_group']
        if self.parameters.get('qos_adaptive_policy_group') is not None:
            options['qos-adaptive-policy-group'] = self.parameters['qos_adaptive_policy_group']
        lun_create = netapp_utils.zapi.NaElement.create_node_with_children(
            'lun-create-by-size', **options)

        try:
            self.server.invoke_successfully(lun_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as exc:
            self.module.fail_json(msg="Error provisioning lun %s of size %s: %s"
                                      % (self.parameters['name'], self.parameters['size'], to_native(exc)),
                                  exception=traceback.format_exc())

    def delete_lun(self, path):
        """
        Delete requested LUN
        """
        if self.use_rest:
            return self.delete_lun_rest()
        lun_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'lun-destroy', **{'path': path,
                              'force': str(self.parameters['force_remove']),
                              'destroy-fenced-lun':
                                  str(self.parameters['force_remove_fenced'])})

        try:
            self.server.invoke_successfully(lun_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as exc:
            self.module.fail_json(msg="Error deleting lun %s: %s" % (path, to_native(exc)),
                                  exception=traceback.format_exc())

    def resize_lun(self, path):
        """
        Resize requested LUN

        :return: True if LUN was actually re-sized, false otherwise.
        :rtype: bool
        """
        if self.use_rest:
            return self.resize_lun_rest()
        lun_resize = netapp_utils.zapi.NaElement.create_node_with_children(
            'lun-resize', **{'path': path,
                             'size': str(self.parameters['size']),
                             'force': str(self.parameters['force_resize'])})
        try:
            self.server.invoke_successfully(lun_resize, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as exc:
            if to_native(exc.code) == "9042":
                # Error 9042 denotes the new LUN size being the same as the
                # old LUN size. This happens when there's barely any difference
                # in the two sizes. For example, from 8388608 bytes to
                # 8194304 bytes. This should go away if/when the default size
                # requested/reported to/from the controller is changed to a
                # larger unit (MB/GB/TB).
                return False
            else:
                self.module.fail_json(msg="Error resizing lun %s: %s" % (path, to_native(exc)),
                                      exception=traceback.format_exc())

        return True

    def set_lun_value(self, path, key, value):
        key_to_zapi = dict(
            comment=('lun-set-comment', 'comment'),
            # The same ZAPI is used for both QOS attributes
            qos_policy_group=('lun-set-qos-policy-group', 'qos-policy-group'),
            qos_adaptive_policy_group=('lun-set-qos-policy-group', 'qos-adaptive-policy-group'),
            space_allocation=('lun-set-space-alloc', 'enable'),
            space_reserve=('lun-set-space-reservation-info', 'enable')
        )
        if key in key_to_zapi:
            zapi, option = key_to_zapi[key]
        else:
            self.module.fail_json(msg="option %s cannot be modified to %s" % (key, value))
        options = dict(path=path)
        if option == 'enable':
            options[option] = self.na_helper.get_value_for_bool(False, value)
        else:
            options[option] = value

        lun_set = netapp_utils.zapi.NaElement.create_node_with_children(zapi, **options)
        try:
            self.server.invoke_successfully(lun_set, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as exc:
            self.module.fail_json(msg="Error setting lun option %s: %s" % (key, to_native(exc)),
                                  exception=traceback.format_exc())
        return

    def modify_lun(self, path, modify):
        """
        update LUN properties (except size or name)
        """
        if self.use_rest:
            return self.modify_lun_rest(modify)
        for key in sorted(modify):
            self.set_lun_value(path, key, modify[key])

    def rename_lun(self, path, new_path):
        """
        rename LUN
        """
        if self.use_rest:
            return self.rename_lun_rest(new_path)
        lun_move = netapp_utils.zapi.NaElement.create_node_with_children(
            'lun-move', **{'path': path,
                           'new-path': new_path})
        try:
            self.server.invoke_successfully(lun_move, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as exc:
            self.module.fail_json(msg="Error moving lun %s: %s" % (path, to_native(exc)),
                                  exception=traceback.format_exc())

    def fail_on_error(self, error, stack=False):
        if error is None:
            return
        elements = dict(msg="Error: %s" % error)
        if stack:
            elements['stack'] = traceback.format_stack()
        self.module.fail_json(**elements)

    def set_total_size(self, validate):
        # fix total_size attribute, report error if total_size is missing (or size is missing)
        attr = 'total_size'
        value = self.na_helper.safe_get(self.parameters, ['san_application_template', attr])
        if value is not None or not validate:
            self.parameters[attr] = value
            return
        lun_count = self.na_helper.safe_get(self.parameters, ['san_application_template', 'lun_count'])
        value = self.parameters.get('size')
        if value is not None and (lun_count is None or lun_count == 1):
            self.parameters[attr] = value
            return
        self.module.fail_json(msg="Error: 'total_size' is a required SAN application template attribute when creating a LUN application")

    def validate_app_create(self):
        # fix total_size attribute
        self.set_total_size(validate=True)

    def validate_app_changes(self, modify, warning):
        saved_modify = dict(modify)
        errors = [
            "Error: the following application parameter cannot be modified: %s.  Received: %s."
            % (key, str(modify))
            for key in modify
            if key not in ('igroup_name', 'os_type', 'lun_count', 'total_size')
        ]

        extra_attrs = tuple()
        if 'lun_count' in modify:
            extra_attrs = ('total_size', 'os_type', 'igroup_name')
        else:
            ignored_keys = [key for key in modify if key not in ('total_size',)]
            for key in ignored_keys:
                self.module.warn(
                    "Ignoring: %s.  This application parameter is only relevant when increasing the LUN count.  Received: %s."
                    % (key, str(saved_modify)))
                modify.pop(key)
        for attr in extra_attrs:
            value = self.parameters.get(attr)
            if value is None:
                value = self.na_helper.safe_get(self.parameters['san_application_template'], [attr])
            if value is None:
                errors.append('Error: %s is a required parameter when increasing lun_count.' % attr)
            else:
                modify[attr] = value
        if errors:
            self.module.fail_json(msg='\n'.join(errors))
        if 'total_size' in modify:
            self.set_total_size(validate=False)
            if warning and 'lun_count' not in modify:
                # can't change total_size, let's ignore it
                self.module.warn(warning)
                modify.pop('total_size')
                saved_modify.pop('total_size')
        if modify and not self.rest_api.meets_rest_minimum_version(True, 9, 8):
            self.module.fail_json(
                msg='Error: modifying %s is not supported on ONTAP 9.7' % ', '.join(saved_modify.keys()))

    def fail_on_large_size_reduction(self, app_current, desired, provisioned_size):
        """ Error if a reduction of size > 10% is requested.
            Warn for smaller reduction and ignore it, to protect against 'rounding' errors.
        """
        total_size = app_current['total_size']
        desired_size = desired.get('total_size')
        warning = None
        if desired_size is not None:
            details = "total_size=%d, provisioned=%d, requested=%d" % (total_size, provisioned_size, desired_size)
            if desired_size < total_size:
                # * 100 to get a percentage, and .0 to force float conversion
                reduction = round((total_size - desired_size) * 100.0 / total_size, 1)
                if reduction > 10:
                    self.module.fail_json(msg="Error: can't reduce size: %s" % details)
                else:
                    warning = "Ignoring small reduction (%.1f %%) in total size: %s" % (reduction, details)
            elif desired_size > total_size and desired_size < provisioned_size:
                # we can't increase, but we can't say it is a problem, as the size is already bigger!
                warning = "Ignoring increase: requested size is too small: %s" % details
        return warning

    def get_luns_rest(self, lun_path=None):
        if lun_path is None and self.parameters.get('flexvol_name') is None:
            return []
        api = 'storage/luns'
        query = {
            'svm.name': self.parameters['vserver'],
            'fields': "comment,lun_maps,name,os_type,qos_policy.name,space"}
        if lun_path is not None:
            query['name'] = lun_path
        else:
            query['location.volume.name'] = self.parameters['flexvol_name']
            if self.parameters.get('qtree_name') is not None:
                query['location.qtree.name'] = self.parameters['qtree_name']
        record, error = rest_generic.get_0_or_more_records(self.rest_api, api, query)
        if error:
            if lun_path is not None:
                self.module.fail_json(msg="Error getting lun_path %s: %s" % (lun_path, to_native(error)),
                                      exception=traceback.format_exc())
            else:
                self.module.fail_json(
                    msg="Error getting LUN's for flexvol %s: %s" % (self.parameters['flexvol_name'], to_native(error)),
                    exception=traceback.format_exc())
        return self.format_get_luns(record)

    def format_get_luns(self, records):
        luns = []
        if not records:
            return None
        for record in records:
            # TODO: Check that path and name are the same in Rest
            lun = {
                'uuid': self.na_helper.safe_get(record, ['uuid']),
                'name': self.na_helper.safe_get(record, ['name']),
                'path': self.na_helper.safe_get(record, ['name']),
                'size': self.na_helper.safe_get(record, ['space', 'size']),
                'comment': self.na_helper.safe_get(record, ['comment']),
                'flexvol_name': self.na_helper.safe_get(record, ['location', 'volume', 'name']),
                'os_type': self.na_helper.safe_get(record, ['os_type']),
                'qos_policy_group': self.na_helper.safe_get(record, ['qos_policy', 'name']),
                'space_reserve': self.na_helper.safe_get(record, ['space', 'guarantee', 'requested']),
                'space_allocation': self.na_helper.safe_get(record,
                                                            ['space', 'scsi_thin_provisioning_support_enabled']),
            }
            luns.append(lun)
        return luns

    def create_lun_rest(self):
        name = self.parameters['name'] if self.asa_r2_system else self.create_lun_path_rest()
        api = 'storage/luns'
        body = {
            'svm.name': self.parameters['vserver'],
            'name': name,
        }
        if self.parameters.get('flexvol_name') is not None:
            body['location.volume.name'] = self.parameters['flexvol_name']
        if self.parameters.get('qtree_name') is not None:
            body['location.qtree.name'] = self.parameters['qtree_name']
        if self.parameters.get('os_type') is not None:
            body['os_type'] = self.parameters['os_type']
        if self.parameters.get('size') is not None:
            body['space.size'] = self.parameters['size']
        if self.parameters.get('space_reserve') is not None:
            if not self.asa_r2_system:
                body['space.guarantee.requested'] = self.parameters['space_reserve']
        if self.parameters.get('space_allocation') is not None:
            body['space.scsi_thin_provisioning_support_enabled'] = self.parameters['space_allocation']
        if self.parameters.get('comment') is not None:
            body['comment'] = self.parameters['comment']
        if self.parameters.get('qos_policy_group') is not None:
            body['qos_policy.name'] = self.parameters['qos_policy_group']
        if self.parameters.get('provisioning_options') is not None:
            body['provisioning_options'] = self.na_helper.filter_out_none_entries(self.parameters.get('provisioning_options'))
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg="Error creating LUN %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def create_lun_path_rest(self):
        """ ZAPI accepts just a name, while REST expects a path. We need to convert a name in to a path for backward compatibility
            If the name start with a slash we will assume it a path and use it as the name
        """
        if not self.parameters['name'].startswith('/') and self.parameters.get('flexvol_name') is not None:
            # if it dosn't start with a slash we will use flexvol name and/or qtree name to build the path
            if self.parameters.get('qtree_name') is not None:
                return '/vol/%s/%s/%s' % (self.parameters['flexvol_name'], self.parameters['qtree_name'], self.parameters['name'])
            return '/vol/%s/%s' % (self.parameters['flexvol_name'], self.parameters['name'])
        return self.parameters['name']

    def delete_lun_rest(self):
        if self.uuid is None:
            self.module.fail_json(msg="Error deleting LUN %s: UUID not found" % self.parameters['name'])
        api = 'storage/luns'
        query = {'allow_delete_while_mapped': self.parameters['force_remove']}
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.uuid, query)
        if error:
            self.module.fail_json(msg="Error deleting LUN %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def rename_lun_rest(self, new_path):
        if self.uuid is None:
            self.module.fail_json(msg="Error renaming LUN %s: UUID not found" % self.parameters['name'])
        api = 'storage/luns'
        body = {'name': new_path}
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
        if error:
            self.module.fail_json(msg="Error renaming LUN %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def resize_lun_rest(self):
        if self.uuid is None:
            self.module.fail_json(msg="Error resizing LUN %s: UUID not found" % self.parameters['name'])
        api = 'storage/luns'
        body = {'space.size': self.parameters['size']}
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
        if error:
            if 'New LUN size is the same as the old LUN size' in error:
                return False
            self.module.fail_json(msg="Error resizing LUN %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        return True

    def modify_lun_rest(self, modify):
        local_modify = modify.copy()
        if self.uuid is None:
            self.module.fail_json(msg="Error modifying LUN %s: UUID not found" % self.parameters['name'])
        api = 'storage/luns'
        body = {}
        if local_modify.get('space_reserve') is not None:
            body['space.guarantee.requested'] = local_modify.pop('space_reserve')
        if local_modify.get('space_allocation') is not None:
            body['space.scsi_thin_provisioning_support_enabled'] = local_modify.pop('space_allocation')
        if local_modify.get('comment') is not None:
            body['comment'] = local_modify.pop('comment')
        if local_modify.get('qos_policy_group') is not None:
            body['qos_policy.name'] = local_modify.pop('qos_policy_group')
        if local_modify != {}:
            self.module.fail_json(
                msg="Error modifying LUN %s: Unknown parameters: %s" % (self.parameters['name'], local_modify))
        dummy, error = rest_generic.patch_async(self.rest_api, api, self.uuid, body)
        if error:
            self.module.fail_json(msg="Error modifying LUN %s: %s" % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def check_for_errors(self, lun_cd_action, current, modify):
        errors = []
        if lun_cd_action == 'create':
            if self.parameters.get('flexvol_name') is None:
                if self.use_rest and not self.asa_r2_system:
                    errors.append("The flexvol_name parameter is required for creating a LUN.")
            if self.use_rest and self.parameters.get('os_type') is None:
                errors.append("The os_type parameter is required for creating a LUN with REST.")
            if self.parameters.get('size') is None:
                self.module.fail_json(msg="size is a required parameter for create.")
        elif modify and 'os_type' in modify:
            self.module.fail_json(msg="os_type cannot be modified: current: %s, desired: %s" % (current['os_type'], modify['os_type']))
        if errors:
            self.module.fail_json(msg=' '.join(errors))

    def set_uuid(self, current):
        if self.use_rest and current is not None and current.get('uuid') is not None:
            self.uuid = current['uuid']

    def app_changes(self, scope):
        # find and validate app changes
        app_current, error = self.rest_app.get_application_details('san')
        self.fail_on_error(error)
        # save application name, as it is overriden in the flattening operation
        app_name = app_current['name']
        # there is an issue with total_size not reflecting the real total_size, and some additional overhead
        provisioned_size = self.na_helper.safe_get(app_current, ['statistics', 'space', 'provisioned'])
        if provisioned_size is None:
            provisioned_size = 0
        if self.debug:
            self.debug['app_current'] = app_current  # will be updated below as it is mutable
            self.debug['got'] = copy.deepcopy(app_current)  # fixed copy
        # flatten
        app_current = app_current['san']  # app template
        app_current.update(app_current['application_components'][0])  # app component
        del app_current['application_components']
        # if component name does not match, assume a change at LUN level
        comp_name = app_current['name']
        if comp_name != self.parameters['name']:
            msg = "desired component/volume name: %s does not match existing component name: %s" % (self.parameters['name'], comp_name)
            if scope == 'application':
                self.module.fail_json(msg='Error: ' + msg + ".  scope=%s" % scope)
            return None, msg + ".  scope=%s, assuming 'lun' scope." % scope
        # restore app name
        app_current['name'] = app_name

        # ready to compare, except for a quirk in size handling
        desired = dict(self.parameters['san_application_template'])
        warning = self.fail_on_large_size_reduction(app_current, desired, provisioned_size)

        # preserve change state before calling modify in case an ignorable total_size change is the only change
        changed = self.na_helper.changed
        app_modify = self.na_helper.get_modified_attributes(app_current, desired)
        self.validate_app_changes(app_modify, warning)
        if not app_modify:
            self.na_helper.changed = changed
            app_modify = None
        return app_modify, None

    def get_app_apply(self):
        scope = self.na_helper.safe_get(self.parameters, ['san_application_template', 'scope'])
        app_current, error = self.rest_app.get_application_uuid()
        self.fail_on_error(error)
        if scope == 'lun' and app_current is None:
            self.module.fail_json(msg='Application not found: %s.  scope=%s.' %
                                      (self.na_helper.safe_get(self.parameters, ['san_application_template', 'name']),
                                       scope))
        return scope, app_current

    def app_actions(self, app_current, scope, actions, results):
        app_modify, app_modify_warning = None, None
        app_cd_action = self.na_helper.get_cd_action(app_current, self.parameters)
        if app_cd_action == 'create':
            # check if target volume already exists
            cp_volume_name = self.parameters['name']
            volume, error = rest_volume.get_volume(self.rest_api, self.parameters['vserver'], cp_volume_name)
            self.fail_on_error(error)
            if volume is not None:
                if scope == 'application':
                    # volume already exists, but not as part of this application
                    app_cd_action = 'convert'
                    if not self.rest_api.meets_rest_minimum_version(True, 9, 8, 0):
                        msg = 'Error: converting a LUN volume to a SAN application container requires ONTAP 9.8 or better.'
                        self.module.fail_json(msg=msg)
                else:
                    # default name already in use, ask user to clarify intent
                    msg = "Error: volume '%s' already exists.  Please use a different group name, or use 'application' scope.  scope=%s"
                    self.module.fail_json(msg=msg % (cp_volume_name, scope))
        if app_cd_action is not None:
            actions.append('app_%s' % app_cd_action)
        if app_cd_action == 'create':
            self.validate_app_create()
        if app_cd_action is None and app_current is not None:
            app_modify, app_modify_warning = self.app_changes(scope)
            if app_modify:
                actions.append('app_modify')
                results['app_modify'] = dict(app_modify)
        return app_cd_action, app_modify, app_modify_warning

    def lun_actions(self, app_current, actions, results, scope, app_modify, app_modify_warning):
        # actions at LUN level
        lun_cd_action, lun_modify, lun_rename = None, None, None
        lun_path, from_lun_path = None, None
        from_name = self.parameters.get('from_name')
        if self.rest_app and app_current:
            # For LUNs created using a SAN application, we're getting lun paths from the backing storage
            lun_path = self.get_lun_path_from_backend(self.parameters['name'])
            if from_name is not None:
                from_lun_path = self.get_lun_path_from_backend(from_name)
        current = self.get_lun(self.parameters['name'], lun_path)
        self.set_uuid(current)
        if current is not None and lun_path is None:
            lun_path = current['path']
        lun_cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if lun_cd_action == 'create' and from_name is not None:
            # create by renaming existing LUN, if it exists
            old_lun = self.get_lun(from_name, from_lun_path)
            lun_rename = self.na_helper.is_rename_action(old_lun, current)
            if lun_rename is None:
                self.module.fail_json(msg="Error renaming lun: %s does not exist" % from_name)
            if lun_rename:
                current = old_lun
                if from_lun_path is None:
                    from_lun_path = current['path']
                head, _sep, tail = from_lun_path.rpartition(from_name)
                if tail:
                    self.module.fail_json(
                        msg="Error renaming lun: %s does not match lun_path %s" % (from_name, from_lun_path))
                self.set_uuid(current)
                lun_path = head + self.parameters['name']
                lun_cd_action = None
                actions.append('lun_rename')
                app_modify_warning = None  # reset warning as we found a match
        if lun_cd_action is not None:
            actions.append('lun_%s' % lun_cd_action)
        if lun_cd_action is None and self.parameters['state'] == 'present':
            # we already handled rename if required
            current.pop('name', None)
            lun_modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if lun_modify:
                actions.append('lun_modify')
                results['lun_modify'] = dict(lun_modify)
                app_modify_warning = None  # reset warning as we found a match
        if lun_cd_action and self.rest_app and app_current:
            msg = 'This module does not support %s a LUN by name %s a SAN application.' % \
                  ('adding', 'to') if lun_cd_action == 'create' else ('removing', 'from')
            if scope == 'auto':
                # ignore LUN not found, as name can be a group name
                self.module.warn(msg + ".  scope=%s, assuming 'application'" % scope)
                if not app_modify:
                    self.na_helper.changed = False
            elif scope == 'lun':
                self.module.fail_json(msg=msg + ".  scope=%s." % scope)
            lun_cd_action = None
        self.check_for_errors(lun_cd_action, current, lun_modify)
        return lun_path, from_lun_path, lun_cd_action, lun_rename, lun_modify, app_modify_warning

    def lun_modify_after_app_update(self, lun_path, results):
        # modify at LUN level, as app modify does not set some LUN level options (eg space_reserve)
        if lun_path is None:
            lun_path = self.get_lun_path_from_backend(self.parameters['name'])
        current = self.get_lun(self.parameters['name'], lun_path)
        self.set_uuid(current)
        # we already handled rename if required
        current.pop('name', None)
        lun_modify = self.na_helper.get_modified_attributes(current, self.parameters)
        if lun_modify:
            results['lun_modify_after_app_update'] = dict(lun_modify)
        self.check_for_errors(None, current, lun_modify)
        return lun_modify

    def apply(self):
        results = {}
        app_cd_action, app_modify, lun_cd_action, lun_modify, lun_rename = None, None, None, None, None
        app_modify_warning, app_current, lun_path, from_lun_path = None, None, None, None
        actions = []
        if self.rest_app:
            scope, app_current = self.get_app_apply()
        else:
            # no application template, fall back to LUN only
            scope = 'lun'
        if self.rest_app and scope != 'lun':
            app_cd_action, app_modify, app_modify_warning = self.app_actions(app_current, scope, actions, results)
        if app_cd_action is None and scope != 'application':
            lun_path, from_lun_path, lun_cd_action, lun_rename, lun_modify, app_modify_warning = \
                self.lun_actions(app_current, actions, results, scope, app_modify, app_modify_warning)
        if self.na_helper.changed and not self.module.check_mode:
            if app_cd_action == 'create':
                self.create_san_application()
            elif app_cd_action == 'convert':
                self.convert_to_san_application(scope)
            elif app_cd_action == 'delete':
                self.rest_app.delete_application()
            elif lun_cd_action == 'create':
                self.create_lun()
            elif lun_cd_action == 'delete':
                self.delete_lun(lun_path)
            else:
                if app_modify:
                    self.modify_san_application(app_modify)
                if lun_rename:
                    self.rename_lun(from_lun_path, lun_path)
                if app_modify:
                    # space_reserve will be set to True
                    # To match input parameters, lun_modify is recomputed.
                    lun_modify = self.lun_modify_after_app_update(lun_path, results)
                size_changed = False
                if lun_modify and 'size' in lun_modify:
                    # Ensure that size was actually changed. Please
                    # read notes in 'resize_lun' function for details.
                    size_changed = self.resize_lun(lun_path)
                    lun_modify.pop('size')
                if lun_modify:
                    self.modify_lun(lun_path, lun_modify)
                if not lun_modify and not lun_rename and not app_modify:
                    # size may not have changed
                    self.na_helper.changed = size_changed

        if app_modify_warning:
            self.module.warn(app_modify_warning)
        result = netapp_utils.generate_result(self.na_helper.changed, actions,
                                              extra_responses={'debug': self.debug} if self.debug else None)
        self.module.exit_json(**result)


def main():
    lun = NetAppOntapLUN()
    lun.apply()


if __name__ == '__main__':
    main()
