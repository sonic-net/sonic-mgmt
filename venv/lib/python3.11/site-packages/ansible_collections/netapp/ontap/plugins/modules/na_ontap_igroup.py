#!/usr/bin/python
''' na_ontap_igroup

 (c) 2018-2025, NetApp, Inc
 # GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''

module: na_ontap_igroup
short_description: NetApp ONTAP iSCSI or FC igroup configuration
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Create/Delete/Rename Igroups and Modify initiators belonging to an igroup

options:
  state:
    description:
      - Whether the specified Igroup should exist or not.
    choices: ['present', 'absent']
    type: str
    default: present

  name:
    description:
      - The name of the igroup to manage.
    required: true
    type: str

  initiator_group_type:
    description:
      - Type of the initiator group.
      - Required when C(state=present).
    choices: ['fcp', 'iscsi', 'mixed']
    type: str
    aliases: ['protocol']

  from_name:
    description:
      - Name of igroup to rename to name.
    version_added: 2.7.0
    type: str

  os_type:
    description:
      - OS type of the initiators within the group.
    type: str
    aliases: ['ostype']

  igroups:
    description:
      - List of igroups to be mapped to the igroup.
      - For a modify operation, this list replaces the existing igroups, or existing initiators.
      - This module does not add or remove specific igroup(s) in an igroup.
      - Mutually exclusive with initiator_names (initiators) and initiator_objects.
      - Requires ONTAP 9.9 or newer.
    type: list
    elements: str
    version_added: 21.3.0

  initiator_names:
    description:
      - List of initiators to be mapped to the igroup.
      - WWPN, WWPN Alias, or iSCSI name of Initiator to add or remove.
      - For a modify operation, this list replaces the existing initiators, or existing igroups.
      - This module does not add or remove specific initiator(s) in an igroup.
      - Mutually exclusive with igroups and initiator_objects.
      - This serves the same purpose as initiator_objects, but without the comment suboption.
    aliases:
      - initiator
      - initiators
    type: list
    elements: str
    version_added: 21.4.0

  initiator_objects:
    description:
      - List of initiators to be mapped to the igroup, with an optional comment field.
      - WWPN, WWPN Alias, or iSCSI name of Initiator to add or remove.
      - For a modify operation, this list replaces the existing initiators, or existing igroups.
      - This module does not add or remove specific initiator(s) in an igroup.
      - Mutually exclusive with initiator_names (initiators) and igroups.
      - Requires ONTAP 9.9 with REST support.
    type: list
    elements: dict
    suboptions:
      name:
        description: name of the initiator.
        type: str
        required: true
      comment:
        description: a more descriptive comment as the WWPN can be quite opaque.
        type: str
    version_added: 21.4.0

  bind_portset:
    description:
      - Name of a current portset to bind to the newly created igroup.
    type: str

  force_remove_initiator:
    description:
      - Forcibly remove the initiator even if there are existing LUNs mapped to this initiator group.
      - This parameter should be used with caution.
    type: bool
    default: false
    aliases: ['allow_delete_while_mapped']

  vserver:
    description:
    - The name of the vserver to use.
    required: true
    type: str

notes:
  - supports check mode.
  - supports ZAPI and REST.
'''

EXAMPLES = '''
- name: Create iSCSI Igroup
  netapp.ontap.na_ontap_igroup:
    state: present
    name: ansibleIgroup3
    initiator_group_type: iscsi
    os_type: linux
    initiator_names: iqn.1994-05.com.redhat:scspa0395855001.rtp.openenglab.netapp.com,abc.com:redhat.com
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create iSCSI Igroup - ONTAP 9.9
  netapp.ontap.na_ontap_igroup:
    state: present
    name: ansibleIgroup3
    initiator_group_type: iscsi
    os_type: linux
    initiator_objects:
      - name: iqn.1994-05.com.redhat:scspa0395855001.rtp.openenglab.netapp.com
        comment: for test only
      - name: abc.com:redhat.com
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Create FC Igroup
  netapp.ontap.na_ontap_igroup:
    state: present
    name: ansibleIgroup4
    initiator_group_type: fcp
    os_type: linux
    initiator_names: 20:00:00:50:56:9f:19:82
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Rename Igroup
  netapp.ontap.na_ontap_igroup:
    state: present
    from_name: ansibleIgroup3
    name: testexamplenewname
    initiator_group_type: iscsi
    os_type: linux
    initiator_names: iqn.1994-05.com.redhat:scspa0395855001.rtp.openenglab.netapp.com
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Modify Igroup Initiators (replaces exisiting initiator_names)
  netapp.ontap.na_ontap_igroup:
    state: present
    name: ansibleIgroup3
    initiator_group_type: iscsi
    os_type: linux
    initiator: iqn.1994-05.com.redhat:scspa0395855001.rtp.openenglab.netapp.com
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete Igroup
  netapp.ontap.na_ontap_igroup:
    state: absent
    name: ansibleIgroup3
    vserver: ansibleVServer
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
'''

RETURN = '''
'''

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapIgroup:
    """Create/Delete/Rename Igroups and Modify initiators list"""
    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            from_name=dict(required=False, type='str', default=None),
            os_type=dict(required=False, type='str', aliases=['ostype']),
            igroups=dict(required=False, type='list', elements='str'),
            initiator_group_type=dict(required=False, type='str',
                                      choices=['fcp', 'iscsi', 'mixed'],
                                      aliases=['protocol']),
            initiator_names=dict(required=False, type='list', elements='str', aliases=['initiator', 'initiators']),
            initiator_objects=dict(required=False, type='list', elements='dict', options=dict(
                name=dict(required=True, type='str'),
                comment=dict(type='str'),
            )),
            vserver=dict(required=True, type='str'),
            force_remove_initiator=dict(required=False, type='bool', default=False, aliases=['allow_delete_while_mapped']),
            bind_portset=dict(required=False, type='str')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
            mutually_exclusive=[('igroups', 'initiator_names'), ('igroups', 'initiator_objects'), ('initiator_objects', 'initiator_names'), ]
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_modify_zapi_to_rest = dict(
            # initiator_group_type (protocol) cannot be changed after create
            bind_portset='portset',
            name='name',
            os_type='os_type'
        )

        self.rest_api = OntapRestAPI(self.module)
        self.use_rest = self.rest_api.is_rest()

        # use the new structure, a list of dict with name/comment as keys.
        if self.parameters.get('initiator_names') is not None:
            self.parameters['initiator_objects'] = [
                dict(name=initiator, comment=None)
                for initiator in self.parameters['initiator_names']]

        if self.parameters.get('initiator_objects') is not None:
            ontap_99_option = 'comment'
            if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9) and\
               any(x[ontap_99_option] is not None for x in self.parameters['initiator_objects']):
                msg = 'Error: in initiator_objects: %s' % self.rest_api.options_require_ontap_version(ontap_99_option, version='9.9', use_rest=self.use_rest)
                self.module.fail_json(msg=msg)
            # sanitize WWNs and convert to lowercase for idempotency
            self.parameters['initiator_objects'] = [
                dict(name=self.na_helper.sanitize_wwn(initiator['name']), comment=initiator['comment'])
                for initiator in self.parameters['initiator_objects']]
            # keep a list of names as it is convenient for add and remove computations
            self.parameters['initiator_names'] = [initiator['name'] for initiator in self.parameters['initiator_objects']]

        def too_old_for_rest(minimum_generation, minimum_major):
            return self.use_rest and not self.rest_api.meets_rest_minimum_version(self.use_rest, minimum_generation, minimum_major, 0)

        ontap_99_options = ['bind_portset']
        if too_old_for_rest(9, 9) and any(x in self.parameters for x in ontap_99_options):
            self.module.warn('Warning: falling back to ZAPI: %s' % self.rest_api.options_require_ontap_version(ontap_99_options, version='9.9'))
            self.use_rest = False

        ontap_99_options = ['igroups']
        if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 1) and any(x in self.parameters for x in ontap_99_options):
            self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version(ontap_99_options, version='9.9.1'))

        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 1):
            if 'igroups' in self.parameters:
                # we may need to remove existing initiators
                self.parameters['initiator_names'] = list()
            elif 'initiator_names' in self.parameters:
                # we may need to remove existing igroups
                self.parameters['igroups'] = list()

        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def fail_on_error(self, error, stack=False):
        if error is None:
            return
        elements = dict(msg="Error: %s" % error)
        if stack:
            elements['stack'] = traceback.format_stack()
        self.module.fail_json(**elements)

    def get_igroup_rest(self, name):
        api = "protocols/san/igroups"
        fields = 'name,uuid,svm,initiators,os_type,protocol'
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 1):
            fields += ',igroups'
        query = dict(name=name, fields=fields)
        query['svm.name'] = self.parameters['vserver']
        record, error = rest_generic.get_one_record(self.rest_api, api, query)
        self.fail_on_error(error)
        if record:
            try:
                igroup_details = dict(
                    name=record['name'],
                    uuid=record['uuid'],
                    vserver=record['svm']['name'],
                    os_type=record['os_type'],
                    initiator_group_type=record['protocol'],
                    name_to_uuid=dict()
                )
            except KeyError as exc:
                self.module.fail_json(msg='Error: unexpected igroup body: %s, KeyError on %s' % (str(record), str(exc)))
            igroup_details['name_to_key'] = {}
            for attr in ('igroups', 'initiators'):
                option = 'initiator_names' if attr == 'initiators' else attr
                if attr in record:
                    igroup_details[option] = [item['name'] for item in record[attr]]
                    if attr == 'initiators':
                        igroup_details['initiator_objects'] = [dict(name=item['name'], comment=item.get('comment')) for item in record[attr]]
                    # for initiators, there is no uuid, so we're using name as the key
                    igroup_details['name_to_uuid'][option] = dict((item['name'], item.get('uuid', item['name'])) for item in record[attr])
                else:
                    igroup_details[option] = []
                    igroup_details['name_to_uuid'][option] = {}
            return igroup_details
        return None

    def get_igroup(self, name):
        """
        Return details about the igroup
        :param:
            name : Name of the igroup

        :return: Details about the igroup. None if not found.
        :rtype: dict
        """
        if self.use_rest:
            return self.get_igroup_rest(name)

        igroup_info = netapp_utils.zapi.NaElement('igroup-get-iter')
        attributes = dict(query={'initiator-group-info': {'initiator-group-name': name,
                                                          'vserver': self.parameters['vserver']}})
        igroup_info.translate_struct(attributes)
        current = None

        try:
            result = self.server.invoke_successfully(igroup_info, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching igroup info %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
            igroup_info = result.get_child_by_name('attributes-list')
            initiator_group_info = igroup_info.get_child_by_name('initiator-group-info')
            initiator_names = []
            initiator_objects = []
            if initiator_group_info.get_child_by_name('initiators'):
                current_initiators = initiator_group_info['initiators'].get_children()
                initiator_names = [initiator['initiator-name'] for initiator in current_initiators]
                initiator_objects = [dict(name=initiator['initiator-name'], comment=None) for initiator in current_initiators]
            current = {
                'initiator_names': initiator_names,
                'initiator_objects': initiator_objects,
                # place holder, not used for ZAPI
                'name_to_uuid': dict(initiator_names=dict())
            }
            zapi_to_params = {
                'vserver': 'vserver',
                'initiator-group-os-type': 'os_type',
                'initiator-group-portset-name': 'bind_portset',
                'initiator-group-type': 'initiator_group_type'
            }
            for attr in zapi_to_params:
                value = igroup_info.get_child_content(attr)
                if value is not None:
                    current[zapi_to_params[attr]] = value
        return current

    def check_option_is_valid(self, option):
        if self.use_rest and option in ('igroups', 'initiator_names'):
            return
        if option == 'initiator_names':
            return
        raise KeyError('check_option_is_valid: option=%s' % option)

    @staticmethod
    def get_rest_name_for_option(option):
        if option == 'initiator_names':
            return 'initiators'
        if option == 'igroups':
            return option
        raise KeyError('get_rest_name_for_option: option=%s' % option)

    def add_initiators_or_igroups_rest(self, uuid, option, names):
        self.check_option_is_valid(option)
        api = "protocols/san/igroups/%s/%s" % (uuid, self.get_rest_name_for_option(option))
        if option == 'initiator_names' and self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 1):
            in_objects = self.parameters['initiator_objects']
            records = [self.na_helper.filter_out_none_entries(item) for item in in_objects if item['name'] in names]
        else:
            records = [dict(name=name) for name in names]
        body = dict(records=records)
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        self.fail_on_error(error)

    def modify_initiators_rest(self, uuid, initiator_objects):
        for initiator in initiator_objects:
            if 'comment' in initiator:
                api = "protocols/san/igroups/%s/initiators" % uuid
                body = dict(comment=initiator['comment'])
                dummy, error = rest_generic.patch_async(self.rest_api, api, initiator['name'], body)
                self.fail_on_error(error)

    def add_initiators_or_igroups(self, uuid, option, current_names):
        """
        Add the list of desired initiators to igroup unless they are already set
        :return: None
        """
        self.check_option_is_valid(option)
        # don't add if initiator_names/igroups is empty string
        if self.parameters.get(option) == [''] or self.parameters.get(option) is None:
            return
        names_to_add = [name for name in self.parameters[option] if name not in current_names]
        if self.use_rest and names_to_add:
            self.add_initiators_or_igroups_rest(uuid, option, names_to_add)
        else:
            for name in names_to_add:
                self.modify_initiator(name, 'igroup-add')

    def delete_initiator_or_igroup_rest(self, uuid, option, name_or_uuid):
        self.check_option_is_valid(option)
        api = "protocols/san/igroups/%s/%s" % (uuid, self.get_rest_name_for_option(option))
        query = {'allow_delete_while_mapped': True} if self.parameters['force_remove_initiator'] else None
        dummy, error = rest_generic.delete_async(self.rest_api, api, name_or_uuid, query=query)
        self.fail_on_error(error)

    def remove_initiators_or_igroups(self, uuid, option, current_names, mapping):
        """
        Removes current names from igroup unless they are still desired
        :return: None
        """
        self.check_option_is_valid(option)
        for name in current_names:
            if name not in self.parameters.get(option, list()):
                if self.use_rest:
                    self.delete_initiator_or_igroup_rest(uuid, option, mapping[name])
                else:
                    self.modify_initiator(name, 'igroup-remove')

    def modify_initiator(self, initiator, zapi):
        """
        Add or remove an initiator to/from an igroup
        """
        options = {'initiator-group-name': self.parameters['name'],
                   'initiator': initiator}
        if zapi == 'igroup-remove' and self.parameters.get('force_remove_initiator'):
            options['force'] = 'true'

        igroup_modify = netapp_utils.zapi.NaElement.create_node_with_children(zapi, **options)

        try:
            self.server.invoke_successfully(igroup_modify, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying igroup initiator %s: %s' % (self.parameters['name'],
                                                                                   to_native(error)),
                                  exception=traceback.format_exc())

    def create_igroup_rest(self):
        api = "protocols/san/igroups"
        body = dict(
            name=self.parameters['name'],
            os_type=self.parameters['os_type'])
        body['svm'] = dict(name=self.parameters['vserver'])
        mapping = dict(
            initiator_group_type='protocol',
            bind_portset='portset',
            igroups='igroups',
            initiator_objects='initiators'
        )
        for option in mapping:
            value = self.parameters.get(option)
            if value is not None:
                if option in ('igroups', 'initiator_objects'):
                    # we may have an empty list, ignore it
                    if option == 'initiator_objects':
                        value = [self.na_helper.filter_out_none_entries(item) for item in value] if value else None
                    else:
                        value = [dict(name=name) for name in value] if value else None
                if value is not None:
                    body[mapping[option]] = value
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        self.fail_on_error(error)

    def create_igroup(self):
        """
        Create the igroup.
        """
        if self.use_rest:
            return self.create_igroup_rest()

        options = {'initiator-group-name': self.parameters['name']}
        if self.parameters.get('os_type') is not None:
            options['os-type'] = self.parameters['os_type']
        if self.parameters.get('initiator_group_type') is not None:
            options['initiator-group-type'] = self.parameters['initiator_group_type']
        if self.parameters.get('bind_portset') is not None:
            options['bind-portset'] = self.parameters['bind_portset']

        igroup_create = netapp_utils.zapi.NaElement.create_node_with_children(
            'igroup-create', **options)

        try:
            self.server.invoke_successfully(igroup_create,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error provisioning igroup %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())
        self.add_initiators_or_igroups(None, 'initiator_names', [])

    @staticmethod
    def change_in_initiator_comments(modify, current):

        if 'initiator_objects' not in current:
            return list()

        # for python 2.6
        comments = dict((item['name'], item['comment']) for item in current['initiator_objects'])

        def has_changed_comment(item):
            return item['name'] in comments and item['comment'] is not None and item['comment'] != comments[item['name']]

        return [item for item in modify['initiator_objects'] if has_changed_comment(item)]

    def modify_igroup_rest(self, uuid, modify):
        api = "protocols/san/igroups"
        body = dict()
        for option in modify:
            if option not in self.rest_modify_zapi_to_rest:
                self.module.fail_json(msg='Error: modifying %s is not supported in REST' % option)
            body[self.rest_modify_zapi_to_rest[option]] = modify[option]
        if body:
            dummy, error = rest_generic.patch_async(self.rest_api, api, uuid, body)
            self.fail_on_error(error)

    def delete_igroup_rest(self, uuid):
        api = "protocols/san/igroups"
        query = {'allow_delete_while_mapped': True} if self.parameters['force_remove_initiator'] else None
        dummy, error = rest_generic.delete_async(self.rest_api, api, uuid, query=query)
        self.fail_on_error(error)

    def delete_igroup(self, uuid):
        """
        Delete the igroup.
        """
        if self.use_rest:
            return self.delete_igroup_rest(uuid)

        igroup_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'igroup-destroy', **{'initiator-group-name': self.parameters['name'],
                                 'force': 'true' if self.parameters['force_remove_initiator'] else 'false'})

        try:
            self.server.invoke_successfully(igroup_delete,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting igroup %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def rename_igroup(self):
        """
        Rename the igroup.
        """
        if self.use_rest:
            self.module.fail_json(msg='Internal error, should not call rename, but use modify')

        igroup_rename = netapp_utils.zapi.NaElement.create_node_with_children(
            'igroup-rename', **{'initiator-group-name': self.parameters['from_name'],
                                'initiator-group-new-name': str(self.parameters['name'])})
        try:
            self.server.invoke_successfully(igroup_rename,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error renaming igroup %s: %s' % (self.parameters['name'], to_native(error)),
                                  exception=traceback.format_exc())

    def report_error_in_modify(self, modify, context):
        if modify:
            if len(modify) > 1:
                tag = 'any of '
            else:
                tag = ''
            self.module.fail_json(msg='Error: modifying %s %s is not supported in %s' % (tag, str(modify), context))

    def validate_modify(self, modify):
        """Identify options that cannot be modified for REST or ZAPI
        """
        if not modify:
            return
        modify_local = dict(modify)
        modify_local.pop('igroups', None)
        modify_local.pop('initiator_names', None)
        modify_local.pop('initiator_objects', None)
        if not self.use_rest:
            self.report_error_in_modify(modify_local, 'ZAPI')
            return
        for option in modify:
            if option in self.rest_modify_zapi_to_rest:
                modify_local.pop(option)
        self.report_error_in_modify(modify_local, 'REST')

    def is_rename_action(self, cd_action, current):
        old = self.get_igroup(self.parameters['from_name'])
        rename = self.na_helper.is_rename_action(old, current)
        if rename is None:
            self.module.fail_json(msg='Error: igroup with from_name=%s not found' % self.parameters.get('from_name'))
        if rename:
            current = old
            cd_action = None
        return cd_action, rename, current

    def modify_igroup(self, uuid, current, modify):
        for attr in ('igroups', 'initiator_names'):
            if attr in current:
                # we need to remove everything first
                self.remove_initiators_or_igroups(uuid, attr, current[attr], current['name_to_uuid'][attr])
        for attr in ('igroups', 'initiator_names'):
            if attr in current:
                self.add_initiators_or_igroups(uuid, attr, current[attr])
            modify.pop(attr, None)
        if 'initiator_objects' in modify:
            if self.use_rest:
                # comments are not supported in ZAPI, we already checked for that in validate changes
                changed_initiator_objects = self.change_in_initiator_comments(modify, current)
                self.modify_initiators_rest(uuid, changed_initiator_objects)
            modify.pop('initiator_objects',)
        if modify:
            # validate_modify ensured modify is empty with ZAPI
            self.modify_igroup_rest(uuid, modify)

    def apply(self):
        uuid = None
        rename, modify = None, None
        current = self.get_igroup(self.parameters['name'])
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'create' and self.parameters.get('from_name'):
            cd_action, rename, current = self.is_rename_action(cd_action, current)
        if cd_action is None and self.parameters['state'] == 'present':
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            # a change in name is handled in rename for ZAPI, but REST can use modify
            if self.use_rest:
                rename = False
            else:
                modify.pop('name', None)
        if current and self.use_rest:
            uuid = current['uuid']
        if cd_action == 'create' and self.use_rest and 'os_type' not in self.parameters:
            self.module.fail_json(msg='Error: os_type is a required parameter when creating an igroup with REST')
        saved_modify = str(modify)
        self.validate_modify(modify)

        if self.na_helper.changed and not self.module.check_mode:
            if rename:
                self.rename_igroup()
            elif cd_action == 'create':
                self.create_igroup()
            elif cd_action == 'delete':
                self.delete_igroup(uuid)
            if modify:
                self.modify_igroup(uuid, current, modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify=saved_modify)
        self.module.exit_json(**result)


def main():
    obj = NetAppOntapIgroup()
    obj.apply()


if __name__ == '__main__':
    main()
