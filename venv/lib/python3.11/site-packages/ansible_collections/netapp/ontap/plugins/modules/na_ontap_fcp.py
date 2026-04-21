#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_fcp
short_description: NetApp ONTAP Start, Stop and Enable FCP services.
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.7.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
- Start, Stop and Enable FCP services.
options:
  state:
    description:
    - Whether the FCP should be enabled or not.
    choices: ['present', 'absent']
    type: str
    default: present

  status:
    description:
    - Whether the FCP should be up or down
    choices: ['up', 'down']
    type: str
    default: up

  vserver:
    description:
    - The name of the vserver to use.
    required: true
    type: str

'''

EXAMPLES = """
- name: Create FCP
  netapp.ontap.na_ontap_fcp:
    state: present
    status: down
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    vserver: "{{ vserver_name }}"
"""

RETURN = """

"""
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppOntapFCP:
    """
    Enable and Disable FCP
    """

    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=True, type='str'),
            status=dict(required=False, type='str', choices=['up', 'down'], default='up')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = OntapRestAPI(self.module)
        if self.rest_api.is_rest():
            self.use_rest = True
        elif HAS_NETAPP_LIB is False:
            self.module.fail_json(msg="the python NetApp-Lib module is required")
        else:
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def create_fcp(self):
        """
        Create's and Starts an FCP
        :return: none
        """
        try:
            self.server.invoke_successfully(netapp_utils.zapi.NaElement('fcp-service-create'), True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating FCP: %s' %
                                  (to_native(error)),
                                  exception=traceback.format_exc())

    def start_fcp(self):
        """
        Starts an existing FCP
        :return: none
        """
        try:
            self.server.invoke_successfully(netapp_utils.zapi.NaElement('fcp-service-start'), True)
        except netapp_utils.zapi.NaApiError as error:
            # Error 13013 denotes fcp service already started.
            if to_native(error.code) == "13013":
                return None
            else:
                self.module.fail_json(msg='Error starting FCP %s' % (to_native(error)),
                                      exception=traceback.format_exc())

    def stop_fcp(self):
        """
        Steps an Existing FCP
        :return: none
        """
        try:
            self.server.invoke_successfully(netapp_utils.zapi.NaElement('fcp-service-stop'), True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error Stoping FCP %s' %
                                      (to_native(error)),
                                  exception=traceback.format_exc())

    def destroy_fcp(self):
        """
        Destroys an already stopped FCP
        :return:
        """
        try:
            self.server.invoke_successfully(netapp_utils.zapi.NaElement('fcp-service-destroy'), True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error destroying FCP %s' %
                                      (to_native(error)),
                                  exception=traceback.format_exc())

    def get_fcp(self):
        if self.use_rest:
            return self.get_fcp_rest()
        fcp_obj = netapp_utils.zapi.NaElement('fcp-service-get-iter')
        fcp_info = netapp_utils.zapi.NaElement('fcp-service-info')
        fcp_info.add_new_child('vserver', self.parameters['vserver'])
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(fcp_info)
        fcp_obj.add_child_elem(query)
        result = self.server.invoke_successfully(fcp_obj, True)
        # There can only be 1 FCP per vserver. If true, one is set up, else one isn't set up
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) >= 1:
            return True
        else:
            return False

    def current_status(self):
        try:
            status = self.server.invoke_successfully(netapp_utils.zapi.NaElement('fcp-service-status'), True)
            return status.get_child_content('is-available') == 'true'
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error destroying FCP: %s' %
                                      (to_native(error)),
                                  exception=traceback.format_exc())

    def status_to_bool(self):
        return self.parameters['status'] == 'up'

    def get_fcp_rest(self):
        options = {'fields': 'enabled,svm.uuid',
                   'svm.name': self.parameters['vserver']}
        api = 'protocols/san/fcp/services'
        record, error = rest_generic.get_one_record(self.rest_api, api, options)
        if error:
            self.module.fail_json(msg="Error on fetching fcp: %s" % error)
        if record:
            record['status'] = 'up' if record.pop('enabled') else 'down'
        return record

    def create_fcp_rest(self):
        params = {'svm.name': self.parameters['vserver'],
                  'enabled': self.status_to_bool()}
        api = 'protocols/san/fcp/services'
        dummy, error = rest_generic.post_async(self.rest_api, api, params)
        if error is not None:
            self.module.fail_json(msg="Error on creating fcp: %s" % error)

    def destroy_fcp_rest(self, current):
        api = 'protocols/san/fcp/services'
        dummy, error = rest_generic.delete_async(self.rest_api, api, current['svm']['uuid'])
        if error is not None:
            self.module.fail_json(msg=" Error on deleting fcp policy: %s" % error)

    def start_stop_fcp_rest(self, enabled, current):
        params = {'enabled': enabled}
        api = 'protocols/san/fcp/services'
        dummy, error = rest_generic.patch_async(self.rest_api, api, current['svm']['uuid'], params)
        if error is not None:
            self.module.fail_json(msg="Error on modifying fcp: %s" % error)

    def zapi_apply(self, current):
        changed = False
        # this is a mess i don't want to touch...
        if self.parameters['state'] == 'present':
            if current:
                if self.parameters['status'] == 'up':
                    if not self.current_status():
                        if not self.module.check_mode:
                            self.start_fcp()
                        changed = True
                else:
                    if self.current_status():
                        if not self.module.check_mode:
                            self.stop_fcp()
                        changed = True
            else:
                if not self.module.check_mode:
                    self.create_fcp()
                    if self.parameters['status'] == 'up':
                        self.start_fcp()
                    elif self.parameters['status'] == 'down':
                        self.stop_fcp()
                changed = True
        else:
            if current:
                if not self.module.check_mode:
                    if self.current_status():
                        self.stop_fcp()
                    self.destroy_fcp()
                changed = True
        return changed

    def apply(self):
        current = self.get_fcp()
        if not self.use_rest:
            changed = self.zapi_apply(current)
            result = netapp_utils.generate_result(changed)
        else:
            cd_action = self.na_helper.get_cd_action(current, self.parameters)
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            changed = self.na_helper.changed
            if self.na_helper.changed and not self.module.check_mode:
                if cd_action == 'create':
                    self.create_fcp_rest()
                elif modify:
                    if modify['status'] == 'up':
                        self.start_stop_fcp_rest(True, current)
                    else:
                        self.start_stop_fcp_rest(False, current)
                elif cd_action == 'delete':
                    if current['status'] == 'up':
                        self.start_stop_fcp_rest(False, current)
                    self.destroy_fcp_rest(current)
            result = netapp_utils.generate_result(changed, cd_action, modify)
        self.module.exit_json(**result)


def main():
    """
    Start, Stop and Enable FCP services.
    """
    obj = NetAppOntapFCP()
    obj.apply()


if __name__ == '__main__':
    main()
