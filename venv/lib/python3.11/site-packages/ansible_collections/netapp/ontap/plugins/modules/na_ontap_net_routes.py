#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_net_routes
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: na_ontap_net_routes
short_description: NetApp ONTAP network routes
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Modify ONTAP network routes.
options:
  state:
    description:
      - Whether you want to create or delete a network route.
    choices: ['present', 'absent']
    type: str
    default: present
  vserver:
    description:
      - The name of the vserver.
      - Required when using ZAPI.
      - When using REST, omit this parameter for cluster scoped routes, or set it to NULL.
    type: str
  destination:
    description:
      - Specify the route destination.
      - Example 10.7.125.5/20, fd20:13::/64.
    required: true
    type: str
  gateway:
    description:
      - Specify the route gateway.
      - Example 10.7.125.1, fd20:13::1.
    required: true
    type: str
  metric:
    description:
      - Specify the route metric.  If this field is not provided, ONTAP will default to 20.
      - Supported from ONTAP 9.11.0 in REST.
      - With REST, trying to modify destination or gateway will also reset metric to 20 in ONTAP 9.10.1 or earlier.
    type: int
  from_destination:
    description:
      - Specify the route destination that should be changed.
    version_added: 2.8.0
    type: str
  from_gateway:
    description:
      - Specify the route gateway that should be changed.
    version_added: 2.8.0
    type: str
  from_metric:
    description:
      - Specify the route metric that should be changed.
      - This parameter is ignored, as the value is read from ONTAP.
      - Not supported with REST, ignored with ZAPI.
    version_added: 2.8.0
    type: int
'''

EXAMPLES = """
- name: Create route
  netapp.ontap.na_ontap_net_routes:
    state: present
    vserver: "{{ vserver_name }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    destination: 10.7.125.5/20
    gateway: 10.7.125.1
    metric: 30

- name: Create route - cluster scope, using REST
  netapp.ontap.na_ontap_net_routes:
    state: present
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    destination: 10.7.125.5/20
    gateway: 10.7.125.1

- name: Create route - vserver scope, using REST
  netapp.ontap.na_ontap_net_routes:
    state: present
    vserver: "{{ vserver_name }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    hostname: "{{ netapp_hostname }}"
    destination: 10.7.125.5/20
    gateway: 10.7.125.1
"""

RETURN = """

"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppOntapNetRoutes:
    """
    Create, Modifies and Destroys a Net Route
    """

    def __init__(self):
        """
        Initialize the Ontap Net Route class
        """
        self.use_rest = False
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            vserver=dict(required=False, type='str'),
            destination=dict(required=True, type='str'),
            gateway=dict(required=True, type='str'),
            metric=dict(required=False, type='int'),
            from_destination=dict(required=False, type='str', default=None),
            from_gateway=dict(required=False, type='str', default=None),
            from_metric=dict(required=False, type='int', default=None),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = netapp_utils.OntapRestAPI(self.module)

        # metric supported from ONTAP 9.11.0 version.
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, ['from_metric'], [['metric', (9, 11, 0)]])
        self.validate_options()
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])

    def validate_options(self):
        errors = []
        example = ''
        if not self.use_rest and 'vserver' not in self.parameters:
            # self.module.fail_json(msg="Error: vserver is a required parameter when using ZAPI")
            errors.append("vserver is a required parameter when using ZAPI")
        for attr in ('destination', 'from_destination'):
            value = self.parameters.get(attr)
            if value is not None and '/' not in value:
                errors.append("Expecting '/' in '%s'" % value)
                example = 'Examples: 10.7.125.5/20, fd20:13::/64'
        if errors:
            if example:
                errors.append(example)
            self.module.fail_json(msg="Error: %s." % '.  '.join(errors))

    @staticmethod
    def sanitize_exception(action, exc):
        if action == 'create' and to_native(exc.code) == '13001' and 'already exists' in to_native(exc.message):
            return None
        if action == 'get' and to_native(exc.code) == "15661":
            # Error 15661 denotes a route doesn't exist.
            return None
        return to_native(exc)

    def create_net_route(self, current=None, fail=True):
        """
        Creates a new Route
        """
        if current is None:
            current = self.parameters
        if self.use_rest:
            api = 'network/ip/routes'
            body = {'gateway': current['gateway']}
            dest = current['destination']
            if isinstance(dest, dict):
                body['destination'] = dest
            else:
                dest = current['destination'].split('/')
                body['destination'] = {'address': dest[0], 'netmask': dest[1]}
            if current.get('vserver') is not None:
                body['svm.name'] = current['vserver']
            if current.get('metric') is not None:
                body['metric'] = current['metric']
            __, error = rest_generic.post_async(self.rest_api, api, body)
        else:
            route_obj = netapp_utils.zapi.NaElement('net-routes-create')
            route_obj.add_new_child("destination", current['destination'])
            route_obj.add_new_child("gateway", current['gateway'])
            metric = current.get('metric')
            if metric is not None:
                route_obj.add_new_child("metric", str(metric))
            try:
                self.server.invoke_successfully(route_obj, True)
                error = None
            except netapp_utils.zapi.NaApiError as exc:
                # return if desired route already exists
                error = self.sanitize_exception('create', exc)
        if error:
            error = 'Error creating net route: %s' % error
            if fail:
                self.module.fail_json(msg=error)
        return error

    def delete_net_route(self, current):
        """
        Deletes a given Route
        """
        if self.use_rest:
            uuid = current['uuid']
            api = 'network/ip/routes'
            dummy, error = rest_generic.delete_async(self.rest_api, api, uuid)
            if error:
                self.module.fail_json(msg='Error deleting net route - %s' % error)
        else:
            route_obj = netapp_utils.zapi.NaElement('net-routes-destroy')
            route_obj.add_new_child("destination", current['destination'])
            route_obj.add_new_child("gateway", current['gateway'])
            try:
                self.server.invoke_successfully(route_obj, True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error deleting net route: %s'
                                      % (to_native(error)),
                                      exception=traceback.format_exc())

    def recreate_net_route(self, current):
        """
        Modify a net route
        Since we cannot modify a route, we are deleting the existing route, and creating a new one.
        """
        self.delete_net_route(current)
        # use existing metric if not specified
        if current.get('metric') is not None and self.parameters.get('metric') is None:
            self.parameters['metric'] = current['metric']
        error = self.create_net_route(fail=False)
        if error:
            # restore the old route, create the route with the existing values
            self.create_net_route(current)
            # Invalid value specified for any of the attributes
            self.module.fail_json(msg='Error modifying net route: %s' % error,
                                  exception=traceback.format_exc())

    def get_net_route(self, params=None):
        """
        Checks to see if a route exist or not
        :return: NaElement object if a route exists, None otherwise
        """
        if params is None:
            params = self.parameters
        if self.use_rest:
            api = "network/ip/routes"
            fields = 'destination,gateway,svm,scope'
            if self.parameters.get('metric') is not None:
                fields += ',metric'
            query = {'destination.address': params['destination'].split('/')[0],
                     'gateway': params['gateway']}
            if params.get('vserver') is None:
                query['scope'] = 'cluster'
            else:
                query['scope'] = 'svm'
                query['svm.name'] = params['vserver']
            record, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
            if error:
                self.module.fail_json(msg='Error fetching net route: %s' % error)
            # even if metric not set, 20 is set by default.
            if record and 'metric' not in record:
                record['metric'] = None
            return record
        else:
            route_obj = netapp_utils.zapi.NaElement('net-routes-get')
            for attr in ('destination', 'gateway'):
                route_obj.add_new_child(attr, params[attr])
            try:
                result = self.server.invoke_successfully(route_obj, True)
            except netapp_utils.zapi.NaApiError as exc:
                # Error 15661 denotes a route doesn't exist.
                error = self.sanitize_exception('get', exc)
                if error is None:
                    return None
                self.module.fail_json(msg='Error fetching net route: %s' % error,
                                      exception=traceback.format_exc())
            if result.get_child_by_name('attributes') is not None:
                route_info = result.get_child_by_name('attributes').get_child_by_name('net-vs-routes-info')
                return {
                    'destination': route_info.get_child_content('destination'),
                    'gateway': route_info.get_child_content('gateway'),
                    'metric': int(route_info.get_child_content('metric'))
                }
            return None

    def apply(self):
        """
        Run Module based on play book
        """
        modify, rename = False, False
        current = self.get_net_route()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action == 'create' and any(self.parameters.get(attr) is not None for attr in ('from_gateway', 'from_destination')):
            # create by renaming existing route if it exists
            # destination and gateway combination is unique, and is considered like an id.
            # So modify destination or gateway is considered a rename action.
            # If one of 'destination', 'gateway' is not in the from field, use the desired value.
            from_params = {'gateway': self.parameters.get('from_gateway', self.parameters['gateway']),
                           'destination': self.parameters.get('from_destination', self.parameters['destination'])}
            if self.parameters.get('vserver'):
                from_params['vserver'] = self.parameters['vserver']
            current = self.get_net_route(from_params)
            if current is None:
                self.module.fail_json(msg="Error modifying: route %s does not exist" % self.parameters['from_destination'])
            rename = True
            cd_action = None

        if cd_action is None and self.parameters.get('metric') is not None and current:
            modify = self.parameters['metric'] != current['metric']
            if modify:
                self.na_helper.changed = True

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_net_route()
            elif cd_action == 'delete':
                self.delete_net_route(current)
            elif rename or modify:
                self.recreate_net_route(current)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify, extra_responses={'rename': rename})
        self.module.exit_json(**result)


def main():
    """
    Creates the NetApp Ontap Net Route object and runs the correct play task
    """
    obj = NetAppOntapNetRoutes()
    obj.apply()


if __name__ == '__main__':
    main()
