#!/usr/bin/python
'''
# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}

DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Call a REST API on ONTAP.
  - Cluster REST API are run using a cluster admin account.
  - Vserver REST API can be run using a vsadmin account or using vserver tunneling (cluster admin with I(vserver_) options).
  - In case of success, a json dictionary is returned as C(response).
  - In case of a REST API error, C(status_code), C(error_code), C(error_message) are set to help with diagnosing the issue,
  - and the call is reported as an error ('failed').
  - Other errors (eg connection issues) are reported as Ansible error.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap_rest
module: na_ontap_restit
short_description: NetApp ONTAP Run any REST API on ONTAP
version_added: "20.4.0"
options:
  api:
    description:
      - The REST API to call (eg I(cluster/software), I(svms/svm)).
    required: true
    type: str
  method:
    description:
      - The REST method to use.
    default: GET
    type: str
  query:
    description:
      - A list of dictionaries for the query parameters
    type: dict
  body:
    description:
      - A dictionary for the info parameter
    type: dict
    aliases: ['info']
  vserver_name:
    description:
      - if provided, forces vserver tunneling.  username identifies a cluster admin account.
    type: str
  vserver_uuid:
    description:
      - if provided, forces vserver tunneling.  username identifies a cluster admin account.
    type: str
  hal_linking:
    description:
      - if true, HAL-encoded links are returned in the response.
    default: false
    type: bool
  wait_for_completion:
    description:
      - when true, POST/PATCH/DELETE can be handled synchronously and asynchronously.
      - if the response indicates that a job is in progress, the job status is checked periodically until is completes.
      - when false, the call returns immediately.
    type: bool
    default: false
    version_added: 21.14.0
  files:
    description:
      - A dictionary for the parameters when using multipart/form-data.
      - This is very infrequently needed, but required to write a file (see examples)
      - When present, requests will automatically set the Content-Type header to multipart/form-data.
    type: dict
    version_added: 21.24.0
  accept_header:
    description:
      - Value for the Accept request HTTP header.
      - This is very infrequently needed, but required to read a file (see examples).
      - For most cases, omit this field.  Set it to "multipart/form-data" when expecting such a format.
      - By default the module is using "application/json" or "application/hal+json" when hal_linking is true.
    type: str
    version_added: 21.24.0
'''

EXAMPLES = """
-
  name: Ontap REST API
  hosts: localhost
  gather_facts: false
  vars:
    login: &login
      hostname: "{{ admin_ip }}"
      username: "{{ admin_username }}"
      password: "{{ admin_password }}"
      https: true
      validate_certs: false
    svm_login: &svm_login
      hostname: "{{ svm_admin_ip }}"
      username: "{{ svm_admin_username }}"
      password: "{{ svm_admin_password }}"
      https: true
      validate_certs: false

  tasks:
    - name: Run ontap REST API command as cluster admin
      netapp.ontap.na_ontap_restit:
        <<: *login
        api: cluster/software
      register: result
    - name: Assertions
      ansible.builtin.assert:
        that: result.status_code==200
        quiet: true

    - name: Run ontap REST API command as cluster admin
      netapp.ontap.na_ontap_restit:
        <<: *login
        api: cluster/software
        query:
          fields: version
      register: result
    - name: Assertions
      ansible.builtin.assert:
        that: result.status_code==200
        quiet: true

    - name: Run ontap REST API command as cluster admin
      netapp.ontap.na_ontap_restit:
        <<: *login
        api: svm/svms
      register: result
    - name: Assertions
      ansible.builtin.assert:
        that: result.status_code==200
        quiet: true

    - name: Run ontap REST API command as cluster admin
      netapp.ontap.na_ontap_restit:
        <<: *login
        api: svm/svms
        query:
          fields: aggregates,cifs,nfs,uuid
          query_fields: name
          query: trident_svm
        hal_linking: true
      register: result

    - name: Run ontap REST API command as vsadmin
      netapp.ontap.na_ontap_restit:
        <<: *svm_login
        api: svm/svms
      register: result
    - name: Assertions
      ansible.builtin.assert:
        that: result.status_code==200
        quiet: true

    - name: Run ontap REST API command as vserver tunneling
      netapp.ontap.na_ontap_restit:
        <<: *login
        api: storage/volumes
        vserver_name: ansibleSVM
      register: result
    - name: Assertions
      ansible.builtin.assert:
        that: result.status_code==200
        quiet: true
    - name: Store UUID
      ansible.builtin.set_fact:
        uuid: "{{ result.response.records | json_query(get_uuid) }}"
      vars:
        get_uuid: "[? name=='deleteme_ln1'].uuid"

    - name: Run ontap REST API command as DELETE method with vserver tunneling
      netapp.ontap.na_ontap_restit:
        <<: *login
        api: "storage/volumes/{{ uuid[0] }}"
        method: DELETE
        vserver_name: ansibleSVM
        query:
          return_timeout: 60
      register: result
      when: uuid | length == 1
    - name: Assertions
      ansible.builtin.assert:
        that: result.skipped | default(false) or result.status_code | default(404) == 200
        quiet: true

    - name: Run ontap REST API command as POST method with vserver tunneling
      netapp.ontap.na_ontap_restit:
        <<: *login
        api: storage/volumes
        method: POST
        vserver_name: ansibleSVM
        query:
          return_records: "true"
          return_timeout: 60
        body:
          name: deleteme_ln1
          aggregates:
            - name: aggr1
      register: result
    - name: Assertions
      ansible.builtin.assert:
        that: result.status_code==201
        quiet: true

    - name: Run ontap REST API command as DELETE method with vserver tunneling
      # delete test volume if present
      netapp.ontap.na_ontap_restit:
        <<: *login
        api: "storage/volumes/{{ result.response.records[0].uuid }}"
        method: DELETE
        vserver_name: ansibleSVM
        query:
          return_timeout: 60
      register: result
    - name: Assertions
      ansible.builtin.assert:
        that: result.status_code==200
        quiet: true

    - name: Create a file
      # assuming credentials are set using module_defaults
      netapp.ontap.na_ontap_restit:
        api: storage/volumes/f3c003cb-2974-11ed-b2f8-005056b38dae/files/laurent123.txt
        method: post
        files:
          data: 'some data'

    - name: Read a file
      # assuming credentials are set using module_defaults
      netapp.ontap.na_ontap_restit:
        api: storage/volumes/f3c003cb-2974-11ed-b2f8-005056b38dae/files/laurent123.txt
        method: get
        accept_header: "multipart/form-data"
        query:
          length: 100

    # error cases
    - name: Run ontap REST API command
      netapp.ontap.na_ontap_restit:
        <<: *login
        api: unknown/endpoint
      register: result
      ignore_errors: true
    - name: Assertions
      ansible.builtin.assert:
        that: result.status_code==404
        quiet: true
"""

RETURN = """
response:
  description:
    - If successful, a json dictionary returned by the REST API.
    - If the REST API was executed but failed, an empty dictionary.
    - Not present if the REST API call cannot be performed.
  returned: On success
  type: dict
status_code:
  description:
    - The http status code.
    - When wait_for_completion is True, this is forced to 0.
  returned: Always
  type: str
error_code:
  description:
    - If the REST API was executed but failed, the error code set by the REST API.
    - Not present if successful, or if the REST API call cannot be performed.
  returned: On error
  type: str
error_message:
  description:
    - If the REST API was executed but failed, the error message set by the REST API.
    - Not present if successful, or if the REST API call cannot be performed.
  returned: On error
  type: str
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


class NetAppONTAPRestAPI(object):
    ''' calls a REST API command '''

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            api=dict(required=True, type='str'),
            method=dict(required=False, type='str', default='GET'),
            query=dict(required=False, type='dict'),
            body=dict(required=False, type='dict', aliases=['info']),
            vserver_name=dict(required=False, type='str'),
            vserver_uuid=dict(required=False, type='str'),
            hal_linking=dict(required=False, type='bool', default=False),
            wait_for_completion=dict(required=False, type='bool', default=False),
            # to support very infrequent form-data format
            files=dict(required=False, type='dict'),
            accept_header=dict(required=False, type='str'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        parameters = self.module.params
        # set up state variables
        self.api = parameters['api']
        self.method = parameters['method']
        self.query = parameters['query']
        self.body = parameters['body']
        self.vserver_name = parameters['vserver_name']
        self.vserver_uuid = parameters['vserver_uuid']
        self.hal_linking = parameters['hal_linking']
        self.wait_for_completion = parameters['wait_for_completion']
        self.files = parameters['files']
        self.accept_header = parameters['accept_header']

        self.rest_api = OntapRestAPI(self.module)

        if self.accept_header is None:
            self.accept_header = 'application/hal+json' if self.hal_linking else 'application/json'

    def build_headers(self):
        return self.rest_api.build_headers(accept=self.accept_header, vserver_name=self.vserver_name, vserver_uuid=self.vserver_uuid)

    def fail_on_error(self, status, response, error):
        if error:
            if isinstance(error, dict):
                error_message = error.pop('message', None)
                error_code = error.pop('code', None)
                if not error:
                    # we exhausted the dictionary
                    error = 'check error_message and error_code for details.'
            else:
                error_message = error
                error_code = None

            msg = "Error when calling '%s': %s" % (self.api, str(error))
            self.module.fail_json(msg=msg, status_code=status, response=response, error_message=error_message, error_code=error_code)

    def run_api(self):
        ''' calls the REST API '''
        # TODO, log usage
        status, response, error = self.rest_api.send_request(self.method, self.api, self.query, self.body, self.build_headers(), self.files)
        self.fail_on_error(status, response, error)

        return status, response

    def run_api_async(self):
        ''' calls the REST API '''
        # TODO, log usage

        args = [self.rest_api, self.api]
        kwargs = {}
        if self.method.upper() == 'POST':
            method = rest_generic.post_async
            kwargs['body'] = self.body
            kwargs['files'] = self.files
        elif self.method.upper() == 'PATCH':
            method = rest_generic.patch_async
            args.append(None)   # uuid should be provided in the API
            kwargs['body'] = self.body
            kwargs['files'] = self.files
        elif self.method.upper() == 'DELETE':
            method = rest_generic.delete_async
            args.append(None)   # uuid should be provided in the API
        else:
            self.module.warn('wait_for_completion ignored for %s method.' % self.method)
            return self.run_api()

        kwargs.update({
            'raw_error': True,
            'headers': self.build_headers()
        })
        if self.query:
            kwargs['query'] = self.query
        response, error = method(*args, **kwargs)
        self.fail_on_error(0, response, error)

        return 0, response

    def apply(self):
        ''' calls the api and returns json output '''
        changed_status = False if self.method.upper() == 'GET' else True

        if self.module.check_mode:
            status_code, response = None, {'check_mode': 'would run %s %s' % (self.method, self.api)}
        elif self.wait_for_completion:
            status_code, response = self.run_api_async()
        else:
            status_code, response = self.run_api()
        self.module.exit_json(changed=changed_status, status_code=status_code, response=response)


def main():
    """
    Execute action from playbook
    """
    restapi = NetAppONTAPRestAPI()
    restapi.apply()


if __name__ == '__main__':
    main()
