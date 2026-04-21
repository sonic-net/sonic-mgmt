#!/usr/bin/python

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_software_update
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Update ONTAP software
  - Requires an https connection and is not supported over http
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_software_update
options:
  state:
    choices: ['present', 'absent']
    description:
      - This module downloads and optionally installs ONTAP software on a cluster.
      - The software package is deleted after a successful installation.
      - If the software package is already present, it is not downloaded and not replaced.
      - When state is absent, the package is deleted from disk.
    default: present
    type: str
  https:
    description:
      - Enable and disable https.
    type: bool
    default: true
  nodes:
    description:
      - List of nodes to be updated, the nodes have to be a part of a HA Pair.
      - Requires ONTAP 9.9 with REST.
    aliases:
      - node
      - nodes_to_update
    type: list
    elements: str
  package_version:
    required: true
    description:
      - Specifies the package version to update ONTAP software to, or to be deleted.
    type: str
  package_url:
    type: str
    description:
      - Specifies the package URL to download the package.
      - Required when state is present unless the package is already present on disk.
  ignore_validation_warning:
    description:
      - Allows the update to continue if warnings are encountered during the validation phase.
    default: False
    type: bool
    aliases:
      - skip_warnings
  download_only:
    description:
      - Allows to download image without update.
    default: False
    type: bool
    version_added: 20.4.0
  validate_after_download:
    description:
      - By default validation is not run after download, as it is already done in the update step.
      - For MetroCluster systems, the C(download_only) parameter should be run first on one of the sites of the MetroCluster.
        After the job completes, update the other sites.
    default: False
    type: bool
    version_added: 21.11.0
  stabilize_minutes:
    description:
      - Number of minutes that the update should wait after a takeover or giveback is completed.
      - Requires ONTAP 9.8 with REST.
    type: int
    version_added: 20.6.0
  timeout:
    description:
      - how long to wait for the update to complete, in seconds.
    default: 1800
    type: int
  force_update:
    description:
      - force an update, even if package_version matches what is reported as installed.
    default: false
    type: bool
    version_added: 20.11.0
short_description: NetApp ONTAP Update Software
version_added: 2.7.0
notes:
  - ONTAP expects the nodes to be in HA pairs to perform non disruptive updates.
  - In a single node setup, the node is updated, and rebooted.
  - Supports ZAPI and REST.
  - Support check_mode.
'''

EXAMPLES = """
- name: start ONTAP software update Precheck on Metrocluster DR Site B
  netapp.ontap.na_ontap_software_update:
    state: present
    nodes: "{{ nodes }}"
    package_url: "{{ url }}"
    download_only: true
    validate_after_download: true
    package_version: "9.16.1P4"
    ignore_validation_warning: true
    timeout: 36000
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: start ONTAP software update on DR Site A
  netapp.ontap.na_ontap_software_update:
    state: present
    nodes: "{{ nodes }}"
    package_url: "{{ url }}"
    package_version: "9.16.1P4"
    ignore_validation_warning: true
    timeout: 36000
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """
validation_reports:
  description: C(validation_reports_after_update) as a string, for backward compatibility.
  returned: always
  type: str
validation_reports_after_download:
  description:
    - List of validation reports, after downloading the software package.
    - Note that it is different from the validation checks reported after attempting an update.
  returned: always
  type: list
validation_reports_after_updates:
  description:
    - List of validation reports, after attemting to update the software package.
  returned: always
  type: list
"""

import time
import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppONTAPSoftwareUpdate:
    """
    Class with ONTAP software update methods
    """

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            https=dict(required=False, type='bool', default=True),
            nodes=dict(required=False, type='list', elements='str', aliases=["node", "nodes_to_update"]),
            package_version=dict(required=True, type='str'),
            package_url=dict(required=False, type='str'),
            ignore_validation_warning=dict(required=False, type='bool', default=False, aliases=["skip_warnings"]),
            download_only=dict(required=False, type='bool', default=False),
            stabilize_minutes=dict(required=False, type='int'),
            timeout=dict(required=False, type='int', default=1800),
            force_update=dict(required=False, type='bool', default=False),
            validate_after_download=dict(required=False, type='bool', default=False),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if self.parameters.get('https') is not True:
            self.module.fail_json(msg='Error: https parameter must be True')
        self.validation_reports_after_download = ['only available if validate_after_download is true']
        self.versions = ['not available with force_update']
        self.rest_api = OntapRestAPI(self.module)
        partially_supported_rest_properties = [['stabilize_minutes', (9, 8)], ['nodes', (9, 9)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, None, partially_supported_rest_properties)
        if not self.use_rest:
            if netapp_utils.has_netapp_lib() is False:
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)

    @staticmethod
    def cluster_image_get_iter():
        """
        Compose NaElement object to query current version
        :return: NaElement object for cluster-image-get-iter with query
        """
        cluster_image_get = netapp_utils.zapi.NaElement('cluster-image-get-iter')
        query = netapp_utils.zapi.NaElement('query')
        cluster_image_info = netapp_utils.zapi.NaElement('cluster-image-info')
        query.add_child_elem(cluster_image_info)
        cluster_image_get.add_child_elem(query)
        return cluster_image_get

    def cluster_image_get_versions(self):
        """
        Get current cluster image versions for each node
        :return: list of tuples (node_id, node_version) or empty list
        """
        if self.use_rest:
            return self.cluster_image_get_rest('versions')
        cluster_image_get_iter = self.cluster_image_get_iter()
        try:
            result = self.server.invoke_successfully(cluster_image_get_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching cluster image details: %s: %s'
                                  % (self.parameters['package_version'], to_native(error)),
                                  exception=traceback.format_exc())
        return ([(image_info.get_child_content('node-id'), image_info.get_child_content('current-version'))
                 for image_info in result.get_child_by_name('attributes-list').get_children()]
                if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0 else [])

    def cluster_image_get_for_node(self, node_name):
        """
        Get current cluster image info for given node
        """
        cluster_image_get = netapp_utils.zapi.NaElement('cluster-image-get')
        cluster_image_get.add_new_child('node-id', node_name)
        try:
            result = self.server.invoke_successfully(cluster_image_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching cluster image details for %s: %s'
                                  % (node_name, to_native(error)),
                                  exception=traceback.format_exc())
        # return cluster image version
        image_info = self.na_helper.safe_get(result, ['attributes', 'cluster-image-info'])
        if image_info:
            return image_info.get_child_content('node-id'), image_info.get_child_content('current-version')
        return None, None

    @staticmethod
    def get_localname(tag):
        return netapp_utils.zapi.etree.QName(tag).localname

    def cluster_image_update_progress_get(self, ignore_connection_error=True):
        """
        Get current cluster image update progress info
        :return: Dictionary of cluster image update progress if query successful, else return None
        """
        cluster_update_progress_get = netapp_utils.zapi.NaElement('cluster-image-update-progress-info')
        cluster_update_progress_info = {}
        try:
            result = self.server.invoke_successfully(cluster_update_progress_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            # return empty dict on error to satisfy package delete upon image update
            if ignore_connection_error:
                return cluster_update_progress_info
            self.module.fail_json(msg='Error fetching cluster image update progress details: %s' % (to_native(error)),
                                  exception=traceback.format_exc())
        # return cluster image update progress details
        if result.get_child_by_name('attributes').get_child_by_name('ndu-progress-info'):
            update_progress_info = result.get_child_by_name('attributes').get_child_by_name('ndu-progress-info')
            cluster_update_progress_info['overall_status'] = update_progress_info.get_child_content('overall-status')
            cluster_update_progress_info['completed_node_count'] = update_progress_info.\
                get_child_content('completed-node-count')
            reports = update_progress_info.get_child_by_name('validation-reports')
            if reports:
                cluster_update_progress_info['validation_reports'] = []
                for report in reports.get_children():
                    checks = {}
                    for check in report.get_children():
                        checks[self.get_localname(check.get_name())] = check.get_content()
                    cluster_update_progress_info['validation_reports'].append(checks)
        return cluster_update_progress_info

    def cluster_image_update(self):
        """
        Update current cluster image
        """
        cluster_update_info = netapp_utils.zapi.NaElement('cluster-image-update')
        cluster_update_info.add_new_child('package-version', self.parameters['package_version'])
        cluster_update_info.add_new_child('ignore-validation-warning',
                                          str(self.parameters['ignore_validation_warning']))
        if self.parameters.get('stabilize_minutes'):
            cluster_update_info.add_new_child('stabilize-minutes',
                                              self.na_helper.get_value_for_int(False, self.parameters['stabilize_minutes']))
        if self.parameters.get('nodes'):
            cluster_nodes = netapp_utils.zapi.NaElement('nodes')
            for node in self.parameters['nodes']:
                cluster_nodes.add_new_child('node-name', node)
            cluster_update_info.add_child_elem(cluster_nodes)
        try:
            self.server.invoke_successfully(cluster_update_info, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            msg = 'Error updating cluster image for %s: %s' % (self.parameters['package_version'], to_native(error))
            cluster_update_progress_info = self.cluster_image_update_progress_get(ignore_connection_error=True)
            validation_reports = cluster_update_progress_info.get('validation_reports')
            if validation_reports is None:
                validation_reports = self.cluster_image_validate()
            self.module.fail_json(
                msg=msg,
                validation_reports=str(validation_reports),
                validation_reports_after_download=self.validation_reports_after_download,
                validation_reports_after_update=validation_reports,
                exception=traceback.format_exc())

    def cluster_image_package_download(self):
        """
        Get current cluster image package download
        :return: True if package already exists, else return False
        """
        cluster_image_package_download_info = netapp_utils.zapi.NaElement('cluster-image-package-download')
        cluster_image_package_download_info.add_new_child('package-url', self.parameters['package_url'])
        try:
            self.server.invoke_successfully(cluster_image_package_download_info, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            # Error 18408 denotes Package image with the same name already exists
            if to_native(error.code) == "18408":
                return self.check_for_existing_package(error)
            else:
                self.module.fail_json(msg='Error downloading cluster image package for %s: %s'
                                      % (self.parameters['package_url'], to_native(error)),
                                      exception=traceback.format_exc())
        return False

    def cluster_image_package_delete(self):
        """
        Delete current cluster image package
        """
        if self.use_rest:
            return self.cluster_image_package_delete_rest()
        cluster_image_package_delete_info = netapp_utils.zapi.NaElement('cluster-image-package-delete')
        cluster_image_package_delete_info.add_new_child('package-version', self.parameters['package_version'])
        try:
            self.server.invoke_successfully(cluster_image_package_delete_info, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting cluster image package for %s: %s'
                                  % (self.parameters['package_version'], to_native(error)),
                                  exception=traceback.format_exc())

    def cluster_image_package_download_progress(self):
        """
        Get current cluster image package download progress
        :return: Dictionary of cluster image download progress if query successful, else return None
        """
        cluster_image_package_download_progress_info = netapp_utils.zapi.\
            NaElement('cluster-image-get-download-progress')
        try:
            result = self.server.invoke_successfully(
                cluster_image_package_download_progress_info, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching cluster image package download progress for %s: %s'
                                  % (self.parameters['package_url'], to_native(error)),
                                  exception=traceback.format_exc())
        # return cluster image download progress details
        cluster_download_progress_info = {}
        if result.get_child_by_name('progress-status'):
            cluster_download_progress_info['progress_status'] = result.get_child_content('progress-status')
            cluster_download_progress_info['progress_details'] = result.get_child_content('progress-details')
            cluster_download_progress_info['failure_reason'] = result.get_child_content('failure-reason')
            return cluster_download_progress_info
        return None

    def cluster_image_validate(self):
        """
        Validate that NDU is feasible.
        :return: List of dictionaries
        """
        if self.use_rest:
            return self.cluster_image_validate_rest()
        cluster_image_validation_info = netapp_utils.zapi.NaElement('cluster-image-validate')
        cluster_image_validation_info.add_new_child('package-version', self.parameters['package_version'])
        try:
            result = self.server.invoke_successfully(
                cluster_image_validation_info, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            return 'Error running cluster image validate: %s' % to_native(error)
        # return cluster validation report
        cluster_report_info = []
        if result.get_child_by_name('cluster-image-validation-report-list'):
            for report in result.get_child_by_name('cluster-image-validation-report-list').get_children():
                info = self.na_helper.safe_get(report, ['required-action', 'required-action-info'])
                required_action = {}
                if info:
                    for action in info.get_children():
                        if action.get_content():
                            required_action[self.get_localname(action.get_name())] = action.get_content()
                cluster_report_info.append(dict(
                    ndu_check=report.get_child_content('ndu-check'),
                    ndu_status=report.get_child_content('ndu-status'),
                    required_action=required_action
                ))
        return cluster_report_info

    def is_update_required(self):
        ''' return True if at least one node is not at the correct version '''
        if self.parameters.get('nodes') and not self.use_rest:
            self.versions = [self.cluster_image_get_for_node(node) for node in self.parameters['nodes']]
        else:
            self.versions = self.cluster_image_get_versions()
        # set comnprehension not supported on 2.6
        current_versions = set([x[1] for x in self.versions])
        if len(current_versions) != 1:
            # mixed set, need to update
            return True
        # only update if versions differ
        return current_versions.pop() != self.parameters['package_version']

    def download_software(self):
        if self.use_rest:
            return self.download_software_rest()
        package_exists = self.cluster_image_package_download()
        if package_exists is False:
            cluster_download_progress = self.cluster_image_package_download_progress()
            while cluster_download_progress is None or cluster_download_progress.get('progress_status') == 'async_pkg_get_phase_running':
                time.sleep(10)
                cluster_download_progress = self.cluster_image_package_download_progress()
            if cluster_download_progress.get('progress_status') != 'async_pkg_get_phase_complete':
                self.module.fail_json(msg='Error downloading package: %s - installed versions: %s'
                                      % (cluster_download_progress['failure_reason'], self.versions))

    def update_software(self):
        if self.use_rest:
            return self.update_software_rest()
        self.cluster_image_update()
        # delete package once update is completed
        cluster_update_progress = {}
        time_left = self.parameters['timeout']
        polling_interval = 25
        # assume in_progress if dict is empty
        while time_left > 0 and cluster_update_progress.get('overall_status', 'in_progress') == 'in_progress':
            time.sleep(polling_interval)
            time_left -= polling_interval
            cluster_update_progress = self.cluster_image_update_progress_get(ignore_connection_error=True)

        if cluster_update_progress.get('overall_status') != 'completed':
            cluster_update_progress = self.cluster_image_update_progress_get(ignore_connection_error=False)

        validation_reports = cluster_update_progress.get('validation_reports')

        if cluster_update_progress.get('overall_status') == 'completed':
            self.cluster_image_package_delete()
            return validation_reports

        if cluster_update_progress.get('overall_status') == 'in_progress':
            msg = 'Timeout error'
            action = '  Should the timeout value be increased?  Current value is %d seconds.' % self.parameters['timeout']
            action += '  The software update continues in background.'
        else:
            msg = 'Error'
            action = ''
        msg += ' updating image using ZAPI: overall_status: %s.' % (cluster_update_progress.get('overall_status', 'cannot get status'))
        msg += action
        self.module.fail_json(
            msg=msg,
            validation_reports=str(validation_reports),
            validation_reports_after_download=self.validation_reports_after_download,
            validation_reports_after_update=validation_reports)

    def cluster_image_get_rest(self, what, fail_on_error=True):
        """return field information for:
            - nodes if what == versions
            - validation_results if what == validation_results
            - state if what == state
            - any other field if what is a valid field name
           call fail_json when there is an error and fail_on_error is True
           return a tuple (info, error) when fail_on_error is False
           return info when fail_on_error is Trie
        """
        api = 'cluster/software'
        field = 'nodes' if what == 'versions' else what
        record, error = rest_generic.get_one_record(self.rest_api, api, fields=field)
        # record can be empty or these keys may not be present when validation is still in progress
        optional_fields = ['validation_results']
        info, error_msg = None, None
        if error or not record:
            if error or field not in optional_fields:
                error_msg = "Error fetching software information for %s: %s" % (field, error or 'no record calling %s' % api)
        elif what == 'versions' and 'nodes' in record:
            nodes = self.parameters.get('nodes')
            if nodes:
                known_nodes = [node['name'] for node in record['nodes']]
                unknown_nodes = [node for node in nodes if node not in known_nodes]
                if unknown_nodes:
                    error_msg = 'Error: node%s not found in cluster: %s.' % ('s' if len(unknown_nodes) > 1 else '', ', '.join(unknown_nodes))
            info = [(node['name'], node['version']) for node in record['nodes'] if nodes is None or node['name'] in nodes]
        elif field in record:
            info = record[field]
        elif field not in optional_fields:
            error_msg = "Unexpected results for what: %s, record: %s" % (what, record)
        if fail_on_error and error_msg:
            self.module.fail_json(msg=error_msg)
        return info if fail_on_error else (info, error_msg)

    def check_for_existing_package(self, error):
        ''' ONTAP returns 'Package image with the same name already exists'
            if a file with the same name already exists.
            We need to confirm the version: if the version matches, we're good,
            otherwise we need to error out.
        '''
        versions, error2 = self.cluster_image_packages_get_rest()
        if self.parameters['package_version'] in versions:
            return True
        if versions:
            self.module.fail_json(msg='Error: another package with the same file name exists: found: %s' % ', '.join(versions))
        self.module.fail_json(msg='Error: ONTAP reported package already exists, but no package found: %s, getting versions: %s' % (error, error2))

    def cluster_image_download_get_rest(self):
        api = 'cluster/software/download'
        field = 'message,state'
        record, error = rest_generic.get_one_record(self.rest_api, api, fields=field)
        if record:
            return record.get('state'), record.get('message'), error
        return None, None, error

    def download_software_rest(self):
        api = 'cluster/software/download'
        body = {
            'url': self.parameters['package_url']
        }
        dummy, error = rest_generic.post_async(self.rest_api, api, body, timeout=0, job_timeout=self.parameters['timeout'])
        if error:
            if 'Package image with the same name already exists' in error:
                return self.check_for_existing_package(error)
            if 'Software get operation already in progress' in error:
                self.module.warn("A download is already in progress.  Resuming existing download.")
                return self.wait_for_condition(self.is_download_complete_rest, 'image download state')
            self.module.fail_json(msg="Error downloading software: %s - current versions: %s" % (error, self.versions))
        return False

    def is_download_complete_rest(self):
        state, dummy, error = self.cluster_image_download_get_rest()
        if error:
            return None, None, error
        return state in ['success', 'failure'], state, error

    def cluster_image_validate_rest(self):
        api = 'cluster/software'
        body = {
            'version': self.parameters['package_version']
        }
        query = {
            'validate_only': 'true'
        }
        dummy, error = rest_generic.patch_async(self.rest_api, api, None, body, query, timeout=0, job_timeout=self.parameters['timeout'])
        if error:
            return "Error validating software: %s" % error

        validation_results = None
        for __ in range(30):
            time.sleep(10)
            validation_results = self.cluster_image_get_rest('validation_results')
            if validation_results is not None:
                break
        return validation_results

    def update_software_rest(self):
        """install the software and invoke clean up and reporting function
        """
        state = self.cluster_image_update_rest()
        self.post_update_tasks_rest(state)

    def post_update_tasks_rest(self, state):
        """delete software package when installation is successful
           report validation_results whether update succeeded or failed
        """
        # fetch validation results
        (validation_reports, error) = self.cluster_image_get_rest('validation_results', fail_on_error=False)

        # success: delete and return
        if state == 'completed':
            self.cluster_image_package_delete()
            return error or validation_reports

        # report error
        if state == 'in_progress':
            msg = 'Timeout error'
            action = '  Should the timeout value be increased?  Current value is %d seconds.' % self.parameters['timeout']
            action += '  The software update continues in background.'
        else:
            msg = 'Error'
            action = ''
        msg += ' updating image using REST: state: %s.' % state
        msg += action
        self.module.fail_json(
            msg=msg,
            validation_reports_after_download=self.validation_reports_after_download,
            validation_reports_after_update=(error or validation_reports))

    def error_is_fatal(self, error):
        ''' a node may not be available during reboot, or the job may be lost '''
        if not error:
            return False
        self.rest_api.log_debug('transient_error', error)
        error_messages = [
            "entry doesn't exist",                                  # job not found
            "Max retries exceeded with url: /api/cluster/jobs"      # connection errors
        ]
        return all(error_message not in error for error_message in error_messages)

    def cluster_image_update_rest(self):
        api = 'cluster/software'
        body = {
            'version': self.parameters['package_version']
        }
        query = {}
        params_to_rest = {
            # module keys to REST keys
            'ignore_validation_warning': 'skip_warnings',
            'nodes': 'nodes_to_update',
            'stabilize_minutes': 'stabilize_minutes',
        }
        for (param_key, rest_key) in params_to_rest.items():
            value = self.parameters.get(param_key)
            if value is not None:
                query[rest_key] = ','.join(value) if rest_key == 'nodes_to_update' else value
        # With ONTAP 9.8, the job persists until the node is rebooted
        # With ONTAP 9.9, the job returns quickly
        dummy, error = rest_generic.patch_async(self.rest_api, api, None, body, query=query or None, timeout=0, job_timeout=self.parameters['timeout'])
        if self.error_is_fatal(error):
            validation_results, v_error = self.cluster_image_get_rest('validation_results', fail_on_error=False)
            self.module.fail_json(msg="Error updating software: %s - validation results: %s" % (error, v_error or validation_results))

        return self.wait_for_condition(self.is_update_complete_rest, 'image update state')

    def is_update_complete_rest(self):
        state, error = self.cluster_image_get_rest('state', fail_on_error=False)
        if error:
            return None, None, error
        return state in ['paused_by_user', 'paused_on_error', 'completed', 'canceled', 'failed'], state, error

    def wait_for_condition(self, is_task_complete, description):
        ''' loop until a condition is met
            is_task_complete is a function that returns (is_complete, state, error)
            if is_complete is True, the condition is met and state is returned
            if is complete is False, the task is called until a timeout is reached
            errors are ignored unless there are too many or a timeout is reached
        '''
        errors = []
        for __ in range(1 + self.parameters['timeout'] // 60):      # floor division
            time.sleep(60)
            is_complete, state, error = is_task_complete()
            if error:
                self.rest_api.log_debug('transient_error', error)
                errors.append(error)
                if len(errors) < 20:
                    continue
                break
            errors = []
            if is_complete:
                break
        if errors:
            msg = "Error: unable to read %s, using timeout %s." % (description, self.parameters['timeout'])
            msg += "  Last error: %s" % error
            msg += "  All errors: %s" % ' -- '.join(errors)
            self.module.fail_json(msg=msg)
        return state

    def cluster_image_packages_get_zapi(self):
        versions = []
        packages_obj = netapp_utils.zapi.NaElement('cluster-image-package-local-get-iter')
        try:
            result = self.server.invoke_successfully(packages_obj, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error getting list of local packages: %s' % to_native(error), exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
            packages_info = result.get_child_by_name('attributes-list')
            versions = [packages_details.get_child_content('package-version') for packages_details in packages_info.get_children()]
        return versions, None

    def cluster_image_packages_get_rest(self):
        if not self.use_rest:
            return self.cluster_image_packages_get_zapi()
        api = 'cluster/software/packages'
        records, error = rest_generic.get_0_or_more_records(self.rest_api, api, fields='version')
        return [record.get('version') for record in records] if records else [], error

    def cluster_image_package_delete_rest(self):
        api = 'cluster/software/packages'
        dummy, error = rest_generic.delete_async(self.rest_api, api, self.parameters['package_version'])
        if error:
            self.module.fail_json(msg='Error deleting cluster software package for %s: %s' % (self.parameters['package_version'], error))

    def apply(self):
        """
        Apply action to update ONTAP software
        """
        # TODO: cluster image update only works for HA configurations.
        # check if node image update can be used for other cases.
        versions, error = self.cluster_image_packages_get_rest()
        already_downloaded = not error and self.parameters['package_version'] in versions
        if self.parameters['state'] == 'absent':
            if error:
                self.module.fail_json(msg='Error: unable to fetch local package list: %s' % error)
            changed = already_downloaded
        else:
            if already_downloaded:
                self.module.warn('Package %s is already present, skipping download.' % self.parameters['package_version'])
            elif not self.parameters.get('package_url'):
                self.module.fail_json(msg='Error: packague_url is a required parameter to download the software package.')
            changed = self.parameters['force_update'] or self.is_update_required()
            validation_reports_after_update = ['only available after update']

        results = {}
        if not self.module.check_mode and changed:
            if self.parameters['state'] == 'absent':
                self.cluster_image_package_delete()
            else:
                if not already_downloaded:
                    already_downloaded = self.download_software()
                if self.parameters['validate_after_download']:
                    self.validation_reports_after_download = self.cluster_image_validate()
                if self.parameters['download_only']:
                    changed = not already_downloaded
                else:
                    validation_reports_after_update = self.update_software()
                results = {
                    'validation_reports': str(validation_reports_after_update),
                    'validation_reports_after_download': self.validation_reports_after_download,
                    'validation_reports_after_update': validation_reports_after_update
                }

        self.module.exit_json(changed=changed, **results)


def main():
    """Execute action"""
    package_obj = NetAppONTAPSoftwareUpdate()
    package_obj.apply()


if __name__ == '__main__':
    main()
