#!/usr/bin/python

# (c) 2019-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
na_ontap_flexcache
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
short_description: NetApp ONTAP FlexCache - create/delete relationship
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Modify/Delete FlexCache volume relationships.
  - This module does not modify an existing FlexCache volume when using ZAPI.
  - When using REST, a prepopulate can be started on an exising FlexCache volume.
  - When using REST, the volume can be mounted or unmounted.  Set path to '' to unmount it.
  - It is required the volume is mounted to prepopulate it.
  - Some actions are also available through the na_ontap_volume.
  - Cache volume can not be deleted in ZAPI.
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
module: na_ontap_flexcache
version_added: 2.8.0
options:
  state:
    choices: ['present', 'absent']
    description:
      - Whether the specified relationship should exist or not.
    default: present
    type: str
  origin_volume:
    description:
      - Name of the origin volume for the FlexCache.
      - Required for creation.
    type: str
  origin_vserver:
    description:
      - Name of the origin vserver for the FlexCache.
      - Required for creation.
    type: str
  origin_cluster:
    description:
      - Name of the origin cluster for the FlexCache.
      - Defaults to cluster associated with target vserver if absent.
      - Not used for creation.
    type: str
  name:
    description:
      - Name of the target volume for the FlexCache.
    required: true
    type: str
    aliases: ['volume']
    version_added: 21.3.0
  junction_path:
    description:
      - Junction path of the cache volume.
    type: str
    aliases: ['path']
  auto_provision_as:
    description:
      - Use this parameter to automatically select existing aggregates for volume provisioning.  Eg flexgroup
      - Note that the fastest aggregate type with at least one aggregate on each node of the cluster will be selected.
      - Ignored when using REST - omit aggr_list for automatic selection.
    type: str
  size:
    description:
      - Size of cache volume.
    type: int
  size_unit:
    description:
    - The unit used to interpret the size parameter.
    choices: ['bytes', 'b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb']
    type: str
    default: gb
  vserver:
    description:
      - Name of the target vserver for the FlexCache.
      - Note that hostname, username, password are intended for the target vserver.
    required: true
    type: str
  aggr_list:
    description:
      - List of aggregates to host target FlexCache volume.
    type: list
    elements: str
    aliases: ['aggregates']
  aggr_list_multiplier:
    description:
      - Aggregate list repeat count.
      - REST - Number of FlexCache constituents per aggregate when the C(aggregates) field is mentioned.
    type: int
    aliases: ['constituents_per_aggregate']
  force_unmount:
    description:
      - Unmount FlexCache volume. Delete the junction path at which the volume is mounted before deleting the FlexCache relationship.
    type: bool
    default: false
  force_offline:
    description:
      - Offline FlexCache volume before deleting the FlexCache relationship.
      - The volume will be destroyed and data can be lost.
    type: bool
    default: false
  time_out:
    description:
      - time to wait for flexcache creation or deletion in seconds
      - if 0, the request is asynchronous
      - default is set to 3 minutes
    type: int
    default: 180
  writeback:
    version_added: 22.13.0
    description:
      - FlexCache Writeback.
      - Requires ONTAP 9.12 or later and only supported with REST.
    type: dict
    suboptions:
      enabled:
        description:
          - Indicates whether or not writeback is enabled for the FlexCache volume.
          - Writeback is a storage method where data is first written to the FlexCache volume and then written to the origin of a FlexCache volume.
        type: bool
        default: no
  prepopulate:
    version_added: 21.3.0
    description:
      - prepopulate FlexCache with data from origin volume.
      - requires ONTAP 9.8 or later, and REST support.
      - dir_paths must be set for this option to be effective.
    type: dict
    suboptions:
      dir_paths:
        description:
          - List of directory paths in the owning SVM's namespace at which the FlexCache volume is mounted.
          - Path must begin with '/'.
        type: list
        elements: str
        required: true
      exclude_dir_paths:
        description:
          - Directory path which needs to be excluded from prepopulation.
          - Path must begin with '/'.
          - Requires ONTAP 9.9 or later.
        type: list
        elements: str
      recurse:
        description:
          - Specifies whether or not the prepopulate action should search through the directory-path recursively.
          - If not set, the default value 'true' is used.
        type: bool
      force_prepopulate_if_already_created:
        description:
          - by default, this module will start a prepopulate task each time it is called, and is not idempotent.
          - if set to false, the prepopulate task is not started if the FlexCache already exists.
        type: bool
        default: true
  relative_size:
    version_added: 22.14.0
    description:
      - Only supported with REST and requires ONTAP 9.13.1 or later.
    type: dict
    suboptions:
      enabled:
        description:
          - Specifies whether the relative sizing is enabled for the FlexCache volume.
        type: bool
      percentage:
        description:
          - Specifies the percent size the FlexCache volume should have relative to the total size of the origin volume.
        type: int
  override_encryption:
    version_added: 22.14.0
    description:
      - If set to true, a plaintext FlexCache volume for an encrypted origin volume is created.
      - Only supported with REST and requires ONTAP 9.14.1 or later.
    type: bool
  atime_scrub:
    version_added: 22.14.0
    description:
      - Only supported with REST and requires ONTAP 9.14.1 or later.
    type: dict
    suboptions:
      enabled:
        description:
          - Specifies whether scrubbing of inactive files based on atime is enabled for the FlexCache volume.
        type: bool
      period:
        description:
          - Specifies the atime duration in days after which a cached file is considered inactive.
        type: int
  cifs_change_notify_enabled:
    version_added: 22.14.0
    description:
      - Specifies whether a CIFS change notification is enabled for the FlexCache volume.
      - Only supported with REST and requires ONTAP 9.15.1 or later.
    type: bool
  global_file_locking_enabled:
    version_added: 22.14.0
    description:
      - Specifies whether or not a FlexCache volume has global file locking mode enabled.
      - When global file locking mode is enabled, the 'is_disconnected_mode_off_for_locks' flag is always set to 'true'.
      - Only supported with REST and requires ONTAP 9.9 or later.
    type: bool
  guarantee_type:
    version_added: 22.14.0
    description:
      - Specifies The type of space guarantee of this volume in the aggregate.
      - A value of 'volume' reserves space on the aggregates for the entire volume.
      - A value of 'none' reserves no space on the aggregates, meaning that writes can fail if an aggregate runs out of space.
      - Only supported with REST and requires ONTAP 9.7 or later.
    choices: ['volume', 'none']
    type: str
  dr_cache:
    version_added: 22.14.0
    description:
      - If set to true, a DR cache is created.
      - Only supported with REST and requires ONTAP 9.9 or later.
    type: bool
'''

EXAMPLES = """
- name: Create FlexCache
  netapp.ontap.na_ontap_flexcache:
    state: present
    origin_volume: test_src
    name: test_dest
    origin_vserver: ansible_src
    vserver: ansible_dest
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"

- name: Delete FlexCache
  netapp.ontap.na_ontap_flexcache:
    state: absent
    name: test_dest
    vserver: ansible_dest
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
"""

RETURN = """

"""

import time
import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic, rest_volume


class NetAppONTAPFlexCache:
    """
    Class with FlexCache methods
    """

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'],
                       default='present'),
            origin_volume=dict(required=False, type='str'),                     # origins[0]
            origin_vserver=dict(required=False, type='str'),                    # origins[0]
            origin_cluster=dict(required=False, type='str'),                    # origins[0]
            auto_provision_as=dict(required=False, type='str'),                 # ignored with REST
            name=dict(required=True, type='str', aliases=['volume']),
            junction_path=dict(required=False, type='str', aliases=['path']),
            size=dict(required=False, type='int'),
            size_unit=dict(default='gb',
                           choices=['bytes', 'b', 'kb', 'mb', 'gb', 'tb',
                                    'pb', 'eb', 'zb', 'yb'], type='str'),
            vserver=dict(required=True, type='str'),
            aggr_list=dict(required=False, type='list', elements='str', aliases=['aggregates']),
            aggr_list_multiplier=dict(required=False, type='int', aliases=['constituents_per_aggregate']),
            force_offline=dict(required=False, type='bool', default=False),
            force_unmount=dict(required=False, type='bool', default=False),
            time_out=dict(required=False, type='int', default=180),
            prepopulate=dict(required=False, type='dict', options=dict(
                dir_paths=dict(required=True, type='list', elements='str'),
                exclude_dir_paths=dict(required=False, type='list', elements='str'),
                recurse=dict(required=False, type='bool'),
                force_prepopulate_if_already_created=dict(required=False, type='bool', default=True),
            )),
            writeback=dict(required=False, type='dict', options=dict(
                enabled=dict(required=False, type='bool', default=False)
            )),
            relative_size=dict(required=False, type='dict', options=dict(
                enabled=dict(required=False, type='bool'),
                percentage=dict(required=False, type='int'),
            )),
            override_encryption=dict(required=False, type='bool'),
            atime_scrub=dict(required=False, type='dict', options=dict(
                enabled=dict(required=False, type='bool'),
                period=dict(required=False, type='int'),
            )),
            cifs_change_notify_enabled=dict(required=False, type='bool'),
            global_file_locking_enabled=dict(required=False, type='bool'),
            guarantee_type=dict(required=False, type='str', choices=['volume', 'none']),
            dr_cache=dict(required=False, type='bool')
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            mutually_exclusive=[
                ('aggr_list', 'auto_provision_as'),
            ],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule(self.module)
        self.parameters = self.na_helper.set_parameters(self.module.params)
        if self.parameters.get('size'):
            self.parameters['size'] = self.parameters['size'] * netapp_utils.POW2_BYTE_MAP[self.parameters['size_unit']]
        # setup later if required
        self.origin_server = None

        self.rest_api = netapp_utils.OntapRestAPI(self.module)
        partially_supported_rest_properties = [['guarantee_type', (9, 7)], ['prepopulate', (9, 8)],
                                               ['global_file_locking_enabled', (9, 9)], ['dr_cache', (9, 9)],
                                               ['writeback', (9, 12)], ['relative_size', (9, 13, 1)],
                                               ['override_encryption', (9, 14, 1)], ['atime_scrub', (9, 14, 1)],
                                               ['cifs_change_notify_enabled', (9, 15, 1)]]
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, None, partially_supported_rest_properties)
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.parameters['vserver'])
        else:
            self.rest_errors()

    def rest_errors(self):
        if 'prepopulate' in self.parameters:
            # sanitize the dictionary, as Ansible fills everything with None values
            self.parameters['prepopulate'] = self.na_helper.filter_out_none_entries(self.parameters['prepopulate'])
            ontap_99_options = ['exclude_dir_paths']
            if not self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9) and any(x in self.parameters['prepopulate'] for x in ontap_99_options):
                options = ['prepopulate: ' + x for x in ontap_99_options]
                self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version(options, version='9.9'))

    def add_parameter_to_dict(self, adict, name, key, tostr=False):
        """
        add defined parameter (not None) to a dict using key
        """
        value = self.parameters.get(name)
        if value is not None:
            adict[key] = str(value) if tostr else value

    def get_job(self, jobid, server):
        """
        Get job details by id
        """
        job_get = netapp_utils.zapi.NaElement('job-get')
        job_get.add_new_child('job-id', jobid)
        try:
            result = server.invoke_successfully(job_get, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            if to_native(error.code) == "15661":
                # Not found
                return None
            self.module.fail_json(msg='Error fetching job info: %s' % to_native(error),
                                  exception=traceback.format_exc())
        job_info = result.get_child_by_name('attributes').get_child_by_name('job-info')
        return {
            'job-progress': job_info['job-progress'],
            'job-state': job_info['job-state'],
            'job-completion': job_info['job-completion'] if job_info.get_child_by_name('job-completion') is not None else None
        }

    def check_job_status(self, jobid):
        """
        Loop until job is complete
        """
        server = self.server
        sleep_time = 5
        time_out = self.parameters['time_out']
        while time_out > 0:
            results = self.get_job(jobid, server)
            # If running as cluster admin, the job is owned by cluster vserver
            # rather than the target vserver.
            if results is None and server == self.server:
                results = netapp_utils.get_cserver(self.server)
                server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=results)
                continue
            if results is None:
                error = 'cannot locate job with id: %s' % jobid
                break
            if results['job-state'] in ('queued', 'running'):
                time.sleep(sleep_time)
                time_out -= sleep_time
                continue
            if results['job-state'] in ('success', 'failure'):
                break
            else:
                self.module.fail_json(msg='Unexpected job status in: %s' % repr(results))

        if results is not None:
            if results['job-state'] == 'success':
                error = None
            elif results['job-state'] in ('queued', 'running'):
                error = 'job completion exceeded expected timer of: %s seconds' % self.parameters['time_out']
            elif results['job-completion'] is not None:
                error = results['job-completion']
            else:
                error = results['job-progress']
        return error

    def flexcache_get_iter(self):
        """
        Compose NaElement object to query current FlexCache relation
        """
        options = {'volume': self.parameters['name']}
        self.add_parameter_to_dict(options, 'origin_volume', 'origin-volume')
        self.add_parameter_to_dict(options, 'origin_vserver', 'origin-vserver')
        self.add_parameter_to_dict(options, 'origin_cluster', 'origin-cluster')
        flexcache_info = netapp_utils.zapi.NaElement.create_node_with_children(
            'flexcache-info', **options)
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(flexcache_info)
        flexcache_get_iter = netapp_utils.zapi.NaElement('flexcache-get-iter')
        flexcache_get_iter.add_child_elem(query)
        return flexcache_get_iter

    def flexcache_get(self):
        """
        Get current FlexCache relations
        :return: Dictionary of current FlexCache details if query successful, else None
        """
        if self.use_rest:
            api = 'storage/flexcache/flexcaches'
            query = {
                'name': self.parameters['name'],
                'svm.name': self.parameters['vserver']
            }
            if 'origin_cluster' in self.parameters:
                query['origins.cluster.name'] = self.parameters['origin_cluster']
            fields = 'svm,name,uuid,path,'
            if 'guarantee_type' in self.parameters:
                fields += 'guarantee.type,'
            if 'global_file_locking_enabled' in self.parameters:
                fields += 'global_file_locking_enabled,'
            if 'dr_cache' in self.parameters:
                fields += 'dr_cache,'
            if 'writeback' in self.parameters:
                fields += 'writeback,'
            if 'relative_size' in self.parameters:
                fields += 'relative_size,'
            if 'override_encryption' in self.parameters:
                fields += 'override_encryption,'
            if 'atime_scrub' in self.parameters:
                fields += 'atime_scrub,'
            if 'cifs_change_notify_enabled' in self.parameters:
                fields += 'cifs_change_notify.enabled,'

            flexcache, error = rest_generic.get_one_record(self.rest_api, api, query, fields)
            self.na_helper.fail_on_error(error)
            if flexcache is None:
                return None
            flexcache_info = dict(
                vserver=flexcache['svm']['name'],
                name=flexcache['name'],
                uuid=flexcache['uuid'],
                junction_path=flexcache.get('path'),
                writeback=flexcache.get('writeback'),
                relative_size=flexcache.get('relative_size'),
                atime_scrub=flexcache.get('atime_scrub'),
                cifs_change_notify_enabled=self.na_helper.safe_get(flexcache, ['cifs_change_notify', 'enabled'])
            )
            return flexcache_info

        flexcache_get_iter = self.flexcache_get_iter()
        flex_info = {}
        try:
            result = self.server.invoke_successfully(flexcache_get_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching FlexCache info: %s' % to_native(error),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) == 1:
            flexcache_info = result.get_child_by_name('attributes-list') \
                                   .get_child_by_name('flexcache-info')
            flex_info['origin_cluster'] = flexcache_info.get_child_content('origin-cluster')
            flex_info['origin_volume'] = flexcache_info.get_child_content('origin-volume')
            flex_info['origin_vserver'] = flexcache_info.get_child_content('origin-vserver')
            flex_info['size'] = flexcache_info.get_child_content('size')
            flex_info['name'] = flexcache_info.get_child_content('volume')
            flex_info['vserver'] = flexcache_info.get_child_content('vserver')

            return flex_info
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) > 1:
            msg = 'Multiple records found for %s:' % self.parameters['name']
            self.module.fail_json(msg='Error fetching FlexCache info: %s' % msg)
        return None

    def flexcache_rest_create_body(self, mappings, params=None):
        """
        maps self.parameters to REST API body attributes, using mappings to identify fields to add
        """
        body = {}
        params = self.parameters if params is None else params
        for key, value in mappings.items():
            if key in params:
                if key == 'aggr_list':
                    body[value] = [dict(name=aggr) for aggr in params[key]]
                else:
                    body[value] = params[key]
            elif key == 'origins':
                # this is an artificial key, to match the REST list of dict structure
                origin = dict(
                    volume=dict(name=params['origin_volume']),
                    svm=dict(name=params['origin_vserver'])
                )
                body[value] = [origin]
        return body

    def flexcache_rest_create(self):
        ''' use POST to create a FlexCache '''
        mappings = dict(
            name='name',
            vserver='svm.name',
            junction_path='path',
            size='size',
            aggr_list='aggregates',
            aggr_list_multiplier='constituents_per_aggregate',
            origins='origins',
            prepopulate='prepopulate',
            writeback='writeback',
            guarantee_type='guarantee.type',
            global_file_locking_enabled='global_file_locking_enabled',
            dr_cache='dr_cache',
            relative_size='relative_size',
            override_encryption='override_encryption',
            atime_scrub='atime_scrub',
            cifs_change_notify_enabled='cifs_change_notify.enabled'
        )
        body = self.flexcache_rest_create_body(mappings)
        api = 'storage/flexcache/flexcaches'
        response, error = rest_generic.post_async(self.rest_api, api, body, job_timeout=self.parameters['time_out'])
        self.na_helper.fail_on_error(error)
        return response

    def flexcache_rest_modify(self, uuid, modify):
        """
        use PATCH to start prepopulating a FlexCache or modify other properties
        """
        mappings = dict(                # name cannot be set, though swagger example shows it
            prepopulate='prepopulate',
            writeback='writeback',
            relative_size='relative_size',
            atime_scrub='atime_scrub',
            cifs_change_notify_enabled='cifs_change_notify.enabled'
        )
        body = self.flexcache_rest_create_body(mappings, modify)
        api = 'storage/flexcache/flexcaches'
        response, error = rest_generic.patch_async(self.rest_api, api, uuid, body, job_timeout=self.parameters['time_out'])
        self.na_helper.fail_on_error(error)
        return response

    def flexcache_create_async(self):
        """
        Create a FlexCache relationship
        """
        options = {'origin-volume': self.parameters['origin_volume'],
                   'origin-vserver': self.parameters['origin_vserver'],
                   'volume': self.parameters['name']}
        self.add_parameter_to_dict(options, 'junction_path', 'junction-path')
        self.add_parameter_to_dict(options, 'auto_provision_as', 'auto-provision-as')
        self.add_parameter_to_dict(options, 'size', 'size', tostr=True)
        if self.parameters.get('aggr_list') and self.parameters.get('aggr_list_multiplier'):
            self.add_parameter_to_dict(options, 'aggr_list_multiplier', 'aggr-list-multiplier', tostr=True)
        flexcache_create = netapp_utils.zapi.NaElement.create_node_with_children('flexcache-create-async', **options)
        if self.parameters.get('aggr_list'):
            aggregates = netapp_utils.zapi.NaElement('aggr-list')
            for aggregate in self.parameters['aggr_list']:
                aggregates.add_new_child('aggr-name', aggregate)
            flexcache_create.add_child_elem(aggregates)
        try:
            result = self.server.invoke_successfully(flexcache_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating FlexCache: %s' % to_native(error),
                                  exception=traceback.format_exc())
        results = {}
        for key in ('result-status', 'result-jobid'):
            if result.get_child_by_name(key):
                results[key] = result[key]
        return results

    def flexcache_create(self):
        """
        Create a FlexCache relationship
        Check job status
        """
        if self.use_rest:
            return self.flexcache_rest_create()

        results = self.flexcache_create_async()
        status = results.get('result-status')
        if status == 'in_progress' and 'result-jobid' in results:
            if self.parameters['time_out'] == 0:
                # asynchronous call, assuming success!
                return
            error = self.check_job_status(results['result-jobid'])
            if error is None:
                return
            else:
                self.module.fail_json(msg='Error when creating flexcache: %s' % error)
        self.module.fail_json(msg='Unexpected error when creating flexcache: results is: %s' % repr(results))

    def flexcache_delete_async(self):
        """
        Delete FlexCache relationship at destination cluster
        """
        options = {'volume': self.parameters['name']}
        flexcache_delete = netapp_utils.zapi.NaElement.create_node_with_children('flexcache-destroy-async', **options)
        try:
            result = self.server.invoke_successfully(flexcache_delete, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error deleting FlexCache: %s' % (to_native(error)),
                                  exception=traceback.format_exc())
        results = {}
        for key in ('result-status', 'result-jobid'):
            if result.get_child_by_name(key):
                results[key] = result[key]
        return results

    def rest_offline_volume(self, current):
        """
        Make the volume offline using REST PATCH method.
        """
        uuid = current.get('uuid')
        if uuid is None:
            error = 'Error, no uuid in current: %s' % str(current)
            self.na_helper.fail_on_error(error)
        body = dict(state='offline')
        return self.patch_volume_rest(uuid, body)

    def volume_offline(self, current):
        """
        Make the FlexCache volume offline at destination cluster
        """
        if self.use_rest:
            self.rest_offline_volume(current)
        else:
            options = {'name': self.parameters['name']}
            xml = netapp_utils.zapi.NaElement.create_node_with_children(
                'volume-offline', **options)
            try:
                self.server.invoke_successfully(xml, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error offlining FlexCache volume: %s'
                                      % (to_native(error)),
                                      exception=traceback.format_exc())

    def rest_mount_volume(self, current, path):
        """
        Mount the volume using REST PATCH method.
        If path is empty string, unmount the volume.
        """
        uuid = current.get('uuid')
        if uuid is None:
            error = 'Error, no uuid in current: %s' % str(current)
            self.na_helper.fail_on_error(error)
        body = dict(nas=dict(path=path))
        return self.patch_volume_rest(uuid, body)

    def rest_unmount_volume(self, current):
        """
        Unmount the volume using REST PATCH method.
        """
        self.rest_mount_volume(current, '') if current.get('junction_path') else None

    def volume_unmount(self, current):
        """
        Unmount FlexCache volume at destination cluster
        """
        if self.use_rest:
            self.rest_unmount_volume(current)
        else:
            options = {'volume-name': self.parameters['name']}
            xml = netapp_utils.zapi.NaElement.create_node_with_children(
                'volume-unmount', **options)
            try:
                self.server.invoke_successfully(xml, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error unmounting FlexCache volume: %s'
                                      % (to_native(error)),
                                      exception=traceback.format_exc())

    def patch_volume_rest(self, uuid, body):
        response, error = rest_volume.patch_volume(self.rest_api, uuid, body)
        self.na_helper.fail_on_error(error)
        return response

    def flexcache_rest_delete(self, current):
        """
        Delete the flexcache using REST DELETE method.
        """
        response = None
        uuid = current.get('uuid')
        if uuid is None:
            error = 'Error, no uuid in current: %s' % str(current)
            self.na_helper.fail_on_error(error)
        api = 'storage/flexcache/flexcaches'
        # There may be a bug in ONTAP.  If return_timeout is >= 15, the call fails with uuid not found!
        # With 5, a job is queued, and completes with success.  With a big enough value, no job is
        # queued, and the API returns in around 15 seconds with a not found error.
        rto = netapp_utils.get_feature(self.module, 'flexcache_delete_return_timeout')
        response, error = rest_generic.delete_async(self.rest_api, api, uuid, timeout=rto, job_timeout=self.parameters['time_out'])
        self.na_helper.fail_on_error(error)
        return response

    def flexcache_delete(self, current):
        """
        Delete FlexCache relationship at destination cluster
        Check job status
        """
        self.module.warn('Cache volume can not be deleted in ZAPI. '
                         'Flexcache relationship was ended.')
        if self.parameters['force_unmount']:
            self.volume_unmount(current)
        if self.parameters['force_offline']:
            self.volume_offline(current)
        if self.use_rest:
            return self.flexcache_rest_delete(current)
        results = self.flexcache_delete_async()
        status = results.get('result-status')
        if status == 'in_progress' and 'result-jobid' in results:
            if self.parameters['time_out'] == 0:
                # asynchronous call, assuming success!
                return None
            error = self.check_job_status(results['result-jobid'])
            if error is not None:
                self.module.fail_json(msg='Error when deleting flexcache: %s' % error)
            return None
        self.module.fail_json(msg='Unexpected error when deleting flexcache: results is: %s' % repr(results))

    def check_parameters(self, cd_action):
        """
        Validate parameters and fail if one or more required params are missing
        """
        if cd_action != 'create':
            return
        if self.parameters['state'] == 'present':
            expected = 'origin_volume', 'origin_vserver'
            missings = [param for param in expected if not self.parameters.get(param)]
            if missings:
                plural = 's' if len(missings) > 1 else ''
                msg = 'Missing parameter%s: %s' % (plural, ', '.join(missings))
                self.module.fail_json(msg=msg)

    def apply(self):
        """
        Apply action to FlexCache
        """
        current = self.flexcache_get()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        modify, mount_unmount = None, None
        prepopulate_if_already_created = None

        if self.parameters['state'] == 'present' and 'prepopulate' in self.parameters:
            prepopulate_if_already_created = self.parameters['prepopulate'].pop('force_prepopulate_if_already_created')

        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if modify:
                if self.use_rest:
                    modify.pop('name', None)
                    if not modify:
                        # ignore modify operation if the only key to modify is 'name'
                        self.na_helper.changed = False
                    mount_unmount = modify.pop('junction_path', None)
                else:
                    self.module.fail_json(msg='FlexCache properties cannot be modified by this module when using ZAPI.  modify: %s' % str(modify))
            if current and prepopulate_if_already_created:
                # force a prepopulate action
                modify.update(dict(prepopulate=self.parameters['prepopulate']))
                self.na_helper.changed = True
                self.module.warn('na_ontap_flexcache is not idempotent when prepopulate is present and force_prepopulate_if_already_created=true')
                if mount_unmount == '' or current['junction_path'] == '':
                    self.module.warn('prepopulate requires the FlexCache volume to be mounted')
        self.check_parameters(cd_action)
        response = None
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                response = self.flexcache_create()
            elif cd_action == 'delete':
                response = self.flexcache_delete(current)
            else:
                if mount_unmount is not None:
                    # mount first, as this is required for prepopulate to succeed (or fail for unmount)
                    self.rest_mount_volume(current, mount_unmount)
                if modify:
                    response = self.flexcache_rest_modify(current['uuid'], modify)
        result = netapp_utils.generate_result(self.na_helper.changed, cd_action, modify, response)
        self.module.exit_json(**result)


def main():
    """Execute action"""
    my_obj = NetAppONTAPFlexCache()
    my_obj.apply()


if __name__ == '__main__':
    main()
