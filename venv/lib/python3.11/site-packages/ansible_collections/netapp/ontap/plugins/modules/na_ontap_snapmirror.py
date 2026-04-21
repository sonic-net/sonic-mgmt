#!/usr/bin/python

'''
na_ontap_snapmirror
'''

# (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
description:
  - Create/Delete/Update/Initialize/Break/Resync/Resume SnapMirror volume/vserver relationships for ONTAP/ONTAP
  - This includes SVM replication, aka vserver DR
  - Create/Delete/Update/Initialize SnapMirror volume relationship between ElementSW and ONTAP
  - Modify schedule for a SnapMirror relationship for ONTAP/ONTAP and ElementSW/ONTAP
  - Pre-requisite for ElementSW to ONTAP relationship or vice-versa is an established SnapMirror endpoint for ONTAP cluster with ElementSW UI
  - Pre-requisite for ElementSW to ONTAP relationship or vice-versa is to have SnapMirror enabled in the ElementSW volume
  - For creating a SnapMirror ElementSW/ONTAP relationship, an existing ONTAP/ElementSW relationship should be present
  - Performs resync if the C(relationship_state=active) and the current mirror state of the snapmirror relationship is broken-off
  - Performs resume if the C(relationship_state=active), the current snapmirror relationship status is quiesced and mirror state is snapmirrored
  - Performs restore if the C(relationship_type=restore) and all other operations will not be performed during this task
extends_documentation_fragment:
  - netapp.ontap.netapp.na_ontap
  - netapp.ontap.netapp.na_ontap_peer
module: na_ontap_snapmirror
options:
  state:
    choices: ['present', 'absent']
    description:
      - Whether the specified relationship should exist or not.
    default: present
    type: str
  source_volume:
    description:
      - Specifies the name of the source volume for the SnapMirror.
      - Deprecated as of 21.2.0, use source_endpoint and path.
    type: str
  destination_volume:
    description:
      - Specifies the name of the destination volume for the SnapMirror.
      - Deprecated as of 21.2.0, use source_endpoint and path.
    type: str
  source_vserver:
    description:
      - Name of the source vserver for the SnapMirror.
      - Deprecated as of 21.2.0, use source_endpoint and path, or svm.
    type: str
  destination_vserver:
    description:
      - Name of the destination vserver for the SnapMirror.
      - Deprecated as of 21.2.0, use destination_endpoint and path, or svm.
    type: str
  source_path:
    description:
      - Specifies the source endpoint of the SnapMirror relationship.
      - If the source is an ONTAP volume, format should be <[vserver:][volume]> or <[[cluster:]//vserver/]volume>
      - If the source is an ElementSW volume, format should be <[Element_SVIP]:/lun/[Element_VOLUME_ID]>
      - If the source is an ElementSW volume, the volume should have SnapMirror enabled.
      - Deprecated as of 21.2.0, use source_endpoint and path.
    type: str
  destination_path:
    description:
      - Specifies the destination endpoint of the SnapMirror relationship.
      - Deprecated as of 21.2.0, use destination_endpoint and path.
    type: str
  relationship_type:
    choices: ['data_protection', 'load_sharing', 'vault', 'restore', 'transition_data_protection',
    'extended_data_protection']
    type: str
    description:
      - Specify the type of SnapMirror relationship.
      - for 'restore' unless 'source_snapshot' is specified the most recent Snapshot copy on the source volume is restored.
      - restore SnapMirror is not idempotent.
      - With REST, only 'extended_data_protection' and 'restore' are supported.
  schedule:
    description:
      - Specify the name of the current schedule, which is used to update the SnapMirror relationship.
      - Optional for create, modifiable.
      - With REST, this option requires ONTAP 9.11.1 or later.
    type: str
    aliases: ['transfer_schedule']
    version_added: 22.2.0
  policy:
    description:
      - Specify the name of the SnapMirror policy that applies to this relationship.
    version_added: 2.8.0
    type: str
  source_hostname:
    description:
      - DEPRECATED - please use C(peer_options).
      - Source hostname or management IP address for ONTAP or ElementSW cluster.
      - If present, when state is absent, the relationship is released at the source before being deleted at destination.
      - It is recommended to always release before deleting, so make sure this parameter is present if the source hostname is known.
    type: str
  source_username:
    description:
      - DEPRECATED - please use C(peer_options).
      - Source username for ONTAP or ElementSW cluster.
      - Optional if this is same as destination username.
    type: str
  source_password:
    description:
      - DEPRECATED - please use C(peer_options).
      - Source password for ONTAP or ElementSW cluster.
      - Optional if this is same as destination password.
    type: str
  connection_type:
    description:
     - Type of SnapMirror relationship.
     - Pre-requisite for either elementsw_ontap or ontap_elementsw the ElementSW volume should have enableSnapmirror option set to true.
     - For using ontap_elementsw, elementsw_ontap snapmirror relationship should exist.
    choices: ['ontap_ontap', 'elementsw_ontap', 'ontap_elementsw']
    default: ontap_ontap
    type: str
    version_added: 2.9.0
  max_transfer_rate:
    description:
     - Specifies the upper bound, in kilobytes per second, at which data is transferred.
     - Default is unlimited, it can be explicitly set to 0 as unlimited.
    type: int
    version_added: 2.9.0
  initialize:
    description:
     - Specifies whether to initialize SnapMirror relation.
     - Default is True, it can be explicitly set to False to avoid initializing SnapMirror relation.
    default: true
    type: bool
    version_added: '19.11.0'
  update:
    description:
     - Specifies whether to update the destination endpoint of the SnapMirror relationship only if the relationship is already present and active.
     - Default is True.
    default: true
    type: bool
    version_added: '20.2.0'
  relationship_info_only:
    description:
     - If relationship-info-only is set to true then only relationship information is removed.
    default: false
    type: bool
    version_added: '20.4.0'
  relationship_state:
    description:
     - Specifies whether to break SnapMirror relation or establish a SnapMirror relationship.
     - state must be present to use this option.
    default: active
    choices: ['active', 'broken']
    type: str
    version_added: '20.2.0'
  source_snapshot:
    description:
     - Specifies the Snapshot from the source to be restored.
    type: str
    version_added: '20.6.0'
  identity_preserve:
    description:
     - Specifies whether or not the identity of the source Vserver is replicated to the destination Vserver.
     - If this parameter is set to true, the source Vserver's configuration will additionally be replicated to the destination.
     - If the parameter is set to false, then only the source Vserver's volumes and RBAC configuration are replicated to the destination.
    type: bool
    version_added: 2.9.0
  create_destination:
    description:
      - Requires ONTAP 9.7 or later.
      - Creates the destination volume if enabled and destination_volume is present or destination_path includes a volume name.
      - Creates and peers the destination vserver for SVM DR.
    type: dict
    version_added: 21.1.0
    suboptions:
      enabled:
        description:
          - Whether to create the destination volume or vserver.
          - This is automatically enabled if any other suboption is present.
        type: bool
        default: true
      storage_service:
        description: storage service associated with the destination endpoint.
        type: dict
        suboptions:
          enabled:
            description: whether to create the destination endpoint using storage service.
            type: bool
          enforce_performance:
            description: whether to enforce storage service performance on the destination endpoint.
            type: bool
          name:
            description: the performance service level (PSL) for this volume endpoint.
            type: str
            choices: ['value', 'performance', 'extreme']
      tiering:
        description:
          - Cloud tiering policy.
        type: dict
        suboptions:
          policy:
            description:
              - Cloud tiering policy.
            choices: ['all', 'auto', 'none', 'snapshot-only']
            type: str
          supported:
            description:
              - enable provisioning of the destination endpoint volumes on FabricPool aggregates.
              - only supported for FlexVol volume, FlexGroup volume, and Consistency Group endpoints.
            type: bool
  destination_cluster:
    description:
      - Requires ONTAP 9.7 or higher.
      - Required to create the destination vserver for SVM DR or the destination volume.
      - Deprecated as of 21.2.0, use destination_endpoint and cluster.
    type: str
    version_added: 21.1.0
  source_cluster:
    description:
      - Requires ONTAP 9.7 or higher.
      - Required to create the peering relationship between source and destination SVMs.
      - Deprecated as of 21.2.0, use source_endpoint and cluster.
    type: str
    version_added: 21.1.0
  source_endpoint:
    description:
      - source endpoint of a SnapMirror relationship.
    type: dict
    version_added: 21.2.0
    suboptions:
      cluster:
        description:
          - Requires ONTAP 9.7 or higher.
          - Required to create the peering relationship between source and destination SVMs.
        type: str
      consistency_group_volumes:
        description:
          - Requires ONTAP 9.8 or higher.
          - Mandatory property for a Consistency Group endpoint. Specifies the list of FlexVol volumes for a Consistency Group.
        type: list
        elements: str
      ipspace:
        description:
          - Requires ONTAP 9.8 or higher.
          - Optional property to specify the IPSpace of the SVM.
        type: str
      path:
        description:
          - The source endpoint for the relationship.
          - If the source is an ONTAP volume (FlexVol or FlexGroup), format should be <vserver:volume>
          - For SVM DR, format should be <vserver:>
          - For a consistency group, format should be <vserver:/cg/cg_name>
          - If the source is an ElementSW volume, format should be <Element_SVIP:/lun/Element_VOLUME_ID>
          - If the source is an ElementSW volume, the volume should have SnapMirror enabled.
        type: str
        required: true
      svm:
        description:
          - The name of the SVM.  Not sure when this is needed.
        type: str
  destination_endpoint:
    description:
      - destination endpoint of a SnapMirror relationship.
    type: dict
    version_added: 21.2.0
    suboptions:
      cluster:
        description:
          - Requires ONTAP 9.7 or higher.
          - Required to create the destination vserver for SVM DR or the destination volume.
        type: str
      consistency_group_volumes:
        description:
          - Requires ONTAP 9.8 or higher.
          - Mandatory property for a Consistency Group endpoint. Specifies the list of FlexVol volumes for a Consistency Group.
        type: list
        elements: str
      ipspace:
        description:
          - Requires ONTAP 9.8 or higher.
          - Optional property to specify the IPSpace of the SVM.
        type: str
      path:
        description:
          - The destination endpoint for the relationship.
          - format is <vserver:volume>, <vserver:>, <vserver:/cg/cg_name>
        type: str
        required: true
      svm:
        description:
          - The name of the SVM.  Not sure when this is needed.
        type: str
  transferring_time_out:
    description:
      - How long to wait when a transfer is in progress (after initializing for instance).  Unit is seconds.
    default: 300
    type: int
    version_added: 21.20.0
  quiesced_time_out:
    description:
        - How long to wait for a relationship to quiesce. Unit is seconds.
    default: 300
    type: int
    version_added: 22.14.0
  clean_up_failure:
    description:
      - An optional parameter to recover from an aborted or failed restore operation.
      - Any temporary RST relationship is removed from the destination Vserver.
      - Only supported with ZAPI.
    default: False
    type: bool
    version_added: 21.20.0
  validate_source_path:
    description:
      - The relationship is found based on the destination as it is unique.
      - By default, the source information is verified and an error is reported if there is a mismatch.
        This would mean the destination is already used by another relationship.
      - The check accounts for a local vserver name that may be different from the remote vserver name.
      - This may be disabled in case the check is too strict, to unconditionally delete a realtionship for instance.
    default: True
    type: bool
    version_added: 21.21.0
  identity_preservation:
    description:
      - Specifies which configuration of the source SVM is replicated to the destination SVM.
      - This property is applicable only for SVM data protection with "async" policy type.
      - Only supported with REST and requires ONTAP 9.11.1 or later.
    type: str
    choices: ['full', 'exclude_network_config', 'exclude_network_and_protocol_config']
    version_added: '22.4.0'
  quick_resync:
    description:
      - Set to true to reduce resync time by not preserving storage efficiency.
      - This property is applicable only for relationships with FlexVol volume endpoints and SVMDR relationships
        when the PATCH state is being changed to "snapmirrored".
      - Only supported with REST.
    type: bool
    version_added: 23.1.0

short_description: "NetApp ONTAP or ElementSW Manage SnapMirror"
version_added: 2.7.0
notes:
  - supports REST and ZAPI.
  - supports check_mode.
  - restore is not idempotent.
  - snapmirror runs on the destination for most operations, peer_options identify the source cluster.
  - ONTAP supports either username/password or a SSL certificate for authentication.
  - ElementSW only supports username/password for authentication.
'''

EXAMPLES = """
# creates and initializes the snapmirror
- name: Create ONTAP/ONTAP SnapMirror
  netapp.ontap.na_ontap_snapmirror:
    state: present
    source_volume: test_src
    destination_volume: test_dest
    source_vserver: ansible_src
    destination_vserver: ansible_dest
    schedule: hourly
    policy: MirrorAllSnapshots
    max_transfer_rate: 1000
    initialize: false
    hostname: "{{ destination_cluster_hostname }}"
    username: "{{ destination_cluster_username }}"
    password: "{{ destination_cluster_password }}"

# creates and initializes the snapmirror between vservers
- name: Create ONTAP/ONTAP vserver SnapMirror
  netapp.ontap.na_ontap_snapmirror:
    state: present
    source_vserver: ansible_src
    destination_vserver: ansible_dest
    identity_preserve: true
    hostname: "{{ destination_cluster_hostname }}"
    username: "{{ destination_cluster_username }}"
    password: "{{ destination_cluster_password }}"

# existing snapmirror relation with status 'snapmirrored' will be initialized
- name: Inititalize ONTAP/ONTAP SnapMirror
  netapp.ontap.na_ontap_snapmirror:
    state: present
    source_path: 'ansible:test'
    destination_path: 'ansible:dest'
    relationship_state: active
    hostname: "{{ destination_cluster_hostname }}"
    username: "{{ destination_cluster_username }}"
    password: "{{ destination_cluster_password }}"

- name: Delete SnapMirror
  netapp.ontap.na_ontap_snapmirror:
    state: absent
    destination_path: <path>
    relationship_info_only: true
    source_hostname: "{{ source_hostname }}"
    hostname: "{{ destination_cluster_hostname }}"
    username: "{{ destination_cluster_username }}"
    password: "{{ destination_cluster_password }}"

- name: Break SnapMirror
  netapp.ontap.na_ontap_snapmirror:
    state: present
    relationship_state: broken
    destination_path: <path>
    source_hostname: "{{ source_hostname }}"
    hostname: "{{ destination_cluster_hostname }}"
    username: "{{ destination_cluster_username }}"
    password: "{{ destination_cluster_password }}"

- name: Restore SnapMirror volume using location (Idempotency)
  netapp.ontap.na_ontap_snapmirror:
    state: present
    source_path: <path>
    destination_path: <path>
    relationship_type: restore
    source_snapshot: "{{ snapshot }}"
    hostname: "{{ destination_cluster_hostname }}"
    username: "{{ destination_cluster_username }}"
    password: "{{ destination_cluster_password }}"

- name: Set schedule to NULL
  netapp.ontap.na_ontap_snapmirror:
    state: present
    destination_path: <path>
    schedule: ""
    hostname: "{{ destination_cluster_hostname }}"
    username: "{{ destination_cluster_username }}"
    password: "{{ destination_cluster_password }}"

- name: Create SnapMirror from ElementSW to ONTAP
  netapp.ontap.na_ontap_snapmirror:
    state: present
    connection_type: elementsw_ontap
    source_path: '10.10.10.10:/lun/300'
    destination_path: 'ansible_test:ansible_dest_vol'
    schedule: hourly
    policy: MirrorLatest
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    source_hostname: " {{ Element_cluster_mvip }}"
    source_username: "{{ Element_cluster_username }}"
    source_password: "{{ Element_cluster_password }}"

- name: Create SnapMirror from ONTAP to ElementSW
  netapp.ontap.na_ontap_snapmirror:
    state: present
    connection_type: ontap_elementsw
    destination_path: '10.10.10.10:/lun/300'
    source_path: 'ansible_test:ansible_dest_vol'
    policy: MirrorLatest
    hostname: "{{ Element_cluster_mvip }}"
    username: "{{ Element_cluster_username }}"
    password: "{{ Element_cluster_password }}"
    source_hostname: " {{ netapp_hostname }}"
    source_username: "{{ netapp_username }}"
    source_password: "{{ netapp_password }}"

- name: Create SnapMirror relationship (create destination volume)
  netapp.ontap.na_ontap_snapmirror:
    state: present
    source_endpoint:
      cluster: "{{ _source_cluster }}"
      path: "{{ source_vserver + ':' + source_volume }}"
    destination_endpoint:
      cluster: "{{ _destination_cluster }}"
      path: "{{ destination_vserver_VOLDP + ':' + destination_volume }}"
    create_destination:
      enabled: true
    hostname: "{{ destination_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    https: true
    validate_certs: false

- name: Create SnapMirror relationship - SVM DR (creating and peering destination svm)
  tags: create_svmdr
  netapp.ontap.na_ontap_snapmirror:
    state: present
    source_endpoint:
    cluster: "{{ _source_cluster }}"
    path: "{{ source_vserver + ':' }}"
    destination_endpoint:
      cluster: "{{ _destination_cluster }}"
      path: "{{ destination_vserver_SVMDR + ':' }}"
    create_destination:
      enabled: true
    hostname: "{{ destination_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    https: true
    validate_certs: false

- name: Resync SnapMirror relationship - SVM DR
  tags: resync_svmdr
  netapp.ontap.na_ontap_snapmirror:
    state: present
    source_endpoint:
    cluster: "{{ _source_cluster }}"
    path: "{{ source_vserver + ':' }}"
    destination_endpoint:
      cluster: "{{ _destination_cluster }}"
      path: "{{ destination_vserver_SVMDR + ':' }}"
    create_destination:
      enabled: true
    relationship_state: active
    quick_resync: true
    hostname: "{{ destination_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    https: true
    validate_certs: false
"""

RETURN = """
"""

import re
import time
import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_elementsw_module import NaElementSWModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic

HAS_SF_SDK = netapp_utils.has_sf_sdk()
try:
    import solidfire.common
except ImportError:
    HAS_SF_SDK = False


class NetAppONTAPSnapmirror(object):
    """
    Class with SnapMirror methods
    """

    def __init__(self):

        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            destination_endpoint=dict(type='dict', options=dict(
                cluster=dict(type='str'),
                consistency_group_volumes=dict(type='list', elements='str'),
                ipspace=dict(type='str'),
                path=dict(required=True, type='str'),
                svm=dict(type='str'),
            )),
            source_endpoint=dict(type='dict', options=dict(
                cluster=dict(type='str'),
                consistency_group_volumes=dict(type='list', elements='str'),
                ipspace=dict(type='str'),
                path=dict(required=True, type='str'),
                svm=dict(type='str'),
            )),
            source_vserver=dict(required=False, type='str'),
            destination_vserver=dict(required=False, type='str'),
            source_volume=dict(required=False, type='str'),
            destination_volume=dict(required=False, type='str'),
            source_path=dict(required=False, type='str'),
            destination_path=dict(required=False, type='str'),
            schedule=dict(required=False, type='str', aliases=['transfer_schedule']),
            policy=dict(required=False, type='str'),
            relationship_type=dict(required=False, type='str',
                                   choices=['data_protection', 'load_sharing',
                                            'vault', 'restore',
                                            'transition_data_protection',
                                            'extended_data_protection']
                                   ),
            connection_type=dict(required=False, type='str',
                                 choices=['ontap_ontap', 'elementsw_ontap', 'ontap_elementsw'],
                                 default='ontap_ontap'),
            peer_options=dict(type='dict', options=netapp_utils.na_ontap_host_argument_spec_peer()),
            source_hostname=dict(required=False, type='str'),
            source_username=dict(required=False, type='str'),
            source_password=dict(required=False, type='str', no_log=True),
            max_transfer_rate=dict(required=False, type='int'),
            initialize=dict(required=False, type='bool', default=True),
            update=dict(required=False, type='bool', default=True),
            identity_preserve=dict(required=False, type='bool'),
            identity_preservation=dict(required=False, type="str", choices=['full', 'exclude_network_config', 'exclude_network_and_protocol_config']),
            relationship_state=dict(required=False, type='str', choices=['active', 'broken'], default='active'),
            relationship_info_only=dict(required=False, type='bool', default=False),
            source_snapshot=dict(required=False, type='str'),
            create_destination=dict(required=False, type='dict', options=dict(
                enabled=dict(type='bool', default=True),
                storage_service=dict(type='dict', options=dict(
                    enabled=dict(type='bool'),
                    enforce_performance=dict(type='bool'),
                    name=dict(type='str', choices=['value', 'performance', 'extreme']),
                )),
                tiering=dict(type='dict', options=dict(
                    policy=dict(type='str', choices=['all', 'auto', 'none', 'snapshot-only']),
                    supported=dict(type='bool')
                )),
            )),
            source_cluster=dict(required=False, type='str'),
            destination_cluster=dict(required=False, type='str'),
            transferring_time_out=dict(required=False, type='int', default=300),
            quiesced_time_out=dict(required=False, type='int', default=300),
            clean_up_failure=dict(required=False, type='bool', default=False),
            validate_source_path=dict(required=False, type='bool', default=True),
            quick_resync=dict(required=False, type='bool'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            mutually_exclusive=[
                ('source_endpoint', 'source_cluster'),
                ('source_endpoint', 'source_path'),
                ('source_endpoint', 'source_volume'),
                ('source_endpoint', 'source_vserver'),
                ('destination_endpoint', 'destination_cluster'),
                ('destination_endpoint', 'destination_path'),
                ('destination_endpoint', 'destination_volume'),
                ('destination_endpoint', 'destination_vserver'),
                ('peer_options', 'source_hostname'),
                ('peer_options', 'source_username'),
                ('peer_options', 'source_password'),
                ('identity_preserve', 'identity_preservation')
            ],
            required_together=(['source_volume', 'destination_volume'],
                               ['source_vserver', 'destination_vserver'],
                               ['source_endpoint', 'destination_endpoint'],
                               ),
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.policy_type = None
        self.new_style = False
        # when deleting, ignore previous errors, but report them if delete fails
        self.previous_errors = []
        # setup later if required
        self.source_server = None
        # only for ElementSW -> ONTAP snapmirroring, validate if ElementSW SDK is available
        if self.parameters.get('connection_type') in ['elementsw_ontap', 'ontap_elementsw'] and HAS_SF_SDK is False:
            self.module.fail_json(msg="Unable to import the SolidFire Python SDK")

        self.src_rest_api = None
        self.src_use_rest = None
        self.set_source_peer()
        self.rest_api, self.use_rest = self.setup_rest()
        if not self.use_rest:
            self.server = self.setup_zapi()

    def set_source_peer(self):
        if self.parameters.get('source_hostname') is None and self.parameters.get('peer_options') is None:
            if self.parameters.get('connection_type') == 'ontap_elementsw':
                return self.module.fail_json(msg='Error: peer_options are required to identify ONTAP cluster with connection_type: ontap_elementsw')
            if self.parameters.get('connection_type') == 'elementsw_ontap':
                return self.module.fail_json(msg='Error: peer_options are required to identify SolidFire cluster with connection_type: elementsw_ontap')
        if self.parameters.get('source_hostname') is not None:
            # if source_hostname is present, peer_options is absent
            self.parameters['peer_options'] = dict(
                hostname=self.parameters.get('source_hostname'),
                username=self.parameters.get('source_username'),
                password=self.parameters.get('source_password'),
            )
        elif self.na_helper.safe_get(self.parameters, ['peer_options', 'hostname']):
            self.parameters['source_hostname'] = self.parameters['peer_options']['hostname']
        if 'peer_options' in self.parameters:
            netapp_utils.setup_host_options_from_module_params(
                self.parameters['peer_options'], self.module,
                netapp_utils.na_ontap_host_argument_spec_peer().keys())

    def setup_rest(self):
        unsupported_rest_properties = ['identity_preserve', 'max_transfer_rate']
        host_options = self.parameters['peer_options'] if self.parameters.get('connection_type') == 'ontap_elementsw' else None
        rest_api = netapp_utils.OntapRestAPI(self.module, host_options=host_options)
        rtype = self.parameters.get('relationship_type')
        if rtype not in (None, 'extended_data_protection', 'restore'):
            unsupported_rest_properties.append('relationship_type')
        used_unsupported_rest_properties = [x for x in unsupported_rest_properties if x in self.parameters]
        ontap_97_options = ['create_destination', 'source_cluster', 'destination_cluster']
        partially_supported_rest_properties = [(property, (9, 7)) for property in ontap_97_options]
        partially_supported_rest_properties.extend([('schedule', (9, 11, 1)), ('identity_preservation', (9, 11, 1))])
        use_rest, error = rest_api.is_rest_supported_properties(
            self.parameters, used_unsupported_rest_properties, partially_supported_rest_properties, report_error=True)
        if error is not None:
            if 'relationship_type' in error:
                error = error.replace('relationship_type', 'relationship_type: %s' % rtype)
            if 'schedule' in error:
                error += ' - With REST use the policy option to define a schedule.'
            self.module.fail_json(msg=error)

        if not use_rest and any(x in self.parameters for x in ontap_97_options):
            self.module.fail_json(msg='Error: %s' % rest_api.options_require_ontap_version(ontap_97_options, version='9.7', use_rest=use_rest))
        return rest_api, use_rest

    def setup_zapi(self):
        if self.parameters.get('identity_preservation'):
            self.module.fail_json(msg="Error: The option identity_preservation is supported only with REST.")
        if not netapp_utils.has_netapp_lib():
            self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
        host_options = self.parameters['peer_options'] if self.parameters.get('connection_type') == 'ontap_elementsw' else None
        return netapp_utils.setup_na_ontap_zapi(module=self.module, host_options=host_options)

    def set_element_connection(self, kind):
        if kind == 'source':
            elem = netapp_utils.create_sf_connection(module=self.module, host_options=self.parameters['peer_options'])
        elif kind == 'destination':
            elem = netapp_utils.create_sf_connection(module=self.module, host_options=self.parameters)
        elementsw_helper = NaElementSWModule(elem)
        return elementsw_helper, elem

    def snapmirror_get_iter(self, destination=None):
        """
        Compose NaElement object to query current SnapMirror relations using destination-path
        SnapMirror relation for a destination path is unique
        :return: NaElement object for SnapMirror-get-iter
        """
        snapmirror_get_iter = netapp_utils.zapi.NaElement('snapmirror-get-iter')
        query = netapp_utils.zapi.NaElement('query')
        snapmirror_info = netapp_utils.zapi.NaElement('snapmirror-info')
        if destination is None:
            destination = self.parameters['destination_path']
        snapmirror_info.add_new_child('destination-location', destination)
        query.add_child_elem(snapmirror_info)
        snapmirror_get_iter.add_child_elem(query)
        return snapmirror_get_iter

    def snapmirror_get(self, destination=None):
        """
        Get current SnapMirror relations
        :return: Dictionary of current SnapMirror details if query successful, else None
        """
        if self.use_rest:
            return self.snapmirror_get_rest(destination)

        snapmirror_get_iter = self.snapmirror_get_iter(destination)
        try:
            result = self.server.invoke_successfully(snapmirror_get_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching snapmirror info: %s' % to_native(error),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) > 0:
            snapmirror_info = result.get_child_by_name('attributes-list').get_child_by_name(
                'snapmirror-info')
            snap_info = {}
            snap_info['mirror_state'] = snapmirror_info.get_child_content('mirror-state')
            snap_info['status'] = snapmirror_info.get_child_content('relationship-status')
            snap_info['schedule'] = snapmirror_info.get_child_content('schedule')
            snap_info['policy'] = snapmirror_info.get_child_content('policy')
            snap_info['relationship_type'] = snapmirror_info.get_child_content('relationship-type')
            snap_info['current_transfer_type'] = snapmirror_info.get_child_content('current-transfer-type')
            snap_info['source_path'] = snapmirror_info.get_child_content('source-location')
            if snapmirror_info.get_child_by_name('max-transfer-rate'):
                snap_info['max_transfer_rate'] = int(snapmirror_info.get_child_content('max-transfer-rate'))
            if snapmirror_info.get_child_by_name('last-transfer-error'):
                snap_info['last_transfer_error'] = snapmirror_info.get_child_content('last-transfer-error')
            if snapmirror_info.get_child_by_name('is-healthy') is not None:
                snap_info['is_healthy'] = self.na_helper.get_value_for_bool(True, snapmirror_info.get_child_content('is-healthy'))
            if snapmirror_info.get_child_by_name('unhealthy-reason'):
                snap_info['unhealthy_reason'] = snapmirror_info.get_child_content('unhealthy-reason')
            if snap_info['schedule'] is None:
                snap_info['schedule'] = ""
            return snap_info
        return None

    def wait_for_idle_status(self):
        # sleep for a maximum of X seconds (with a default of 5 minutes), in 30 seconds increments
        transferring_time_out = self.parameters['transferring_time_out']
        increment = 30
        if transferring_time_out <= 0:
            return self.snapmirror_get()
        for __ in range(0, transferring_time_out, increment):
            time.sleep(increment)
            current = self.snapmirror_get()
            if current and current['status'] != 'transferring':
                return current
        self.module.warn('SnapMirror relationship is still transferring after %d seconds.' % transferring_time_out)
        return current

    def wait_for_quiesced_status(self):
        # sleep for a maximum of X seconds (with a default of 5 minutes), in 10 seconds increments
        quiesced_time_out = self.parameters['quiesced_time_out']
        increment = 10
        for __ in range(0, quiesced_time_out, increment):
            time.sleep(increment)
            sm_info = self.snapmirror_get()
            if sm_info and (sm_info['status'] == 'quiesced' or sm_info['mirror_state'] == 'paused'):
                return
        self.module.fail_json(msg='Taking a long time to quiesce SnapMirror relationship after %d seconds, try again later' % quiesced_time_out)

    def check_if_remote_volume_exists(self):
        """
        Validate existence of source volume
        :return: True if volume exists, False otherwise
        """
        self.set_source_cluster_connection()

        if self.src_use_rest:
            return self.check_if_remote_volume_exists_rest()

        # do a get volume to check if volume exists or not
        volume_info = netapp_utils.zapi.NaElement('volume-get-iter')
        volume_attributes = netapp_utils.zapi.NaElement('volume-attributes')
        volume_id_attributes = netapp_utils.zapi.NaElement('volume-id-attributes')
        volume_id_attributes.add_new_child('name', self.parameters['source_volume'])
        # if source_volume is present, then source_vserver is also guaranteed to be present
        volume_id_attributes.add_new_child('vserver-name', self.parameters['source_vserver'])
        volume_attributes.add_child_elem(volume_id_attributes)
        query = netapp_utils.zapi.NaElement('query')
        query.add_child_elem(volume_attributes)
        volume_info.add_child_elem(query)
        try:
            result = self.source_server.invoke_successfully(volume_info, True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching source volume details %s: %s'
                                  % (self.parameters['source_volume'], to_native(error)),
                                  exception=traceback.format_exc())
        return bool(result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0)

    def get_svm_from_destination_vserver_or_path(self):
        svm_name = self.parameters.get('destination_vserver')
        if svm_name is None:
            path = self.parameters.get('destination_path')
            if path is not None:
                # if there is no ':' in path, it returns path
                svm_name = path.split(':', 1)[0]
        return svm_name

    def set_initialization_state(self):
        """
        return:
        'snapmirrored' for relationships with a policy of type 'async'
        'in_sync' for relationships with a policy of type 'sync'
        """
        policy_type = 'async'                               # REST defaults to Asynchronous
        if self.na_helper.safe_get(self.parameters, ['destination_endpoint', 'consistency_group_volumes']) is not None:
            # except for consistency groups
            policy_type = 'sync'
        if self.parameters.get('policy') is not None:
            svm_name = self.get_svm_from_destination_vserver_or_path()
            policy_type, error = self.snapmirror_policy_rest_get(self.parameters['policy'], svm_name)
            if error:
                error = 'Error fetching SnapMirror policy: %s' % error
            elif policy_type is None:
                error = 'Error: cannot find policy %s for vserver %s' % (self.parameters['policy'], svm_name)
            elif policy_type not in ('async', 'sync'):
                error = 'Error: unexpected type: %s for policy %s for vserver %s' % (policy_type, self.parameters['policy'], svm_name)
            if error:
                self.module.fail_json(msg=error)
        return 'snapmirrored' if policy_type == 'async' else 'in_sync'

    @staticmethod
    def string_or_none(value):
        """ REST expect null for "" """
        return value or None

    def get_create_body(self):
        """
        It gathers the required information for snapmirror create
        """
        initialized = False
        body = {
            "source": self.na_helper.filter_out_none_entries(self.parameters['source_endpoint']),
            "destination": self.na_helper.filter_out_none_entries(self.parameters['destination_endpoint'])
        }
        if self.na_helper.safe_get(self.parameters, ['create_destination', 'enabled']):     # testing for True
            body['create_destination'] = self.na_helper.filter_out_none_entries(self.parameters['create_destination'])
            if self.parameters['initialize']:
                body['state'] = self.set_initialization_state()
                initialized = True
        if self.na_helper.safe_get(self.parameters, ['policy']) is not None:
            body['policy'] = {'name': self.parameters['policy']}
        if self.na_helper.safe_get(self.parameters, ['schedule']) is not None:
            body['transfer_schedule'] = {'name': self.string_or_none(self.parameters['schedule'])}
        if self.parameters.get('identity_preservation'):
            body['identity_preservation'] = self.parameters['identity_preservation']
        return body, initialized

    def snapmirror_create(self):
        """
        Create a SnapMirror relationship
        """
        if self.parameters.get('peer_options') and self.parameters.get('source_volume') and not self.check_if_remote_volume_exists():
            self.module.fail_json(msg='Source volume does not exist. Please specify a volume that exists')
        if self.use_rest:
            return self.snapmirror_rest_create()

        options = {'source-location': self.parameters['source_path'],
                   'destination-location': self.parameters['destination_path']}
        snapmirror_create = netapp_utils.zapi.NaElement.create_node_with_children('snapmirror-create', **options)
        if self.parameters.get('relationship_type'):
            snapmirror_create.add_new_child('relationship-type', self.parameters['relationship_type'])
        if self.parameters.get('schedule'):
            snapmirror_create.add_new_child('schedule', self.parameters['schedule'])
        if self.parameters.get('policy'):
            snapmirror_create.add_new_child('policy', self.parameters['policy'])
        if self.parameters.get('max_transfer_rate'):
            snapmirror_create.add_new_child('max-transfer-rate', str(self.parameters['max_transfer_rate']))
        if self.parameters.get('identity_preserve'):
            snapmirror_create.add_new_child('identity-preserve', self.na_helper.get_value_for_bool(False, self.parameters['identity_preserve']))
        try:
            self.server.invoke_successfully(snapmirror_create, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error creating SnapMirror %s' % to_native(error),
                                  exception=traceback.format_exc())
        if self.parameters['initialize']:
            self.snapmirror_initialize()

    def set_source_cluster_connection(self):
        """
        Setup ontap ZAPI or REST server connection for source hostname
        :return: None
        """
        self.src_rest_api = netapp_utils.OntapRestAPI(self.module, host_options=self.parameters['peer_options'])
        unsupported_rest_properties = ['identity_preserve', 'max_transfer_rate', 'schedule']
        rtype = self.parameters.get('relationship_type')
        if rtype not in (None, 'extended_data_protection', 'restore'):
            unsupported_rest_properties.append('relationship_type')
        used_unsupported_rest_properties = [x for x in unsupported_rest_properties if x in self.parameters]
        self.src_use_rest, error = self.src_rest_api.is_rest(used_unsupported_rest_properties)
        if error is not None:
            if 'relationship_type' in error:
                error = error.replace('relationship_type', 'relationship_type: %s' % rtype)
            self.module.fail_json(msg=error)
        if not self.src_use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            self.source_server = netapp_utils.setup_na_ontap_zapi(module=self.module, host_options=self.parameters['peer_options'])

    def delete_snapmirror(self, relationship_type, mirror_state):
        """
        Delete a SnapMirror relationship
        #1. Quiesce the SnapMirror relationship at destination
        #2. Break the SnapMirror relationship at the destination
        #3. Release the SnapMirror at source
        #4. Delete SnapMirror at destination
        """
        # Quiesce and Break at destination
        if relationship_type not in ['load_sharing', 'vault'] and mirror_state not in ['uninitialized', 'broken-off', 'broken_off']:
            self.snapmirror_break(before_delete=True)
        # if source is ONTAP, release the destination at source cluster
        # if the source_hostname is unknown, do not run snapmirror_release
        if self.parameters.get('peer_options') is not None and self.parameters.get('connection_type') != 'elementsw_ontap' and not self.use_rest:
            self.set_source_cluster_connection()
            if self.get_destination():
                # Release at source
                # Note: REST remove the source from destination, so not required to release from source for REST
                self.snapmirror_release()
        # Delete at destination
        self.snapmirror_delete()

    def snapmirror_quiesce(self):
        """
        Quiesce SnapMirror relationship - disable all future transfers to this destination
        """
        if self.use_rest:
            return self.snapmirror_quiesce_rest()

        options = {'destination-location': self.parameters['destination_path']}

        snapmirror_quiesce = netapp_utils.zapi.NaElement.create_node_with_children(
            'snapmirror-quiesce', **options)
        try:
            self.server.invoke_successfully(snapmirror_quiesce, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error quiescing SnapMirror: %s'
                                  % (to_native(error)), exception=traceback.format_exc())
        # checking if quiesce was passed successfully
        self.wait_for_quiesced_status()

    def snapmirror_delete(self):
        """
        Delete SnapMirror relationship at destination cluster
        """
        if self.use_rest:
            return self.snapmirror_delete_rest()
        options = {'destination-location': self.parameters['destination_path']}

        snapmirror_delete = netapp_utils.zapi.NaElement.create_node_with_children(
            'snapmirror-destroy', **options)
        try:
            self.server.invoke_successfully(snapmirror_delete,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            msg = 'Error deleting SnapMirror: %s' % to_native(error)
            if self.previous_errors:
                msg += '.  Previous error(s): %s' % ' -- '.join(self.previous_errors)
            self.module.fail_json(msg=msg, exception=traceback.format_exc())

    def snapmirror_break(self, destination=None, before_delete=False):
        """
        Break SnapMirror relationship at destination cluster
        #1. Quiesce the SnapMirror relationship at destination
        #2. Break the SnapMirror relationship at the destination
        """
        self.snapmirror_quiesce()

        if self.use_rest:
            if self.parameters['current_mirror_state'] == 'broken_off' or self.parameters['current_transfer_status'] == 'transferring':
                self.na_helper.changed = False
                self.module.fail_json(msg="snapmirror data are transferring")
            return self.snapmirror_mod_init_resync_break_quiesce_resume_rest(state="broken_off", before_delete=before_delete)
        if destination is None:
            destination = self.parameters['destination_path']
        options = {'destination-location': destination}
        snapmirror_break = netapp_utils.zapi.NaElement.create_node_with_children(
            'snapmirror-break', **options)
        try:
            self.server.invoke_successfully(snapmirror_break,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            msg = 'Error breaking SnapMirror relationship: %s' % to_native(error)
            if before_delete:
                # record error but proceed with deletion
                self.previous_errors.append(msg)
            else:
                self.module.fail_json(msg=msg, exception=traceback.format_exc())

    def snapmirror_release(self):
        """
        Release SnapMirror relationship from source cluster
        """
        # if it's REST call, then not required to run release
        if self.use_rest:
            return
        options = {'destination-location': self.parameters['destination_path'],
                   'relationship-info-only': self.na_helper.get_value_for_bool(False, self.parameters['relationship_info_only'])}
        snapmirror_release = netapp_utils.zapi.NaElement.create_node_with_children(
            'snapmirror-release', **options)
        try:
            self.source_server.invoke_successfully(snapmirror_release,
                                                   enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error releasing SnapMirror relationship: %s'
                                  % (to_native(error)),
                                  exception=traceback.format_exc())

    def snapmirror_abort(self):
        """
        Abort a SnapMirror relationship in progress
        """
        if self.use_rest:
            return self.snapmirror_abort_rest()

        options = {'destination-location': self.parameters['destination_path']}
        snapmirror_abort = netapp_utils.zapi.NaElement.create_node_with_children(
            'snapmirror-abort', **options)
        try:
            self.server.invoke_successfully(snapmirror_abort,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error aborting SnapMirror relationship: %s'
                                  % (to_native(error)),
                                  exception=traceback.format_exc())

    def snapmirror_initialize(self, current=None):
        """
        Initialize SnapMirror based on relationship state
        """
        if current and current['status'] == 'transferring' or self.parameters.get('current_transfer_status') == 'transferring':
            # Operation already in progress, let's wait for it to end
            current = self.wait_for_idle_status()
        if not current:
            current = self.snapmirror_get()
        if self.use_rest:
            if current['mirror_state'] == 'uninitialized' and current['status'] != 'transferring':
                state = 'in_sync' if self.policy_type == 'sync' else 'snapmirrored'
                self.snapmirror_mod_init_resync_break_quiesce_resume_rest(state=state)
                self.wait_for_idle_status()
            return
        if current['mirror_state'] != 'snapmirrored':
            initialize_zapi = 'snapmirror-initialize'
            if self.parameters.get('relationship_type') == 'load_sharing':
                initialize_zapi = 'snapmirror-initialize-ls-set'
                options = {'source-location': self.parameters['source_path']}
            else:
                options = {'destination-location': self.parameters['destination_path']}
            snapmirror_init = netapp_utils.zapi.NaElement.create_node_with_children(
                initialize_zapi, **options)
            try:
                self.server.invoke_successfully(snapmirror_init,
                                                enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error initializing SnapMirror: %s'
                                      % (to_native(error)),
                                      exception=traceback.format_exc())
            self.wait_for_idle_status()

    def snapmirror_resync(self, current=None):
        """
        resync SnapMirror based on relationship state
        """
        if self.use_rest:
            state = 'in_sync' if self.policy_type == 'sync' else 'snapmirrored'
            quick_resync = False
            if 'quick_resync' in self.parameters:
                quick_resync = self.parameters.get('quick_resync')
            self.snapmirror_mod_init_resync_break_quiesce_resume_rest(state=state, quick_resync=quick_resync)
        else:
            options = {'destination-location': self.parameters['destination_path']}
            snapmirror_resync = netapp_utils.zapi.NaElement.create_node_with_children('snapmirror-resync', **options)
            try:
                self.server.invoke_successfully(snapmirror_resync, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error resyncing SnapMirror relationship: %s' % (to_native(error)),
                                      exception=traceback.format_exc())
        self.wait_for_idle_status()

    def snapmirror_resume(self):
        """
        resume SnapMirror based on relationship state
        """
        if self.use_rest:
            state = 'in_sync' if self.policy_type == 'sync' else 'snapmirrored'
            return self.snapmirror_mod_init_resync_break_quiesce_resume_rest(state=state)

        options = {'destination-location': self.parameters['destination_path']}
        snapmirror_resume = netapp_utils.zapi.NaElement.create_node_with_children('snapmirror-resume', **options)
        try:
            self.server.invoke_successfully(snapmirror_resume, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error resuming SnapMirror relationship: %s' % (to_native(error)), exception=traceback.format_exc())

    def snapmirror_restore(self):
        """
        restore SnapMirror based on relationship state
        """
        if self.use_rest:
            return self.snapmirror_restore_rest()

        options = {'destination-location': self.parameters['destination_path'],
                   'source-location': self.parameters['source_path']}
        if self.parameters.get('source_snapshot'):
            options['source-snapshot'] = self.parameters['source_snapshot']
        if self.parameters.get('clean_up_failure'):
            # only send it when True
            options['clean-up-failure'] = self.na_helper.get_value_for_bool(False, self.parameters['clean_up_failure'])
        snapmirror_restore = netapp_utils.zapi.NaElement.create_node_with_children('snapmirror-restore', **options)
        try:
            self.server.invoke_successfully(snapmirror_restore, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error restoring SnapMirror relationship: %s' % (to_native(error)), exception=traceback.format_exc())

    def snapmirror_modify(self, modify):
        """
        Modify SnapMirror schedule or policy
        """
        if self.use_rest:
            return self.snapmirror_mod_init_resync_break_quiesce_resume_rest(modify=modify)

        options = {'destination-location': self.parameters['destination_path']}
        snapmirror_modify = netapp_utils.zapi.NaElement.create_node_with_children(
            'snapmirror-modify', **options)
        param_to_zapi = {
            'schedule': 'schedule',
            'policy': 'policy',
            'max_transfer_rate': 'max-transfer-rate'
        }
        for param_key, value in modify.items():
            snapmirror_modify.add_new_child(param_to_zapi[param_key], str(value))
        try:
            self.server.invoke_successfully(snapmirror_modify,
                                            enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error modifying SnapMirror schedule or policy: %s'
                                  % (to_native(error)),
                                  exception=traceback.format_exc())

    def snapmirror_update(self, relationship_type):
        """
        Update data in destination endpoint
        """
        if self.use_rest:
            return self.snapmirror_update_rest()

        zapi = 'snapmirror-update'
        options = {'destination-location': self.parameters['destination_path']}
        if relationship_type == 'load_sharing':
            zapi = 'snapmirror-update-ls-set'
            options = {'source-location': self.parameters['source_path']}

        snapmirror_update = netapp_utils.zapi.NaElement.create_node_with_children(
            zapi, **options)
        try:
            self.server.invoke_successfully(snapmirror_update, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error updating SnapMirror: %s'
                                  % (to_native(error)),
                                  exception=traceback.format_exc())

    @staticmethod
    def new_option(option, prefix):
        new_option_name = option[len(prefix):]
        if new_option_name == 'vserver':
            new_option_name = 'path (or svm)'
        elif new_option_name == 'volume':
            new_option_name = 'path'
        return '%sendpoint:%s' % (prefix, new_option_name)

    def too_old(self, minimum_generation, minimum_major):
        return not self.rest_api.meets_rest_minimum_version(self.use_rest, minimum_generation, minimum_major, 0)

    def set_new_style(self):
        # if source_endpoint or destination_endpoint if present, both are required
        # then sanitize inputs to support new style
        if not self.parameters.get('destination_endpoint') or not self.parameters.get('source_endpoint'):
            self.module.fail_json(msg='Missing parameters: Source endpoint or Destination endpoint')
        # sanitize inputs
        self.parameters['source_endpoint'] = self.na_helper.filter_out_none_entries(self.parameters['source_endpoint'])
        self.parameters['destination_endpoint'] = self.na_helper.filter_out_none_entries(self.parameters['destination_endpoint'])
        # options requiring 9.7 or better, and REST
        ontap_97_options = ['cluster', 'ipspace']
        if self.too_old(9, 7) and any(x in self.parameters['source_endpoint'] for x in ontap_97_options):
            self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version(ontap_97_options, version='9.7', use_rest=self.use_rest))
        if self.too_old(9, 7) and any(x in self.parameters['destination_endpoint'] for x in ontap_97_options):
            self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version(ontap_97_options, version='9.7', use_rest=self.use_rest))
        # options requiring 9.8 or better, and REST
        ontap_98_options = ['consistency_group_volumes']
        if self.too_old(9, 8) and any(x in self.parameters['source_endpoint'] for x in ontap_98_options):
            self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version(ontap_98_options, version='9.8', use_rest=self.use_rest))
        if self.too_old(9, 8) and any(x in self.parameters['destination_endpoint'] for x in ontap_98_options):
            self.module.fail_json(msg='Error: %s' % self.rest_api.options_require_ontap_version(ontap_98_options, version='9.8', use_rest=self.use_rest))
        # fill in old style parameters
        self.parameters['source_cluster'] = self.na_helper.safe_get(self.parameters, ['source_endpoint', 'cluster'])
        self.parameters['source_path'] = self.na_helper.safe_get(self.parameters, ['source_endpoint', 'path'])
        self.parameters['source_vserver'] = self.na_helper.safe_get(self.parameters, ['source_endpoint', 'svm'])
        self.parameters['destination_cluster'] = self.na_helper.safe_get(self.parameters, ['destination_endpoint', 'cluster'])
        self.parameters['destination_path'] = self.na_helper.safe_get(self.parameters, ['destination_endpoint', 'path'])
        self.parameters['destination_vserver'] = self.na_helper.safe_get(self.parameters, ['destination_endpoint', 'svm'])
        self.new_style = True

    def set_endpoints(self):
        # use new structures for source and destination endpoints
        for location in ('source', 'destination'):
            endpoint = '%s_endpoint' % location
            self.parameters[endpoint] = {}
            # skipping svm for now, as it is not accepted and not needed with path
            # for old, new in (('path', 'path'), ('vserver', 'svm'), ('cluster', 'cluster')):
            for old, new in (('path', 'path'), ('cluster', 'cluster')):
                value = self.parameters.get('%s_%s' % (location, old))
                if value is not None:
                    self.parameters[endpoint][new] = value

    def check_parameters(self):
        """
        Validate parameters and fail if one or more required params are missing
        Update source and destination path from vserver and volume parameters
        """
        for option in ['source_cluster', 'source_path', 'source_volume', 'source_vserver']:
            if option in self.parameters:
                self.module.warn('option: %s is deprecated, please use %s' % (option, self.new_option(option, 'source_')))
        for option in ['destination_cluster', 'destination_path', 'destination_volume', 'destination_vserver']:
            if option in self.parameters:
                self.module.warn('option: %s is deprecated, please use %s' % (option, self.new_option(option, 'destination_')))

        if self.parameters.get('source_endpoint') or self.parameters.get('destination_endpoint'):
            self.set_new_style()
        if self.parameters.get('source_path') or self.parameters.get('destination_path'):
            if (not self.parameters.get('destination_path') or not self.parameters.get('source_path'))\
               and (self.parameters['state'] == 'present' or (self.parameters['state'] == 'absent' and not self.parameters.get('destination_path'))):
                self.module.fail_json(msg='Missing parameters: Source path or Destination path')
        elif self.parameters.get('source_volume'):
            if not self.parameters.get('source_vserver') or not self.parameters.get('destination_vserver'):
                self.module.fail_json(msg='Missing parameters: source vserver or destination vserver or both')
            self.parameters['source_path'] = self.parameters['source_vserver'] + ":" + self.parameters['source_volume']
            self.parameters['destination_path'] = self.parameters['destination_vserver'] + ":" +\
                self.parameters['destination_volume']
        elif self.parameters.get('source_vserver') and self.parameters.get('source_endpoint') is None:
            self.parameters['source_path'] = self.parameters['source_vserver'] + ":"
            self.parameters['destination_path'] = self.parameters['destination_vserver'] + ":"

        if self.use_rest and not self.new_style:
            self.set_endpoints()

    def get_destination(self):
        """
        get the destination info
        # Note: REST module to get_destination is not required as it's used in only ZAPI.
        """
        result = None
        get_dest_iter = netapp_utils.zapi.NaElement('snapmirror-get-destination-iter')
        query = netapp_utils.zapi.NaElement('query')
        snapmirror_dest_info = netapp_utils.zapi.NaElement('snapmirror-destination-info')
        snapmirror_dest_info.add_new_child('destination-location', self.parameters['destination_path'])
        query.add_child_elem(snapmirror_dest_info)
        get_dest_iter.add_child_elem(query)
        try:
            result = self.source_server.invoke_successfully(get_dest_iter, enable_tunneling=True)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg='Error fetching snapmirror destinations info: %s' % to_native(error),
                                  exception=traceback.format_exc())
        if result.get_child_by_name('num-records') and \
                int(result.get_child_content('num-records')) > 0:
            return True
        return None

    @staticmethod
    def element_source_path_format_matches(value):
        return re.match(pattern=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\/lun\/[0-9]+",
                        string=value)

    def check_elementsw_parameters(self, kind='source'):
        """
        Validate all ElementSW cluster parameters required for managing the SnapMirror relationship
        Validate if both source and destination paths are present
        Validate if source_path follows the required format
        Validate SVIP
        Validate if ElementSW volume exists
        :return: None
        """
        path = None
        if kind == 'destination':
            path = self.parameters.get('destination_path')
        elif kind == 'source':
            path = self.parameters.get('source_path')
        if path is None:
            self.module.fail_json(msg="Error: Missing required parameter %s_path for "
                                      "connection_type %s" % (kind, self.parameters['connection_type']))
        if NetAppONTAPSnapmirror.element_source_path_format_matches(path) is None:
            self.module.fail_json(msg="Error: invalid %s_path %s. "
                                      "If the path is a ElementSW cluster, the value should be of the format"
                                      " <Element_SVIP>:/lun/<Element_VOLUME_ID>" % (kind, path))
        # validate source_path
        elementsw_helper, elem = self.set_element_connection(kind)
        self.validate_elementsw_svip(path, elem)
        self.check_if_elementsw_volume_exists(path, elementsw_helper)

    def validate_elementsw_svip(self, path, elem):
        """
        Validate ElementSW cluster SVIP
        :return: None
        """
        result = None
        try:
            result = elem.get_cluster_info()
        except solidfire.common.ApiServerError as err:
            self.module.fail_json(msg="Error fetching SVIP", exception=to_native(err))
        if result and result.cluster_info.svip:
            cluster_svip = result.cluster_info.svip
            svip = path.split(':')[0]  # split IP address from source_path
            if svip != cluster_svip:
                self.module.fail_json(msg="Error: Invalid SVIP")

    def check_if_elementsw_volume_exists(self, path, elementsw_helper):
        """
        Check if remote ElementSW volume exists
        :return: None
        """
        volume_id, vol_id = None, path.split('/')[-1]
        try:
            volume_id = elementsw_helper.volume_id_exists(int(vol_id))
        except solidfire.common.ApiServerError as err:
            self.module.fail_json(msg="Error fetching Volume details", exception=to_native(err))

        if volume_id is None:
            self.module.fail_json(msg="Error: Source volume does not exist in the ElementSW cluster")

    def check_health(self):
        """
        Checking the health of the snapmirror
        """
        if self.parameters.get('connection_type') == 'ontap_elementsw':
            return
        current = self.snapmirror_get()
        if current is not None and not current.get('is_healthy', True):
            msg = ['SnapMirror relationship exists but is not healthy.']
            if 'unhealthy_reason' in current:
                msg.append('Unhealthy reason: %s' % current['unhealthy_reason'])
            if 'last_transfer_error' in current:
                msg.append('Last transfer error: %s' % current['last_transfer_error'])
            self.module.warn('  '.join(msg))

    def check_if_remote_volume_exists_rest(self):
        """
        Check the remote volume exists using REST
        """
        if self.src_use_rest:
            if self.parameters.get('source_volume') is not None and self.parameters.get('source_vserver') is not None:
                volume_name = self.parameters['source_volume']
                svm_name = self.parameters['source_vserver']
                options = {'name': volume_name, 'svm.name': svm_name, 'fields': 'name,svm.name'}
                api = 'storage/volumes'
                record, error = rest_generic.get_one_record(self.src_rest_api, api, options)
                if error:
                    self.module.fail_json(msg='Error fetching source volume: %s' % error)
                return record is not None
            return False
        self.module.fail_json(msg='REST is not supported on Source')

    def snapmirror_restore_rest(self):
        ''' snapmirror restore using rest '''
        # Use the POST /api/snapmirror/relationships REST API call with the property "restore=true" to create the SnapMirror restore relationship
        # Use the POST /api/snapmirror/relationships/{relationship.uuid}/transfers REST API call to start the restore transfer on the SnapMirror relationship
        # run this API calls on Source cluster
        # if the source_hostname is unknown, do not run snapmirror_restore
        body = {'destination.path': self.parameters['destination_path'], 'source.path': self.parameters['source_path'], 'restore': 'true'}
        api = 'snapmirror/relationships'
        dummy, error = rest_generic.post_async(self.rest_api, api, body, timeout=120)
        if error:
            self.module.fail_json(msg='Error restoring SnapMirror: %s' % to_native(error), exception=traceback.format_exc())
        relationship_uuid = self.get_relationship_uuid()
        # REST API call to start the restore transfer on the SnapMirror relationship
        if relationship_uuid is None:
            self.module.fail_json(msg="Error restoring SnapMirror: unable to get UUID for the SnapMirror relationship.")

        body = {'source_snapshot': self.parameters['source_snapshot']} if self.parameters.get('source_snapshot') else {}
        api = 'snapmirror/relationships/%s/transfers' % relationship_uuid
        dummy, error = rest_generic.post_async(self.rest_api, api, body, timeout=60, job_timeout=120)
        if error:
            self.module.fail_json(msg='Error restoring SnapMirror Transfer: %s' % to_native(error), exception=traceback.format_exc())

    def get_relationship_uuid(self, after_create=True):
        # this may be called after a create including restore, so we may need to fetch the data
        if after_create and self.parameters.get('uuid') is None:
            self.snapmirror_get()
        return self.parameters.get('uuid')

    def snapmirror_mod_init_resync_break_quiesce_resume_rest(self, state=None, modify=None, before_delete=False, quick_resync=False):
        """
        To perform SnapMirror modify, init, resume, resync and break.
        1. Modify only update SnapMirror policy which passes the policy in body.
        2. To perform SnapMirror init - state=in_sync when type=sync otherwise state=snapmirrored and mirror_state=uninitialized.
        3. To perform SnapMirror resync - state=snapmirrored and mirror_state=broken_off.
        4. To perform SnapMirror break -  state=broken_off and transfer_state not transferring.
        5. To perform SnapMirror quiesce - state=pause and mirror_state not broken_off.
        6. To perform SnapMirror resume - state=snapmirrored.
        """
        uuid = self.get_relationship_uuid()
        if uuid is None:
            self.module.fail_json(msg="Error in updating SnapMirror relationship: unable to get UUID for the SnapMirror relationship.")

        body = {}
        if quick_resync:
            body['quick_resync'] = self.parameters.get('quick_resync')
        if state is not None:
            body["state"] = state
        elif modify:
            for key in modify:
                if key == 'policy':
                    body[key] = {"name": modify[key]}
                elif key == 'schedule':
                    body['transfer_schedule'] = {"name": self.string_or_none(modify[key])}
                else:
                    self.module.warn(msg="Unexpected key in modify: %s, value: %s" % (key, modify[key]))
        else:
            self.na_helper.changed = False
            return
        api = 'snapmirror/relationships'
        dummy, error = rest_generic.patch_async(self.rest_api, api, uuid, body)
        if error:
            msg = 'Error patching SnapMirror: %s: %s' % (body, to_native(error))
            if before_delete:
                self.previous_errors.append(msg)
            else:
                self.module.fail_json(msg=msg, exception=traceback.format_exc())

    def snapmirror_update_rest(self):
        """
        Perform an update on the relationship using POST on /snapmirror/relationships/{relationship.uuid}/transfers
        """
        uuid = self.get_relationship_uuid()
        if uuid is None:
            self.module.fail_json(msg="Error in updating SnapMirror relationship: unable to get UUID for the SnapMirror relationship.")
        api = 'snapmirror/relationships/%s/transfers' % uuid
        body = {}
        dummy, error = rest_generic.post_async(self.rest_api, api, body)
        if error:
            self.module.fail_json(msg='Error updating SnapMirror relationship: %s:' % to_native(error), exception=traceback.format_exc())

    def snapmirror_abort_rest(self):
        """
        Abort a SnapMirror relationship in progress using REST
        """
        uuid = self.get_relationship_uuid(after_create=False)
        transfer_uuid = self.parameters.get('transfer_uuid')
        if uuid is None or transfer_uuid is None:
            self.module.fail_json(msg="Error in aborting SnapMirror: unable to get either uuid: %s or transfer_uuid: %s." % (uuid, transfer_uuid))
        api = 'snapmirror/relationships/%s/transfers' % uuid
        body = {"state": "aborted"}
        dummy, error = rest_generic.patch_async(self.rest_api, api, transfer_uuid, body)
        if error:
            self.module.fail_json(msg='Error aborting SnapMirror: %s' % to_native(error), exception=traceback.format_exc())

    def snapmirror_quiesce_rest(self):
        """
        SnapMirror quiesce using REST
        """
        if (self.parameters['current_mirror_state'] == 'paused'
                or self.parameters['current_mirror_state'] == 'broken_off'
                or self.parameters['current_transfer_status'] == 'transferring'):
            return
        self.snapmirror_mod_init_resync_break_quiesce_resume_rest(state="paused")
        self.wait_for_quiesced_status()

    def snapmirror_delete_rest(self):
        """
        Delete SnapMirror relationship at destination cluster using REST
        """
        uuid = self.get_relationship_uuid(after_create=False)
        if uuid is None:
            self.module.fail_json(msg='Error in deleting SnapMirror: %s, unable to get UUID for the SnapMirror relationship.' % uuid)
        api = 'snapmirror/relationships'
        query = dict(return_timeout=120)
        retry = 3
        while retry > 0:
            dummy, error = rest_generic.delete_async(self.rest_api, api, uuid, query)
            if error and 'Timeout error: Process still running' in error:
                time.sleep(120)
                retry -= 1
            elif error:
                msg = 'Error deleting SnapMirror: %s' % to_native(error)
                if self.previous_errors:
                    msg += '.  Previous error(s): %s' % ' -- '.join(self.previous_errors)
                self.module.fail_json(msg=msg, exception=traceback.format_exc())
            else:
                return

    def snapmirror_rest_create(self):
        """
        Create a SnapMirror relationship using REST
        """
        body, initialized = self.get_create_body()
        api = 'snapmirror/relationships'
        dummy, error = rest_generic.post_async(self.rest_api, api, body, timeout=120)
        if error:
            self.module.fail_json(msg='Error creating SnapMirror: %s' % to_native(error), exception=traceback.format_exc())
        if self.parameters['initialize']:
            if initialized:
                self.wait_for_idle_status()
            else:
                self.snapmirror_initialize()

    def snapmirror_get_rest(self, destination=None):
        """ Get the current snapmirror info """
        if destination is None and "destination_path" in self.parameters:
            # check_param get the value if it's given in other format like destination_endpoint etc..
            destination = self.parameters['destination_path']

        api = 'snapmirror/relationships'
        fields = 'uuid,state,transfer.state,transfer.uuid,policy.name,policy.type,unhealthy_reason.message,healthy,source'
        if 'schedule' in self.parameters:
            fields += ',transfer_schedule'
        options = {'destination.path': destination, 'fields': fields}
        record, error = rest_generic.get_one_record(self.rest_api, api, options)
        if error:
            self.module.fail_json(msg="Error getting SnapMirror %s: %s" % (destination, to_native(error)),
                                  exception=traceback.format_exc())
        if record is not None:
            snap_info = {}
            self.parameters['uuid'] = self.na_helper.safe_get(record, ['uuid'])
            self.parameters['transfer_uuid'] = self.na_helper.safe_get(record, ['transfer', 'uuid'])
            self.parameters['current_mirror_state'] = self.na_helper.safe_get(record, ['state'])
            snap_info['mirror_state'] = self.na_helper.safe_get(record, ['state'])
            snap_info['status'] = self.na_helper.safe_get(record, ['transfer', 'state'])
            self.parameters['current_transfer_status'] = self.na_helper.safe_get(record, ['transfer', 'state'])
            snap_info['policy'] = self.na_helper.safe_get(record, ['policy', 'name'])
            self.policy_type = self.na_helper.safe_get(record, ['policy', 'type'])
            # REST API supports only Extended Data Protection (XDP) SnapMirror relationship
            snap_info['relationship_type'] = 'extended_data_protection'
            # initialized to avoid name keyerror
            snap_info['current_transfer_type'] = ""
            snap_info['max_transfer_rate'] = ""
            if 'unhealthy_reason' in record:
                snap_info['last_transfer_error'] = self.na_helper.safe_get(record, ['unhealthy_reason'])
                snap_info['unhealthy_reason'] = self.na_helper.safe_get(record, ['unhealthy_reason'])
            snap_info['is_healthy'] = self.na_helper.safe_get(record, ['healthy'])
            snap_info['source_path'] = self.na_helper.safe_get(record, ['source', 'path'])
            # if the field is absent, assume ""
            snap_info['schedule'] = self.na_helper.safe_get(record, ['transfer_schedule', 'name']) or ""
            return snap_info
        return None

    def snapmirror_policy_rest_get(self, policy_name, svm_name):
        """
        get policy type
        There is a set of system level policies, and users can create their own for a SVM
        REST does not return a svm entry for system policies
        svm_name may not exist yet as it can be created when creating the snapmirror relationship
        """
        policy_type = None
        system_policy_type = None           # policies not associated to a SVM
        api = 'snapmirror/policies'
        query = {
            "name": policy_name,
            "fields": "svm.name,type"
        }
        records, error = rest_generic.get_0_or_more_records(self.rest_api, api, query)
        if error is None and records is not None:
            for record in records:
                if 'svm' in record:
                    if record['svm']['name'] == svm_name:
                        policy_type = record['type']
                        break
                else:
                    system_policy_type = record['type']
        if policy_type is None:
            policy_type = system_policy_type
        return policy_type, error

    def add_break_action(self, actions, current):
        # If current is not None, it means the state is present otherwise we would take a delete action
        if current and self.parameters['relationship_state'] == 'broken':
            if current['mirror_state'] == 'uninitialized':
                self.module.fail_json(msg='SnapMirror relationship cannot be broken if mirror state is uninitialized')
            elif current['relationship_type'] in ['load_sharing', 'vault']:
                self.module.fail_json(msg='SnapMirror break is not allowed in a load_sharing or vault relationship')
            elif current['mirror_state'] not in ['broken-off', 'broken_off']:
                actions.append('break')
                self.na_helper.changed = True

    def add_active_actions(self, actions, current):
        # add initialize or resume action as needed
        # add resync or check_for_update action as needed
        # If current is not None, it means the state is present otherwise we would take a delete action
        if current and self.parameters['relationship_state'] == 'active':
            # check for initialize
            if self.parameters['initialize'] and current['mirror_state'] == 'uninitialized' and current['current_transfer_type'] != 'initialize':
                actions.append('initialize')
                # set changed explicitly for initialize
                self.na_helper.changed = True
            # resume when state is quiesced
            if current['status'] == 'quiesced' or current['mirror_state'] == 'paused':
                actions.append('resume')
                # set changed explicitly for resume
                self.na_helper.changed = True
            # resync when state is broken-off
            if current['mirror_state'] in ['broken-off', 'broken_off']:
                actions.append('resync')
                # set changed explicitly for resync
                self.na_helper.changed = True
            # Update when create is called again, or modify is being called
            elif self.parameters['update']:
                actions.append('check_for_update')

    def get_svm_peer(self, source_svm, destination_svm):
        if self.use_rest:
            api = 'svm/peers'
            query = {'name': source_svm, 'svm.name': destination_svm}
            record, error = rest_generic.get_one_record(self.rest_api, api, query, fields='peer')
            if error:
                self.module.fail_json(msg='Error retrieving SVM peer: %s' % error)
            if record:
                return self.na_helper.safe_get(record, ['peer', 'svm', 'name']), self.na_helper.safe_get(record, ['peer', 'cluster', 'name'])
        else:
            query = {
                'query': {
                    'vserver-peer-info': {
                        'peer-vserver': source_svm,
                        'vserver': destination_svm
                    }
                }
            }
            get_request = netapp_utils.zapi.NaElement('vserver-peer-get-iter')
            get_request.translate_struct(query)
            try:
                result = self.server.invoke_successfully(get_request, enable_tunneling=True)
            except netapp_utils.zapi.NaApiError as error:
                self.module.fail_json(msg='Error fetching vserver peer info: %s' % to_native(error),
                                      exception=traceback.format_exc())
            if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) > 0:
                info = result.get_child_by_name('attributes-list').get_child_by_name('vserver-peer-info')
                return info['remote-vserver-name'], info['peer-cluster']

        return None, None

    def validate_source_path(self, current):
        """ There can only be one destination, so we use it as the key
            But we want to make sure another relationship is not already using the destination
            It's a bit complicated as the source SVM name can be aliased to a local name if there are conflicts
            So the source can be ansibleSVM: and show locally as ansibleSVM: if there is not conflict or ansibleSVM.1:
            or any alias the user likes.
            And in the input paramters, it may use the remote name or local alias.
        """
        if not current:
            return
        source_path = self.na_helper.safe_get(self.parameters, ['source_endpoint', 'path']) or self.parameters.get('source_path')
        destination_path = self.na_helper.safe_get(self.parameters, ['destination_endpoint', 'path']) or self.parameters.get('destination_path')
        source_cluster = self.na_helper.safe_get(self.parameters, ['source_endpoint', 'cluster']) or self.parameters.get('source_cluster')
        current_source_path = current.pop('source_path', None)
        if source_path and current_source_path and self.parameters.get('validate_source_path'):
            if self.parameters['connection_type'] != 'ontap_ontap':
                # take things at face value
                if current_source_path != source_path:
                    self.module.fail_json(msg='Error: another relationship is present for the same destination with source_path:'
                                              ' "%s".  Desired: %s on %s'
                                          % (current_source_path, source_path, source_cluster))
                return
            # with ONTAP -> ONTAP, vserver names can be aliased
            current_source_svm, dummy, dummy = current_source_path.rpartition(':')
            if not current_source_svm:
                self.module.warn('Unexpected source path: %s, skipping validation.' % current_source_path)
            destination_svm, dummy, dummy = destination_path.rpartition(':')
            if not destination_svm:
                self.module.warn('Unexpected destination path: %s, skipping validation.' % destination_path)
            if not current_source_svm or not destination_svm:
                return
            peer_svm, peer_cluster = self.get_svm_peer(current_source_svm, destination_svm)
            if peer_svm is not None:
                real_source_path = current_source_path.replace(current_source_svm, peer_svm, 1)
                # match either the local name or the remote name
                if (real_source_path != source_path and current_source_path != source_path)\
                   or (peer_cluster is not None and source_cluster is not None and source_cluster != peer_cluster):
                    self.module.fail_json(msg='Error: another relationship is present for the same destination with source_path:'
                                              ' "%s" (%s on cluster %s).  Desired: %s on %s'
                                          % (current_source_path, real_source_path, peer_cluster, source_path, source_cluster))

    def get_actions(self):
        restore = self.parameters.get('relationship_type', '') == 'restore'
        current = None if restore else self.snapmirror_get()
        self.validate_source_path(current)
        # ONTAP automatically convert DP to XDP
        if current and current['relationship_type'] == 'extended_data_protection' and self.parameters.get('relationship_type') == 'data_protection':
            self.parameters['relationship_type'] = 'extended_data_protection'
        cd_action = None if restore else self.na_helper.get_cd_action(current, self.parameters)
        modify = None
        if cd_action is None and self.parameters['state'] == 'present' and not restore:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            if modify and 'relationship_type' in modify:
                self.module.fail_json(msg='Error: cannot modify relationship_type from %s to %s.' %
                                      (current['relationship_type'], modify['relationship_type']))
        actions = []
        if self.parameters['state'] == 'present' and restore:
            actions.append('restore')
            self.na_helper.changed = True
        elif cd_action == 'create':
            actions.append('create')
        elif cd_action == 'delete':
            if current['status'] == 'transferring' or self.parameters.get('current_transfer_status') == 'transferring':
                actions.append('abort')
            actions.append('delete')
        else:
            if modify:
                actions.append('modify')
            # If current is not None, it means the state is present otherwise we would take a delete action
            self.add_break_action(actions, current)
            self.add_active_actions(actions, current)
        return actions, current, modify

    def take_actions(self, actions, current, modify):
        if 'restore' in actions:
            self.snapmirror_restore()
        if 'create' in actions:
            self.snapmirror_create()
        if 'abort' in actions:
            self.snapmirror_abort()
            self.wait_for_idle_status()
        if 'delete' in actions:
            self.delete_snapmirror(current['relationship_type'], current['mirror_state'])
        if 'modify' in actions:
            self.snapmirror_modify(modify)
        if 'break' in actions:
            self.snapmirror_break()
        if 'initialize' in actions:
            self.snapmirror_initialize(current)
        if 'resume' in actions:
            self.snapmirror_resume()
        if 'resync' in actions:
            self.snapmirror_resync(current)

    def apply(self):
        """
        Apply action to SnapMirror
        """
        # source is ElementSW
        if self.parameters['state'] == 'present' and self.parameters.get('connection_type') == 'elementsw_ontap':
            self.check_elementsw_parameters()
        elif self.parameters.get('connection_type') == 'ontap_elementsw':
            self.check_elementsw_parameters('destination')
        else:
            self.check_parameters()
        if self.parameters['state'] == 'present' and self.parameters.get('connection_type') == 'ontap_elementsw':
            current_elementsw_ontap = self.snapmirror_get(self.parameters['source_path'])
            if current_elementsw_ontap is None:
                self.module.fail_json(msg='Error: creating an ONTAP to ElementSW snapmirror relationship requires an '
                                          'established SnapMirror relation from ElementSW to ONTAP cluster')

        actions, current, modify = self.get_actions()
        if self.na_helper.changed and not self.module.check_mode:
            self.take_actions(actions, current, modify)
        if 'check_for_update' in actions:
            current = self.snapmirror_get()
            if current['mirror_state'] == 'snapmirrored':
                actions.append('update')
                if not self.module.check_mode:
                    self.snapmirror_update(current['relationship_type'])
                self.na_helper.changed = True

        self.check_health()
        if self.previous_errors:
            self.module.warn('Ignored error(s): %s' % ' -- '.join(self.previous_errors))

        results = dict(changed=self.na_helper.changed)
        if actions:
            results['actions'] = actions
        self.module.exit_json(**results)


def main():
    """Execute action"""
    snapmirror_obj = NetAppONTAPSnapmirror()
    snapmirror_obj.apply()


if __name__ == '__main__':
    main()
