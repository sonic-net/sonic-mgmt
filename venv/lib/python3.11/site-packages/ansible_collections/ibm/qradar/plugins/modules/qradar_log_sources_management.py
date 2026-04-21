#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: qradar_log_sources_management
short_description: Qradar Log Sources Management resource module
description:
  - This module allows for addition, deletion, or modification of Log Sources in QRadar
version_added: "2.1.0"
options:
  config:
    description: A dictionary of Qradar Log Sources options
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of Log Source
        type: str
      description:
        description:
          - Description of log source
        type: str
      type_name:
        description:
          - Type of resource by name
        type: str
      type_id:
        description:
          - The type of the log source. Must correspond to an existing log source type.
        type: int
      identifier:
        description:
          - Log Source Identifier (Typically IP Address or Hostname of log source)
        type: str
      protocol_type_id:
        description:
          - Type of protocol by id, as defined in QRadar Log Source Types Documentation
        type: int
      enabled:
        description:
          - If the log source is enabled, the condition is set to 'true'; otherwise,
            the condition is set to 'false'.
        type: bool
      gateway:
        description:
          - If the log source is configured as a gateway, the condition is set to 'true';
            otherwise, the condition is set to 'false'. A gateway log source is a stand-alone
            protocol configuration. The log source receives no events itself, and serves as a
            host for a protocol configuration that retrieves event data to feed other log sources.
            It acts as a "gateway" for events from multiple systems to enter the event pipeline.
        type: bool
      internal:
        description:
          - If the log source is internal (when the log source type is defined as internal),
            the condition is set to 'true'.
        type: bool
      target_event_collector_id:
        description:
          - The ID of the event collector where the log source sends its data.
            The ID must correspond to an existing event collector.
        type: int
      coalesce_events:
        description:
          - If events collected by this log source are coalesced based on common properties,
            the condition is set to 'true'. If each individual event is stored,
            then the condition is set to 'false'.
        type: bool
      store_event_payload:
        description:
          - If the payloads of events that are collected by this log source are stored,
            the condition is set to 'true'. If only the normalized event records are stored,
            then the condition is set to 'false'.
        type: bool
      language_id:
        description:
          - The language of the events that are being processed by this log source.
            Must correspond to an existing log source language. Individual log source types
            can support only a subset of all available log source languages,
            as indicated by the supported_language_ids field of the log source type structure
        type: int
      group_ids:
        description:
          - The set of log source group IDs this log source is a member of.
            Each ID must correspond to an existing log source group.
        type: list
        elements: str
      requires_deploy:
        description:
          - Set to 'true' if you need to deploy changes to enable the log source for use;
            otherwise, set to 'false' if the log source is already active.
        type: bool
      status:
        description:
          - The status of the log source.
        type: dict
        suboptions:
          last_updated:
            description: last_updated
            type: int
          messages:
            description: last_updated
            type: str
          status:
            description: last_updated
            type: str
      average_eps:
        description:
          - The average events per second (EPS) rate of the log source over the last 60 seconds.
        type: int
      protocol_parameters:
        description:
          - The set of protocol parameters
          - If not provided module will set the protocol parameters by itself
          - Note, parameter will come to use mostly in case when facts are gathered and fired
            with some modifications to params or in case of round trip scenarios.
        type: list
        elements: dict
        suboptions:
          id:
            description: The ID of the protocol type.
            type: int
          name:
            description: The unique name of the protocol type.
            type: str
          value:
            description: The allowed protocol value.
            type: str
  state:
    description:
      - The state the configuration should be left in
      - The state I(gathered) will get the module API configuration from the device
        and transform it into structured data in the format as per the module argspec
        and the value is returned in the I(gathered) key within the result.
    type: str
    choices:
      - merged
      - replaced
      - gathered
      - deleted

author: Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>
"""

EXAMPLES = """

# Using MERGED state
# -------------------

- name: Add Snort n Apache log sources to IBM QRadar
  ibm.qradar.qradar_log_sources_management:
    config:
      - name: "Snort logs"
        type_name: "Snort Open Source IDS"
        description: "Snort IDS remote logs from rsyslog"
        identifier: "192.0.2.1"
      - name: "Apache HTTP Server logs"
        type_name: "Apache HTTP Server"
        description: "Apache HTTP Server remote logs from rsyslog"
        identifier: "198.51.100.1"
    state: merged

# RUN output:
# -----------

#   qradar_log_sources_management:
#     after:
#     - auto_discovered: false
#       average_eps: 0
#       coalesce_events: true
#       creation_date: 1654727311444
#       credibility: 5
#       description: Snort IDS remote logs from rsyslog
#       enabled: true
#       gateway: false
#       group_ids:
#       - 0
#       id: 181
#       internal: false
#       language_id: 1
#       last_event_time: 0
#       log_source_extension_id: null
#       modified_date: 1654727311444
#       name: Snort logs
#       protocol_parameters:
#       - id: 1
#         name: incomingPayloadEncoding
#         value: UTF-8
#       - id: 0
#         name: identifier
#         value: 192.0.2.1
#       protocol_type_id: 0
#       requires_deploy: true
#       status:
#         last_updated: 0
#         messages: null
#         status: NA
#       store_event_payload: true
#       target_event_collector_id: 7
#       type_id: 2
#       wincollect_external_destination_ids: null
#       wincollect_internal_destination_id: null
#     - auto_discovered: false
#       average_eps: 0
#       coalesce_events: true
#       creation_date: 1654727311462
#       credibility: 5
#       description: Apache HTTP Server remote logs from rsyslog
#       enabled: true
#       gateway: false
#       group_ids:
#       - 0
#       id: 182
#       internal: false
#       language_id: 1
#       last_event_time: 0
#       log_source_extension_id: null
#       modified_date: 1654727311462
#       name: Apache HTTP Server logs
#       protocol_parameters:
#       - id: 1
#         name: incomingPayloadEncoding
#         value: UTF-8
#       - id: 0
#         name: identifier
#         value: 198.51.100.1
#       protocol_type_id: 0
#       requires_deploy: true
#       status:
#         last_updated: 0
#         messages: null
#         status: NA
#       store_event_payload: true
#       target_event_collector_id: 7
#       type_id: 10
#       wincollect_external_destination_ids: null
#       wincollect_internal_destination_id: null
#     before: []

# Using REPLACED state
# --------------------

- name: Replace existing Log sources to IBM QRadar
  ibm.qradar.qradar_log_sources_management:
    state: replaced
    config:
      - name: "Apache HTTP Server logs"
        type_name: "Apache HTTP Server"
        description: "REPLACED Apache HTTP Server remote logs from rsyslog"
        identifier: "192.0.2.1"

# RUN output:
# -----------

#   qradar_log_sources_management:
#     after:
#     - auto_discovered: false
#       average_eps: 0
#       coalesce_events: true
#       creation_date: 1654727944017
#       credibility: 5
#       description: REPLACED Apache HTTP Server remote logs from rsyslog
#       enabled: true
#       gateway: false
#       group_ids:
#       - 0
#       id: 183
#       internal: false
#       language_id: 1
#       last_event_time: 0
#       log_source_extension_id: null
#       modified_date: 1654727944017
#       name: Apache HTTP Server logs
#       protocol_parameters:
#       - id: 1
#         name: incomingPayloadEncoding
#         value: UTF-8
#       - id: 0
#         name: identifier
#         value: 192.0.2.1
#       protocol_type_id: 0
#       requires_deploy: true
#       status:
#         last_updated: 0
#         messages: null
#         status: NA
#       store_event_payload: true
#       target_event_collector_id: 7
#       type_id: 10
#       wincollect_external_destination_ids: null
#       wincollect_internal_destination_id: null
#     before:
#     - auto_discovered: false
#       average_eps: 0
#       coalesce_events: true
#       creation_date: 1654727311462
#       credibility: 5
#       description: Apache HTTP Server remote logs from rsyslog
#       enabled: true
#       gateway: false
#       group_ids:
#       - 0
#       id: 182
#       internal: false
#       language_id: 1
#       last_event_time: 0
#       log_source_extension_id: null
#       modified_date: 1654727311462
#       name: Apache HTTP Server logs
#       protocol_parameters:
#       - name: identifier
#         value: 198.51.100.1
#       - name: incomingPayloadEncoding
#         value: UTF-8
#       protocol_type_id: 0
#       requires_deploy: true
#       status:
#         last_updated: 0
#         messages: null
#         status: NA
#       store_event_payload: true
#       target_event_collector_id: 7
#       type_id: 10
#       wincollect_external_destination_ids: null
#       wincollect_internal_destination_id: null

# Using GATHERED state
# --------------------

- name: Gather Snort n Apache log source from IBM QRadar
  ibm.qradar.qradar_log_sources_management:
    config:
      - name: "Snort logs"
      - name: "Apache HTTP Server logs"
    state: gathered

# RUN output:
# -----------

# gathered:
#   - auto_discovered: false
#     average_eps: 0
#     coalesce_events: true
#     creation_date: 1654727311444
#     credibility: 5
#     description: Snort IDS remote logs from rsyslog
#     enabled: true
#     gateway: false
#     group_ids:
#     - 0
#     id: 181
#     internal: false
#     language_id: 1
#     last_event_time: 0
#     log_source_extension_id: null
#     modified_date: 1654728103340
#     name: Snort logs
#     protocol_parameters:
#     - id: 0
#       name: identifier
#       value: 192.0.2.1
#     - id: 1
#       name: incomingPayloadEncoding
#       value: UTF-8
#     protocol_type_id: 0
#     requires_deploy: true
#     status:
#       last_updated: 0
#       messages: null
#       status: NA
#     store_event_payload: true
#     target_event_collector_id: 7
#     type_id: 2
#     wincollect_external_destination_ids: null
#     wincollect_internal_destination_id: null
#   - auto_discovered: false
#     average_eps: 0
#     coalesce_events: true
#     creation_date: 1654727944017
#     credibility: 5
#     description: Apache HTTP Server remote logs from rsyslog
#     enabled: true
#     gateway: false
#     group_ids:
#     - 0
#     id: 183
#     internal: false
#     language_id: 1
#     last_event_time: 0
#     log_source_extension_id: null
#     modified_date: 1654728103353
#     name: Apache HTTP Server logs
#     protocol_parameters:
#     - id: 0
#       name: identifier
#       value: 192.0.2.1
#     - id: 1
#       name: incomingPayloadEncoding
#       value: UTF-8
#     protocol_type_id: 0
#     requires_deploy: true
#     status:
#       last_updated: 0
#       messages: null
#       status: NA
#     store_event_payload: true
#     target_event_collector_id: 7
#     type_id: 10
#     wincollect_external_destination_ids: null
#     wincollect_internal_destination_id: null

- name: TO Gather ALL log sources from IBM QRadar
  tags: gather_log_all
  ibm.qradar.qradar_log_sources_management:
    state: gathered

# Using DELETED state
# -------------------

- name: Delete Snort n Apache log source from IBM QRadar
  ibm.qradar.qradar_log_sources_management:
    config:
      - name: "Snort logs"
      - name: "Apache HTTP Server logs"
    state: deleted

# RUN output:
# -----------

#   qradar_log_sources_management:
#     after: []
#     before:
#     - auto_discovered: false
#       average_eps: 0
#       coalesce_events: true
#       creation_date: 1654727311444
#       credibility: 5
#       description: Snort IDS remote logs from rsyslog
#       enabled: true
#       gateway: false
#       group_ids:
#       - 0
#       id: 181
#       internal: false
#       language_id: 1
#       last_event_time: 0
#       log_source_extension_id: null
#       modified_date: 1654728103340
#       name: Snort logs
#       protocol_parameters:
#       - id: 0
#         name: identifier
#         value: 192.0.2.1
#       - id: 1
#         name: incomingPayloadEncoding
#         value: UTF-8
#       protocol_type_id: 0
#       requires_deploy: true
#       status:
#         last_updated: 0
#         messages: null
#         status: NA
#       store_event_payload: true
#       target_event_collector_id: 7
#       type_id: 2
#       wincollect_external_destination_ids: null
#       wincollect_internal_destination_id: null
#     - auto_discovered: false
#       average_eps: 0
#       coalesce_events: true
#       creation_date: 1654727944017
#       credibility: 5
#       description: Apache HTTP Server remote logs from rsyslog
#       enabled: true
#       gateway: false
#       group_ids:
#       - 0
#       id: 183
#       internal: false
#       language_id: 1
#       last_event_time: 0
#       log_source_extension_id: null
#       modified_date: 1654728103353
#       name: Apache HTTP Server logs
#       protocol_parameters:
#       - id: 0
#         name: identifier
#         value: 192.0.2.1
#       - id: 1
#         name: incomingPayloadEncoding
#         value: UTF-8
#       protocol_type_id: 0
#       requires_deploy: true
#       status:
#         last_updated: 0
#         messages: null
#         status: NA
#       store_event_payload: true
#       target_event_collector_id: 7
#       type_id: 10
#       wincollect_external_destination_ids: null
#       wincollect_internal_destination_id: null
"""

RETURN = """
before:
  description: The configuration as structured data prior to module invocation.
  returned: always
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
after:
  description: The configuration as structured data after module completion.
  returned: when changed
  type: list
  sample: The configuration returned will always be in the same format of the parameters above.
"""
