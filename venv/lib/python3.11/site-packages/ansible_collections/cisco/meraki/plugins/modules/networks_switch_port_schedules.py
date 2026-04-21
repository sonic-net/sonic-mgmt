#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_switch_port_schedules
short_description: Resource module for networks _switch _port _schedules
description:
  - Manage operations create, update and delete of the resource networks _switch _port _schedules.
  - Add a switch port schedule.
  - Delete a switch port schedule.
  - Update a switch port schedule.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  name:
    description: The name for your port schedule. Required.
    type: str
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  portSchedule:
    description: The schedule for switch port scheduling. Schedules are applied to days of the week. When it's empty, default schedule with all
      days of a week are configured. Any unspecified day in the schedule is added as a default schedule configuration of the day.
    suboptions:
      friday:
        description: The schedule object for Friday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      monday:
        description: The schedule object for Monday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      saturday:
        description: The schedule object for Saturday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      sunday:
        description: The schedule object for Sunday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      thursday:
        description: The schedule object for Thursday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      tuesday:
        description: The schedule object for Tuesday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
      wednesday:
        description: The schedule object for Wednesday.
        suboptions:
          active:
            description: Whether the schedule is active (true) or inactive (false) during the time specified between 'from' and 'to'. Defaults
              to true.
            type: bool
          from:
            description: The time, from '00 00' to '24 00'. Must be less than the time specified in 'to'. Defaults to '00 00'. Only 30 minute
              increments are allowed.
            type: str
          to:
            description: The time, from '00 00' to '24 00'. Must be greater than the time specified in 'from'. Defaults to '24 00'. Only 30 minute
              increments are allowed.
            type: str
        type: dict
    type: dict
  portScheduleId:
    description: PortScheduleId path parameter. Port schedule ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for switch createNetworkSwitchPortSchedule
    description: Complete reference of the createNetworkSwitchPortSchedule API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-network-switch-port-schedule
  - name: Cisco Meraki documentation for switch deleteNetworkSwitchPortSchedule
    description: Complete reference of the deleteNetworkSwitchPortSchedule API.
    link: https://developer.cisco.com/meraki/api-v1/#!delete-network-switch-port-schedule
  - name: Cisco Meraki documentation for switch updateNetworkSwitchPortSchedule
    description: Complete reference of the updateNetworkSwitchPortSchedule API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-switch-port-schedule
notes:
  - SDK Method used are
    switch.Switch.create_network_switch_port_schedule,
    switch.Switch.delete_network_switch_port_schedule,
    switch.Switch.update_network_switch_port_schedule,
  - Paths used are
    post /networks/{networkId}/switch/portSchedules,
    delete /networks/{networkId}/switch/portSchedules/{portScheduleId},
    put /networks/{networkId}/switch/portSchedules/{portScheduleId},
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.networks_switch_port_schedules:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    state: present
    name: Weekdays schedule
    networkId: string
    portSchedule:
      friday:
        active: true
        from: '9:00'
        to: '17:00'
      monday:
        active: true
        from: '9:00'
        to: '17:00'
      saturday:
        active: false
        from: 0:00
        to: '24:00'
      sunday:
        active: false
        from: 0:00
        to: '24:00'
      thursday:
        active: true
        from: '9:00'
        to: '17:00'
      tuesday:
        active: true
        from: '9:00'
        to: '17:00'
      wednesday:
        active: true
        from: '9:00'
        to: '17:00'
- name: Delete by id
  cisco.meraki.networks_switch_port_schedules:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    state: absent
    networkId: string
    portScheduleId: string
- name: Update by id
  cisco.meraki.networks_switch_port_schedules:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    state: present
    name: Weekdays schedule
    networkId: string
    portSchedule:
      friday:
        active: true
        from: '9:00'
        to: '17:00'
      monday:
        active: true
        from: '9:00'
        to: '17:00'
      saturday:
        active: false
        from: 0:00
        to: '24:00'
      sunday:
        active: false
        from: 0:00
        to: '24:00'
      thursday:
        active: true
        from: '9:00'
        to: '17:00'
      tuesday:
        active: true
        from: '9:00'
        to: '17:00'
      wednesday:
        active: true
        from: '9:00'
        to: '17:00'
    portScheduleId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "name": "string",
      "networkId": "string",
      "portSchedule": {
        "friday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "monday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "saturday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "sunday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "thursday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "tuesday": {
          "active": true,
          "from": "string",
          "to": "string"
        },
        "wednesday": {
          "active": true,
          "from": "string",
          "to": "string"
        }
      }
    }
"""
