#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):

    # Standard files documentation fragment
    DOCUMENTATION = r'''
options:
    meraki_base_url:
        description:
          - meraki_base_url (string), preceding all endpoint resources
        type: str
        default: https://api.meraki.com/api/v1
    meraki_api_key:
        description:
          - meraki_api_key (string), API key generated in dashboard; can also be set as an environment variable MERAKI_DASHBOARD_API_KEY
        type: str
        required: true
    meraki_single_request_timeout:
        description:
          - meraki_single_request_timeout (integer), maximum number of seconds for each API call
        type: int
        default: 60
    meraki_certificate_path:
        description:
          - meraki_certificate_path (string), path for TLS/SSL certificate verification if behind local proxy
        type: str
        default: ''
    meraki_requests_proxy:
        description:
          - meraki_requests_proxy (string), proxy server and port, if needed, for HTTPS
        type: str
        default: ''
    meraki_wait_on_rate_limit:
        description:
          - meraki_wait_on_rate_limit (boolean), retry if 429 rate limit error encountered?
        type: bool
        default: true
    meraki_nginx_429_retry_wait_time:
        description:
          - meraki_nginx_429_retry_wait_time (integer), Nginx 429 retry wait time
        type: int
        default: 60
    meraki_action_batch_retry_wait_time:
        description:
          - meraki_action_batch_retry_wait_time (integer), action batch concurrency error retry wait time
        type: int
        default: 60
    meraki_retry_4xx_error:
        description:
          - meraki_retry_4xx_error (boolean), retry if encountering other 4XX error (besides 429)?
        type: bool
        default: false
    meraki_retry_4xx_error_wait_time:
        description:
          - meraki_retry_4xx_error_wait_time (integer), other 4XX error retry wait time
        type: int
        default: 60
    meraki_maximum_retries:
        description:
          - meraki_maximum_retries (integer), retry up to this many times when encountering 429s or other server-side errors
        type: int
        default: 2
    meraki_output_log:
        description:
          - meraki_output_log (boolean), create an output log file?
        type: bool
        default: true
    meraki_log_file_prefix:
        description:
          - meraki_log_file_prefix (string), log file name appended with date and timestamp
        type: str
        default: meraki_api_
    meraki_log_path:
        description:
          - log_path (string), path to output log; by default, working directory of script if not specified
        type: str
        default: ''
    meraki_print_console:
        description:
          - meraki_print_console (boolean), print logging output to console?
        type: bool
        default: true
    meraki_suppress_logging:
        description:
          - meraki_suppress_logging (boolean), disable all logging? you're on your own then!
        type: bool
        default: false
    meraki_simulate:
        description:
          - meraki_simulate (boolean), simulate POST/PUT/DELETE calls to prevent changes?
        type: bool
        default: false
    meraki_be_geo_id:
        description:
          - meraki_be_geo_id (string), optional partner identifier for API usage tracking; can also be set as an environment variable BE_GEO_ID
        type: str
        default: ''
    meraki_use_iterator_for_get_pages:
        description:
          - meraki_use_iterator_for_get_pages (boolean), list* methods will return an iterator with each object instead of a complete list with all items
        type: bool
        default: false
    meraki_inherit_logging_config:
        description:
          - meraki_inherit_logging_config (boolean), Inherits your own logger instance
        type: bool
        default: false
notes:
    - "Does not support C(check_mode)"
    - "The plugin runs on the control node and does not use any ansible connection plugins, but instead the embedded connection manager"
    - "from Cisco Dashboard API Python(SDK)"
    - "The parameters starting with dnac_ are used by the Cisco DNAC Python SDK to establish the connection"
'''
