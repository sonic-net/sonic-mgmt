#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_system_npu_npqueues_profile
short_description: Configure a NP7 class profile.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    system_npu_npqueues_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cos0:
                type: str
                description: Queue number of CoS 0.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            cos1:
                type: str
                description: Queue number of CoS 1.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            cos2:
                type: str
                description: Queue number of CoS 2.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            cos3:
                type: str
                description: Queue number of CoS 3.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            cos4:
                type: str
                description: Queue number of CoS 4.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            cos5:
                type: str
                description: Queue number of CoS 5.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            cos6:
                type: str
                description: Queue number of CoS 6.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            cos7:
                type: str
                description: Queue number of CoS 7.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp0:
                type: str
                description: Queue number of DSCP 0.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp1:
                type: str
                description: Queue number of DSCP 1.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp10:
                type: str
                description: Queue number of DSCP 10.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp11:
                type: str
                description: Queue number of DSCP 11.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp12:
                type: str
                description: Queue number of DSCP 12.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp13:
                type: str
                description: Queue number of DSCP 13.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp14:
                type: str
                description: Queue number of DSCP 14.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp15:
                type: str
                description: Queue number of DSCP 15.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp16:
                type: str
                description: Queue number of DSCP 16.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp17:
                type: str
                description: Queue number of DSCP 17.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp18:
                type: str
                description: Queue number of DSCP 18.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp19:
                type: str
                description: Queue number of DSCP 19.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp2:
                type: str
                description: Queue number of DSCP 2.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp20:
                type: str
                description: Queue number of DSCP 20.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp21:
                type: str
                description: Queue number of DSCP 21.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp22:
                type: str
                description: Queue number of DSCP 22.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp23:
                type: str
                description: Queue number of DSCP 23.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp24:
                type: str
                description: Queue number of DSCP 24.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp25:
                type: str
                description: Queue number of DSCP 25.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp26:
                type: str
                description: Queue number of DSCP 26.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp27:
                type: str
                description: Queue number of DSCP 27.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp28:
                type: str
                description: Queue number of DSCP 28.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp29:
                type: str
                description: Queue number of DSCP 29.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp3:
                type: str
                description: Queue number of DSCP 3.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp30:
                type: str
                description: Queue number of DSCP 30.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp31:
                type: str
                description: Queue number of DSCP 31.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp32:
                type: str
                description: Queue number of DSCP 32.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp33:
                type: str
                description: Queue number of DSCP 33.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp34:
                type: str
                description: Queue number of DSCP 34.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp35:
                type: str
                description: Queue number of DSCP 35.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp36:
                type: str
                description: Queue number of DSCP 36.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp37:
                type: str
                description: Queue number of DSCP 37.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp38:
                type: str
                description: Queue number of DSCP 38.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp39:
                type: str
                description: Queue number of DSCP 39.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp4:
                type: str
                description: Queue number of DSCP 4.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp40:
                type: str
                description: Queue number of DSCP 40.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp41:
                type: str
                description: Queue number of DSCP 41.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp42:
                type: str
                description: Queue number of DSCP 42.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp43:
                type: str
                description: Queue number of DSCP 43.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp44:
                type: str
                description: Queue number of DSCP 44.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp45:
                type: str
                description: Queue number of DSCP 45.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp46:
                type: str
                description: Queue number of DSCP 46.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp47:
                type: str
                description: Queue number of DSCP 47.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp48:
                type: str
                description: Queue number of DSCP 48.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp49:
                type: str
                description: Queue number of DSCP 49.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp5:
                type: str
                description: Queue number of DSCP 5.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp50:
                type: str
                description: Queue number of DSCP 50.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp51:
                type: str
                description: Queue number of DSCP 51.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp52:
                type: str
                description: Queue number of DSCP 52.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp53:
                type: str
                description: Queue number of DSCP 53.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp54:
                type: str
                description: Queue number of DSCP 54.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp55:
                type: str
                description: Queue number of DSCP 55.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp56:
                type: str
                description: Queue number of DSCP 56.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp57:
                type: str
                description: Queue number of DSCP 57.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp58:
                type: str
                description: Queue number of DSCP 58.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp59:
                type: str
                description: Queue number of DSCP 59.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp6:
                type: str
                description: Queue number of DSCP 6.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp60:
                type: str
                description: Queue number of DSCP 60.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp61:
                type: str
                description: Queue number of DSCP 61.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp62:
                type: str
                description: Queue number of DSCP 62.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp63:
                type: str
                description: Queue number of DSCP 63.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp7:
                type: str
                description: Queue number of DSCP 7.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp8:
                type: str
                description: Queue number of DSCP 8.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            dscp9:
                type: str
                description: Queue number of DSCP 9.
                choices:
                    - 'queue0'
                    - 'queue1'
                    - 'queue2'
                    - 'queue3'
                    - 'queue4'
                    - 'queue5'
                    - 'queue6'
                    - 'queue7'
            id:
                type: int
                description: Profile ID.
                required: true
            type:
                type: str
                description: Profile type.
                choices:
                    - 'cos'
                    - 'dscp'
            weight:
                type: int
                description: Class weight.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure a NP7 class profile.
      fortinet.fortimanager.fmgr_system_npu_npqueues_profile:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        system_npu_npqueues_profile:
          id: 0 # Required variable, integer
          # cos0: <value in [queue0, queue1, queue2, ...]>
          # cos1: <value in [queue0, queue1, queue2, ...]>
          # cos2: <value in [queue0, queue1, queue2, ...]>
          # cos3: <value in [queue0, queue1, queue2, ...]>
          # cos4: <value in [queue0, queue1, queue2, ...]>
          # cos5: <value in [queue0, queue1, queue2, ...]>
          # cos6: <value in [queue0, queue1, queue2, ...]>
          # cos7: <value in [queue0, queue1, queue2, ...]>
          # dscp0: <value in [queue0, queue1, queue2, ...]>
          # dscp1: <value in [queue0, queue1, queue2, ...]>
          # dscp10: <value in [queue0, queue1, queue2, ...]>
          # dscp11: <value in [queue0, queue1, queue2, ...]>
          # dscp12: <value in [queue0, queue1, queue2, ...]>
          # dscp13: <value in [queue0, queue1, queue2, ...]>
          # dscp14: <value in [queue0, queue1, queue2, ...]>
          # dscp15: <value in [queue0, queue1, queue2, ...]>
          # dscp16: <value in [queue0, queue1, queue2, ...]>
          # dscp17: <value in [queue0, queue1, queue2, ...]>
          # dscp18: <value in [queue0, queue1, queue2, ...]>
          # dscp19: <value in [queue0, queue1, queue2, ...]>
          # dscp2: <value in [queue0, queue1, queue2, ...]>
          # dscp20: <value in [queue0, queue1, queue2, ...]>
          # dscp21: <value in [queue0, queue1, queue2, ...]>
          # dscp22: <value in [queue0, queue1, queue2, ...]>
          # dscp23: <value in [queue0, queue1, queue2, ...]>
          # dscp24: <value in [queue0, queue1, queue2, ...]>
          # dscp25: <value in [queue0, queue1, queue2, ...]>
          # dscp26: <value in [queue0, queue1, queue2, ...]>
          # dscp27: <value in [queue0, queue1, queue2, ...]>
          # dscp28: <value in [queue0, queue1, queue2, ...]>
          # dscp29: <value in [queue0, queue1, queue2, ...]>
          # dscp3: <value in [queue0, queue1, queue2, ...]>
          # dscp30: <value in [queue0, queue1, queue2, ...]>
          # dscp31: <value in [queue0, queue1, queue2, ...]>
          # dscp32: <value in [queue0, queue1, queue2, ...]>
          # dscp33: <value in [queue0, queue1, queue2, ...]>
          # dscp34: <value in [queue0, queue1, queue2, ...]>
          # dscp35: <value in [queue0, queue1, queue2, ...]>
          # dscp36: <value in [queue0, queue1, queue2, ...]>
          # dscp37: <value in [queue0, queue1, queue2, ...]>
          # dscp38: <value in [queue0, queue1, queue2, ...]>
          # dscp39: <value in [queue0, queue1, queue2, ...]>
          # dscp4: <value in [queue0, queue1, queue2, ...]>
          # dscp40: <value in [queue0, queue1, queue2, ...]>
          # dscp41: <value in [queue0, queue1, queue2, ...]>
          # dscp42: <value in [queue0, queue1, queue2, ...]>
          # dscp43: <value in [queue0, queue1, queue2, ...]>
          # dscp44: <value in [queue0, queue1, queue2, ...]>
          # dscp45: <value in [queue0, queue1, queue2, ...]>
          # dscp46: <value in [queue0, queue1, queue2, ...]>
          # dscp47: <value in [queue0, queue1, queue2, ...]>
          # dscp48: <value in [queue0, queue1, queue2, ...]>
          # dscp49: <value in [queue0, queue1, queue2, ...]>
          # dscp5: <value in [queue0, queue1, queue2, ...]>
          # dscp50: <value in [queue0, queue1, queue2, ...]>
          # dscp51: <value in [queue0, queue1, queue2, ...]>
          # dscp52: <value in [queue0, queue1, queue2, ...]>
          # dscp53: <value in [queue0, queue1, queue2, ...]>
          # dscp54: <value in [queue0, queue1, queue2, ...]>
          # dscp55: <value in [queue0, queue1, queue2, ...]>
          # dscp56: <value in [queue0, queue1, queue2, ...]>
          # dscp57: <value in [queue0, queue1, queue2, ...]>
          # dscp58: <value in [queue0, queue1, queue2, ...]>
          # dscp59: <value in [queue0, queue1, queue2, ...]>
          # dscp6: <value in [queue0, queue1, queue2, ...]>
          # dscp60: <value in [queue0, queue1, queue2, ...]>
          # dscp61: <value in [queue0, queue1, queue2, ...]>
          # dscp62: <value in [queue0, queue1, queue2, ...]>
          # dscp63: <value in [queue0, queue1, queue2, ...]>
          # dscp7: <value in [queue0, queue1, queue2, ...]>
          # dscp8: <value in [queue0, queue1, queue2, ...]>
          # dscp9: <value in [queue0, queue1, queue2, ...]>
          # type: <value in [cos, dscp]>
          # weight: <integer>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/system/npu/np-queues/profile',
        '/pm/config/global/obj/system/npu/np-queues/profile'
    ]
    url_params = ['adom']
    module_primary_key = 'id'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu_npqueues_profile': {
            'type': 'dict',
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
            'options': {
                'cos0': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'cos1': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'cos2': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'cos3': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'cos4': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'cos5': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'cos6': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'cos7': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp0': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp1': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp10': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp11': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp12': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp13': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp14': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp15': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp16': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp17': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp18': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp19': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp2': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp20': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp21': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp22': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp23': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp24': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp25': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp26': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp27': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp28': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp29': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp3': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp30': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp31': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp32': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp33': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp34': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp35': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp36': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp37': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp38': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp39': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp4': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp40': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp41': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp42': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp43': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp44': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp45': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp46': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp47': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp48': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp49': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp5': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp50': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp51': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp52': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp53': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp54': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp55': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp56': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp57': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp58': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp59': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp6': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp60': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp61': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp62': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp63': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp7': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp8': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'dscp9': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                    'type': 'str'
                },
                'id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'required': True, 'type': 'int'},
                'type': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['cos', 'dscp'], 'type': 'str'},
                'weight': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_npqueues_profile'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
