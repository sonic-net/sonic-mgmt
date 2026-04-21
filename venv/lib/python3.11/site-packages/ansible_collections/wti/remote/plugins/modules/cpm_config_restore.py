#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (C) 2019 Red Hat Inc.
# Copyright (C) 2020 Western Telematic Inc.
#
# GNU General Public License v3.0+
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# Module to retrieve WTI Parameters from WTI OOB and PDU devices.
# CPM remote_management
#
from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: cpm_config_restore
version_added: "2.9.0"
author: "Western Telematic Inc. (@wtinetworkgear)"
short_description: Send operational parameters to WTI OOB and PDU devices
description:
    - "Send operational parameters to WTI OOB and PDU devices"
options:
    cpm_url:
        description:
            - This is the URL of the WTI device to get the parameters from.
        type: str
        required: true
    cpm_username:
        description:
            - This is the Username of the WTI device to get the parameters from.
        type: str
        required: true
    cpm_password:
        description:
            - This is the Password of the WTI device to get the parameters from.
        type: str
        required: true
    cpm_path:
        description:
            - This is the directory path to the existing the WTI device configuration file.
        type: str
        required: false
        default: "/tmp/"
    cpm_filename:
        description:
            - This is the filename of the existing WTI device configuration file.
        type: str
        required: true
    use_https:
        description:
            - Designates to use an https connection or http connection.
        type: bool
        required: false
        default: true
    validate_certs:
        description:
            - If false, SSL certificates will not be validated. This should only be used
            - on personally controlled sites using self-signed certificates.
        type: bool
        required: false
        default: true
    use_proxy:
        description: Flag to control if the lookup will observe HTTP proxy environment variables when present.
        type: bool
        required: false
        default: false
notes:
  - Use C(groups/cpm) in C(module_defaults) to set common options used between CPM modules.)
"""

EXAMPLES = """
- name: Get the Parameters for a WTI device
  cpm_config_restore:
    cpm_url: "nonexist.wti.com"
    cpm_username: "super"
    cpm_password: "super"
    cpm_path: "/tmp/"
    cpm_filename: "wti-192-10-10-239-2020-02-13T16-05-57-xml"
    use_https: true
    validate_certs: false
"""

RETURN = """
data:
  description: The output XML configuration of the WTI device queried
  returned: always
  type: complex
  contains:
    filelength:
      description: Length of the file uploaded in bytes
      returned: success
      type: int
      sample:
        - filelength: 329439
    status:
      description: List of status returns from backup operation
      returned: success
      type: list
      sample:
        - code: 0
          text: "ok"
          unittimestamp: "2020-02-14T00:18:57+00:00"
"""

import base64

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_bytes, to_native
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url, ConnectionError, SSLValidationError


def get_unit_type(filedata):
    beginsearch = filedata.find("unit_type_info=\"")
    beginsearch = (beginsearch + 16)
    endsearch = filedata.find("\">", beginsearch)
    if (((endsearch == -1) | (beginsearch == -1)) | (endsearch < beginsearch) | ((endsearch - beginsearch) > 16)):
        header = "wti"
    else:
        header = filedata[beginsearch:beginsearch + (endsearch - beginsearch)]
    return (header)


def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        cpm_url=dict(type='str', required=True),
        cpm_username=dict(type='str', required=True),
        cpm_password=dict(type='str', required=True, no_log=True),
        cpm_path=dict(type='str', default="/tmp/"),
        cpm_filename=dict(type='str', required=True),
        use_https=dict(type='bool', default=True),
        validate_certs=dict(type='bool', default=True),
        use_proxy=dict(type='bool', default=False)
    )

    result = dict(
        changed=False,
        data=''
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    try:
        f = open(to_native(module.params['cpm_path']) + to_native(module.params['cpm_filename']), "rb")
        cszData = f.read()
        f.close()
    except Exception as e:
        json_string = "{\"status\": { \"code\": \"1\", \"text\": \"error: " + str(e) + "\" }}"
        result['data'] = json_string
        module.exit_json(**result)

    auth = to_text(base64.b64encode(to_bytes('{0}:{1}'.format(to_native(module.params['cpm_username']), to_native(module.params['cpm_password'])),
                   errors='surrogate_or_strict')))

    if module.params['use_https'] is True:
        protocol = "https://"
    else:
        protocol = "http://"

    fullurl = ("%s%s/cgi-bin/getfile" % (protocol, to_native(module.params['cpm_url'])))

    try:
        xmlfile = open(to_native(module.params['cpm_path']) + to_native(module.params['cpm_filename']), 'rb')
        xmlfile.close()
        response = open_url(fullurl, data=cszData, method='POST', validate_certs=module.params['validate_certs'], use_proxy=module.params['use_proxy'],
                            headers={'Content-Type': 'application/xml', 'Authorization': "Basic %s" % auth})

    except HTTPError as e:
        fail_json = dict(msg='GET: Received HTTP error for {0} : {1}'.format(fullurl, to_native(e)), changed=False)
        module.fail_json(**fail_json)
    except URLError as e:
        fail_json = dict(msg='GET: Failed lookup url for {0} : {1}'.format(fullurl, to_native(e)), changed=False)
        module.fail_json(**fail_json)
    except SSLValidationError as e:
        fail_json = dict(msg='GET: Error validating the server''s certificate for {0} : {1}'.format(fullurl, to_native(e)), changed=False)
        module.fail_json(**fail_json)
    except ConnectionError as e:
        fail_json = dict(msg='GET: Error connecting to {0} : {1}'.format(fullurl, to_native(e)), changed=False)
        module.fail_json(**fail_json)

    result['data'] = response.read()
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
