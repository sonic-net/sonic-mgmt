#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_add_custom_trusted_ca_certificate
short_description: Create new custom trusted CA certificate.
description:
  - Create new custom trusted CA certificate.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  base64_certificate:
    description:
      - Certificate file encoded in base64.<br/>Valid file formats, x509.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: add-custom-trusted-ca-certificate
  cp_mgmt_add_custom_trusted_ca_certificate:
    base64_certificate:
      "MIIEkzCCAnugAwIBAgIVAO5SRZQELwNNhWF+8st6ox9uXYgeMA0GCSqGSIb3DQEBCwUAMIGrMQswCQYDVQQGEwJJTDEPMA0GA1UECBMGSXNyYWVsMS4wLAYDVQQKEyVDaGVja1BvaW50IFNvZnR3YXJlIF
       lY2hub2xvZ2llcyBMVEQuMQwwCgYDVQQLEwNNSVMxIjAgBgNVBAMTGUNoZWNrUG9pbnQtU1NMLUluc3BlY3Rpb24xKTAnBgkqhkiG9w0BCQEWGmlsX3NlY3VyaXR5QGNoZWNrcG9pbnQuY29tMB4XDTIzM
       MxMzAwMDAwMFoXDTIzMDYxMTIzNTk1OVowbzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEzARBgNVBAcTCk1lbmxvIFBhcmsxHTAbBgNVBAoTFE1ldGEgUGxhdGZvcm1zLCBJbmMuMRcw
       QYDVQQDDA4qLndoYXRzYXBwLm5ldDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPjo05vRHAJYYWx55SOu2b1ZIQPOOtJNipSBXf1BFBDQhrkp20YTA296MzKii2j3TgVi/1t44cW5mD1RWobfAQujgbM
       gbAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHQGA1UdEQRtMGuCDioud2hhdHNhcHAubmV0ghIqLmNkbi53aGF0c2FwcC5uZXSCEiouc25yLndoYXRzYXBwLm5ldIIOKi53aGF0c2FwcC5jb2
       CBXdhLm1lggx3aGF0c2FwcC5jb22CDHdoYXRzYXBwLm5ldDAOBgNVHQ8BAf8EBAMCBaAwCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOCAgEAA/sIadLr9ahEVq8h9HuofHODUuzxVFulAZu8uSiyY4ACb
       Hcvm36MYQCzYV56t4fe+I++ls8KAESZgdE0KoD5/6efzK05Ufok+y15QexAR5AxZlJqtoHIuc7iOolPbkLW77GKrbgfEgmwOCX9/86Pug4ZSrrBUPPt9i3accNkAP+SH9Lft1geS2E/q+xcRhbhDcYTYD5
       X0MiEv0UaAzwS3adWAZbD7R42u+xNCpX8iUyiwp2UvMf0l/+Q8CAtw4D5s/8hD7Vqvrv4H/ZfV7SrZ+rPrihi01t6LlcpZ2YMucX/tSgDzkjYWmT26V2OgRklM0aQWvHD3DVpghIJfI2swAAJJ5wvqwcJe
       WHAQb3aQZgHXjGF/LyBYCQsohTHUL7rhL8CxNlDTNhN2e+NRFGYGer157RCmM8xKroe3/X9pYifbzyEWInqQ+ycmLsQyAd7pPW+W1K1tlk9Niqk3dNQ10daYGau3IPWF5+iHtOlWjLcQrSj60Uv7Ebi0E+
       Oe0tDabunCj6SEauGFxeJhM9xUZnOwb5wqIt+uGqPQ9WRJLehqwdFhiWOqwUfNcksn7l0M6e9Mnkh1J2kGxamQ0bvK7ftpm5O8MTAft0y882IfC++Zuk4gLhQoeE3s6877/rrHRJB/H8ZUaaBxAi2qH0NZ
       ParXUxOkil5rVgFqI="
"""

RETURN = """
cp_mgmt_add_custom_trusted_ca_certificate:
  description: The checkpoint add-custom-trusted-ca-certificate output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        base64_certificate=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full'])
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "add-custom-trusted-ca-certificate"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
