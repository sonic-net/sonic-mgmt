# -*- coding: utf-8 -*-

# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2016 Red Hat Inc.
# (c) 2017 Cisco Systems Inc.
#
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)
#


class ModuleDocFragment(object):
    # Cisco Intersight doc fragment
    DOCUMENTATION = '''
options:
  api_private_key:
    description:
    - 'Filename (absolute path) or string of PEM formatted private key data to be used for Intersight API authentication.'
    - If a string is used, Ansible vault should be used to encrypt string data.
    - "Ex. ansible-vault encrypt_string --vault-id tme@/Users/dsoper/Documents/vault_password_file '-----BEGIN EC PRIVATE KEY-----"
    - "    <your private key data>"
    - "    -----END EC PRIVATE KEY-----'"
    - If not set, the value of the INTERSIGHT_API_PRIVATE_KEY environment variable is used.
    type: path
    required: yes
  api_uri:
    description:
    - URI used to access the Intersight API.
    - If not set, the value of the INTERSIGHT_API_URI environment variable is used.
    type: str
    default: https://intersight.com/api/v1
  api_key_id:
    description:
    - Public API Key ID associated with the private key.
    - If not set, the value of the INTERSIGHT_API_KEY_ID environment variable is used.
    type: str
    required: yes
  validate_certs:
    description:
    - Boolean control for verifying the api_uri TLS certificate
    type: bool
    default: yes
  use_proxy:
    description:
    - If C(no), it will not use a proxy, even if one is defined in an environment variable on the target hosts.
    type: bool
    default: yes
'''
