#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
from ansible.module_utils.basic import AnsibleModule


def convert_to_eos(cipher_name):
    # Set the cipher suite as 256 xpn by default
    eos_cipher_name = 'aes256-gcm-xpn'

    if cipher_name == 'GCM-AES-XPN-256':
        eos_cipher_name = 'aes256-gcm-xpn'
    elif cipher_name == 'GCM-AES-128':
        eos_cipher_name = 'aes128-gcm'
    elif cipher_name == 'GCM-AES-256':
        eos_cipher_name = 'aes256-gcm'
    elif cipher_name == 'GCM-AES-XPN-128':
        eos_cipher_name = 'aes128-gcm-xpn'

    return eos_cipher_name


# This API support EoS based templates now
def get_macsec_profile(module, macsec_profile, vm_type):
    with open('/tmp/profile.json') as f:
        macsec_profiles = json.load(f)

        profile = macsec_profiles.get(macsec_profile)
        if profile:
            profile['macsec_profile'] = macsec_profile

            # Currently handling ceos, add more cases for vsonic etc
            if vm_type == 'ceos':
                # Get the cipher suite in eos terminology
                eos_cipher_suite_name = convert_to_eos(profile['cipher_suite'])
                profile['cipher_suite'] = eos_cipher_suite_name

    return profile


def main():
    module = AnsibleModule(argument_spec=dict(
                           macsec_profile=dict(required=True, type='str'),
                           vm_type=dict(required=True, type='str')))

    macsec_profile = module.params['macsec_profile']
    vm_type = module.params['vm_type']
    module.exit_json(profile=get_macsec_profile(module, macsec_profile, vm_type), changed=False)


if __name__ == "__main__":
    main()
