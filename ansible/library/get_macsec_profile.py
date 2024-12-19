#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
from ansible.module_utils.basic import AnsibleModule


def get_macsec_profile(module, macsec_profile):
    with open('/tmp/profile.json') as f:
        macsec_profiles = json.load(f)
        for k, v in list(macsec_profiles.items()):
            if k == macsec_profile:
                profile = v
                # Update the macsec profile name in the profile context
                profile['macsec_profile'] = k
                break
    return profile


def main():
    module = AnsibleModule(argument_spec=dict(macsec_profile=dict(required=True, type='str')))

    macsec_profile = module.params['macsec_profile']
    module.exit_json(profile=get_macsec_profile(module, macsec_profile), changed=False)


if __name__ == "__main__":
    main()
