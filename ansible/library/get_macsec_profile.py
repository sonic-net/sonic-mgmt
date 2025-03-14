#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
from ansible.module_utils.basic import AnsibleModule


def get_macsec_profile(module, macsec_profile):
    with open('/tmp/profile.json') as f:
        macsec_profiles = json.load(f)

        profile = macsec_profiles.get(macsec_profile)
        if profile:
            profile['macsec_profile'] = macsec_profile

    return profile


def main():
    module = AnsibleModule(argument_spec=dict(macsec_profile=dict(required=True, type='str')))

    macsec_profile = module.params['macsec_profile']
    module.exit_json(profile=get_macsec_profile(module, macsec_profile), changed=False)


if __name__ == "__main__":
    main()
