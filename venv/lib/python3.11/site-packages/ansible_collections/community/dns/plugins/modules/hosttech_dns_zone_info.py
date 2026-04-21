#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: hosttech_dns_zone_info

short_description: Retrieve zone information in Hosttech DNS service

version_added: 0.2.0

description:
  - Retrieves zone information in Hosttech DNS service.
extends_documentation_fragment:
  - community.dns.hosttech
  - community.dns.hosttech.zone_id_type
  - community.dns.module_zone_info
  - community.dns.attributes
  - community.dns.attributes.actiongroup_hosttech
  - community.dns.attributes.info_module
  - community.dns.attributes.idempotent_not_modify_state

attributes:
  action_group:
    version_added: 2.4.0

author:
  - Felix Fontein (@felixfontein)
"""

EXAMPLES = r"""
- name: Retrieve details for foo.com zone
  community.dns.hosttech_dns_zone_info:
    zone_name: foo.com
    hosttech_username: foo
    hosttech_password: bar
  register: rec

- name: Retrieve details for zone 23
  community.dns.hosttech_dns_zone_info:
    zone_id: 23
    hosttech_token: access_token
"""

RETURN = r"""
zone_name:
  description: The name of the zone.
  type: int
  returned: success
  sample: example.com

zone_id:
  description: The ID of the zone.
  type: int
  returned: success
  sample: 23

zone_info:
  description:
    - Extra information returned by the API.
  type: dict
  returned: success
  version_added: 2.0.0
  sample:
    dnssec: true
    dnssec_email: test@example.com
    ds_records: []
    email: test@example.com
    ttl: 3600
  contains:
    dnssec:
      description:
        - Whether DNSSEC is enabled for the zone or not.
      type: bool
      returned: When O(hosttech_token) has been specified.
    dnssec_email:
      description:
        - The email address contacted when the DNSSEC key is changed.
        - Is V(none) if DNSSEC is not enabled.
      type: str
      returned: When O(hosttech_token) has been specified.
    ds_records:
      description:
        - The DS records.
        - See L(Section 5 of RFC 4034,https://datatracker.ietf.org/doc/html/rfc4034#section-5) and
          L(Section 2.1 of RFC 4034,https://datatracker.ietf.org/doc/html/rfc4034#section-2.1) for details.
        - Is V(none) if DNSSEC is not enabled.
      type: list
      elements: dict
      returned: When O(hosttech_token) has been specified.
      contains:
        algorithm:
          description:
            - This value is the algorithm number of the DNSKEY RR referred to by the DS record.
            - A list of values can be found in L(Appendix A.1 of RFC 4034,https://datatracker.ietf.org/doc/html/rfc4034#appendix-A.1).
          type: int
          sample: 8
        digest:
          description:
            - A digest of the DNSKEY RR record this DS record refers to.
          type: str
          sample: 012356789ABCDEF0123456789ABCDEF012345678
        digest_type:
          description:
            - This value identifies the algorithm used to construct the digest.
            - A list of values can be found in L(Appendix A.2 of RFC 4034,https://datatracker.ietf.org/doc/html/rfc4034#appendix-A.2).
          type: int
          sample: 1
        flags:
          description:
            - The Zone Key flag. See L(Section 2.1.1 of RFC 4034,https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1)
              for details.
          type: int
          sample: 257
        key_tag:
          description:
            - The Key Tag field lists the key tag of the DNSKEY RR referred to by the DS record.
          type: int
          sample: 12345
        protocol:
          description:
            - Must be 3 according to RFC 4034.
          type: int
          sample: 3
        public_key:
          description:
            - The public key material.
          type: str
          sample: >-
            MuhdzsQdqEGShwjtJDKZZjdKqUSGluFzTTinpuEeIRzLLcgkwgAPKWFa
            eQntNlmcNDeCziGwpdvhJnvKXEMbFcZwsaDIJuWqERxAQNGABWfPlCLh
            HQPnbpRPNKipSdBaUhuOubvFvjBpFAwiwSAapRDVsAgKvjXucfXpFfYb
            pCundbAXBWhbpHVbqgmGoixXzFSwUsGVYLPpBCiDlLJwzjRKYYaoVYge
            kMtKFYUVnWIKbectWkDFdVqXwkKigCUDiuTTJxOBRJRNzGiDNMWBjYSm
            bBCAHMaMYaghLbYTwyKXltdHTHwBwtswGNfpnEdSpKFzZJonBZArQfHD
            lfceKgmKwEF=
    email:
      description:
        - The zone's DNS contact mail in the SOA record.
      type: str
    ttl:
      description:
        - The zone's TTL.
      type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.dns.plugins.module_utils.argspec import (
    ModuleOptionProvider,
)
from ansible_collections.community.dns.plugins.module_utils.hosttech.api import (
    create_hosttech_api,
    create_hosttech_argument_spec,
    create_hosttech_provider_information,
)
from ansible_collections.community.dns.plugins.module_utils.http import ModuleHTTPHelper
from ansible_collections.community.dns.plugins.module_utils.module.zone_info import (
    create_module_argument_spec,
    run_module,
)


def main():
    provider_information = create_hosttech_provider_information()
    argument_spec = create_hosttech_argument_spec()
    argument_spec.merge(create_module_argument_spec(provider_information=provider_information))
    module = AnsibleModule(supports_check_mode=True, **argument_spec.to_kwargs())
    run_module(module, lambda: create_hosttech_api(ModuleOptionProvider(module), ModuleHTTPHelper(module)), provider_information=provider_information)


if __name__ == '__main__':
    main()
