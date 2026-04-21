#!/usr/bin/python
# Copyright (c) 2024 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = """
module: acme_certificate_order_validate
author: Felix Fontein (@felixfontein)
version_added: 2.24.0
short_description: Validate authorizations of an ACME v2 order
description:
  - Validates pending authorizations of an ACME v2 order.
    This is the second to last step of obtaining a new certificate with the
    L(ACME protocol,https://tools.ietf.org/html/rfc8555) from a Certificate
    Authority such as L(Let's Encrypt,https://letsencrypt.org/).
    This module does not support ACME v1, the original version of the ACME protocol before standardization.
  - This module needs to be used in conjunction with the
    M(community.crypto.acme_certificate_order_create) and
    M(community.crypto.acme_certificate_order_finalize) modules.
seealso:
  - module: community.crypto.acme_certificate_order_create
    description: Create an ACME order.
  - module: community.crypto.acme_certificate_order_finalize
    description: Finalize an ACME order after satisfying the challenges.
  - module: community.crypto.acme_certificate_order_info
    description: Obtain information for an ACME order.
  - name: The Let's Encrypt documentation
    description: Documentation for the Let's Encrypt Certification Authority.
                 Provides useful information for example on rate limits.
    link: https://letsencrypt.org/docs/
  - name: Automatic Certificate Management Environment (ACME)
    description: The specification of the ACME protocol (RFC 8555).
    link: https://tools.ietf.org/html/rfc8555
  - name: ACME TLS ALPN Challenge Extension
    description: The specification of the V(tls-alpn-01) challenge (RFC 8737).
    link: https://www.rfc-editor.org/rfc/rfc8737.html
  - module: community.crypto.acme_challenge_cert_helper
    description: Helps preparing V(tls-alpn-01) challenges.
  - module: community.crypto.acme_inspect
    description: Allows to debug problems.
  - module: community.crypto.acme_certificate_deactivate_authz
    description: Allows to deactivate (invalidate) ACME v2 orders.
extends_documentation_fragment:
  - community.crypto._acme.basic
  - community.crypto._acme.account
  - community.crypto._attributes
  - community.crypto._attributes.actiongroup_acme
  - community.crypto._attributes.files
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
  safe_file_operations:
    support: full
  idempotent:
    support: full
options:
  challenge:
    description:
      - The challenge to be performed for every pending authorization.
      - Must be provided if there is at least one pending authorization.
      - In case of authorization reuse, or in case of CAs which use External Account Binding
        and other means of validating certificate assurance, it might not be necessary
        to provide this option.
    type: str
    choices:
      - 'http-01'
      - 'dns-01'
      - 'tls-alpn-01'
  order_uri:
    description:
      - The order URI provided by RV(community.crypto.acme_certificate_order_create#module:order_uri).
    type: str
    required: true
  deactivate_authzs:
    description:
      - "Deactivate authentication objects (authz) in case an error happens."
      - "Authentication objects are bound to an account key and remain valid
         for a certain amount of time, and can be used to issue certificates
         without having to re-authenticate the domain. This can be a security
         concern."
    type: bool
    default: true
"""

EXAMPLES = r"""
---
### Example with HTTP-01 challenge ###

- name: Create a challenge for sample.com using a account key from a variable
  community.crypto.acme_certificate_order_create:
    account_key_content: "{{ account_private_key }}"
    csr: /etc/pki/cert/csr/sample.com.csr
  register: sample_com_challenge

# Alternative first step:
- name: Create a challenge for sample.com using a account key from Hashi Vault
  community.crypto.acme_certificate_order_create:
    account_key_content: >-
      {{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/account_private_key:value') }}
    csr: /etc/pki/cert/csr/sample.com.csr
  register: sample_com_challenge

# Alternative first step:
- name: Create a challenge for sample.com using a account key file
  community.crypto.acme_certificate_order_create:
    account_key_src: /etc/pki/cert/private/account.key
    csr_content: "{{ lookup('file', '/etc/pki/cert/csr/sample.com.csr') }}"
  register: sample_com_challenge

# Perform the necessary steps to fulfill the challenge. For example:
#
# - name: Copy http-01 challenges
#   ansible.builtin.copy:
#     dest: /var/www/{{ item.identifier }}/{{ item.challenges['http-01'].resource }}
#     content: "{{ item.challenges['http-01'].resource_value }}"
#   loop: "{{ sample_com_challenge.challenge_data }}"
#   when: "'http-01' in item.challenges"

- name: Let the challenge be validated
  community.crypto.acme_certificate_order_validate:
    account_key_src: /etc/pki/cert/private/account.key
    order_uri: "{{ sample_com_challenge.order_uri }}"
    challenge: http-01

- name: Retrieve the cert and intermediate certificate
  community.crypto.acme_certificate_order_finalize:
    account_key_src: /etc/pki/cert/private/account.key
    csr: /etc/pki/cert/csr/sample.com.csr
    order_uri: "{{ sample_com_challenge.order_uri }}"
    cert_dest: /etc/httpd/ssl/sample.com.crt
    fullchain_dest: /etc/httpd/ssl/sample.com-fullchain.crt
    chain_dest: /etc/httpd/ssl/sample.com-intermediate.crt

---
### Example with DNS challenge against production ACME server ###

- name: Create a challenge for sample.com using a account key file.
  community.crypto.acme_certificate_order_create:
    acme_directory: https://acme-v01.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    csr: /etc/pki/cert/csr/sample.com.csr
  register: sample_com_challenge

# Perform the necessary steps to fulfill the challenge. For example:
#
# - name: Create DNS records for dns-01 challenges
#   community.aws.route53:
#     zone: sample.com
#     record: "{{ item.key }}"
#     type: TXT
#     ttl: 60
#     state: present
#     wait: true
#     # Note: item.value is a list of TXT entries, and route53
#     # requires every entry to be enclosed in quotes
#     value: "{{ item.value | map('community.dns.quote_txt', always_quote=true) | list }}"
#   loop: "{{ sample_com_challenge.challenge_data_dns | dict2items }}"

- name: Let the challenge be validated
  community.crypto.acme_certificate_order_validate:
    acme_directory: https://acme-v01.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    order_uri: "{{ sample_com_challenge.order_uri }}"
    challenge: dns-01

- name: Retrieve the cert and intermediate certificate
  community.crypto.acme_certificate_order_finalize:
    acme_directory: https://acme-v01.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    csr: /etc/pki/cert/csr/sample.com.csr
    order_uri: "{{ sample_com_challenge.order_uri }}"
    cert_dest: /etc/httpd/ssl/sample.com.crt
    fullchain_dest: /etc/httpd/ssl/sample.com-fullchain.crt
    chain_dest: /etc/httpd/ssl/sample.com-intermediate.crt
"""

RETURN = """
account_uri:
  description: ACME account URI.
  returned: success
  type: str
validating_challenges:
  description: List of challenges whose validation was triggered.
  returned: success
  type: list
  elements: dict
  contains:
    identifier:
      description:
        - The identifier the challenge is for.
      type: str
      returned: always
    identifier_type:
      description:
        - The identifier's type for the challenge.
      type: str
      returned: always
      choices:
        - dns
        - ip
    authz_url:
      description:
        - The URL of the authorization object for this challenge.
      type: str
      returned: always
    challenge_type:
      description:
        - The challenge's type.
      type: str
      returned: always
      choices:
        - http-01
        - dns-01
        - tls-alpn-01
    challenge_url:
      description:
        - The URL of the challenge object.
      type: str
      returned: always
"""

import typing as t

from ansible_collections.community.crypto.plugins.module_utils._acme.acme import (
    create_backend,
    create_default_argspec,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.certificate import (
    ACMECertificateClient,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ModuleFailException,
)


if t.TYPE_CHECKING:
    from ansible_collections.community.crypto.plugins.module_utils._acme.challenges import (  # pragma: no cover
        Authorization,
    )


def main() -> t.NoReturn:
    argument_spec = create_default_argspec(with_certificate=False)
    argument_spec.update_argspec(
        order_uri={"type": "str", "required": True},
        challenge={"type": "str", "choices": ["http-01", "dns-01", "tls-alpn-01"]},
        deactivate_authzs={"type": "bool", "default": True},
    )
    module = argument_spec.create_ansible_module()

    backend = create_backend(module, needs_acme_v2=False)

    try:
        client = ACMECertificateClient(module=module, backend=backend)
        done = False
        order = None
        try:
            # Step 1: load order
            order = client.load_order()
            client.check_that_authorizations_can_be_used(order)

            # Step 2: find all pending authorizations
            pending_authzs = client.collect_pending_authzs(order)

            # Step 3: figure out challenges to use
            challenges = {}
            for authz in pending_authzs:
                challenges[authz.combined_identifier] = module.params["challenge"]

            missing_challenge_authzs = [k for k, v in challenges.items() if v is None]
            if missing_challenge_authzs:
                missing_challenge_authzs_str = ", ".join(
                    sorted(missing_challenge_authzs)
                )
                raise ModuleFailException(
                    "The challenge parameter must be supplied if there are pending authorizations."
                    f" The following authorizations are pending: {missing_challenge_authzs_str}"
                )

            bad_challenge_authzs = [
                authz.combined_identifier
                for authz in pending_authzs
                if authz.find_challenge(
                    challenge_type=challenges[authz.combined_identifier]
                )
                is None
            ]
            if bad_challenge_authzs:
                authz_challenges_pairs = ", ".join(
                    sorted(
                        f"{authz} with {challenges[authz]}"
                        for authz in bad_challenge_authzs
                    )
                )
                raise ModuleFailException(
                    f"The following authorizations do not support the selected challenges: {authz_challenges_pairs}"
                )

            def is_pending(authz: Authorization) -> bool:
                challenge_name = challenges[authz.combined_identifier]
                challenge_obj = authz.find_challenge(challenge_type=challenge_name)
                return challenge_obj is not None and challenge_obj.status == "pending"

            really_pending_authzs = [
                authz for authz in pending_authzs if is_pending(authz)
            ]

            # Step 4: validate pending authorizations
            authzs_with_challenges_to_wait_for = client.call_validate(
                really_pending_authzs,
                get_challenge=lambda authz: challenges[authz.combined_identifier],
                wait=False,
            )

            done = True
        finally:
            if order and module.params["deactivate_authzs"] and not done:
                client.deactivate_authzs(order)
        module.exit_json(
            changed=len(authzs_with_challenges_to_wait_for) > 0,
            account_uri=client.client.account_uri,
            validating_challenges=[
                {
                    "identifier": authz.identifier,
                    "identifier_type": authz.identifier_type,
                    "authz_url": authz.url,
                    "challenge_type": challenge_type,
                    "challenge_url": challenge.url if challenge else None,
                }
                for authz, challenge_type, challenge in authzs_with_challenges_to_wait_for
            ],
        )
    except ModuleFailException as e:
        e.do_fail(module=module)


if __name__ == "__main__":
    main()
