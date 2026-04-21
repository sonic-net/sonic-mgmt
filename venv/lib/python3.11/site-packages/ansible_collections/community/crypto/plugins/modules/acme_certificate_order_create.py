#!/usr/bin/python
# Copyright (c) 2024 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = """
module: acme_certificate_order_create
author: Felix Fontein (@felixfontein)
version_added: 2.24.0
short_description: Create an ACME v2 order
description:
  - Creates an ACME v2 order. This is the first step of obtaining a new certificate
    with the L(ACME protocol,https://tools.ietf.org/html/rfc8555) from a Certificate
    Authority such as L(Let's Encrypt,https://letsencrypt.org/).
    This module does not support ACME v1, the original version of the ACME protocol
    before standardization.
  - The current implementation supports the V(http-01), V(dns-01) and V(tls-alpn-01)
    challenges.
  - This module needs to be used in conjunction with the
    M(community.crypto.acme_certificate_order_validate) and.
    M(community.crypto.acme_certificate_order_finalize) module.
    An order can be effectively deactivated with the
    M(community.crypto.acme_certificate_deactivate_authz) module.
    Note that both modules require the output RV(order_uri) of this module.
  - To create or modify ACME accounts, use the M(community.crypto.acme_account) module.
    This module will I(not) create or update ACME accounts.
  - Between the call of this module and M(community.crypto.acme_certificate_order_finalize),
    you have to fulfill the required steps for the chosen challenge by whatever means necessary.
    For V(http-01) that means creating the necessary challenge file on the destination webserver.
    For V(dns-01) the necessary dns record has to be created. For V(tls-alpn-01) the necessary
    certificate has to be created and served. It is I(not) the responsibility of this module to
    perform these steps.
  - For details on how to fulfill these challenges, you might have to read through
    L(the main ACME specification,https://tools.ietf.org/html/rfc8555#section-8)
    and the L(TLS-ALPN-01 specification,https://www.rfc-editor.org/rfc/rfc8737.html#section-3).
    Also, consider the examples provided for this module.
  - The module includes support for IP identifiers according to
    the L(RFC 8738,https://www.rfc-editor.org/rfc/rfc8738.html) ACME extension.
seealso:
  - module: community.crypto.acme_certificate_order_validate
    description: Validate pending authorizations of an ACME order.
  - module: community.crypto.acme_certificate_order_finalize
    description: Finalize an ACME order after satisfying the challenges.
  - module: community.crypto.acme_certificate_order_info
    description: Obtain information for an ACME order.
  - module: community.crypto.acme_certificate_deactivate_authz
    description: Deactivate all authorizations (authz) of an ACME order, effectively deactivating
                 the order itself.
  - module: community.crypto.acme_certificate_renewal_info
    description: Determine whether a certificate should be renewed.
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
  - module: community.crypto.openssl_privatekey
    description: Can be used to create private keys (both for certificates and accounts).
  - module: community.crypto.openssl_privatekey_pipe
    description: Can be used to create private keys without writing it to disk (both for certificates and accounts).
  - module: community.crypto.openssl_csr
    description: Can be used to create a Certificate Signing Request (CSR).
  - module: community.crypto.openssl_csr_pipe
    description: Can be used to create a Certificate Signing Request (CSR) without writing it to disk.
  - module: community.crypto.acme_account
    description: Allows to create, modify or delete an ACME account.
  - module: community.crypto.acme_inspect
    description: Allows to debug problems.
extends_documentation_fragment:
  - community.crypto._acme.basic
  - community.crypto._acme.account
  - community.crypto._acme.certificate
  - community.crypto._attributes
  - community.crypto._attributes.actiongroup_acme
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
  idempotent:
    support: none
options:
  deactivate_authzs:
    description:
      - "Deactivate authentication objects (authz) when issuing the certificate
         failed."
      - "Authentication objects are bound to an account key and remain valid
         for a certain amount of time, and can be used to issue certificates
         without having to re-authenticate the domain. This can be a security
         concern."
    type: bool
    default: true
  replaces_cert_id:
    description:
      - If provided, will request the order to replace the certificate identified by this certificate ID
        according to L(Section 5 of RFC 9773, https://www.rfc-editor.org/rfc/rfc9773.html#section-5).
      - This certificate ID must be computed as specified in
        L(Section 4.1 of RFC 9773, https://www.rfc-editor.org/rfc/rfc9773.html#section-4.1).
        It is returned as return value RV(community.crypto.acme_certificate_renewal_info#module:cert_id) of the
        M(community.crypto.acme_certificate_renewal_info) module.
      - ACME servers might refuse to create new orders that indicate to replace a certificate for which
        an active replacement order already exists. This can happen if this module is used to create an order,
        and then the playbook/role fails in case the challenges cannot be set up. If the playbook/role does not
        record the order data to continue with the existing order, but tries to create a new one on the next run,
        creating the new order might fail. If O(order_creation_error_strategy=fail) this will make the module fail.
        O(order_creation_error_strategy=auto) and O(order_creation_error_strategy=retry_without_replaces_cert_id)
        will avoid this by leaving away C(replaces) on retries.
      - If O(order_creation_error_strategy=fail), for the above reason, this option should only be used
        if the role/playbook using it keeps track of order data accross restarts, or if it takes care to
        deactivate orders whose processing is aborted. Orders can be deactivated with the
        M(community.crypto.acme_certificate_deactivate_authz) module.
    type: str
  profile:
    description:
      - Chose a specific profile for certificate selection. The available profiles depend on the CA.
      - See L(a blog post by Let's Encrypt, https://letsencrypt.org/2025/01/09/acme-profiles/) and
        L(draft-aaron-acme-profiles-00, https://datatracker.ietf.org/doc/draft-aaron-acme-profiles/)
        for more information.
    type: str
  order_creation_error_strategy:
    description:
      - Selects the error handling strategy for ACME protocol errors if creating a new ACME order fails.
    type: str
    choices:
      auto:
        - An unspecified algorithm that tries to be clever.
        - Right now identical to V(retry_without_replaces_cert_id).
      always:
        - Always retry, until the limit in O(order_creation_max_retries) has been reached.
      fail:
        - Simply fail in case of errors. Do not attempt to retry.
      retry_without_replaces_cert_id:
        - If O(replaces_cert_id) is present, creating the order will be tried again without C(replaces).
        - The only exception is an error of type C(urn:ietf:params:acme:error:alreadyReplaced), that indicates that
          the certificate was already replaced. This usually means something went wrong and the user should investigate.
    default: auto
  order_creation_max_retries:
    description:
      - Depending on the strategy selected in O(order_creation_error_strategy), will retry creating new orders
        for at most the specified amount of times.
    type: int
    default: 3
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
challenge_data:
  description:
    - For every identifier, provides the challenge information.
    - Only challenges which are not yet valid are returned.
  returned: changed
  type: list
  elements: dict
  contains:
    identifier:
      description:
        - The identifier for this challenge.
      type: str
      sample: example.com
    identifier_type:
      description:
        - The identifier's type.
        - V(dns) for DNS names, and V(ip) for IP addresses.
      type: str
      choices:
        - dns
        - ip
      sample: dns
    challenges:
      description:
        - Information for different challenge types supported for this identifier.
        - Note that the keys are not valid Jinja2 identifiers.
      type: dict
      contains:
        http-01:
          description:
            - Information for V(http-01) authorization.
            - The server needs to make the path RV(challenge_data[].challenges.http-01.resource)
              accessible via HTTP (which might redirect to HTTPS). A C(GET) operation to this path
              needs to provide the value from RV(challenge_data[].challenges.http-01.resource_value).
          returned: if the identifier supports V(http-01) authorization
          type: dict
          contains:
            resource:
              description:
                - The path the value has to be provided under.
              returned: success
              type: str
              sample: .well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA
            resource_value:
              description:
                - The value the resource has to produce for the validation.
              returned: success
              type: str
              sample: IlirfxKKXA...17Dt3juxGJ-PCt92wr-oA
        dns-01:
          description:
            - Information for V(dns-01) authorization.
            - A DNS TXT record needs to be created with the record name RV(challenge_data[].challenges.dns-01.record)
              and value RV(challenge_data[].challenges.dns-01.resource_value).
          returned: if the identifier supports V(dns-01) authorization
          type: dict
          contains:
            resource:
              description:
                - Always contains the string V(_acme-challenge).
              type: str
              sample: _acme-challenge
            resource_value:
              description:
                - The value the resource has to produce for the validation.
              returned: success
              type: str
              sample: IlirfxKKXA...17Dt3juxGJ-PCt92wr-oA
            record:
              description: The full DNS record's name for the challenge.
              returned: success
              type: str
              sample: _acme-challenge.example.com
        tls-alpn-01:
          description:
            - Information for V(tls-alpn-01) authorization.
            - A certificate needs to be created for the DNS name RV(challenge_data[].challenges.tls-alpn-01.resource)
              with acmeValidation X.509 extension of value RV(challenge_data[].challenges.tls-alpn-01.resource_value).
              This certificate needs to be served when the application-layer protocol C(acme-tls/1) is negotiated for
              a HTTPS connection to port 443 with the SNI extension for the domain name
              (RV(challenge_data[].challenges.tls-alpn-01.resource_original)) being validated.
            - See U(https://www.rfc-editor.org/rfc/rfc8737.html#section-3) for details.
          returned: if the identifier supports V(tls-alpn-01) authorization
          type: dict
          contains:
            resource:
              description:
                - The DNS name for DNS identifiers, and the reverse DNS mapping (RFC1034, RFC3596) for IP addresses.
              returned: success
              type: str
              sample: example.com
            resource_original:
              description:
                - The original identifier including type identifier.
              returned: success
              type: str
              sample: dns:example.com
            resource_value:
              description:
                - The value the resource has to produce for the validation.
                - "B(Note:) this return value contains a Base64 encoded version of the correct
                   binary blob which has to be put into the acmeValidation X.509 extension; see
                   U(https://www.rfc-editor.org/rfc/rfc8737.html#section-3) for details. To do this,
                   you might need the P(ansible.builtin.b64decode#filter) Jinja filter to extract
                   the binary blob from this return value."
              returned: success
              type: str
              sample: AAb=
challenge_data_dns:
  description:
    - List of TXT values per DNS record for V(dns-01) challenges.
    - Only challenges which are not yet valid are returned.
  returned: success
  type: dict
order_uri:
  description: ACME order URI.
  returned: success
  type: str
account_uri:
  description: ACME account URI.
  returned: success
  type: str
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


def main() -> t.NoReturn:
    argument_spec = create_default_argspec(with_certificate=True)
    argument_spec.update_argspec(
        deactivate_authzs={"type": "bool", "default": True},
        replaces_cert_id={"type": "str"},
        profile={"type": "str"},
        order_creation_error_strategy={
            "type": "str",
            "default": "auto",
            "choices": ["auto", "always", "fail", "retry_without_replaces_cert_id"],
        },
        order_creation_max_retries={"type": "int", "default": 3},
    )
    module = argument_spec.create_ansible_module()

    backend = create_backend(module, needs_acme_v2=False)

    try:
        client = ACMECertificateClient(module=module, backend=backend)

        profile = module.params["profile"]
        if profile is not None:
            meta_profiles = (client.client.directory.get("meta") or {}).get(
                "profiles"
            ) or {}
            if not meta_profiles:
                raise ModuleFailException(
                    msg='The ACME CA does not support profiles. Please omit the "profile" option.'
                )
            if profile not in meta_profiles:
                raise ModuleFailException(
                    msg=f"The ACME CA does not support selected profile {profile!r}."
                )

        order = None
        done = False
        try:
            order = client.create_order(
                replaces_cert_id=module.params["replaces_cert_id"], profile=profile
            )
            client.check_that_authorizations_can_be_used(order)
            done = True
        finally:
            if module.params["deactivate_authzs"] and order and not done:
                client.deactivate_authzs(order)
        data, data_dns = client.get_challenges_data(order)
        module.exit_json(
            changed=True,
            order_uri=order.url,
            account_uri=client.client.account_uri,
            challenge_data=data,
            challenge_data_dns=data_dns,
        )
    except ModuleFailException as e:
        e.do_fail(module=module)


if __name__ == "__main__":
    main()
