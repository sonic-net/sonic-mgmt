#!/usr/bin/python
# Copyright (c) 2024 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = """
module: acme_certificate_order_finalize
author: Felix Fontein (@felixfontein)
version_added: 2.24.0
short_description: Finalize an ACME v2 order
description:
  - Finalizes an ACME v2 order and obtains the certificate and certificate chains.
    This is the final step of obtaining a new certificate with the
    L(ACME protocol,https://tools.ietf.org/html/rfc8555) from a Certificate
    Authority such as L(Let's Encrypt,https://letsencrypt.org/).
    This module does not support ACME v1, the original version of the ACME protocol before standardization.
  - This module needs to be used in conjunction with the
    M(community.crypto.acme_certificate_order_create) and.
    M(community.crypto.acme_certificate_order_validate) modules.
seealso:
  - module: community.crypto.acme_certificate_order_create
    description: Create an ACME order.
  - module: community.crypto.acme_certificate_order_validate
    description: Validate pending authorizations of an ACME order.
  - module: community.crypto.acme_certificate_order_info
    description: Obtain information for an ACME order.
  - name: The Let's Encrypt documentation
    description: Documentation for the Let's Encrypt Certification Authority.
                 Provides useful information for example on rate limits.
    link: https://letsencrypt.org/docs/
  - name: Automatic Certificate Management Environment (ACME)
    description: The specification of the ACME protocol (RFC 8555).
    link: https://tools.ietf.org/html/rfc8555
  - module: community.crypto.certificate_complete_chain
    description: Allows to find the root certificate for the returned fullchain.
  - module: community.crypto.acme_certificate_revoke
    description: Allows to revoke certificates.
  - module: community.crypto.acme_inspect
    description: Allows to debug problems.
  - module: community.crypto.acme_certificate_deactivate_authz
    description: Allows to deactivate (invalidate) ACME v2 orders.
extends_documentation_fragment:
  - community.crypto._acme.basic
  - community.crypto._acme.account
  - community.crypto._acme.certificate
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
  order_uri:
    description:
      - The order URI provided by RV(community.crypto.acme_certificate_order_create#module:order_uri).
    type: str
    required: true
  cert_dest:
    description:
      - "The destination file for the certificate."
    type: path
  fullchain_dest:
    description:
      - "The destination file for the full chain (that is, a certificate followed
         by chain of intermediate certificates)."
    type: path
  chain_dest:
    description:
      - If specified, the intermediate certificate will be written to this file.
    type: path
  deactivate_authzs:
    description:
      - "Deactivate authentication objects (authz) after issuing a certificate,
         or when issuing the certificate failed."
      - V(never) never deactivates them.
      - V(always) always deactivates them in cases of errors or when the certificate was issued.
      - V(on_error) only deactivates them in case of errors.
      - V(on_success) only deactivates them in case the certificate was successfully issued.
      - "Authentication objects are bound to an account key and remain valid
         for a certain amount of time, and can be used to issue certificates
         without having to re-authenticate the domain. This can be a security
         concern."
    type: str
    choices:
      - never
      - on_error
      - on_success
      - always
    default: always
  retrieve_all_alternates:
    description:
      - "When set to V(true), will retrieve all alternate trust chains offered by the ACME CA.
         These will not be written to disk, but will be returned together with the main
         chain as RV(all_chains). See the documentation for the RV(all_chains) return
         value for details."
    type: bool
    default: false
  select_chain:
    description:
      - "Allows to specify criteria by which an (alternate) trust chain can be selected."
      - "The list of criteria will be processed one by one until a chain is found
         matching a criterium. If such a chain is found, it will be used by the
         module instead of the default chain."
      - "If a criterium matches multiple chains, the first one matching will be
         returned. The order is determined by the ordering of the C(Link) headers
         returned by the ACME server and might not be deterministic."
      - "Every criterium can consist of multiple different conditions, like O(select_chain[].issuer)
         and O(select_chain[].subject). For the criterium to match a chain, all conditions must apply
         to the same certificate in the chain."
      - "This option can only be used with the C(cryptography) backend."
    type: list
    elements: dict
    suboptions:
      test_certificates:
        description:
          - "Determines which certificates in the chain will be tested."
          - "V(all) tests all certificates in the chain (excluding the leaf, which is
             identical in all chains)."
          - "V(first) only tests the first certificate in the chain, that is the one which
             signed the leaf."
          - "V(last) only tests the last certificate in the chain, that is the one furthest
             away from the leaf. Its issuer is the root certificate of this chain."
        type: str
        default: all
        choices: [first, last, all]
      issuer:
        description:
          - "Allows to specify parts of the issuer of a certificate in the chain must
             have to be selected."
          - "If O(select_chain[].issuer) is empty, any certificate will match."
          - 'An example value would be V({"commonName": "My Preferred CA Root"}).'
        type: dict
      subject:
        description:
          - "Allows to specify parts of the subject of a certificate in the chain must
             have to be selected."
          - "If O(select_chain[].subject) is empty, any certificate will match."
          - 'An example value would be V({"CN": "My Preferred CA Intermediate"})'
        type: dict
      subject_key_identifier:
        description:
          - "Checks for the SubjectKeyIdentifier extension. This is an identifier based
             on the private key of the intermediate certificate."
          - "The identifier must be of the form
             V(A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1)."
        type: str
      authority_key_identifier:
        description:
          - "Checks for the AuthorityKeyIdentifier extension. This is an identifier based
             on the private key of the issuer of the intermediate certificate."
          - "The identifier must be of the form
             V(C4:A7:B1:A4:7B:2C:71:FA:DB:E1:4B:90:75:FF:C4:15:60:85:89:10)."
        type: str
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
all_chains:
  description:
    - When O(retrieve_all_alternates=true), the module will query the ACME server for
      alternate chains. This return value will contain a list of all chains returned,
      the first entry being the main chain returned by the server.
    - See L(Section 7.4.2 of RFC8555,https://tools.ietf.org/html/rfc8555#section-7.4.2)
      for details.
  returned: success and O(retrieve_all_alternates=true)
  type: list
  elements: dict
  contains:
    cert:
      description:
        - The leaf certificate itself, in PEM format.
      type: str
      returned: always
    chain:
      description:
        - The certificate chain, excluding the root, as concatenated PEM certificates.
      type: str
      returned: always
    full_chain:
      description:
        - The certificate chain, excluding the root, but including the leaf certificate,
          as concatenated PEM certificates.
      type: str
      returned: always
selected_chain:
  description:
    - The selected certificate chain.
    - If O(select_chain) is not specified, this will be the main chain returned by the
      ACME server.
  returned: success
  type: dict
  contains:
    cert:
      description:
        - The leaf certificate itself, in PEM format.
      type: str
      returned: always
    chain:
      description:
        - The certificate chain, excluding the root, as concatenated PEM certificates.
      type: str
      returned: always
    full_chain:
      description:
        - The certificate chain, excluding the root, but including the leaf certificate,
          as concatenated PEM certificates.
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
    from ansible_collections.community.crypto.plugins.module_utils._acme.certificates import (  # pragma: no cover
        CertificateChain,
    )


def main() -> t.NoReturn:
    argument_spec = create_default_argspec(with_certificate=True)
    argument_spec.update_argspec(
        order_uri={"type": "str", "required": True},
        cert_dest={"type": "path"},
        fullchain_dest={"type": "path"},
        chain_dest={"type": "path"},
        deactivate_authzs={
            "type": "str",
            "default": "always",
            "choices": ["never", "always", "on_error", "on_success"],
        },
        retrieve_all_alternates={"type": "bool", "default": False},
        select_chain={
            "type": "list",
            "elements": "dict",
            "options": {
                "test_certificates": {
                    "type": "str",
                    "default": "all",
                    "choices": ["first", "last", "all"],
                },
                "issuer": {"type": "dict"},
                "subject": {"type": "dict"},
                "subject_key_identifier": {"type": "str"},
                "authority_key_identifier": {"type": "str"},
            },
        },
    )
    module = argument_spec.create_ansible_module()

    backend = create_backend(module, needs_acme_v2=False)

    try:
        client = ACMECertificateClient(module=module, backend=backend)
        select_chain_matcher = client.parse_select_chain(module.params["select_chain"])
        other = {}
        done = False
        order = None
        try:
            # Step 1: load order
            order = client.load_order()

            download_all_chains = (
                len(select_chain_matcher) > 0
                or module.params["retrieve_all_alternates"]
            )
            changed = False
            alternate_chains: list[CertificateChain] | None
            if order.status == "valid":
                # Step 2 and 3: download certificate(s) and chain(s)
                cert, alternate_chains = client.download_certificate(
                    order,
                    download_all_chains=download_all_chains,
                )
            else:
                client.check_that_authorizations_can_be_used(order)

                # Step 2: wait for authorizations to validate
                pending_authzs = client.collect_pending_authzs(order)
                client.wait_for_validation(pending_authzs)

                # Step 3: finalize order, wait, then download certificate(s) and chain(s)
                cert, alternate_chains = client.get_certificate(
                    order,
                    download_all_chains=download_all_chains,
                )
                changed = True

            # Step 4: pick chain, write certificates, and provide return values
            if alternate_chains is not None:
                # Prepare return value for all alternate chains
                if module.params["retrieve_all_alternates"]:
                    all_chains = [cert.to_json()]
                    for alt_chain in alternate_chains:
                        all_chains.append(alt_chain.to_json())
                    other["all_chains"] = all_chains

                # Try to select alternate chain depending on criteria
                if select_chain_matcher:
                    matching_chain = client.find_matching_chain(
                        chains=[cert] + alternate_chains,
                        select_chain_matcher=select_chain_matcher,
                    )
                    if matching_chain:
                        cert = matching_chain
                    else:
                        module.debug("Found no matching alternative chain")

            if client.write_cert_chain(
                cert=cert,
                cert_dest=module.params["cert_dest"],
                fullchain_dest=module.params["fullchain_dest"],
                chain_dest=module.params["chain_dest"],
            ):
                changed = True

            done = True
        finally:
            if (
                module.params["deactivate_authzs"] == "always"
                or (module.params["deactivate_authzs"] == "on_success" and done)
                or (module.params["deactivate_authzs"] == "on_error" and not done)
            ) and order:
                client.deactivate_authzs(order)
        module.exit_json(
            changed=changed,
            account_uri=client.client.account_uri,
            selected_chain=cert.to_json(),
            **other,
        )
    except ModuleFailException as e:
        e.do_fail(module=module)


if __name__ == "__main__":
    main()
