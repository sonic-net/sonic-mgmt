#!/usr/bin/python
# Copyright (c) 2024 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = """
module: acme_certificate_order_info
author: Felix Fontein (@felixfontein)
version_added: 2.24.0
short_description: Obtain information for an ACME v2 order
description:
  - Obtain information for an ACME v2 order.
    This can be used during the process of obtaining a new certificate with the
    L(ACME protocol,https://tools.ietf.org/html/rfc8555) from a Certificate
    Authority such as L(Let's Encrypt,https://letsencrypt.org/).
    This module does not support ACME v1, the original version of the ACME protocol before standardization.
  - This module needs to be used in conjunction with the
    M(community.crypto.acme_certificate_order_create),
    M(community.crypto.acme_certificate_order_validate), and
    M(community.crypto.acme_certificate_order_finalize) modules.
seealso:
  - module: community.crypto.acme_certificate_order_create
    description: Create an ACME order.
  - module: community.crypto.acme_certificate_order_validate
    description: Validate pending authorizations of an ACME order.
  - module: community.crypto.acme_certificate_order_finalize
    description: Finalize an ACME order after satisfying the challenges.
  - name: Automatic Certificate Management Environment (ACME)
    description: The specification of the ACME protocol (RFC 8555).
    link: https://tools.ietf.org/html/rfc8555
  - name: ACME TLS ALPN Challenge Extension
    description: The specification of the V(tls-alpn-01) challenge (RFC 8737).
    link: https://www.rfc-editor.org/rfc/rfc8737.html
  - module: community.crypto.acme_inspect
    description: Allows to debug problems.
  - module: community.crypto.acme_certificate_deactivate_authz
    description: Allows to deactivate (invalidate) ACME v2 orders.
extends_documentation_fragment:
  - community.crypto._acme.basic
  - community.crypto._acme.account
  - community.crypto._attributes
  - community.crypto._attributes.actiongroup_acme
  - community.crypto._attributes.idempotent_not_modify_state
  - community.crypto._attributes.info_module
options:
  order_uri:
    description:
      - The order URI provided by RV(community.crypto.acme_certificate_order_create#module:order_uri).
    type: str
    required: true
"""

EXAMPLES = r"""
---
- name: Create a challenge for sample.com using a account key from a variable
  community.crypto.acme_certificate_order_create:
    account_key_content: "{{ account_private_key }}"
    csr: /etc/pki/cert/csr/sample.com.csr
  register: order

- name: Obtain information on the order
  community.crypto.acme_certificate_order_info:
    account_key_src: /etc/pki/cert/private/account.key
    order_uri: "{{ order.order_uri }}"
  register: order_info

- name: Show information
  ansible.builtin.debug:
    var: order_info
"""

RETURN = """
account_uri:
  description: ACME account URI.
  returned: success
  type: str
order_uri:
  description: ACME order URI.
  returned: success
  type: str
order:
  description:
    - The order object.
    - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.3) for its specification.
  returned: success
  type: dict
  contains:
    status:
      description:
        - The status of this order.
        - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.6) for state changes.
      type: str
      returned: always
      choices:
        - pending
        - ready
        - processing
        - valid
        - invalid
    expires:
      description:
        - The timestamp after which the server will consider this order invalid.
        - Encoded in the format specified in L(RFC 3339, https://www.rfc-editor.org/rfc/rfc3339).
      type: str
      returned: if RV(order.status) is V(pending) or V(valid), and sometimes in other situations
    identifiers:
      description:
        - An array of identifier objects that the order pertains to.
      returned: always
      type: list
      elements: dict
      contains:
        type:
          description:
            - The type of identifier.
            - So far V(dns) and V(ip) are defined values.
          type: str
          returned: always
          sample: dns
          choices:
            - dns
            - ip
        value:
          description:
            - The identifier itself.
          type: str
          returned: always
          sample: example.com
    notBefore:
      description:
        - The requested value of the C(notBefore) field in the certificate.
        - Encoded in the date format defined in L(RFC 3339, https://www.rfc-editor.org/rfc/rfc3339).
      type: str
      returned: depending on order
    notAfter:
      description:
        - The requested value of the C(notAfter) field in the certificate.
        - Encoded in the date format defined in L(RFC 3339, https://www.rfc-editor.org/rfc/rfc3339).
      type: str
      returned: depending on order
    error:
      description:
        - The error that occurred while processing the order, if any.
        - This field is structured as a L(problem document according to RFC 7807, https://www.rfc-editor.org/rfc/rfc7807).
      type: dict
      returned: sometimes
    authorizations:
      description:
        - For pending orders, the authorizations that the client needs to complete before the
          requested certificate can be issued, including unexpired authorizations that the client
          has completed in the past for identifiers specified in the order.
        - The authorizations required are dictated by server policy; there may not be a 1:1
          relationship between the order identifiers and the authorizations required.
        - For final orders (in the V(valid) or V(invalid) state), the authorizations that were
          completed.  Each entry is a URL from which an authorization can be fetched with a POST-as-GET request.
        - The authorizations themselves are returned as RV(authorizations_by_identifier).
      type: list
      elements: str
      returned: always
    finalize:
      description:
        - A URL that a CSR must be POSTed to once all of the order's authorizations are satisfied to finalize the
          order.  The result of a successful finalization will be the population of the certificate URL for the order.
      type: str
      returned: always
    certificate:
      description:
        - A URL for the certificate that has been issued in response to this order.
      type: str
      returned: when the certificate has been issued
    replaces:
      description:
        - If the order was created to replace an existing certificate using the C(replaces) mechanism from
          L(RFC 9773, https://www.rfc-editor.org/rfc/rfc9773.html), this provides the
          certificate ID of the certificate that will be replaced by this order.
      type: str
      returned: when the certificate order is replacing a certificate through RFC 9773
    profile:
      description:
        - If the ACME CA supports profiles through the L(draft-aaron-acme-profiles,
          https://datatracker.ietf.org/doc/draft-aaron-acme-profiles/) mechanism and informs about the profile
          selected for this order, this field will contain the name of the profile used.
      type: str
      returned: depending on the ACME CA
authorizations_by_identifier:
  description:
    - A dictionary mapping identifiers to their authorization objects.
  returned: success
  type: dict
  contains:
    identifier:
      description:
        - The keys in this dictionary are the identifiers. C(identifier) is a placeholder used in the documentation.
        - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.4) for how authorization objects look like.
      type: dict
      contains:
        identifier:
          description:
            - The identifier that the account is authorized to represent.
          type: dict
          returned: always
          contains:
            type:
              description:
                - The type of identifier.
                - So far V(dns) and V(ip) are defined values.
              type: str
              returned: always
              sample: dns
              choices:
                - dns
                - ip
            value:
              description:
                - The identifier itself.
              type: str
              returned: always
              sample: example.com
        status:
          description:
            - The status of this authorization.
            - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.6) for state changes.
          type: str
          choices:
            - pending
            - valid
            - invalid
            - deactivated
            - expired
            - revoked
          returned: always
        expires:
          description:
            - The timestamp after which the server will consider this authorization invalid.
            - Encoded in the format specified in L(RFC 3339, https://www.rfc-editor.org/rfc/rfc3339).
          type: str
          returned: if RV(authorizations_by_identifier.identifier.status=valid), and sometimes in other situations
        challenges:
          description:
            - For pending authorizations, the challenges that the client can fulfill in order to prove
              possession of the identifier.
            - For valid authorizations, the challenge that was validated.
            - For invalid authorizations, the challenge that was attempted and failed.
            - Each array entry is an object with parameters required to validate the challenge.
              A client should attempt to fulfill one of these challenges, and a server should consider
              any one of the challenges sufficient to make the authorization valid.
            - See U(https://www.rfc-editor.org/rfc/rfc8555#section-8) for the general structure. The structure
              of every entry depends on the challenge's type. For C(tls-alpn-01) challenges, the structure is
              defined in U(https://www.rfc-editor.org/rfc/rfc8737.html#section-3).
          type: list
          elements: dict
          returned: always
          contains:
            type:
              description:
                - The type of challenge encoded in the object.
              type: str
              returned: always
              choices:
                - http-01
                - dns-01
                - tls-alpn-01
            url:
              description:
                - The URL to which a response can be posted.
              type: str
              returned: always
            status:
              description:
                - The status of this challenge.
                - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.6) for state changes.
              type: str
              choices:
                - pending
                - processing
                - valid
                - invalid
              returned: always
            validated:
              description:
                - The time at which the server validated this challenge.
                - Encoded in the format specified in L(RFC 3339, https://www.rfc-editor.org/rfc/rfc3339).
              type: str
              returned: always if RV(authorizations_by_identifier.identifier.challenges[].type=valid), otherwise in some situations
            error:
              description:
                - Error that occurred while the server was validating the challenge, if any.
                - This field is structured as a L(problem document according to RFC 7807, https://www.rfc-editor.org/rfc/rfc7807).
              type: dict
              returned: always if RV(authorizations_by_identifier.identifier.challenges[].type=invalid), otherwise in some situations
        wildcard:
          description:
            - This field B(must) be present and true for authorizations created as a result of a
              C(newOrder) request containing a DNS identifier with a value that was a wildcard
              domain name.  For other authorizations, it B(must) be absent.
            - Wildcard domain names are described in U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.3)
              of the ACME specification.
          type: bool
          returned: sometimes
authorizations_by_status:
  description:
    - For every status, a list of identifiers whose authorizations have this status.
  returned: success
  type: dict
  contains:
    pending:
      description:
        - A list of all identifiers whose authorizations are in the C(pending) state.
        - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.6) for state changes
          of authorizations.
      type: list
      elements: str
      returned: always
    invalid:
      description:
        - A list of all identifiers whose authorizations are in the C(invalid) state.
        - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.6) for state changes
          of authorizations.
      type: list
      elements: str
      returned: always
    valid:
      description:
        - A list of all identifiers whose authorizations are in the C(valid) state.
        - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.6) for state changes
          of authorizations.
      type: list
      elements: str
      returned: always
    revoked:
      description:
        - A list of all identifiers whose authorizations are in the C(revoked) state.
        - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.6) for state changes
          of authorizations.
      type: list
      elements: str
      returned: always
    deactivated:
      description:
        - A list of all identifiers whose authorizations are in the C(deactivated) state.
        - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.6) for state changes
          of authorizations.
      type: list
      elements: str
      returned: always
    expired:
      description:
        - A list of all identifiers whose authorizations are in the C(expired) state.
        - See U(https://www.rfc-editor.org/rfc/rfc8555#section-7.1.6) for state changes
          of authorizations.
      type: list
      elements: str
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


def main() -> t.NoReturn:
    argument_spec = create_default_argspec(with_certificate=False)
    argument_spec.update_argspec(
        order_uri={"type": "str", "required": True},
    )
    module = argument_spec.create_ansible_module(supports_check_mode=True)

    backend = create_backend(module, needs_acme_v2=False)

    try:
        client = ACMECertificateClient(module=module, backend=backend)
        order = client.load_order()
        authorizations_by_identifier: dict[str, dict[str, t.Any]] = {}
        authorizations_by_status: dict[str, list[str]] = {
            "pending": [],
            "invalid": [],
            "valid": [],
            "revoked": [],
            "deactivated": [],
            "expired": [],
        }
        for identifier, authz in order.authorizations.items():
            authorizations_by_identifier[identifier] = authz.to_json()
            if authz.status is not None:
                authorizations_by_status[authz.status].append(identifier)
        module.exit_json(
            changed=False,
            account_uri=client.client.account_uri,
            order_uri=order.url,
            order=order.data,
            authorizations_by_identifier=authorizations_by_identifier,
            authorizations_by_status=authorizations_by_status,
        )
    except ModuleFailException as e:
        e.do_fail(module=module)


if __name__ == "__main__":
    main()
