#!/usr/bin/python
# Copyright (c) 2018 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: acme_ari_info
author: "Felix Fontein (@felixfontein)"
version_added: 2.20.0
short_description: Retrieves ACME Renewal Information (ARI) for a certificate
description:
  - Allows to retrieve renewal information on a certificate obtained with the L(ACME protocol,https://tools.ietf.org/html/rfc8555).
  - This module only works with the ACME v2 protocol, and requires the ACME server to support the ARI extension
    (L(RFC 9773, https://www.rfc-editor.org/rfc/rfc9773.html)).
extends_documentation_fragment:
  - community.crypto._acme.basic
  - community.crypto._acme.no_account
  - community.crypto._attributes
  - community.crypto._attributes.info_module
  - community.crypto._attributes.idempotent_not_modify_state
options:
  certificate_path:
    description:
      - A path to the X.509 certificate to request information for.
      - Exactly one of O(certificate_path) and O(certificate_content) must be provided.
    type: path
  certificate_content:
    description:
      - The content of the X.509 certificate to request information for.
      - Exactly one of O(certificate_path) and O(certificate_content) must be provided.
    type: str
seealso:
  - module: community.crypto.acme_certificate
    description: Allows to obtain a certificate using the ACME protocol.
  - module: community.crypto.acme_certificate_revoke
    description: Allows to revoke a certificate using the ACME protocol.
"""

EXAMPLES = r"""
---
- name: Retrieve renewal information for a certificate
  community.crypto.acme_ari_info:
    certificate_path: /etc/httpd/ssl/sample.com.crt
  register: cert_data

- name: Show the certificate renewal information
  ansible.builtin.debug:
    var: cert_data.renewal_info
"""

RETURN = r"""
renewal_info:
  description: The ARI renewal info object (U(https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2)).
  returned: success
  type: dict
  contains:
    suggestedWindow:
      description:
        - Describes the window during which the certificate should be renewed.
      type: dict
      returned: always
      contains:
        start:
          description:
            - The start of the window during which the certificate should be renewed.
            - The format is specified in L(RFC 3339,https://www.rfc-editor.org/info/rfc3339).
          returned: always
          type: str
          sample: '2021-01-03T00:00:00Z'
        end:
          description:
            - The end of the window during which the certificate should be renewed.
            - The format is specified in L(RFC 3339,https://www.rfc-editor.org/info/rfc3339).
          returned: always
          type: str
          sample: '2021-01-03T00:00:00Z'
    explanationURL:
      description:
        - A URL pointing to a page which may explain why the suggested renewal window is what it is.
        - For example, it may be a page explaining the CA's dynamic load-balancing strategy, or a page documenting which certificates
          are affected by a mass revocation event. Should be shown to the user.
      returned: depends on the ACME server
      type: str
      sample: https://example.com/docs/ari
    retryAfter:
      description:
        - A timestamp before the next retry to ask for this information should not be made.
      returned: depends on the ACME server
      type: str
      sample: '2024-04-29T01:17:10.236921+00:00'
"""

import typing as t

from ansible_collections.community.crypto.plugins.module_utils._acme.acme import (
    ACMEClient,
    create_backend,
    create_default_argspec,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ModuleFailException,
)


def main() -> t.NoReturn:
    argument_spec = create_default_argspec(with_account=False)
    argument_spec.update_argspec(
        certificate_path={"type": "path"},
        certificate_content={"type": "str"},
    )
    argument_spec.update(
        required_one_of=[("certificate_path", "certificate_content")],
        mutually_exclusive=[("certificate_path", "certificate_content")],
    )
    module = argument_spec.create_ansible_module(supports_check_mode=True)
    backend = create_backend(module, needs_acme_v2=True)

    try:
        client = ACMEClient(module=module, backend=backend)
        if not client.directory.has_renewal_info_endpoint():
            module.fail_json(
                msg="The ACME endpoint does not support ACME Renewal Information retrieval"
            )
        renewal_info = client.get_renewal_info(
            cert_filename=module.params["certificate_path"],
            cert_content=module.params["certificate_content"],
            include_retry_after=True,
        )
        module.exit_json(renewal_info=renewal_info)
    except ModuleFailException as e:
        e.do_fail(module=module)


if __name__ == "__main__":
    main()
