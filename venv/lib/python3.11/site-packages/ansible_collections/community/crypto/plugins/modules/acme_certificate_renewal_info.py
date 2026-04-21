#!/usr/bin/python
# Copyright (c) 2018 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: acme_certificate_renewal_info
author: "Felix Fontein (@felixfontein)"
version_added: 2.20.0
short_description: Determine whether a certificate should be renewed or not
description:
  - Uses various information to determine whether a certificate should be renewed or not.
  - If available, the ARI extension (ACME Renewal Information, L(RFC 9773, https://www.rfc-editor.org/rfc/rfc9773.html)) is
    used.
extends_documentation_fragment:
  - community.crypto._acme.basic
  - community.crypto._acme.no_account
  - community.crypto._attributes
  - community.crypto._attributes.info_module
  - community.crypto._attributes.idempotent_not_modify_state
attributes:
  idempotent:
    support: partial
    details:
      - The module is not idempotent if O(now) is a relative timestamp, or is not specified.
      - If O(use_ari=true), the module is not idempotent if O(ari_algorithm=standard).
options:
  certificate_path:
    description:
      - A path to the X.509 certificate to determine renewal of.
      - In case the certificate does not exist, the module will always return RV(should_renew=true).
      - O(certificate_path) and O(certificate_content) are mutually exclusive.
    type: path
  certificate_content:
    description:
      - The content of the X.509 certificate to determine renewal of.
      - O(certificate_path) and O(certificate_content) are mutually exclusive.
    type: str
  use_ari:
    description:
      - Whether to use ARI information, if available.
      - Set this to V(false) if the ACME server implements ARI in a way that is incompatible with this module.
    type: bool
    default: true
  ari_algorithm:
    description:
      - If ARI information is used, selects which algorithm is used to determine whether to renew now.
      - V(standard) selects the L(algorithm provided in the the ARI specification,
        https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2).
      - V(start) returns RV(should_renew=true) once the start of the renewal interval has been reached.
    type: str
    choices:
      - standard
      - start
    default: standard
  remaining_days:
    description:
      - The number of days the certificate must have left being valid.
      - For example, if O(remaining_days=20), this check causes RV(should_renew=true) if the certificate is valid for less
        than 20 days.
    type: int
  remaining_percentage:
    description:
      - The percentage of the certificate's validity period that should be left.
      - For example, if O(remaining_percentage=0.1), and the certificate's validity period is 90 days, this check causes RV(should_renew=true)
        if the certificate is valid for less than 9 days.
      - Must be a value between 0 and 1.
    type: float
  now:
    description:
      - Use this timestamp instead of the current timestamp to determine whether a certificate should be renewed.
      - Time can be specified either as relative time or as absolute timestamp.
      - Time will always be interpreted as UTC.
      - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer + C([w | d | h | m | s]) (for example
        V(+32w1d2h)).
    type: str
  treat_parsing_error_as_non_existing:
    description:
      - Determines the behavior when the certificate file exists or its contents are provided, but the certificate cannot be parsed.
      - If V(true), will exit successfully with RV(exists=true), RV(parsable=false), and RV(should_renew=true).
      - If V(false), the module will fail.
      - If the file exists, but cannot be loaded due to I/O errors or permission errors, the module always fails.
    type: bool
    default: false
    version_added: 2.24.0
seealso:
  - module: community.crypto.acme_certificate
    description: Allows to obtain a certificate using the ACME protocol.
  - module: community.crypto.acme_ari_info
    description: Obtain renewal information for a certificate.
"""

EXAMPLES = r"""
---
- name: Retrieve renewal information for a certificate
  community.crypto.acme_certificate_renewal_info:
    certificate_path: /etc/httpd/ssl/sample.com.crt
  register: cert_data

- name: Should the certificate be renewed?
  ansible.builtin.debug:
    var: cert_data.should_renew
"""

RETURN = r"""
should_renew:
  description:
    - Whether the certificate should be renewed.
    - If no certificate is provided, or the certificate is expired, will always be V(true).
  returned: success
  type: bool
  sample: true

exists:
  description:
    - Whether the certificate file exists, or O(certificate_content) was provided.
  returned: success
  type: bool
  sample: true
  version_added: 2.24.0

parsable:
  description:
    - Whether the certificate file exists, or O(certificate_content) was provided, and the certificate can be parsed.
    - Can only differ from RV(exists) if O(treat_parsing_error_as_non_existing=true).
  returned: success
  type: bool
  sample: true
  version_added: 2.24.0

msg:
  description:
    - Information on the reason for renewal.
    - Should be shown to the user, as in case of ARI triggered renewal it can contain important information, for example on
      forced revocations for misissued certificates.
  type: str
  returned: success
  sample: The certificate does not exist.

supports_ari:
  description:
    - Whether ARI information was used to determine renewal. This can be used to determine whether to specify
      O(community.crypto.acme_certificate#module:include_renewal_cert_id=when_ari_supported)
      for the M(community.crypto.acme_certificate) module.
    - If O(use_ari=false), this will always be V(false).
  returned: success
  type: bool
  sample: true

cert_id:
  description:
    - The certificate ID according to L(Section 4.1 in RFC 9773, https://www.rfc-editor.org/rfc/rfc9773.html#section-4.1).
  returned: success, the certificate exists, and has an Authority Key Identifier X.509 extension
  type: str
  sample: aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE
"""

import os
import random
import typing as t

from ansible_collections.community.crypto.plugins.module_utils._acme.acme import (
    ACMEClient,
    create_backend,
    create_default_argspec,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ModuleFailException,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.io import read_file
from ansible_collections.community.crypto.plugins.module_utils._acme.utils import (
    compute_cert_id,
)


def main() -> t.NoReturn:
    argument_spec = create_default_argspec(with_account=False)
    argument_spec.update_argspec(
        certificate_path={"type": "path"},
        certificate_content={"type": "str"},
        use_ari={"type": "bool", "default": True},
        ari_algorithm={
            "type": "str",
            "choices": ["standard", "start"],
            "default": "standard",
        },
        remaining_days={"type": "int"},
        remaining_percentage={"type": "float"},
        now={"type": "str"},
        treat_parsing_error_as_non_existing={"type": "bool", "default": False},
    )
    argument_spec.update(
        mutually_exclusive=[("certificate_path", "certificate_content")],
    )
    module = argument_spec.create_ansible_module(supports_check_mode=True)
    backend = create_backend(module, needs_acme_v2=True)

    result = {
        "changed": False,
        "msg": "The certificate is still valid and no condition was reached",
        "exists": False,
        "parsable": False,
        "supports_ari": False,
    }

    def complete(should_renew: bool, **kwargs: t.Any) -> t.NoReturn:
        result["should_renew"] = should_renew
        result.update(kwargs)
        module.exit_json(**result)

    if (
        not module.params["certificate_path"]
        and not module.params["certificate_content"]
    ):
        complete(True, msg="No certificate was specified")

    if module.params["certificate_path"] is not None:
        if not os.path.exists(module.params["certificate_path"]):
            complete(True, msg="The certificate file does not exist")
        if module.params["treat_parsing_error_as_non_existing"]:
            try:
                read_file(module.params["certificate_path"])
            except ModuleFailException as e:
                e.do_fail(module=module)

    result["exists"] = True
    try:
        cert_info = backend.get_cert_information(
            cert_filename=module.params["certificate_path"],
            cert_content=module.params["certificate_content"],
        )
    except ModuleFailException as e:
        if module.params["treat_parsing_error_as_non_existing"]:
            complete(True, msg=f"Certificate cannot be parsed: {e.msg}")
        e.do_fail(module=module)

    result["parsable"] = True
    try:
        cert_id = compute_cert_id(
            backend=backend,
            cert_info=cert_info,
            none_if_required_information_is_missing=True,
        )
        if cert_id is not None:
            result["cert_id"] = cert_id

        if module.params["now"]:
            now = backend.parse_module_parameter(value=module.params["now"], name="now")
        else:
            now = backend.get_now()

        if now >= cert_info.not_valid_after:
            complete(True, msg="The certificate has already expired")

        client = ACMEClient(module=module, backend=backend)
        if (
            cert_id is not None
            and module.params["use_ari"]
            and client.directory.has_renewal_info_endpoint()
        ):
            renewal_info = client.get_renewal_info(cert_id=cert_id)
            window_start = backend.parse_acme_timestamp(
                renewal_info["suggestedWindow"]["start"]
            )
            window_end = backend.parse_acme_timestamp(
                renewal_info["suggestedWindow"]["end"]
            )
            msg_append = ""
            if "explanationURL" in renewal_info:
                msg_append = f". Information on renewal interval: {renewal_info['explanationURL']}"
            result["supports_ari"] = True
            if now > window_end:
                complete(
                    True,
                    msg=f"The suggested renewal interval provided by ARI is in the past{msg_append}",
                )
            if module.params["ari_algorithm"] == "start":
                if now > window_start:
                    complete(
                        True,
                        msg=f"The suggested renewal interval provided by ARI has begun{msg_append}",
                    )
            else:
                random_time = backend.interpolate_timestamp(
                    window_start, window_end, percentage=random.random()
                )
                if now > random_time:
                    complete(
                        True,
                        msg=f"The picked random renewal time {random_time} in sugested renewal internal provided by ARI is in the past{msg_append}",
                    )

        if module.params["remaining_days"] is not None:
            remaining_days = (cert_info.not_valid_after - now).days
            if remaining_days < module.params["remaining_days"]:
                complete(
                    True,
                    msg=f"The certificate expires in {remaining_days} days",
                )

        if module.params["remaining_percentage"] is not None:
            timestamp = backend.interpolate_timestamp(
                cert_info.not_valid_before,
                cert_info.not_valid_after,
                percentage=1 - module.params["remaining_percentage"],
            )
            if timestamp < now:
                complete(
                    True,
                    msg=f"The remaining percentage {module.params['remaining_percentage'] * 100}% of the certificate's lifespan was reached on {timestamp}",
                )

        complete(False)
    except ModuleFailException as e:
        e.do_fail(module=module)


if __name__ == "__main__":
    main()
