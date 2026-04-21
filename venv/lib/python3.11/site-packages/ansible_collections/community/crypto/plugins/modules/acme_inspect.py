#!/usr/bin/python
# Copyright (c) 2018 Felix Fontein (@felixfontein)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: acme_inspect
author: "Felix Fontein (@felixfontein)"
short_description: Send direct requests to an ACME server
description:
  - Allows to send direct requests to an ACME server with the L(ACME protocol,https://tools.ietf.org/html/rfc8555), which
    is supported by CAs such as L(Let's Encrypt,https://letsencrypt.org/).
  - This module can be used to debug failed certificate request attempts, for example when M(community.crypto.acme_certificate)
    fails or encounters a problem which you wish to investigate.
  - The module can also be used to directly access features of an ACME servers which are not yet supported by the Ansible
    ACME modules.
notes:
  - The O(account_uri) option must be specified for properly authenticated ACME v2 requests (except a C(new-account) request).
  - "Using the C(ansible) tool, M(community.crypto.acme_inspect) can be used to directly execute ACME requests without the
    need of writing a playbook. For example, the following command retrieves the ACME account with ID 1 from Let's Encrypt
    (assuming C(/path/to/key) is the correct private account key): C(ansible localhost -m acme_inspect -a \"account_key_src=/path/to/key
    acme_directory=https://acme-v02.api.letsencrypt.org/directory account_uri=https://acme-v02.api.letsencrypt.org/acme/acct/1
    method=get url=https://acme-v02.api.letsencrypt.org/acme/acct/1\")."
seealso:
  - name: Automatic Certificate Management Environment (ACME)
    description: The specification of the ACME protocol (RFC 8555).
    link: https://tools.ietf.org/html/rfc8555
  - name: ACME TLS ALPN Challenge Extension
    description: The specification of the C(tls-alpn-01) challenge (RFC 8737).
    link: https://www.rfc-editor.org/rfc/rfc8737.html
extends_documentation_fragment:
  - community.crypto._acme.basic
  - community.crypto._acme.account
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
  url:
    description:
      - The URL to send the request to.
      - Must be specified if O(method) is not V(directory-only).
    type: str
  method:
    description:
      - The method to use to access the given URL on the ACME server.
      - The value V(post) executes an authenticated POST request. The content must be specified in the O(content) option.
      - The value V(get) executes an authenticated POST-as-GET request for ACME v2, and a regular GET request for ACME v1.
      - The value V(directory-only) only retrieves the directory, without doing a request.
    type: str
    default: get
    choices:
      - get
      - post
      - directory-only
  content:
    description:
      - An encoded JSON object which will be sent as the content if O(method) is V(post).
      - Required when O(method) is V(post), and not allowed otherwise.
    type: str
  fail_on_acme_error:
    description:
      - If O(method) is V(post) or V(get), make the module fail in case an ACME error is returned.
    type: bool
    default: true
"""

EXAMPLES = r"""
---
- name: Get directory
  community.crypto.acme_inspect:
    acme_directory: https://acme-staging-v02.api.letsencrypt.org/directory
    method: directory-only
  register: directory

- name: Create an account
  community.crypto.acme_inspect:
    acme_directory: https://acme-staging-v02.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    url: "{{ directory.newAccount}}"
    method: post
    content: '{"termsOfServiceAgreed":true}'
  register: account_creation
  # account_creation.headers.location contains the account URI
  # if creation was successful

- name: Get account information
  community.crypto.acme_inspect:
    acme_directory: https://acme-staging-v02.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    account_uri: "{{ account_creation.headers.location }}"
    url: "{{ account_creation.headers.location }}"
    method: get

- name: Update account contacts
  community.crypto.acme_inspect:
    acme_directory: https://acme-staging-v02.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    account_uri: "{{ account_creation.headers.location }}"
    url: "{{ account_creation.headers.location }}"
    method: post
    content: '{{ account_info | to_json }}'
  vars:
    account_info:
      # For valid values, see
      # https://tools.ietf.org/html/rfc8555#section-7.3
      contact:
        - mailto:me@example.com

- name: Create certificate order
  community.crypto.acme_certificate:
    acme_directory: https://acme-staging-v02.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    account_uri: "{{ account_creation.headers.location }}"
    csr: /etc/pki/cert/csr/sample.com.csr
    fullchain_dest: /etc/httpd/ssl/sample.com-fullchain.crt
    challenge: http-01
    modify_account: false
  register: certificate_request

# Assume something went wrong. certificate_request.order_uri contains
# the order URI.

- name: Get order information
  community.crypto.acme_inspect:
    acme_directory: https://acme-staging-v02.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    account_uri: "{{ account_creation.headers.location }}"
    url: "{{ certificate_request.order_uri }}"
    method: get
  register: order

- name: Get first authz for order
  community.crypto.acme_inspect:
    acme_directory: https://acme-staging-v02.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    account_uri: "{{ account_creation.headers.location }}"
    url: "{{ order.output_json.authorizations[0] }}"
    method: get
  register: authz

- name: Get HTTP-01 challenge for authz
  community.crypto.acme_inspect:
    acme_directory: https://acme-staging-v02.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    account_uri: "{{ account_creation.headers.location }}"
    url: "{{ authz.output_json.challenges | selectattr('type', 'equalto', 'http-01') }}"
    method: get
  register: http01challenge

- name: Activate HTTP-01 challenge manually
  community.crypto.acme_inspect:
    acme_directory: https://acme-staging-v02.api.letsencrypt.org/directory
    account_key_src: /etc/pki/cert/private/account.key
    account_uri: "{{ account_creation.headers.location }}"
    url: "{{ http01challenge.url }}"
    method: post
    content: '{}'
"""

RETURN = r"""
directory:
  description: The ACME directory's content.
  returned: always
  type: dict
  sample: {
    "a85k3x9f91A4": "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
    "keyChange": "https://acme-v02.api.letsencrypt.org/acme/key-change",
    "meta": {
      "caaIdentities": ["letsencrypt.org"],
      "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf",
      "website": "https://letsencrypt.org",
    },
    "newAccount": "https://acme-v02.api.letsencrypt.org/acme/new-acct",
    "newNonce": "https://acme-v02.api.letsencrypt.org/acme/new-nonce",
    "newOrder": "https://acme-v02.api.letsencrypt.org/acme/new-order",
    "revokeCert": "https://acme-v02.api.letsencrypt.org/acme/revoke-cert"
  }
headers:
  description: The request's HTTP headers (with lowercase keys).
  returned: always
  type: dict
  sample: {
    "boulder-requester": "12345",
    "cache-control": "max-age=0, no-cache, no-store",
    "connection": "close",
    "content-length": "904",
    "content-type": "application/json",
    "cookies": {},
    "cookies_string": "",
    "date": "Wed, 07 Nov 2018 12:34:56 GMT",
    "expires": "Wed, 07 Nov 2018 12:44:56 GMT",
    "link": '<https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf>;rel="terms-of-service"',
    "msg": "OK (904 bytes)",
    "pragma": "no-cache",
    "replay-nonce": "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH",
    "server": "nginx",
    "status": 200,
    "strict-transport-security": "max-age=604800",
    "url": "https://acme-v02.api.letsencrypt.org/acme/acct/46161",
    "x-frame-options": "DENY",
  }
output_text:
  description: The raw text output.
  returned: always
  type: str
  sample: "{\\n  \\\"id\\\": 12345,\\n  \\\"key\\\": {\\n    \\\"kty\\\": \\\"RSA\\\",\\n ..."
output_json:
  description: The output parsed as JSON.
  returned: if output can be parsed as JSON
  type: dict
  sample:
    - id: 12345
    - key:
        - kty: RSA
        - '...'
"""

import typing as t

from ansible.module_utils.common.text.converters import to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils._acme.acme import (
    ACMEClient,
    create_backend,
    create_default_argspec,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ACMEProtocolException,
    ModuleFailException,
)


def main() -> t.NoReturn:
    argument_spec = create_default_argspec(require_account_key=False)
    argument_spec.update_argspec(
        url={"type": "str"},
        method={
            "type": "str",
            "choices": ["get", "post", "directory-only"],
            "default": "get",
        },
        content={"type": "str"},
        fail_on_acme_error={"type": "bool", "default": True},
    )
    argument_spec.update(
        required_if=[
            ("method", "get", ["url"]),
            ("method", "post", ["url", "content"]),
            ("method", "get", ["account_key_src", "account_key_content"], True),
            ("method", "post", ["account_key_src", "account_key_content"], True),
        ],
    )
    module = argument_spec.create_ansible_module()
    backend = create_backend(module, needs_acme_v2=False)

    result: dict[str, t.Any] = {}
    changed = False
    try:
        # Get hold of ACMEClient and ACMEAccount objects (includes directory)
        client = ACMEClient(module=module, backend=backend)
        method: t.Literal["get", "post", "directory-only"] = module.params["method"]
        result["directory"] = client.directory.directory
        # Do we have to do more requests?
        if method != "directory-only":
            url = module.params["url"]
            fail_on_acme_error = module.params["fail_on_acme_error"]
            # Do request
            if method == "get":
                data, info = client.get_request(
                    url, parse_json_result=False, fail_on_error=False
                )
            elif method == "post":
                changed = True  # only POSTs can change
                data, info = client.send_signed_request(
                    url,
                    to_bytes(module.params["content"]),
                    parse_json_result=False,
                    encode_payload=False,
                    fail_on_error=False,
                )
            else:
                raise AssertionError("Can never be reached")  # pragma: no cover
            # Update results
            result.update(
                {
                    "headers": info,
                    "output_text": to_text(data),
                }
            )
            # See if we can parse the result as JSON
            try:
                result["output_json"] = module.from_json(to_text(data))
            except Exception:
                pass
            # Fail if error was returned
            if fail_on_acme_error and info["status"] >= 400:
                raise ACMEProtocolException(module=module, info=info, content=data)
        # Done!
        module.exit_json(changed=changed, **result)
    except ModuleFailException as e:
        e.do_fail(module=module, **result)


if __name__ == "__main__":
    main()
