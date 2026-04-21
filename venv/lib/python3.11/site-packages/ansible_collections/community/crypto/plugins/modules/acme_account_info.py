#!/usr/bin/python
# Copyright (c) 2018 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: acme_account_info
author: "Felix Fontein (@felixfontein)"
short_description: Retrieves information on ACME accounts
description:
  - Allows to retrieve information on accounts a CA supporting the L(ACME protocol,https://tools.ietf.org/html/rfc8555), such
    as L(Let's Encrypt,https://letsencrypt.org/).
  - This module only works with the ACME v2 protocol.
notes:
  - The M(community.crypto.acme_account) module allows to modify, create and delete ACME accounts.
  - This module was called C(acme_account_facts) before Ansible 2.8. The usage did not change.
extends_documentation_fragment:
  - community.crypto._acme.basic
  - community.crypto._acme.account
  - community.crypto._attributes
  - community.crypto._attributes.actiongroup_acme
  - community.crypto._attributes.info_module
  - community.crypto._attributes.idempotent_not_modify_state
options:
  retrieve_orders:
    description:
      - Whether to retrieve the list of order URLs or order objects, if provided by the ACME server.
      - A value of V(ignore) will not fetch the list of orders.
      - If the value is not V(ignore) and the ACME server supports orders, the RV(order_uris) return value is always populated.
        The RV(orders) return value is only returned if this option is set to V(object_list).
      - Currently, Let's Encrypt does not return orders, so the RV(orders) result will always be empty.
    type: str
    choices:
      - ignore
      - url_list
      - object_list
    default: ignore
seealso:
  - module: community.crypto.acme_account
    description: Allows to create, modify or delete an ACME account.
"""

EXAMPLES = r"""
---
- name: Check whether an account with the given account key exists
  community.crypto.acme_account_info:
    account_key_src: /etc/pki/cert/private/account.key
  register: account_data
- name: Verify that account exists
  ansible.builtin.assert:
    that:
      - account_data.exists
- name: Print account URI
  ansible.builtin.debug:
    var: account_data.account_uri
- name: Print account contacts
  ansible.builtin.debug:
    var: account_data.account.contact

- name: Check whether the account exists and is accessible with the given account key
  acme_account_info:
    account_key_content: "{{ acme_account_key }}"
    account_uri: "{{ acme_account_uri }}"
  register: account_data
- name: Verify that account exists
  ansible.builtin.assert:
    that:
      - account_data.exists
- name: Print account contacts
  ansible.builtin.debug:
    var: account_data.account.contact
"""

RETURN = r"""
exists:
  description: Whether the account exists.
  returned: always
  type: bool

account_uri:
  description: ACME account URI, or None if account does not exist.
  returned: always
  type: str

account:
  description: The account information, as retrieved from the ACME server.
  returned: if account exists
  type: dict
  contains:
    contact:
      description: The challenge resource that must be created for validation.
      returned: always
      type: list
      elements: str
      sample: ['mailto:me@example.com', 'tel:00123456789']
    status:
      description: The account's status.
      returned: always
      type: str
      choices: ['valid', 'deactivated', 'revoked']
      sample: valid
    orders:
      description:
        - A URL where a list of orders can be retrieved for this account.
        - Use the O(retrieve_orders) option to query this URL and retrieve the complete list of orders.
      returned: always
      type: str
      sample: https://example.ca/account/1/orders
    public_account_key:
      description: The public account key as a L(JSON Web Key,https://tools.ietf.org/html/rfc7517).
      returned: always
      type: str
      sample: '{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}'

orders:
  description:
    - The list of orders.
  type: list
  elements: dict
  returned: if account exists, O(retrieve_orders) is V(object_list), and server supports order listing
  contains:
    status:
      description: The order's status.
      type: str
      choices:
        - pending
        - ready
        - processing
        - valid
        - invalid
    expires:
      description:
        - When the order expires.
        - Timestamp should be formatted as described in RFC3339.
        - Only required to be included in result when RV(orders[].status) is V(pending) or V(valid).
      type: str
      returned: when server gives expiry date
    identifiers:
      description:
        - List of identifiers this order is for.
      type: list
      elements: dict
      contains:
        type:
          description: Type of identifier.
          type: str
          choices:
            - dns
            - ip
        value:
          description: Name of identifier. Hostname or IP address.
          type: str
        wildcard:
          description: "Whether RV(orders[].identifiers[].value) is actually a wildcard. The wildcard prefix C(*.) is not
            included in RV(orders[].identifiers[].value) if this is V(true)."
          type: bool
          returned: required to be included if the identifier is wildcarded
    notBefore:
      description:
        - The requested value of the C(notBefore) field in the certificate.
        - Date should be formatted as described in RFC3339.
        - Server is not required to return this.
      type: str
      returned: when server returns this
    notAfter:
      description:
        - The requested value of the C(notAfter) field in the certificate.
        - Date should be formatted as described in RFC3339.
        - Server is not required to return this.
      type: str
      returned: when server returns this
    error:
      description:
        - In case an error occurred during processing, this contains information about the error.
        - The field is structured as a problem document (RFC7807).
      type: dict
      returned: when an error occurred
    authorizations:
      description:
        - A list of URLs for authorizations for this order.
      type: list
      elements: str
    finalize:
      description:
        - A URL used for finalizing an ACME order.
      type: str
    certificate:
      description:
        - The URL for retrieving the certificate.
      type: str
      returned: when certificate was issued

order_uris:
  description:
    - The list of orders.
    - If O(retrieve_orders) is V(url_list), this will be a list of URLs.
    - If O(retrieve_orders) is V(object_list), this will be a list of objects.
  type: list
  elements: str
  returned: if account exists, O(retrieve_orders) is not V(ignore), and server supports order listing
  version_added: 1.5.0
"""

import typing as t

from ansible_collections.community.crypto.plugins.module_utils._acme.account import (
    ACMEAccount,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.acme import (
    ACMEClient,
    create_backend,
    create_default_argspec,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ACMEProtocolException,
    ModuleFailException,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.utils import (
    process_links,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule  # pragma: no cover


def _collect_next(info: dict[str, t.Any]) -> list[str]:
    result: list[str] = []

    def f(link: str, relation: str) -> None:
        if relation == "next":
            result.append(link)

    process_links(info=info, callback=f)
    return result


def get_orders_list(
    module: AnsibleModule, client: ACMEClient, orders_url: str
) -> list[str]:
    """
    Retrieves order URL list (handles pagination).
    """
    orders: list[str] = []
    next_orders_url: str | None = orders_url
    while next_orders_url:
        # Get part of orders list
        res, info = client.get_request(
            next_orders_url, parse_json_result=True, fail_on_error=True
        )
        if not isinstance(res, dict):
            raise ACMEProtocolException(
                module=module,
                msg="Unexpected account information",
                info=info,
                content_json=res,
            )
        if not res.get("orders"):
            if orders:
                module.warn(
                    f"When retrieving orders list part {next_orders_url}, got empty result list"
                )
            break
        # Add order URLs to result list
        orders.extend(res["orders"])
        # Extract URL of next part of results list
        new_orders_url: list[str | None] = []
        new_orders_url.extend(_collect_next(info))
        new_orders_url.append(None)
        previous_orders_url, next_orders_url = next_orders_url, new_orders_url.pop(0)
        if next_orders_url == previous_orders_url:
            # Prevent infinite loop
            next_orders_url = None
    return orders


def get_order(client: ACMEClient, order_url: str) -> dict[str, t.Any]:
    """
    Retrieve order data.
    """
    result, info = client.get_request(
        order_url, parse_json_result=True, fail_on_error=True
    )
    if not isinstance(result, dict):
        raise ACMEProtocolException(
            module=client.module,
            msg="Unexpected order data",
            info=info,
            content_json=result,
        )
    return result


def main() -> t.NoReturn:
    argument_spec = create_default_argspec()
    argument_spec.update_argspec(
        retrieve_orders={
            "type": "str",
            "default": "ignore",
            "choices": ["ignore", "url_list", "object_list"],
        },
    )
    module = argument_spec.create_ansible_module(supports_check_mode=True)
    backend = create_backend(module, needs_acme_v2=True)

    try:
        client = ACMEClient(module=module, backend=backend)
        account = ACMEAccount(client=client)
        # Check whether account exists
        created, account_data = account.setup_account(
            contact=[],
            allow_creation=False,
            remove_account_uri_if_not_exists=True,
        )
        if created:
            raise AssertionError("Unwanted account creation")  # pragma: no cover
        result: dict[str, t.Any] = {
            "changed": False,
            "exists": False,
            "account_uri": None,
        }
        if client.account_uri is not None and account_data:
            result["account_uri"] = client.account_uri
            result["exists"] = True
            # Make sure promised data is there
            account_data_dict = dict(account_data)
            if "contact" not in account_data:
                account_data_dict["contact"] = []
            if client.account_key_data:
                account_data_dict["public_account_key"] = client.account_key_data["jwk"]
            result["account"] = account_data_dict
            # Retrieve orders list
            if (
                account_data.get("orders")
                and module.params["retrieve_orders"] != "ignore"
            ):
                orders = get_orders_list(module, client, account_data["orders"])
                result["order_uris"] = orders
                if module.params["retrieve_orders"] == "object_list":
                    result["orders"] = [get_order(client, order) for order in orders]
        module.exit_json(**result)
    except ModuleFailException as e:
        e.do_fail(module=module)


if __name__ == "__main__":
    main()
