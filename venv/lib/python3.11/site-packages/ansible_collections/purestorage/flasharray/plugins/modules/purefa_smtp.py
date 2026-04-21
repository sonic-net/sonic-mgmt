#!/usr/bin/python
# -*- coding: utf-8 -*-

# 2018, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_smtp
version_added: '1.0.0'
author:
  - Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
short_description: Configure FlashArray SMTP settings
description:
- Set or erase configuration for the SMTP settings.
- If username/password are set this will always force a change as there is
  no way to see if the password is differnet from the current SMTP configuration.
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Set or delete SMTP configuration
    default: present
    type: str
    choices: [ absent, present ]
  password:
    description:
    - The SMTP password.
    type: str
  user:
    description:
    - The SMTP username.
    type: str
  relay_host:
    description:
    - IPv4 or IPv6 address or FQDN. A port number may be appended.
    type: str
  sender_domain:
    description:
    - Domain name.
    type: str
  sender:
    description:
    - The local-part of the email address used when sending alert email messages.
    type: str
    version_added: "1.33.0"
  subject_prefix:
    description:
    - Optional string added to the beginning of the subject when sending alert
      email messages.
    - HTML tags are not allowed.
    type: str
    version_added: "1.33.0"
  body_prefix:
    description:
    - Optional string added to the beginning of the email body when sending
      alert email messages.
    - HTML tags are not allowed.
    type: str
    version_added: "1.33.0"
  encryption_mode:
    description:
    - Enforces an encryption mode when sending alert email messages.
    - Use empty string to clear.
    type: str
    choices: [ 'starttls', '' ]
    default: starttls
    version_added: "1.33.0"
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete exisitng SMTP settings
  purestorage.flasharray.purefa_smtp:
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: Set SMTP settings
  purestorage.flasharray.purefa_smtp:
    sender_domain: purestorage.com
    password: account_password
    user: smtp_account
    sender: array_email
    body_prefix: "SMTP-Body"
    subject_prefix: "SMTP"
    relay_host: 10.2.56.78:2345
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import SmtpServer
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)


def delete_smtp(module, array):
    """Delete SMTP settings"""
    changed = True
    if not module.check_mode:
        res = array.patch_smtp_servers(
            smtp=SmtpServer(
                sender_domain="None",
                user_name="",
                password="",
                relay_host="",
                encryption_mode="",
                sender_username="",
                subject_prefix="",
                body_prefix="",
            )
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Delete SMTP settigs failed. Error: {0}".foramt(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_smtp(module, array):
    """Set SMTP settings"""
    changed = False
    # Currently only 1 SMTP server is configurable
    current_smtp = list(array.get_smtp_servers().items)[0]
    current_server = {
        "sender_domain": getattr(current_smtp, "sender_domain", None),
        "relay_host": getattr(current_smtp, "relay_host", None),
        "user_name": getattr(current_smtp, "user_name", None),
        "encryption_mode": getattr(current_smtp, "encryption_mode", None),
        "sender_username": getattr(current_smtp, "sender_username", None),
        "subject_prefix": getattr(current_smtp, "subject_prefix", None),
        "body_prefix": getattr(current_smtp, "body_prefix", None),
    }
    new_server = {
        "sender_domain": getattr(current_smtp, "sender_domain", ""),
        "relay_host": getattr(current_smtp, "relay_host", ""),
        "user_name": getattr(current_smtp, "user_name", ""),
        "encryption_mode": getattr(current_smtp, "encryption_mode", ""),
        "sender_username": getattr(current_smtp, "sender_username", ""),
        "subject_prefix": getattr(current_smtp, "subject_prefix", ""),
        "body_prefix": getattr(current_smtp, "body_prefix", ""),
    }

    if (
        module.params["sender_domain"]
        and current_server["sender_domain"] != module.params["sender_domain"]
    ):
        new_server["sender_domain"] = module.params["sender_domain"]
    if (
        module.params["relay_host"]
        and current_server["relay_host"] != module.params["relay_host"]
    ):
        new_server["relay_host"] = module.params["relay_host"]
    if (
        module.params["user"]
        and current_server["user_name"] != module.params["user_name"]
    ):
        new_server["user_name"] = module.params["user"]
    if (
        module.params["sender"]
        and current_server["sender_username"] != module.params["sender"]
    ):
        new_server["sender_username"] = module.params["sender"]
    if (
        module.params["body_prefix"]
        and current_server["body_prefix"] != module.params["body_prefix"]
    ):
        new_server["body_prefix"] = module.params["body_prefix"]
    if (
        module.params["subject_prefix"]
        and current_server["subject_prefix"] != module.params["subject_prefix"]
    ):
        new_server["subject_prefix"] = module.params["subject_prefix"]
    if (
        module.params["encryption_mode"]
        and current_server["encryption_mode"] != module.params["encryption_mode"]
    ):
        new_server["encryption_mode"] = module.params["encryption_mode"]
    if new_server != current_server or module.params["password"]:
        changed = True
        if not module.check_mode:
            if module.params["password"]:
                res = array.patch_smtp_servers(
                    smtp=SmtpServer(
                        sender_domain=new_server["sender_domain"],
                        user_name=module.params["user"],
                        password=module.params["password"],
                        relay_host=new_server["relay_host"],
                        encryption_mode=new_server["encryption_mode"],
                        sender_username=new_server["sender_username"],
                        subject_prefix=new_server["subject_prefix"],
                        body_prefix=new_server["body_prefix"],
                    )
                )
            else:
                res = array.patch_smtp_servers(
                    smtp=SmtpServer(
                        sender_domain=new_server["sender_domain"],
                        relay_host=new_server["relay_host"],
                        encryption_mode=new_server["encryption_mode"],
                        sender_username=new_server["sender_username"],
                        subject_prefix=new_server["subject_prefix"],
                        body_prefix=new_server["body_prefix"],
                    )
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change SMTP server details. Error: {0}".format(
                        res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            sender_domain=dict(type="str"),
            password=dict(type="str", no_log=True),
            user=dict(type="str"),
            sender=dict(type="str"),
            subject_prefix=dict(type="str"),
            body_prefix=dict(type="str"),
            encryption_mode=dict(
                type="str", choices=["starttls", ""], default="starttls"
            ),
            relay_host=dict(type="str"),
        )
    )

    required_together = [["user", "password"]]
    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        supports_check_mode=True,
    )
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this mudule")

    state = module.params["state"]
    array = get_array(module)

    if state == "absent":
        delete_smtp(module, array)
    elif state == "present":
        create_smtp(module, array)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
