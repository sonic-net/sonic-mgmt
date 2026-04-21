#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_remote_location
short_description: Manages remote locations
description:
- Manage remote locations on Cisco ACI Multi-Site.
author:
- Akini Ross (@akinross)
options:
  remote_location:
    description:
    - The remote location's name.
    type: str
    aliases: [ name ]
  description:
    description:
    - The remote location's description.
    type: str
  remote_protocol:
    description:
    - The protocol used to export to the remote server.
    - If the remote location is a Windows server, you must use the C(sftp) protocol.
    choices: [ scp, sftp ]
    type: str
  remote_host:
    description:
    - The host name or IP address of the remote server.
    type: str
  remote_path:
    description:
    - The full path to a directory on the remote server where backups are saved.
    - The path must start with a slash (/) character and must not contain periods (.) or backslashes (\).
    - The directory must already exist on the server.
    type: str
  remote_port:
    description:
    - The port used to connect to the remote server.
    default: 22
    type: int
  authentication_type:
    description:
    - The authentication method used to connect to the remote server.
    choices: [ password, ssh ]
    type: str
  remote_username:
    description:
    - The username used to log in to the remote server.
    type: str
  remote_password:
    description:
    - The password used to log in to the remote server.
    type: str
  remote_ssh_key:
    description:
    - The private ssh key used to log in to the remote server.
    - The private ssh key must be provided in PEM format.
    - The private ssh key must be a single line string with linebreaks represent as "\n".
    type: str
  remote_ssh_passphrase:
    description:
    - The private ssh key passphrase used to log in to the remote server.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Query all remote locations
  cisco.mso.mso_remote_location:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
  register: backups

- name: Query a remote location
  cisco.mso.mso_remote_location:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    remote_location: ansible_test
    state: query
  register: query_result

- name: Configure a remote location
  cisco.mso.mso_remote_location:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    remote_location: ansible_test
    remote_protocol: scp
    remote_host: 10.0.0.1
    remote_path: /username/backup
    remote_authentication_type: password
    remote_username: username
    remote_password: password
    state: present

- name: Delete a remote location
  cisco.mso.mso_remote_location:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    remote_location: ansible_test
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        remote_location=dict(type="str", aliases=["name"]),
        description=dict(type="str"),
        remote_protocol=dict(type="str", choices=["scp", "sftp"]),
        remote_host=dict(type="str"),
        remote_path=dict(type="str"),
        remote_port=dict(type="int", default=22),
        authentication_type=dict(type="str", choices=["password", "ssh"]),
        remote_username=dict(type="str"),
        remote_password=dict(type="str", no_log=True),
        remote_ssh_key=dict(type="str", no_log=True),
        remote_ssh_passphrase=dict(type="str", no_log=True),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["remote_location", "remote_protocol", "remote_host", "remote_path", "authentication_type"]],
            ["state", "absent", ["remote_location"]],
            ["authentication_type", "password", ["remote_username", "remote_password"]],
            ["authentication_type", "ssh", ["remote_ssh_key"]],
        ],
    )

    location_name = module.params.get("remote_location")
    description = module.params.get("description")
    protocol = module.params.get("remote_protocol")
    host = module.params.get("remote_host")
    path = module.params.get("remote_path")
    port = module.params.get("remote_port")
    authentication_type = module.params.get("authentication_type")
    username = module.params.get("remote_username")
    password = module.params.get("remote_password")
    ssh_key = module.params.get("remote_ssh_key")
    passphrase = module.params.get("remote_ssh_passphrase")
    state = module.params.get("state")

    mso = MSOModule(module)
    api_path = "platform/remote-locations"
    mso.existing = mso.query_objs(api_path, key="remoteLocations")

    remote_location_obj = None
    if location_name and mso.existing:
        remote_location_obj = next((item for item in mso.existing if item.get("name") == location_name), None)
        if remote_location_obj:
            mso.existing = remote_location_obj

    if state == "query":
        if location_name and not remote_location_obj:
            existing_location_list = ", ".join([item.get("name") for item in mso.existing])
            mso.module.fail_json(msg="Remote location {0} not found. Remote locations configured: {1}".format(location_name, existing_location_list))

    elif state == "absent":
        mso.previous = mso.existing

        if module.check_mode:
            mso.existing = {}
        elif remote_location_obj:
            mso.existing = mso.request("{0}/{1}".format(api_path, remote_location_obj.get("id")), method="DELETE")

    elif state == "present":
        mso.previous = mso.existing

        credential = dict(
            authType=authentication_type if authentication_type == "password" else "sshKey",
            hostname=host,
            port=port,
            protocolType=protocol,
            remotePath=path,
            username=username,
        )

        if authentication_type == "password":
            credential.update(password=password)
        else:
            credential.update(sshKey=ssh_key)
            if passphrase:
                credential.update(passPhrase=passphrase)

        payload = dict(name=location_name, credential=credential)

        if description:
            payload.update(description=description)

        mso.proposed = payload

        if module.check_mode:
            mso.existing = mso.proposed
        else:
            if remote_location_obj:
                payload.update(id=remote_location_obj.get("id"))
                mso.existing = mso.request("{0}/{1}".format(api_path, remote_location_obj.get("id")), method="PUT", data=payload)
            else:
                mso.existing = mso.request(api_path, method="POST", data=payload)

        mso.existing["credential"].pop("password", None)
        mso.existing["credential"].pop("sshKey", None)
        mso.existing["credential"].pop("passPhrase", None)

    mso.exit_json()


if __name__ == "__main__":
    main()
