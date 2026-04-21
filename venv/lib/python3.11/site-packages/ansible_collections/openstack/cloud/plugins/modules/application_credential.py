#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 Red Hat, Inc.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: application_credential
short_description: Manage OpenStack Identity (Keystone) application credentials
author: OpenStack Ansible SIG
description:
  - Create or delete an OpenStack Identity (Keystone) application credential.
  - When the secret parameter is not set a secret will be generated and returned
  - in the response. Existing credentials cannot be modified so running this module
  - against an existing credential will result in it being deleted and recreated.
  - This needs to be taken into account when the secret is generated, as the secret
  - will change on each run of the module.
options:
  name:
    description:
      - Name of the application credential.
    required: true
    type: str
  description:
    description:
      - Application credential description.
    type: str
  secret:
    description:
      - Secret to use for authentication
      - (if not provided, one will be generated).
    type: str
  roles:
    description:
      - Roles to authorize (name or ID).
    type: list
    elements: dict
    suboptions:
      name:
        description: Name of role
        type: str
      id:
        description: ID of role
        type: str
      domain_id:
        description: Domain ID
        type: str
  expires_at:
    description:
      - Sets an expiration date for the application credential,
      - format of YYYY-mm-ddTHH:MM:SS
      - (if not provided, the application credential will not expire).
    type: str
  unrestricted:
    description:
      - Enable application credential to create and delete other application
      - credentials and trusts (this is potentially dangerous behavior and is
      - disabled by default).
    default: false
    type: bool
  access_rules:
    description:
      - List of access rules, each containing a request method, path, and service.
    type: list
    elements: dict
    suboptions:
      service:
        description: Name of service endpoint
        type: str
        required: true
      path:
        description: Path portion of access URL
        type: str
        required: true
      method:
        description: HTTP method
        type: str
        required: true
  state:
    description:
      - Should the resource be present or absent.
      - Application credentials are immutable so running with an existing present
      - credential will result in the credential being deleted and recreated.
    choices: [present, absent]
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
"""

EXAMPLES = r"""
- name: Create application credential
  openstack.cloud.application_credential:
    cloud: mycloud
    description: demodescription
    name: democreds
    state: present

- name: Create application credential with expiration, access rules and roles
  openstack.cloud.application_credential:
    cloud: mycloud
    description: demodescription
    name: democreds
    access_rules:
    - service: "compute"
      path: "/v2.1/servers"
      method: "GET"
    expires_at: "2024-02-29T09:29:59"
    roles:
    - name: Member
    state: present

- name: Delete application credential
  openstack.cloud.application_credential:
    cloud: mycloud
    name: democreds
    state: absent
"""

RETURN = r"""
application_credential:
  description: Dictionary describing the project.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    id:
      description: The ID of the application credential.
      type: str
      sample: "2e73d1b4f0cb473f920bd54dfce3c26d"
    name:
      description: The name of the application credential.
      type: str
      sample: "appcreds"
    secret:
      description: Secret to use for authentication
                   (if not provided, returns the generated value).
      type: str
      sample: "JxE7LajLY75NZgDH1hfu0N_6xS9hQ-Af40W3"
    description:
      description: A description of the application credential's purpose.
      type: str
      sample: "App credential"
    expires_at:
      description: The expiration time of the application credential in UTC,
                   if one was specified.
      type: str
      sample: "2024-02-29T09:29:59.000000"
    project_id:
      description: The ID of the project the application credential was created
                   for and that authentication requests using this application
                   credential will be scoped to.
      type: str
      sample: "4b633c451ac74233be3721a3635275e5"
    roles:
      description: A list of one or more roles that this application credential
                   has associated with its project. A token using this application
                   credential will have these same roles.
      type: list
      elements: dict
      sample: [{"name": "Member"}]
    access_rules:
      description: A list of access_rules objects
      type: list
      elements: dict
      sample:
      - id: "edecb6c791d541a3b458199858470d20"
        service: "compute"
        path: "/v2.1/servers"
        method: "GET"
    unrestricted:
      description: A flag indicating whether the application credential may be
                   used for creation or destruction of other application credentials
                   or trusts.
      type: bool
cloud:
  description: The current cloud config with the username and password replaced
               with the name and secret of the application credential. This
               can be passed to the cloud parameter of other tasks, or written
               to an openstack cloud config file.
  returned: On success when I(state) is C(present).
  type: dict
  sample:
    auth_type: "v3applicationcredential"
    auth:
      auth_url: "https://192.0.2.1/identity"
      application_credential_secret: "JxE7LajLY75NZgDH1hfu0N_6xS9hQ-Af40W3"
      application_credential_id: "3e73d1b4f0cb473f920bd54dfce3c26d"
"""

import copy

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import (
    OpenStackModule,
)

try:
    import openstack.config
except ImportError:
    pass


class IdentityApplicationCredentialModule(OpenStackModule):
    argument_spec = dict(
        name=dict(required=True),
        description=dict(),
        secret=dict(no_log=True),
        roles=dict(
            type="list",
            elements="dict",
            options=dict(name=dict(), id=dict(), domain_id=dict()),
        ),
        expires_at=dict(),
        unrestricted=dict(type="bool", default=False),
        access_rules=dict(
            type="list",
            elements="dict",
            options=dict(
                service=dict(required=True),
                path=dict(required=True),
                method=dict(required=True),
            ),
        ),
        state=dict(default="present", choices=["absent", "present"]),
    )
    module_kwargs = dict()
    cloud = None

    def openstack_cloud_from_module(self):
        # Fetch cloud param before it is popped
        self.cloud = self.params["cloud"]
        return OpenStackModule.openstack_cloud_from_module(self)

    def run(self):
        state = self.params["state"]

        creds = self._find()

        if state == "present" and not creds:
            # Create creds
            creds = self._create().to_dict(computed=False)
            cloud_config = self._get_cloud_config(creds)
            self.exit_json(
                changed=True, application_credential=creds, cloud=cloud_config
            )

        elif state == "present" and creds:
            # Recreate immutable creds
            self._delete(creds)
            creds = self._create().to_dict(computed=False)
            cloud_config = self._get_cloud_config(creds)
            self.exit_json(
                changed=True, application_credential=creds, cloud=cloud_config
            )

        elif state == "absent" and creds:
            # Delete creds
            self._delete(creds)
            self.exit_json(changed=True)

        elif state == "absent" and not creds:
            # Do nothing
            self.exit_json(changed=False)

    def _get_user_id(self):
        return self.conn.session.get_user_id()

    def _create(self):
        kwargs = dict(
            (k, self.params[k])
            for k in [
                "name",
                "description",
                "secret",
                "expires_at",
                "unrestricted",
                "access_rules",
            ]
            if self.params[k] is not None
        )

        roles = self.params["roles"]
        if roles:
            kwroles = []
            for role in roles:
                kwroles.append(
                    dict(
                        (k, role[k])
                        for k in ["name", "id", "domain_id"]
                        if role[k] is not None
                    )
                )
            kwargs["roles"] = kwroles

        kwargs["user"] = self._get_user_id()
        creds = self.conn.identity.create_application_credential(**kwargs)
        return creds

    def _get_cloud_config(self, creds):
        cloud_region = openstack.config.OpenStackConfig().get_one(self.cloud)

        conf = cloud_region.config
        cloud_config = copy.deepcopy(conf)
        cloud_config["auth_type"] = "v3applicationcredential"
        cloud_config["auth"] = {
            "application_credential_id": creds["id"],
            "application_credential_secret": creds["secret"],
            "auth_url": conf["auth"]["auth_url"],
        }

        return cloud_config

    def _delete(self, creds):
        user = self._get_user_id()
        self.conn.identity.delete_application_credential(user, creds.id)

    def _find(self):
        name = self.params["name"]
        user = self._get_user_id()
        return self.conn.identity.find_application_credential(
            user=user, name_or_id=name
        )


def main():
    module = IdentityApplicationCredentialModule()
    module()


if __name__ == "__main__":
    main()
