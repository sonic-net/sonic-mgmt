#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: digital_ocean_spaces
short_description: Create and remove DigitalOcean Spaces.
description:
  - Create and remove DigitalOcean Spaces.
author: Mark Mercado (@mamercad)
version_added: 1.15.0
options:
  state:
    description:
     - Whether the Space should be present or absent.
    default: present
    type: str
    choices: ["present", "absent"]
  name:
    description:
      - The name of the Spaces to create or delete.
    required: true
    type: str
  region:
    description:
      - The region to create or delete the Space in.
    aliases: ["region_id"]
    required: true
    type: str
  aws_access_key_id:
    description:
      - The AWS_ACCESS_KEY_ID to use.
    required: true
    type: str
    aliases: ["AWS_ACCESS_KEY_ID"]
  aws_secret_access_key:
    description:
      - The AWS_SECRET_ACCESS_KEY to use.
    required: true
    type: str
    aliases: ["AWS_SECRET_ACCESS_KEY"]
requirements:
  - boto3
extends_documentation_fragment:
  - community.digitalocean.digital_ocean.documentation
"""


EXAMPLES = r"""
- name: Create a Space in nyc3
  community.digitalocean.digital_ocean_spaces:
    state: present
    name: my-space
    region: nyc3

- name: Delete a Space in nyc3
  community.digitalocean.digital_ocean_spaces:
    state: absent
    name: my-space
    region: nyc3
"""


RETURN = r"""
data:
  description: DigitalOcean Space
  returned: present
  type: dict
  sample:
    space:
      endpoint_url: https://nyc3.digitaloceanspaces.com
      name: gh-ci-space-1
      region: nyc3
      space_url: https://gh-ci-space-1.nyc3.digitaloceanspaces.com
msg:
  description: Informational message
  returned: always
  type: str
  sample: Created Space gh-ci-space-1 in nyc3
"""

from ansible.module_utils.basic import (
    AnsibleModule,
    missing_required_lib,
    env_fallback,
    to_native,
)
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)
from traceback import format_exc

try:
    import boto3

    HAS_BOTO3 = True
except Exception:
    HAS_BOTO3 = False


def run(module):
    state = module.params.get("state")
    name = module.params.get("name")
    region = module.params.get("region")
    aws_access_key_id = module.params.get("aws_access_key_id")
    aws_secret_access_key = module.params.get("aws_secret_access_key")

    try:
        session = boto3.session.Session()
        client = session.client(
            "s3",
            region_name=region,
            endpoint_url=f"https://{region}.digitaloceanspaces.com",
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        response = client.list_buckets()
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=format_exc())

    response_metadata = response.get("ResponseMetadata")
    http_status_code = response_metadata.get("HTTPStatusCode")

    if http_status_code == 200:
        spaces = [
            {
                "name": space["Name"],
                "region": region,
                "endpoint_url": f"https://{region}.digitaloceanspaces.com",
                "space_url": f"https://{space['Name']}.{region}.digitaloceanspaces.com",
            }
            for space in response["Buckets"]
        ]
    else:
        module.fail_json(changed=False, msg=f"Failed to list Spaces in {region}")

    if state == "present":
        for space in spaces:
            if space["name"] == name:
                module.exit_json(changed=False, data={"space": space})

        if module.check_mode:
            module.exit_json(changed=True, msg=f"Would create Space {name} in {region}")

        try:
            response = client.create_bucket(Bucket=name)
        except Exception as e:
            module.fail_json(msg=to_native(e), exception=format_exc())

        response_metadata = response.get("ResponseMetadata")
        http_status_code = response_metadata.get("HTTPStatusCode")
        if http_status_code == 200:
            module.exit_json(
                changed=True,
                msg=f"Created Space {name} in {region}",
                data={
                    "space": {
                        "name": name,
                        "region": region,
                        "endpoint_url": f"https://{region}.digitaloceanspaces.com",
                        "space_url": f"https://{name}.{region}.digitaloceanspaces.com",
                    }
                },
            )

        module.fail_json(
            changed=False, msg=f"Failed to create Space {name} in {region}"
        )

    elif state == "absent":
        have_it = False
        for space in spaces:
            if space["name"] == name:
                have_it = True

        if module.check_mode:
            if have_it:
                module.exit_json(
                    changed=True, msg=f"Would delete Space {name} in {region}"
                )
            else:
                module.exit_json(changed=False, msg=f"No Space {name} in {region}")

        if have_it:
            try:
                reponse = client.delete_bucket(Bucket=name)
            except Exception as e:
                module.fail_json(msg=to_native(e), exception=format_exc())

            response_metadata = response.get("ResponseMetadata")
            http_status_code = response_metadata.get("HTTPStatusCode")
            if http_status_code == 200:
                module.exit_json(changed=True, msg=f"Deleted Space {name} in {region}")

            module.fail_json(
                changed=True, msg=f"Failed to delete Space {name} in {region}"
            )

        module.exit_json(changed=False, msg=f"No Space {name} in {region}")


def main():
    argument_spec = DigitalOceanHelper.digital_ocean_argument_spec()
    argument_spec.update(
        state=dict(type="str", choices=["present", "absent"], default="present"),
        name=dict(type="str", required=True),
        region=dict(type="str", aliases=["region_id"], required=True),
        aws_access_key_id=dict(
            type="str",
            aliases=["AWS_ACCESS_KEY_ID"],
            fallback=(env_fallback, ["AWS_ACCESS_KEY_ID"]),
            required=True,
            no_log=True,
        ),
        aws_secret_access_key=dict(
            type="str",
            aliases=["AWS_SECRET_ACCESS_KEY"],
            fallback=(env_fallback, ["AWS_SECRET_ACCESS_KEY"]),
            required=True,
            no_log=True,
        ),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    if not HAS_BOTO3:
        module.fail_json(msg=missing_required_lib("boto3"))

    run(module)


if __name__ == "__main__":
    main()
