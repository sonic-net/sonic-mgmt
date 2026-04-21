#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Joshua Coronado (@joshuajcoronado) <joshua@coronado.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["deprecated"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
author:
  - Joshua Coronado (@joshuajcoronado)
deprecated:
  alternative: cisco.meraki.networks_webhooks_payload_templates
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description:
  - Allows for querying, deleting, creating, and updating of webhook payload templates.
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_webhook_payload_template
options:
  body:
    description:
      - The liquid template used for the body of the webhook message.
    type: str
  headers:
    default: []
    description:
      - List of the liquid templates used with the webhook headers.
    elements: dict
    suboptions:
      name:
        description:
          - The name of the header template.
        type: str
      template:
        description:
          - The liquid template for the headers
        type: str
    type: list
  name:
    description:
      - Name of the template.
    type: str
  net_id:
    description:
      - ID of network containing access points.
    type: str
  net_name:
    description:
      - Name of network containing access points.
    type: str
  state:
    choices:
      - absent
      - query
      - present
    default: query
    description:
      - Specifies whether payload template should be queried, created, modified, or
        deleted.
    type: str
short_description: Manage webhook payload templates for a network in the Meraki cloud
"""

EXAMPLES = r"""
- name: Query all configuration templates
  meraki_webhook_payload_template:
    auth_key: abc12345
    org_name: YourOrg
    state: query
  delegate_to: localhost
- name: Query specific configuration templates
  meraki_webhook_payload_template:
    auth_key: abc12345
    org_name: YourOrg
    state: query
    name: Twitter
  delegate_to: localhost
- name: Create payload template
  meraki_webhook_payload_template:
    auth_key: abc12345
    org_name: YourOrg
    state: query
    name: TestTemplate
    body: Testbody
    headers:
      - name: testheader
        template: testheadertemplate
  delegate_to: localhost
- name: Delete a configuration template
  meraki_config_template:
    auth_key: abc123
    state: absent
    org_name: YourOrg
    name: TestTemplate
  delegate_to: localhost
"""

RETURN = r"""
data:
    description: Information about queried object.
    returned: success
    type: complex
    contains:
        name:
            description:
                - The name of the template
            returned: success
            type: str
            sample: testTemplate
        body:
            description:
                - The liquid template used for the body of the webhook message.
            returned: success
            type: str
            sample: {"event_type":"{{ alertTypeId }}","client_payload":{"text":"{{ alertData }}"}}
        headers:
            description: List of the liquid templates used with the webhook headers.
            returned: success
            type: list
            contains:
                name:
                    description:
                        - The name of the template
                    returned: success
                    type: str
                    sample: testTemplate
                template:
                    description:
                        - The liquid template for the header
                    returned: success
                    type: str
                    sample: "Bearer {{ sharedSecret }}"
"""

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import (
    MerakiModule,
    meraki_argument_spec,
)


def get_webhook_payload_templates(meraki, net_id):
    path = meraki.construct_path("get_all", net_id=net_id)
    response = meraki.request(path, "GET")
    if meraki.status != 200:
        meraki.fail_json(msg="Unable to get webhook payload templates")
    return response


def delete_template(meraki, net_id, template_id):
    changed = True
    if meraki.check_mode:
        return {}, changed
    else:
        path = meraki.construct_path(
            "update", net_id=net_id, custom={"template_id": template_id}
        )
        response = meraki.request(path, method="DELETE")
        if meraki.status != 204:
            meraki.fail_json(msg="Unable to remove webhook payload templates")
        return response, changed


def create_template(meraki, net_id, template):
    changed = True

    if meraki.check_mode:
        return template, changed
    else:
        path = meraki.construct_path("get_all", net_id=net_id)
        response = meraki.request(path, "POST", payload=json.dumps(template))
        if meraki.status != 201:
            meraki.fail_json(msg="Unable to create webhook payload template")
        return response, changed


def update_template(meraki, net_id, template, payload):
    changed = False

    if template["body"] != payload["body"]:
        changed = True

    if meraki.is_update_required(template["headers"], payload["headers"]):
        changed = True

    if changed:
        meraki.generate_diff(template, payload)
        if meraki.check_mode:
            return payload, changed
        else:
            path = meraki.construct_path(
                "update",
                net_id=net_id,
                custom={"template_id": template["payloadTemplateId"]},
            )
            response = meraki.request(
                path, method="PUT", payload=json.dumps(payload)
            )
            if meraki.status != 200:
                meraki.fail_json(
                    msg="Unable to update webhook payload template"
                )
            return response, changed

    return template, changed


def main():

    # define the available arguments/parameters that a user can pass to
    # the module
    argument_spec = meraki_argument_spec()
    argument_spec.update(
        state=dict(
            type="str", choices=["absent", "query", "present"], default="query"
        ),
        name=dict(type="str", default=None),
        net_name=dict(type="str"),
        net_id=dict(type="str"),
        body=dict(type="str", default=None),
        headers=dict(
            type="list",
            default=[],
            elements="dict",
            options=dict(
                name=dict(type="str"),
                template=dict(type="str"),
            ),
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    meraki = MerakiModule(module, function="webhook_payload_template")
    meraki.params["follow_redirects"] = "all"

    query_all_urls = {
        "webhook_payload_template": "/networks/{net_id}/webhooks/payloadTemplates"
    }
    update_urls = {
        "webhook_payload_template": "/networks/{net_id}/webhooks/payloadTemplates/{template_id}"
    }

    meraki.url_catalog["get_all"].update(query_all_urls)
    meraki.url_catalog["update"] = update_urls

    org_id = meraki.params["org_id"]
    if meraki.params["org_name"]:
        org_id = meraki.get_org_id(meraki.params["org_name"])
    net_id = meraki.params["net_id"]

    if net_id is None:
        if meraki.params["net_name"] is not None:
            nets = meraki.get_nets(org_id=org_id)
            net_id = meraki.get_net_id(
                net_name=meraki.params["net_name"], data=nets
            )

    templates = {
        template["name"]: template
        for template in get_webhook_payload_templates(meraki, net_id)
    }

    if meraki.params["state"] == "query":
        meraki.result["changed"] = False

        if meraki.params["name"]:
            if meraki.params["name"] in templates:
                meraki.result["data"] = templates[meraki.params["name"]]
            else:
                meraki.fail_json(
                    msg="Unable to get webhook payload template named: {0}".format(
                        meraki.params["name"]
                    )
                )
        else:
            meraki.result["data"] = templates

    elif meraki.params["state"] == "present":
        if meraki.params["name"] is None:
            meraki.fail_json(msg="name is a required parameter")

        if meraki.params["body"] is None:
            meraki.fail_json(
                msg="body is a required parameter when state is present"
            )

        headers = []

        for header in meraki.params["headers"]:
            for key in ["name", "template"]:
                if key not in header:
                    meraki.fail_json(
                        msg="{0} is a required parameter for a header".format(
                            key
                        )
                    )
                if not header[key]:
                    meraki.fail_json(
                        msg="{0} in header must be a string".format(key)
                    )
            headers.append(
                dict(name=header["name"], template=header["template"])
            )

        payload = {
            "name": meraki.params["name"],
            "body": meraki.params["body"],
            "headers": meraki.params["headers"],
        }

        if meraki.params["name"] in templates:
            (
                meraki.result["data"],
                meraki.result["changed"],
            ) = update_template(
                meraki, net_id, templates[meraki.params["name"]], payload
            )
        else:
            (
                meraki.result["data"],
                meraki.result["changed"],
            ) = create_template(meraki, net_id, payload)

    elif meraki.params["state"] == "absent":
        if meraki.params["name"] in templates:
            (
                meraki.result["data"],
                meraki.result["changed"],
            ) = delete_template(
                meraki,
                net_id,
                templates[meraki.params["name"]]["payloadTemplateId"],
            )
        else:
            meraki.result["changed"] = False
            meraki.result["data"] = {}

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == "__main__":
    main()
