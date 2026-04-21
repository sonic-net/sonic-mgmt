#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
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
  - Kevin Breit (@kbreit)
deprecated:
  alternative: cisco.meraki.organizations_action_batches
  removed_in: 3.0.0
  why: Updated modules released with increased functionality
description:
  - Allows for management of Action Batch jobs for Meraki.
extends_documentation_fragment: cisco.meraki.meraki
module: meraki_action_batch
notes:
  - This module is in active development and the interface may change.
options:
  action_batch_id:
    description:
      - ID of an existing Action Batch job.
    type: str
  actions:
    description:
      - List of actions the job should execute.
    elements: dict
    suboptions:
      body:
        description:
          - Required body of action.
        type: raw
      operation:
        choices:
          - create
          - destroy
          - update
          - claim
          - bind
          - split
          - unbind
          - combine
          - update_order
          - cycle
          - swap
          - assignSeats
          - move
          - moveSeats
          - renewSeats
        description:
          - Operation type of action
        type: str
      resource:
        description:
          - Path to Action Batch resource.
        type: str
    type: list
  confirmed:
    default: false
    description:
      - Whether job is to be executed.
    type: bool
  net_id:
    description:
      - ID of network, if applicable.
    type: str
  net_name:
    description:
      - Name of network, if applicable.
    type: str
  state:
    choices:
      - query
      - present
      - absent
    default: present
    description:
      - Specifies whether to lookup, create, or delete an Action Batch job.
    type: str
  synchronous:
    default: true
    description:
      - Whether job is a synchronous or asynchronous job.
    type: bool
short_description: Manage Action Batch jobs within the Meraki Dashboard.
"""


EXAMPLES = r"""
- name: Query all Action Batches
  meraki_action_batch:
    auth_key: abc123
    org_name: YourOrg
    state: query
  delegate_to: localhost
- name: Query one Action Batch job
  meraki_action_batch:
    auth_key: abc123
    org_name: YourOrg
    state: query
    action_batch_id: 12345
  delegate_to: localhost
- name: Create an Action Batch job
  meraki_action_batch:
    auth_key: abc123
    org_name: YourOrg
    state: present
    actions:
      - resource: /organizations/org_123/networks
        operation: create
        body:
          name: AnsibleActionBatch1
          productTypes:
            - switch
  delegate_to: localhost
- name: Update Action Batch job
  meraki_action_batch:
    auth_key: abc123
    org_name: YourOrg
    state: present
    action_batch_id: 12345
    synchronous: false
- name: Create an Action Batch job with multiple actions
  meraki_action_batch:
    auth_key: abc123
    org_name: YourOrg
    state: present
    actions:
      - resource: /organizations/org_123/networks
        operation: create
        body:
          name: AnsibleActionBatch2
          productTypes:
            - switch
      - resource: /organizations/org_123/networks
        operation: create
        body:
          name: AnsibleActionBatch3
          productTypes:
            - switch
  delegate_to: localhost
- name: Delete an Action Batch job
  meraki_action_batch:
    auth_key: abc123
    org_name: YourOrg
    state: absent
    action_batch_id: 12345
  delegate_to: localhost
"""

RETURN = r"""
data:
    description: Information about action batch jobs.
    type: complex
    returned: always
    contains:
        id:
            description: Unique ID of action batch job.
            returned: success
            type: str
            sample: 123
        organization_id:
            description: Unique ID of organization which owns batch job.
            returned: success
            type: str
            sample: 2930418
        confirmed:
            description: Whether action batch job was confirmed for execution.
            returned: success
            type: bool
        synchronous:
            description: Whether action batch job executes synchronously or asynchronously.
            returned: success
            type: bool
        status:
            description: Information about the action batch job state.
            type: complex
            contains:
                completed:
                    description: Whether job has completed.
                    type: bool
                    returned: success
                failed:
                    description: Whether execution of action batch job failed.
                    type: bool
                    returned: success
                errors:
                    description: List of errors, if any, created during execution.
                    type: list
                    returned: success
                created_resources:
                    description: List of resources created during execution.
                    type: list
                    returned: success
                    sample: [{"id": 100, "uri": "/networks/L_XXXXX/groupPolicies/100"}]
        actions:
            description: List of actions associated to job.
            type: dict
"""

from ansible.module_utils.basic import AnsibleModule, json
from ansible_collections.cisco.meraki.plugins.module_utils.network.meraki.meraki import (
    MerakiModule,
    meraki_argument_spec,
)


def _construct_payload(meraki):
    payload = dict()
    payload["confirmed"] = meraki.params["confirmed"]
    payload["synchronous"] = meraki.params["synchronous"]
    if meraki.params["actions"] is not None:  # No payload is specified for an update
        payload["actions"] = list()
        for action in meraki.params["actions"]:
            action_detail = dict()
            if action["resource"] is not None:
                action_detail["resource"] = action["resource"]
            if action["operation"] is not None:
                action_detail["operation"] = action["operation"]
            if action["body"] is not None:
                action_detail["body"] = action["body"]
            payload["actions"].append(action_detail)
    return payload


def main():

    # define the available arguments/parameters that a user can pass to
    # the module

    actions_arg_spec = dict(
        operation=dict(
            type="str",
            choices=[
                "create",
                "destroy",
                "update",
                "claim",
                "bind",
                "split",
                "unbind",
                "combine",
                "update_order",
                "cycle",
                "swap",
                "assignSeats",
                "move",
                "moveSeats",
                "renewSeats",
            ],
        ),
        resource=dict(type="str"),
        body=dict(type="raw"),
    )

    argument_spec = meraki_argument_spec()
    argument_spec.update(
        state=dict(
            type="str", choices=["present", "query", "absent"], default="present"
        ),
        net_name=dict(type="str"),
        net_id=dict(type="str"),
        action_batch_id=dict(type="str", default=None),
        confirmed=dict(type="bool", default=False),
        synchronous=dict(type="bool", default=True),
        actions=dict(
            type="list", default=None, elements="dict", options=actions_arg_spec
        ),
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    meraki = MerakiModule(module, function="action_batch")
    meraki.params["follow_redirects"] = "all"

    query_urls = {"action_batch": "/organizations/{org_id}/actionBatches"}
    query_one_urls = {
        "action_batch": "/organizations/{org_id}/actionBatches/{action_batch_id}"
    }
    create_urls = {"action_batch": "/organizations/{org_id}/actionBatches"}
    update_urls = {
        "action_batch": "/organizations/{org_id}/actionBatches/{action_batch_id}"
    }
    delete_urls = {
        "action_batch": "/organizations/{org_id}/actionBatches/{action_batch_id}"
    }

    meraki.url_catalog["get_all"].update(query_urls)
    meraki.url_catalog["get_one"].update(query_one_urls)
    meraki.url_catalog["create"] = create_urls
    meraki.url_catalog["update"] = update_urls
    meraki.url_catalog["delete"] = delete_urls

    payload = None

    if not meraki.params["org_name"] and not meraki.params["org_id"]:
        meraki.fail_json(msg="org_name or org_id is required")

    org_id = meraki.params["org_id"]
    if org_id is None:
        org_id = meraki.get_org_id(meraki.params["org_name"])

    if meraki.params["state"] == "query":
        if meraki.params["action_batch_id"] is None:  # Get all Action Batches
            path = meraki.construct_path("get_all", org_id=org_id)
            response = meraki.request(path, method="GET")
            if meraki.status == 200:
                meraki.result["data"] = response
                meraki.exit_json(**meraki.result)
        elif meraki.params["action_batch_id"] is not None:  # Query one Action Batch job
            path = meraki.construct_path(
                "get_one",
                org_id=org_id,
                custom={"action_batch_id": meraki.params["action_batch_id"]},
            )
            response = meraki.request(path, method="GET")
            if meraki.status == 200:
                meraki.result["data"] = response
                meraki.exit_json(**meraki.result)
    elif meraki.params["state"] == "present":
        if meraki.params["action_batch_id"] is None:  # Create a new Action Batch job
            payload = _construct_payload(meraki)
            path = meraki.construct_path("create", org_id=org_id)
            response = meraki.request(path, method="POST", payload=json.dumps(payload))
            if meraki.status == 201:
                meraki.result["data"] = response
                meraki.result["changed"] = True
                meraki.exit_json(**meraki.result)
        elif meraki.params["action_batch_id"] is not None:
            path = meraki.construct_path(
                "get_one",
                org_id=org_id,
                custom={"action_batch_id": meraki.params["action_batch_id"]},
            )
            current = meraki.request(path, method="GET")
            payload = _construct_payload(meraki)
            if (
                meraki.params["actions"] is not None
            ):  # Cannot update the body once a job is submitted
                meraki.fail_json(msg="Body cannot be updated on existing job.")
            if (
                meraki.is_update_required(current, payload) is True
            ):  # Job needs to be modified
                path = meraki.construct_path(
                    "update",
                    org_id=org_id,
                    custom={"action_batch_id": meraki.params["action_batch_id"]},
                )
                response = meraki.request(
                    path, method="PUT", payload=json.dumps(payload)
                )
                if meraki.status == 200:
                    meraki.result["data"] = response
                    meraki.result["changed"] = True
                    meraki.exit_json(**meraki.result)
            else:  # Idempotent response
                meraki.result["data"] = current
                meraki.exit_json(**meraki.result)
    elif meraki.params["state"] == "absent":
        path = meraki.construct_path(
            "delete",
            org_id=org_id,
            custom={"action_batch_id": meraki.params["action_batch_id"]},
        )
        response = meraki.request(path, method="DELETE")
        if meraki.status == 204:
            meraki.result["data"] = response
            meraki.result["changed"] = True

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == "__main__":
    main()
