#!/usr/bin/python
# -*- coding: utf-8 -*-
# https://github.com/ansible/ansible/issues/65816
# https://github.com/PyCQA/pylint/issues/214

# (c) 2018, Adam Miller (admiller@redhat.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: adaptive_response_notable_event
short_description: Manage Splunk Enterprise Security Notable Event Adaptive Responses
description:
  - This module allows for creation, deletion, and modification of Splunk
    Enterprise Security Notable Event Adaptive Responses that are associated
    with a correlation search
version_added: "1.0.0"
deprecated:
  alternative: splunk_adaptive_response_notable_events
  why: Newer and updated modules released with more functionality.
  removed_at_date: '2024-09-01'
options:
  name:
    description:
      - Name of notable event
    required: true
    type: str
  correlation_search_name:
    description:
      - Name of correlation search to associate this notable event adaptive response with
    required: true
    type: str
  description:
    description:
      - Description of the notable event, this will populate the description field for the web console
    required: true
    type: str
  state:
    description:
      - Add or remove a data source.
    required: true
    choices: [ "present", "absent" ]
    type: str
  security_domain:
    description:
      - Splunk Security Domain
    type: str
    required: false
    choices:
      - "access"
      - "endpoint"
      - "network"
      - "threat"
      - "identity"
      - "audit"
    default: "threat"
  severity:
    description:
      - Severity rating
    type: str
    required: false
    choices:
      - "informational"
      - "low"
      - "medium"
      - "high"
      - "critical"
      - "unknown"
    default: "high"
  default_owner:
    description:
      - Default owner of the notable event, if unset it will default to Splunk System Defaults
    type: str
    required: false
  default_status:
    description:
      - Default status of the notable event, if unset it will default to Splunk System Defaults
    type: str
    required: false
    choices:
      - "unassigned"
      - "new"
      - "in progress"
      - "pending"
      - "resolved"
      - "closed"
  drill_down_name:
    description:
      - Name for drill down search, Supports variable substitution with fields from the matching event.
    type: str
    required: false
  drill_down_search:
    description:
      - Drill down search, Supports variable substitution with fields from the matching event.
    type: str
    required: false
  drill_down_earliest_offset:
    description:
      - Set the amount of time before the triggering event to search for related
        events. For example, 2h. Use \"$info_min_time$\" to set the drill-down time
        to match the earliest time of the search
    type: str
    required: false
    default: \"$info_min_time$\"
  drill_down_latest_offset:
    description:
      - Set the amount of time after the triggering event to search for related
        events. For example, 1m. Use \"$info_max_time$\" to set the drill-down
        time to match the latest time of the search
    type: str
    required: false
    default: \"$info_max_time$\"
  investigation_profiles:
    description:
      - Investigation profile to assiciate the notable event with.
    type: str
    required: false
  next_steps:
    description:
      - List of adaptive responses that should be run next
      - Describe next steps and response actions that an analyst could take to address this threat.
    type: list
    elements: str
    required: false
    default: []
  recommended_actions:
    description:
      - List of adaptive responses that are recommended to be run next
      - Identifying Recommended Adaptive Responses will highlight those actions
        for the analyst when looking at the list of response actions available,
        making it easier to find them among the longer list of available actions.
    type: list
    elements: str
    required: false
    default: []
  asset_extraction:
    description:
      - list of assets to extract, select any one or many of the available choices
      - defaults to all available choices
    type: list
    elements: str
    choices:
      - src
      - dest
      - dvc
      - orig_host
    default:
      - src
      - dest
      - dvc
      - orig_host
    required: false
  identity_extraction:
    description:
      - list of identity fields to extract, select any one or many of the available choices
      - defaults to all available choices
    type: list
    elements: str
    choices:
      - user
      - src_user
    default:
      - user
      - src_user
    required: false
author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>
"""
# FIXME - adaptive response action association is probably going to need to be a separate module we stitch together in a role

EXAMPLES = """
- name: Example of using splunk.es.adaptive_response_notable_event module
  splunk.es.adaptive_response_notable_event:
    name: "Example notable event from Ansible"
    correlation_search_name: "Example Correlation Search From Ansible"
    description: "Example notable event from Ansible, description."
    state: "present"
    next_steps:
      - ping
      - nslookup
    recommended_actions:
      - script
      - ansiblesecurityautomation
"""

import json

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import quote_plus, urlencode
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.splunk.es.plugins.module_utils.splunk import SplunkRequest


def main():
    argspec = dict(
        name=dict(required=True, type="str"),
        correlation_search_name=dict(required=True, type="str"),
        description=dict(required=True, type="str"),
        state=dict(choices=["present", "absent"], required=True),
        security_domain=dict(
            choices=[
                "access",
                "endpoint",
                "network",
                "threat",
                "identity",
                "audit",
            ],
            required=False,
            default="threat",
        ),
        severity=dict(
            choices=[
                "informational",
                "low",
                "medium",
                "high",
                "critical",
                "unknown",
            ],
            required=False,
            default="high",
        ),
        default_owner=dict(required=False, type="str"),
        default_status=dict(
            choices=[
                "unassigned",
                "new",
                "in progress",
                "pending",
                "resolved",
                "closed",
            ],
            required=False,
        ),
        drill_down_name=dict(required=False, type="str"),
        drill_down_search=dict(required=False, type="str"),
        drill_down_earliest_offset=dict(
            required=False,
            type="str",
            default="$info_min_time$",
        ),
        drill_down_latest_offset=dict(
            required=False,
            type="str",
            default="$info_max_time$",
        ),
        investigation_profiles=dict(required=False, type="str"),
        next_steps=dict(required=False, type="list", elements="str", default=[]),
        recommended_actions=dict(
            required=False,
            type="list",
            elements="str",
            default=[],
        ),
        asset_extraction=dict(
            required=False,
            type="list",
            elements="str",
            default=["src", "dest", "dvc", "orig_host"],
            choices=["src", "dest", "dvc", "orig_host"],
        ),
        identity_extraction=dict(
            required=False,
            type="list",
            elements="str",
            default=["user", "src_user"],
            choices=["user", "src_user"],
        ),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    splunk_request = SplunkRequest(
        module,
        override=False,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        not_rest_data_keys=["state"],
    )

    query_dict = splunk_request.get_by_path(
        "servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{0}".format(
            quote_plus(module.params["correlation_search_name"]),
        ),
    )

    # Have to custom craft the data here because they overload the saved searches
    # endpoint in the rest api and we want to hide the nuance from the user
    request_post_data = {}

    # FIXME  need to figure out how to properly support these, the possible values appear to
    #       be dynamically created based on what the search is indexing
    # request_post_data['action.notable.param.extract_assets'] = '[\"src\",\"dest\",\"dvc\",\"orig_host\"]'
    # request_post_data['action.notable.param.extract_identities'] = [\"src_user\",\"user\"]
    if module.params["next_steps"]:
        if len(module.params["next_steps"]) == 1:
            next_steps = "[[action|{0}]]".format(module.params["next_steps"][0])
        else:
            next_steps = ""
            for next_step in module.params["next_steps"]:
                if next_steps:
                    next_steps += "\n[[action|{0}]]".format(next_step)
                else:
                    next_steps = "[[action|{0}]]".format(next_step)

        # NOTE: version:1 appears to be hard coded when you create this via the splunk web UI
        #       but I don't know what it is/means because there's no docs on it
        next_steps_dict = {"version": 1, "data": next_steps}
        request_post_data["action.notable.param.next_steps"] = json.dumps(
            next_steps_dict,
        )

    if module.params["recommended_actions"]:
        if len(module.params["recommended_actions"]) == 1:
            request_post_data["action.notable.param.recommended_actions"] = module.params[
                "recommended_actions"
            ][0]
        else:
            request_post_data["action.notable.param.recommended_actions"] = ",".join(
                module.params["recommended_actions"],
            )

    request_post_data["action.notable.param.rule_description"] = module.params["description"]
    request_post_data["action.notable.param.rule_title"] = module.params["name"]
    request_post_data["action.notable.param.security_domain"] = module.params["security_domain"]
    request_post_data["action.notable.param.severity"] = module.params["severity"]
    request_post_data["action.notable.param.asset_extraction"] = module.params["asset_extraction"]
    request_post_data["action.notable.param.identity_extraction"] = module.params[
        "identity_extraction"
    ]

    # NOTE: this field appears to be hard coded when you create this via the splunk web UI
    #       but I don't know what it is/means because there's no docs on it
    request_post_data["action.notable.param.verbose"] = "0"

    if module.params["default_owner"]:
        request_post_data["action.notable.param.default_owner"] = module.params["default_owner"]

    if module.params["default_status"]:
        request_post_data["action.notable.param.default_status"] = module.params["default_status"]

    request_post_data = utils.remove_empties(request_post_data)

    if query_dict:
        request_post_data["search"] = query_dict["entry"][0]["content"]["search"]
        if "actions" in query_dict["entry"][0]["content"]:
            if query_dict["entry"][0]["content"]["actions"] == "notable":
                pass
            elif (
                len(query_dict["entry"][0]["content"]["actions"].split(",")) > 0
                and "notable" not in query_dict["entry"][0]["content"]["actions"]
            ):
                request_post_data["actions"] = (
                    query_dict["entry"][0]["content"]["actions"] + ", notable"
                )
            else:
                request_post_data["actions"] = "notable"
    else:
        module.fail_json(
            msg="Unable to find correlation search: {0}",
            splunk_data=query_dict,
        )

    if module.params["state"] == "present":
        needs_change = False
        for arg in request_post_data:
            if arg in query_dict["entry"][0]["content"]:
                if to_text(query_dict["entry"][0]["content"][arg]) != to_text(
                    request_post_data[arg],
                ):
                    needs_change = True
        if not needs_change:
            module.exit_json(
                changed=False,
                msg="Nothing to do.",
                splunk_data=query_dict,
            )
        if module.check_mode and needs_change:
            module.exit_json(
                changed=True,
                msg="A change would have been made if not in check mode.",
                splunk_data=query_dict,
            )
        if needs_change:
            splunk_data = splunk_request.create_update(
                "servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{0}".format(
                    quote_plus(module.params["correlation_search_name"]),
                ),
                data=urlencode(request_post_data),
            )
            module.exit_json(
                changed=True,
                msg="{0} updated.".format(module.params["correlation_search_name"]),
                splunk_data=splunk_data,
            )

    if module.params["state"] == "absent":
        # FIXME - need to figure out how to clear the action.notable.param fields from the api endpoint
        module.exit_json(
            changed=True,
            msg="Deleted {0}.".format(module.params["name"]),
            splunk_data=splunk_data,
        )
        for arg in request_post_data:
            if arg in query_dict["entry"][0]["content"]:
                needs_change = True
                del query_dict["entry"][0]["content"][arg]
        if not needs_change:
            module.exit_json(
                changed=False,
                msg="Nothing to do.",
                splunk_data=query_dict,
            )
        if module.check_mode and needs_change:
            module.exit_json(
                changed=True,
                msg="A change would have been made if not in check mode.",
                splunk_data=query_dict,
            )
        if needs_change:
            splunk_data = splunk_request.create_update(
                "servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{0}".format(
                    quote_plus(module.params["correlation_search_name"]),
                ),
                data=urlencode(request_post_data),
            )
            module.exit_json(
                changed=True,
                msg="{0} updated.".format(module.params["correlation_search_name"]),
                splunk_data=splunk_data,
            )

    module.exit_json(changed=False, msg="Nothing to do.", splunk_data=query_dict)


if __name__ == "__main__":
    main()
