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
module: correlation_search
short_description: Manage Splunk Enterprise Security Correlation Searches
description:
  - This module allows for creation, deletion, and modification of Splunk Enterprise Security Correlation Searches
version_added: "1.0.0"
deprecated:
  alternative: splunk_correlation_searches
  why: Newer and updated modules released with more functionality.
  removed_at_date: '2024-09-01'
options:
  name:
    description:
      - Name of coorelation search
    required: true
    type: str
  description:
    description:
      - Description of the coorelation search, this will populate the description field for the web console
    required: true
    type: str
  state:
    description:
      - Add, remove, enable, or disiable a correlation search.
    required: true
    choices: [ "present", "absent", "enabled", "disabled" ]
    type: str
  search:
    description:
      - SPL search string
    type: str
    required: true
  app:
    description:
      - Splunk app to associate the correlation seach with
    type: str
    required: false
    default: "SplunkEnterpriseSecuritySuite"
  ui_dispatch_context:
    description:
      - Set an app to use for links such as the drill-down search in a notable
        event or links in an email adaptive response action. If None, uses the
        Application Context.
    type: str
    required: false
  time_earliest:
    description:
      - Earliest time using relative time modifiers.
    type: str
    required: false
    default: "-24h"
  time_latest:
    description:
      - Latest time using relative time modifiers.
    type: str
    required: false
    default: "now"
  cron_schedule:
    description:
      - Enter a cron-style schedule.
      - For example C('*/5 * * * *') (every 5 minutes) or C('0 21 * * *') (every day at 9 PM).
      - Real-time searches use a default schedule of C('*/5 * * * *').
    type: str
    required: false
    default: "*/5 * * * *"
  scheduling:
    description:
      - Controls the way the scheduler computes the next execution time of a scheduled search.
      - >
        Learn more:
        https://docs.splunk.com/Documentation/Splunk/7.2.3/Report/Configurethepriorityofscheduledreports#Real-time_scheduling_and_continuous_scheduling
    type: str
    required: false
    default: "real-time"
    choices:
      - "real-time"
      - "continuous"
  schedule_window:
    description:
      - Let report run at any time within a window that opens at its scheduled run time,
        to improve efficiency when there are many concurrently scheduled reports.
        The "auto" setting automatically determines the best window width for the report.
    type: str
    required: false
    default: "0"
  schedule_priority:
    description:
      - Raise the scheduling priority of a report. Set to "Higher" to prioritize
        it above other searches of the same scheduling mode, or "Highest" to
        prioritize it above other searches regardless of mode. Use with discretion.
    type: str
    required: false
    default: "Default"
    choices:
      - "Default"
      - "Higher"
      - "Highest"
  trigger_alert_when:
    description:
      - Raise the scheduling priority of a report. Set to "Higher" to prioritize
        it above other searches of the same scheduling mode, or "Highest" to
        prioritize it above other searches regardless of mode. Use with discretion.
    type: str
    required: false
    default: "number of events"
    choices:
      - "number of events"
      - "number of results"
      - "number of hosts"
      - "number of sources"
  trigger_alert_when_condition:
    description:
      - Conditional to pass to C(trigger_alert_when)
    type: str
    required: false
    default: "greater than"
    choices:
      - "greater than"
      - "less than"
      - "equal to"
      - "not equal to"
      - "drops by"
      - "rises by"
  trigger_alert_when_value:
    description:
      - Value to pass to C(trigger_alert_when)
    type: str
    required: false
    default: "10"
  throttle_window_duration:
    description:
      - "How much time to ignore other events that match the field values specified in Fields to group by."
    type: str
    required: false
  throttle_fields_to_group_by:
    description:
      - "Type the fields to consider for matching events for throttling."
    type: str
    required: false
  suppress_alerts:
    description:
      - "To suppress alerts from this correlation search or not"
    type: bool
    required: false
    default: false
notes:
  - >
    The following options are not yet supported:
    throttle_window_duration, throttle_fields_to_group_by, and adaptive_response_actions

author: Ansible Security Automation Team (@maxamillion) <https://github.com/ansible-security>
"""
# FIXME - adaptive response action association is probaby going to need to be a separate module we stitch together in a role

EXAMPLES = """
- name: Example of creating a correlation search with splunk.es.coorelation_search
  splunk.es.correlation_search:
    name: "Example Coorelation Search From Ansible"
    description: "Example Coorelation Search From Ansible, description."
    search: 'source="/var/log/snort.log"'
    state: "present"
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six.moves.urllib.parse import quote_plus, urlencode
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import utils

from ansible_collections.splunk.es.plugins.module_utils.splunk import SplunkRequest


def main():
    argspec = dict(
        name=dict(required=True, type="str"),
        description=dict(required=True, type="str"),
        state=dict(choices=["present", "absent", "enabled", "disabled"], required=True),
        search=dict(required=True, type="str"),
        app=dict(type="str", required=False, default="SplunkEnterpriseSecuritySuite"),
        ui_dispatch_context=dict(type="str", required=False),
        time_earliest=dict(type="str", required=False, default="-24h"),
        time_latest=dict(type="str", required=False, default="now"),
        cron_schedule=dict(type="str", required=False, default="*/5 * * * *"),
        scheduling=dict(
            type="str",
            required=False,
            default="real-time",
            choices=["real-time", "continuous"],
        ),
        schedule_window=dict(type="str", required=False, default="0"),
        schedule_priority=dict(
            type="str",
            required=False,
            default="Default",
            choices=["Default", "Higher", "Highest"],
        ),
        trigger_alert_when=dict(
            type="str",
            required=False,
            default="number of events",
            choices=[
                "number of events",
                "number of results",
                "number of hosts",
                "number of sources",
            ],
        ),
        trigger_alert_when_condition=dict(
            type="str",
            required=False,
            default="greater than",
            choices=[
                "greater than",
                "less than",
                "equal to",
                "not equal to",
                "drops by",
                "rises by",
            ],
        ),
        trigger_alert_when_value=dict(type="str", required=False, default="10"),
        throttle_window_duration=dict(type="str", required=False),
        throttle_fields_to_group_by=dict(type="str", required=False),
        suppress_alerts=dict(type="bool", required=False, default=False),
    )

    module = AnsibleModule(argument_spec=argspec, supports_check_mode=True)

    if module.params["state"] in ["present", "enabled"]:
        module_disabled_state = False
    else:
        module_disabled_state = True

    splunk_request = SplunkRequest(
        module,
        override=False,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        not_rest_data_keys=["state"],
    )

    try:
        query_dict = splunk_request.get_by_path(
            "servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{0}".format(
                quote_plus(module.params["name"]),
            ),
        )
    except HTTPError as e:
        # the data monitor doesn't exist
        query_dict = {}

    # Have to custom craft the data here because they overload the saved searches
    # endpoint in the rest api and we want to hide the nuance from the user
    request_post_data = {}
    request_post_data["name"] = module.params["name"]
    request_post_data["action.correlationsearch.enabled"] = "1"
    request_post_data["is_scheduled"] = True
    request_post_data["dispatch.rt_backfill"] = True
    request_post_data["action.correlationsearch.label"] = module.params["name"]
    request_post_data["description"] = module.params["description"]
    request_post_data["search"] = module.params["search"]
    request_post_data["request.ui_dispatch_app"] = module.params["app"]
    if module.params["ui_dispatch_context"]:
        request_post_data["request.ui_dispatch_context"] = module.params["ui_dispatch_context"]
    request_post_data["dispatch.earliest_time"] = module.params["time_earliest"]
    request_post_data["dispatch.latest_time"] = module.params["time_latest"]
    request_post_data["cron_schedule"] = module.params["cron_schedule"]
    if module.params["scheduling"] == "real-time":
        request_post_data["realtime_schedule"] = True
    else:
        request_post_data["realtime_schedule"] = False
    request_post_data["schedule_window"] = module.params["schedule_window"]
    request_post_data["schedule_priority"] = module.params["schedule_priority"].lower()
    request_post_data["alert_type"] = module.params["trigger_alert_when"]
    request_post_data["alert_comparator"] = module.params["trigger_alert_when_condition"]
    request_post_data["alert_threshold"] = module.params["trigger_alert_when_value"]
    request_post_data["alert.suppress"] = module.params["suppress_alerts"]
    request_post_data["disabled"] = module_disabled_state

    request_post_data = utils.remove_empties(request_post_data)

    if module.params["state"] in ["present", "enabled", "disabled"]:
        if query_dict:
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
                # FIXME - need to find a reasonable way to deal with action.correlationsearch.enabled
                del request_post_data[
                    "name"
                ]  # If this is present, splunk assumes we're trying to create a new one wit the same name
                splunk_data = splunk_request.create_update(
                    "servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{0}".format(
                        quote_plus(module.params["name"]),
                    ),
                    data=urlencode(request_post_data),
                )
                module.exit_json(
                    changed=True,
                    msg="{0} updated.",
                    splunk_data=splunk_data,
                )
        else:
            # Create it
            splunk_data = splunk_request.create_update(
                "servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches",
                data=urlencode(request_post_data),
            )
            module.exit_json(changed=True, msg="{0} created.", splunk_data=splunk_data)

    elif module.params["state"] == "absent":
        if query_dict:
            splunk_data = splunk_request.delete_by_path(
                "services/saved/searches/{0}".format(quote_plus(module.params["name"])),
            )
            module.exit_json(
                changed=True,
                msg="Deleted {0}.".format(module.params["name"]),
                splunk_data=splunk_data,
            )

    module.exit_json(changed=False, msg="Nothing to do.", splunk_data=query_dict)


if __name__ == "__main__":
    main()
