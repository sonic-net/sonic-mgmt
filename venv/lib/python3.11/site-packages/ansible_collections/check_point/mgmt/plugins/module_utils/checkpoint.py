# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2022 Red Hat Inc.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import time
from ansible.module_utils.six import iteritems
from ansible.module_utils.connection import ConnectionError
from ansible.module_utils.connection import Connection
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)

BASE_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Ansible",
}

checkpoint_argument_spec_for_action_module = dict(
    auto_publish_session=dict(type="bool", default=False),
    wait_for_task_timeout=dict(type="int", default=30),
    version=dict(type="str"),
)

checkpoint_argument_spec_for_objects = dict(
    auto_publish_session=dict(type="bool", default=False),
    wait_for_task=dict(type="bool", default=True),
    wait_for_task_timeout=dict(type="int", default=30),
    state=dict(type="str", choices=["present", "absent"], default="present"),
    version=dict(type="str"),
)

checkpoint_argument_spec_for_facts = dict(version=dict(type="str"))

checkpoint_argument_spec_for_commands = dict(
    wait_for_task=dict(type="bool", default=True),
    wait_for_task_timeout=dict(type="int", default=30),
    version=dict(type="str"),
    auto_publish_session=dict(type="bool", default=False),
)

delete_params = [
    "name",
    "uid",
    "layer",
    "exception-group-name",
    "rule-name",
    "package",
    "ignore-errors",
    "ignore-warnings",
    "gateway-uid",
    "url"
]

remove_from_set_payload = {
    "lsm-cluster": [
        "security-profile",
        "name-prefix",
        "name-suffix",
        "main-ip-address",
    ],
    "md-permissions-profile": ["permission-level"],
    "access-section": ["position"],
    "nat-section": ["position"],
    "https-section": ["position"],
    "mobile-access-section": ["position"],
    "mobile-access-profile-section": ["position"],
}

remove_from_add_payload = {"lsm-cluster": ["name"]}


def _fail_json(msg):
    """Replace the AnsibleModule fail_json here
    :param msg: The message for the failure
    :type msg: str
    """
    raise Exception(msg)


def map_params_to_obj(module_params, key_transform):
    """The fn to convert the api returned params to module params
    :param module_params: Module params
    :param key_transform: Dict with module equivalent API params
    :rtype: A dict
    :returns: dict with module prams transformed having API expected params
    """
    obj = {}
    for k, v in iteritems(key_transform):
        if k in module_params and (
            module_params.get(k)
            or module_params.get(k) == 0
            or module_params.get(k) is False
        ):
            val = module_params.pop(k)
            if isinstance(val, list):
                temp = []
                for each in val:
                    if isinstance(each, dict):
                        temp.append(map_params_to_obj(each, key_transform))
                if temp:
                    val = temp
            if isinstance(val, dict):
                temp_child = {}
                for each_k, each_v in iteritems(val):
                    if "_" in each_k:
                        temp_param = "-".join(each_k.split("_"))
                        if isinstance(each_v, dict):
                            temp_dict = map_params_to_obj(
                                each_v, key_transform
                            )
                            each_v = temp_dict
                        temp_child.update({temp_param: each_v})
                    else:
                        temp_child.update({each_k: each_v})
                obj[v] = temp_child
            else:
                obj[v] = val
    if module_params:
        obj.update(module_params)
    return obj


def map_obj_to_params(module_return_params, key_transform, return_param):
    """The fn to convert the api returned params to module params
    :param module_return_params: API returned response params
    :param key_transform: Module params
    :rtype: A dict
    :returns: dict with api returned value to module param value
    """
    temp = {}
    if module_return_params.get(return_param):
        temp[return_param] = []
        for each in module_return_params[return_param]:
            api_temp = {}
            for k, v in iteritems(key_transform):
                if v in each and (
                    each.get(v) or each.get(v) == 0 or each.get(v) is False
                ):
                    api_temp[k] = each.pop(v)
            if each:
                api_temp.update(each)
            temp[return_param].append(api_temp)
    else:
        for k, v in iteritems(key_transform):
            if v in module_return_params and (
                module_return_params.get(v)
                or module_return_params.get(v) == 0
                or module_return_params.get(v) is False
            ):
                if isinstance(module_return_params[v], dict):
                    temp_child = {}
                    for each_k, each_v in iteritems(module_return_params[v]):
                        if "-" in each_k:
                            temp_param = "_".join(each_k.split("-"))
                            if temp_param in key_transform:
                                temp_child.update({temp_param: each_v})
                        else:
                            temp_child.update({each_k: each_v})
                    temp[k] = temp_child
                    module_return_params.pop(v)
                else:
                    temp[k] = module_return_params.pop(v)
        if module_return_params:
            temp.update(module_return_params)
    return temp


def verify_want_have_diff(want, have, remove_key_from_diff):
    for each in remove_key_from_diff:
        if each in want:
            del want[each]
    diff = utils.dict_diff(have, want)
    return diff


def remove_unwanted_key(payload, remove_keys):
    for each in remove_keys:
        if each in payload:
            del payload[each]
    return payload


def sync_show_params_with_add_params(search_result, key_transform):
    temp = {}
    remove_keys = ["type", "meta-info"]
    for k, v in iteritems(search_result):
        if k in remove_keys:
            continue
        if isinstance(v, dict):
            if v.get("name"):
                temp.update({k: v["name"]})
            else:
                temp_child = {}
                for each_k, each_v in iteritems(v):
                    if isinstance(each_v, dict):
                        if each_v.get("name"):
                            temp_child.update({each_k: each_v["name"]})
                    else:
                        temp_child.update({each_k: each_v})
                temp.update({k: temp_child})
        elif isinstance(v, list):
            temp[k] = []
            for each in v:
                if each.get("name"):
                    temp[k].append(each["name"])
                else:
                    temp.update(each)
        else:
            temp.update({k: v})
    temp = map_obj_to_params(temp, key_transform, "")
    return temp


# parse failure message with code and response
def parse_fail_message(code, response):
    return "Checkpoint device returned error {0} with message {1}".format(
        code, response
    )


# send the request to checkpoint
def send_request(connection, version, url, payload=None):
    code, response = connection.send_request(
        "/web_api/" + version + url, payload
    )

    return code, response


# get the payload from the user parameters
def is_checkpoint_param(parameter):
    if (
        parameter == "auto_publish_session"
        or parameter == "state"
        or parameter == "wait_for_task"
        or parameter == "wait_for_task_timeout"
        or parameter == "version"
    ):
        return False
    return True


def contains_show_identifier_param(payload):
    identifier_params = ["name", "uid", "assigned-domain", "task-id", "signature", "url", "best-practice-id"]
    for param in identifier_params:
        if payload.get(param) is not None:
            return True
    return False


# build the payload from the parameters which has value (not None), and they are parameter of checkpoint API as well
def get_payload_from_parameters(params):
    payload = {}
    for parameter in params:
        parameter_value = params[parameter]
        if parameter_value is not None and is_checkpoint_param(parameter):
            if isinstance(parameter_value, dict):
                payload[
                    parameter.replace("_", "-")
                ] = get_payload_from_parameters(parameter_value)
            elif (
                    isinstance(parameter_value, list)
                    and len(parameter_value) != 0
                    and isinstance(parameter_value[0], dict)
            ):
                payload_list = []
                for element_dict in parameter_value:
                    payload_list.append(
                        get_payload_from_parameters(element_dict)
                    )
                payload[parameter.replace("_", "-")] = payload_list
            else:
                # special handle for this param in order to avoid two params called "version"
                if (
                        parameter == "gateway_version"
                        or parameter == "cluster_version"
                        or parameter == "server_version"
                        or parameter == "check_point_host_version"
                        or parameter == "target_version"
                        or parameter == "vsx_version"
                ):
                    parameter = "version"

                # message & syslog_facility are internally used by Ansible, so need to avoid param duplicity
                elif parameter == "login_message":
                    parameter = "message"

                payload[parameter.replace("_", "-")] = parameter_value

    return payload


# wait for task
def wait_for_task(module, version, connection, task_id):
    task_id_payload = {"task-id": task_id, "details-level": "full"}
    task_complete = False
    minutes_until_timeout = 30
    if (
            module.params["wait_for_task_timeout"] is not None
            and module.params["wait_for_task_timeout"] >= 0
    ):
        minutes_until_timeout = module.params["wait_for_task_timeout"]
    max_num_iterations = minutes_until_timeout * 30
    current_iteration = 0

    # As long as there is a task in progress
    while not task_complete and current_iteration < max_num_iterations:
        current_iteration += 1
        # Check the status of the task
        code, response = send_request(
            connection, version, "show-task", task_id_payload
        )

        attempts_counter = 0
        while code != 200:
            if attempts_counter < 5:
                attempts_counter += 1
                time.sleep(2)
                code, response = send_request(
                    connection, version, "show-task", task_id_payload
                )
            else:
                response["message"] = (
                    "ERROR: Failed to handle asynchronous tasks as synchronous, tasks result is"
                    " undefined. " + response["message"]
                )
                module.fail_json(msg=parse_fail_message(code, response))

        # Count the number of tasks that are not in-progress
        completed_tasks = 0
        for task in response["tasks"]:
            if task["status"] == "failed":
                (
                    status_description,
                    comments,
                ) = get_status_description_and_comments(task)
                if comments and status_description:
                    module.fail_json(
                        msg="Task {0} with task id {1} failed. Message: {2} with description: {3} - "
                        "Look at the logs for more details ".format(
                            task["task-name"],
                            task["task-id"],
                            comments,
                            status_description,
                        )
                    )
                elif comments:
                    module.fail_json(
                        msg="Task {0} with task id {1} failed. Message: {2} - Look at the logs for more details ".format(
                            task["task-name"], task["task-id"], comments
                        )
                    )
                elif status_description:
                    module.fail_json(
                        msg="Task {0} with task id {1} failed. Message: {2} - Look at the logs for more "
                        "details ".format(
                            task["task-name"],
                            task["task-id"],
                            status_description,
                        )
                    )
                else:
                    module.fail_json(
                        msg="Task {0} with task id {1} failed. Look at the logs for more details".format(
                            task["task-name"], task["task-id"]
                        )
                    )
            if task["status"] == "in progress":
                break
            completed_tasks += 1

        # Are we done? check if all tasks are completed
        if completed_tasks == len(response["tasks"]) and completed_tasks != 0:
            task_complete = True
        else:
            time.sleep(2)  # Wait for two seconds
    if not task_complete:
        module.fail_json(
            msg="ERROR: Timeout. Task-id: {0}.".format(
                task_id_payload["task-id"]
            )
        )
    else:
        return response


# Getting a status description and comments of task failure details
def get_status_description_and_comments(task):
    status_description = None
    comments = None
    if "comments" in task and task["comments"]:
        comments = task["comments"]
    if "task-details" in task and task["task-details"]:
        task_details = task["task-details"][0]
        if "statusDescription" in task_details:
            status_description = task_details["statusDescription"]
    return status_description, comments


# if failed occurred, in some cases we want to discard changes before exiting. We also notify the user about the `discard`
def discard_and_fail(module, code, response, connection, version):
    discard_code, discard_response = send_request(
        connection, version, "discard"
    )
    if discard_code != 200:
        try:
            module.fail_json(
                msg=parse_fail_message(code, response)
                + " Failed to discard session {0}"
                " with error {1} with message {2}".format(
                    connection.get_session_uid(),
                    discard_code,
                    discard_response,
                )
            )
        except Exception:
            # Read-only mode without UID
            module.fail_json(
                msg=parse_fail_message(code, response)
                + " Failed to discard session"
                " with error {0} with message {1}".format(
                    discard_code, discard_response
                )
            )

    module.fail_json(
        msg=parse_fail_message(code, response)
        + " Unpublished changes were discarded"
    )


# handle publish command, and wait for it to end if the user asked so
def handle_publish(module, connection, version):
    if (
        "auto_publish_session" in module.params
        and module.params["auto_publish_session"]
    ):
        publish_code, publish_response = send_request(
            connection, version, "publish"
        )
        if publish_code != 200:
            discard_and_fail(
                module, publish_code, publish_response, connection, version
            )
        if module.params["wait_for_task"]:
            wait_for_task(
                module, version, connection, publish_response["task-id"]
            )


# if user insert a specific version, we add it to the url
def get_version(module):
    return (
        ("v" + module.params["version"] + "/")
        if module.params.get("version")
        else ""
    )


# if code is 400 (bad request) or 500 (internal error) - fail
def handle_equals_failure(module, equals_code, equals_response):
    if equals_code == 400 or equals_code == 500:
        module.fail_json(msg=parse_fail_message(equals_code, equals_response))
    if (
        equals_code == 404
        and equals_response["code"] == "generic_err_command_not_found"
    ):
        module.fail_json(
            msg="Relevant hotfix is not installed on Check Point server. See sk114661 on Check Point Support Center."
        )


# handle call
def handle_call(
    connection,
    version,
    call,
    payload,
    module,
    to_publish,
    to_discard_on_failure,
):
    code, response = send_request(connection, version, call, payload)
    if code != 200:
        if to_discard_on_failure:
            discard_and_fail(module, code, response, connection, version)
        else:
            module.fail_json(msg=parse_fail_message(code, response))
    else:
        if "wait_for_task" in module.params and module.params["wait_for_task"]:
            if "task-id" in response:
                response = wait_for_task(
                    module, version, connection, response["task-id"]
                )
            elif "tasks" in response:
                for task in response["tasks"]:
                    if "task-id" in task:
                        task_id = task["task-id"]
                        response[task_id] = wait_for_task(
                            module, version, connection, task["task-id"]
                        )
                del response["tasks"]
    if to_publish:
        handle_publish(module, connection, version)
    return response


# handle a command
def api_command(module, command):
    payload = get_payload_from_parameters(module.params)
    connection = Connection(module._socket_path)
    version = get_version(module)

    code, response = send_request(connection, version, command, payload)
    result = {"changed": True}

    if command.startswith("show"):
        result['changed'] = False

    if code == 200:
        if module.params["wait_for_task"]:
            if "task-id" in response:
                response = wait_for_task(
                    module, version, connection, response["task-id"]
                )
            elif "tasks" in response:
                for task in response["tasks"]:
                    if "task-id" in task:
                        task_id = task["task-id"]
                        response[task_id] = wait_for_task(
                            module, version, connection, task["task-id"]
                        )
                del response["tasks"]

        result[command] = response

        handle_publish(module, connection, version)
    else:
        if command.startswith("show"):
            module.fail_json(msg=parse_fail_message(code, response))
        else:
            discard_and_fail(module, code, response, connection, version)

    return result


# handle api call facts
def api_call_facts(module, api_call_object, api_call_object_plural_version):
    payload = get_payload_from_parameters(module.params)
    connection = Connection(module._socket_path)
    version = get_version(module)

    # if there isn't an identifier param, the API command will be in plural version (e.g. show-hosts instead of show-host)
    if not contains_show_identifier_param(payload):
        api_call_object = api_call_object_plural_version

    response = handle_call(
        connection,
        version,
        "show-" + api_call_object,
        payload,
        module,
        False,
        False,
    )
    result = {api_call_object.replace("-", "_"): response}
    return result


# handle delete
def handle_delete(
    equals_code,
    payload,
    delete_params,
    connection,
    version,
    api_call_object,
    module,
    result,
):
    # else equals_code is 404 and no need to delete because he doesn't exist
    if equals_code == 200:
        if module.check_mode:
            result["changed"] = True
            result["message"] = "This would delete the object"
            return
        payload_for_delete = extract_payload_with_some_params(
            payload, delete_params
        )
        response = handle_call(
            connection,
            version,
            "delete-" + api_call_object,
            payload_for_delete,
            module,
            True,
            True,
        )
        result["changed"] = True
    else:
        if module.check_mode:
            result["changed"] = False
            result["message"] = "The object does not exist, no deletion would occur"


# handle the call and set the result with 'changed' and the response
def handle_call_and_set_result(
    connection, version, call, payload, module, result
):
    response = handle_call(
        connection, version, call, payload, module, True, True
    )
    result["changed"] = True
    result[call] = response


# handle api call
def api_call(module, api_call_object):
    payload = get_payload_from_parameters(module.params)
    connection = Connection(module._socket_path)
    version = get_version(module)

    result = {"changed": False}

    payload_for_equals = {"type": api_call_object, "params": payload}
    equals_code, equals_response = send_request(
        connection, version, "equals", payload_for_equals
    )
    handle_equals_failure(module, equals_code, equals_response)

    if module.params["state"] == "present":
        if equals_code == 200:
            # else objects are equals and there is no need for set request
            if not equals_response["equals"]:
                if module.check_mode:
                    return {"changed": True, "message": "This would edit the object"}
                build_payload(
                    api_call_object, payload, remove_from_set_payload
                )
                handle_call_and_set_result(
                    connection,
                    version,
                    "set-" + api_call_object,
                    payload,
                    module,
                    result,
                )
            else:
                if module.check_mode:
                    return {"changed": False, "message": "Object exists with desired configuration"}
        elif equals_code == 404:
            if module.check_mode:
                return {"changed": True, "message": "This would create the object"}
            build_payload(api_call_object, payload, remove_from_add_payload)
            handle_call_and_set_result(
                connection,
                version,
                "add-" + api_call_object,
                payload,
                module,
                result,
            )
    elif module.params["state"] == "absent":
        handle_delete(
            equals_code,
            payload,
            delete_params,
            connection,
            version,
            api_call_object,
            module,
            result,
        )
    if not module.check_mode:
        result["checkpoint_session_uid"] = connection.get_session_uid()
    return result


# returns a generator of the entire rulebase. show_rulebase_identifier_payload can be either package or layer
def get_rulebase_generator(
    connection, version, show_rulebase_identifier_payload, show_rulebase_command, rules_amount
):
    offset = 0
    limit = 100
    while True:
        payload_for_show_rulebase = {
            "limit": limit,
            "offset": offset,
        }
        payload_for_show_rulebase.update(show_rulebase_identifier_payload)
        # in case there are empty sections after the last rule, we need them to appear in the reply and the limit might
        # cut them out
        if offset + limit >= rules_amount:
            del payload_for_show_rulebase["limit"]
        code, response = send_request(
            connection,
            version,
            show_rulebase_command,
            payload_for_show_rulebase,
        )
        offset = response["to"]
        total = response["total"]
        rulebase = response["rulebase"]
        yield rulebase
        if total <= offset:
            return


# get 'to' or 'from' of given section
def get_edge_position_in_section(
    connection, version, identifier, section_name, edge
):
    code, response = send_request(
        connection,
        version,
        "show-layer-structure",
        {"name": identifier, "details-level": "uid"},
    )
    if 'code' in response and response["code"] == "generic_err_command_not_found":
        raise ValueError(
            "The use of the relative_position field with a section as its value is available only for"
            " version 1.7.1 with JHF take 42 and above"
        )
    sections_in_layer = response["root-section"]["children"]
    for section in sections_in_layer:
        if section["name"] == section_name:
            return int(section[edge + "-rule"])

    return None


# return the total amount of rules in the rulebase of the given layer
def get_rules_amount(connection, version, show_rulebase_payload, show_rulebase_command):
    payload = {"limit": 0}
    payload.update(show_rulebase_payload)
    code, response = send_request(
        connection,
        version,
        show_rulebase_command,
        payload,
    )
    return int(response["total"])


def keep_searching_rulebase(
    position, current_section, relative_position, relative_position_is_section
):
    position_not_found = position is None
    if relative_position_is_section and "above" not in relative_position:
        # if 'above' in relative_position then get_number_and_section_from_relative_position returns the previous section
        # so there isn't a need to further search for the relative section
        relative_section = list(relative_position.values())[0]
        return position_not_found or current_section != relative_section
    # if relative position is a rule then get_number_and_section_from_relative_position has already entered the section
    # (if exists) that the relative rule is in
    return position_not_found


def relative_position_is_section(
    connection, version, api_call_object, layer_or_package_payload, relative_position
):
    if "top" in relative_position or "bottom" in relative_position:
        return True

    show_section_command = "show-access-section" if 'access' in api_call_object else "show-nat-section"
    relative_position_value = list(relative_position.values())[0]
    payload = {"name": relative_position_value}
    payload.update(layer_or_package_payload)
    code, response = send_request(
        connection,
        version,
        show_section_command,
        payload,
    )
    if code == 200:
        return True
    return False


def get_number_and_section_from_relative_position(
    payload,
    connection,
    version,
    rulebase,
    above_relative_position,
    pos_before_relative_empty_section,
    api_call_object,
    prev_section=None,
    current_section=None,
):
    section_name = current_section
    position = None
    for rules in rulebase:
        if "rulebase" in rules:
            # cases relevant for relative-position=section
            if (
                "above" in payload["position"]
                and rules["name"] == payload["position"]["above"]
            ):
                if len(rules["rulebase"]) == 0:
                    position = (
                        pos_before_relative_empty_section
                        if above_relative_position
                        else pos_before_relative_empty_section + 1
                    )
                else:
                    # if the entire section isn't present in rulebase, the 'from' value of the section might not be
                    # the first position in the section, which is why we use get_edge_position_in_section
                    from_value = get_edge_position_in_section(
                        connection,
                        version,
                        list(get_relevant_layer_or_package_identifier(api_call_object, payload).values())[0],
                        rules["name"],
                        "from",
                    )
                    if from_value is not None:  # section exists in rulebase
                        position = (
                            max(from_value - 1, 1)
                            if above_relative_position
                            else from_value
                        )
                return (
                    position,
                    section_name,
                    above_relative_position,
                    pos_before_relative_empty_section,
                    prev_section,
                )

            # we update this only after the 'above' case since the section that should be returned in that case isn't
            # the one we are currently iterating over (but the one beforehand)
            prev_section = section_name
            section_name = rules["name"]

            if (
                "bottom" in payload["position"]
                and rules["name"] == payload["position"]["bottom"]
            ):
                if len(rules["rulebase"]) == 0:
                    position = (
                        pos_before_relative_empty_section
                        if above_relative_position
                        else pos_before_relative_empty_section + 1
                    )
                else:
                    # if the entire section isn't present in rulebase, the 'to' value of the section might not be the
                    # last position in the section, which is why we use get_edge_position_in_section
                    to_value = get_edge_position_in_section(
                        connection,
                        version,
                        list(get_relevant_layer_or_package_identifier(api_call_object, payload).values())[0],
                        section_name,
                        "to",
                    )
                    if to_value is not None and to_value == int(
                        rules["to"]
                    ):  # meaning the entire section is present in rulebase
                        # is the rule already at the bottom of the section. Can infer this only if the entire section is
                        # present in rulebase
                        is_bottom = (
                            rules["rulebase"][-1]["name"] == payload["name"]
                        )
                        position = (
                            to_value
                            if (above_relative_position or is_bottom)
                            else to_value + 1
                        )
                    # else: need to keep searching the rulebase, so position=None is returned
                return (
                    position,
                    section_name,
                    above_relative_position,
                    pos_before_relative_empty_section,
                    prev_section,
                )

            # setting a rule 'below' a section is equivalent to setting the rule at the top of that section
            if (
                "below" in payload["position"]
                and section_name == payload["position"]["below"]
            ) or (
                "top" in payload["position"]
                and section_name == payload["position"]["top"]
            ):
                if len(rules["rulebase"]) == 0:
                    position = (
                        pos_before_relative_empty_section
                        if above_relative_position
                        else pos_before_relative_empty_section + 1
                    )
                else:
                    # is the rule already at the top of the section
                    is_top = rules["rulebase"][0]["name"] == payload["name"]
                    position = (
                        max(int(rules["from"]) - 1, 1)
                        if (above_relative_position or not is_top)
                        else int(rules["from"])
                    )
                return (
                    position,
                    section_name,
                    above_relative_position,
                    pos_before_relative_empty_section,
                    prev_section,
                )

            if len(rules["rulebase"]) != 0:
                # if search_entire_rulebase=True: even if rules['rulebase'] is cut (due to query limit) this will
                # eventually be updated to the correct value in further calls
                pos_before_relative_empty_section = int(rules["to"])

            rules = rules["rulebase"]
            for rule in rules:
                if payload["name"] == rule["name"]:
                    above_relative_position = True
                # cases relevant for relative-position=rule
                if (
                    "below" in payload["position"]
                    and rule["name"] == payload["position"]["below"]
                ):
                    position = (
                        int(rule["rule-number"])
                        if above_relative_position
                        else int(rule["rule-number"]) + 1
                    )
                    return (
                        position,
                        section_name,
                        above_relative_position,
                        pos_before_relative_empty_section,
                        prev_section,
                    )
                elif (
                    "above" in payload["position"]
                    and rule["name"] == payload["position"]["above"]
                ):
                    position = (
                        max(int(rule["rule-number"]) - 1, 1)
                        if above_relative_position
                        else int(rule["rule-number"])
                    )
                    return (
                        position,
                        section_name,
                        above_relative_position,
                        pos_before_relative_empty_section,
                        prev_section,
                    )

        else:  # cases relevant for relative-position=rule
            if payload["name"] == rules["name"]:
                above_relative_position = True
            if (
                "below" in payload["position"]
                and rules["name"] == payload["position"]["below"]
            ):
                position = (
                    int(rules["rule-number"])
                    if above_relative_position
                    else int(rules["rule-number"]) + 1
                )
                return (
                    position,
                    section_name,
                    above_relative_position,
                    pos_before_relative_empty_section,
                    prev_section,
                )
            elif (
                "above" in payload["position"]
                and rules["name"] == payload["position"]["above"]
            ):
                position = (
                    max(int(rules["rule-number"]) - 1, 1)
                    if above_relative_position
                    else int(rules["rule-number"])
                )
                return (
                    position,
                    section_name,
                    above_relative_position,
                    pos_before_relative_empty_section,
                    prev_section,
                )

    return (
        position,
        section_name,
        above_relative_position,
        pos_before_relative_empty_section,
        prev_section,
    )  # None, None, False/True, x>=1, None


# get the position in integer format and the section it is.
def get_number_and_section_from_position(
    payload, connection, version, api_call_object
):
    show_rulebase_command = get_relevant_show_rulebase_command(api_call_object)
    if "position" in payload:
        section_name = None
        if not isinstance(payload["position"], dict):
            position = payload["position"]
            if position == "top":
                position = 1
                return position, section_name
            elif position == "bottom":
                show_rulebase_payload = get_relevant_show_rulebase_identifier_payload(api_call_object, payload)
                position = get_rules_amount(
                    connection,
                    version,
                    show_rulebase_payload,
                    show_rulebase_command,
                )
                show_rulebase_payload.update({"offset": position - 1})
                code, response = send_request(
                    connection,
                    version,
                    show_rulebase_command,
                    show_rulebase_payload,
                )
                rulebase = reversed(response["rulebase"])
            else:  # is a number so we need to get the section (if exists) of the rule in that position
                position = int(position)
                payload_for_show_obj_rulebase = build_rulebase_payload(
                    api_call_object, payload, position
                )
                code, response = send_request(
                    connection,
                    version,
                    show_rulebase_command,
                    payload_for_show_obj_rulebase,
                )
                rulebase = response["rulebase"]
                if position > response["total"]:
                    raise ValueError(
                        "The given position "
                        + str(position)
                        + " of rule "
                        + payload["name"]
                        + "exceeds the total amount of rules in the rulebase"
                    )
                #  in case position=1 and there are empty sections at the beginning of the rulebase we want to skip them
                i = 0
                for rules in rulebase:
                    if "rulebase" in rules and len(rules["rulebase"]) == 0:
                        i += 1
                rulebase = rulebase[i:]

            for rules in rulebase:
                if "rulebase" in rules:
                    section_name = rules["name"]
                    return position, section_name
                else:
                    return position, section_name  # section = None

        else:
            search_entire_rulebase = payload["search-entire-rulebase"]
            position = None
            # is the rule we're getting its position number above the rule it is relatively positioned to
            above_relative_position = False
            # no from-to in empty sections so can't infer the position from them -> need to keep track of the position
            # before the empty relative section
            pos_before_relative_empty_section = 1
            show_rulebase_payload = get_relevant_show_rulebase_identifier_payload(api_call_object, payload)
            if not search_entire_rulebase:
                code, response = send_request(
                    connection,
                    version,
                    show_rulebase_command,
                    show_rulebase_payload,
                )
                rulebase = response["rulebase"]
                (
                    position,
                    section_name,
                    above_relative_position,
                    pos_before_relative_empty_section,
                    prev_section
                ) = get_number_and_section_from_relative_position(
                    payload,
                    connection,
                    version,
                    rulebase,
                    above_relative_position,
                    pos_before_relative_empty_section,
                    api_call_object,
                )
            else:
                layer_or_package_payload = get_relevant_layer_or_package_identifier(api_call_object, payload)
                rules_amount = get_rules_amount(
                    connection,
                    version,
                    show_rulebase_payload,
                    show_rulebase_command,
                )
                relative_pos_is_section = relative_position_is_section(
                    connection, version, api_call_object, layer_or_package_payload, payload["position"]
                )
                rulebase_generator = get_rulebase_generator(
                    connection,
                    version,
                    show_rulebase_payload,
                    show_rulebase_command,
                    rules_amount,
                )
                # need to keep track of the previous section in case the iteration starts with a new section and
                # we want to set the rule above a section - so the section the rule should be at is the previous one
                prev_section = None
                for rulebase in rulebase_generator:
                    (
                        position,
                        section_name,
                        above_relative_position,
                        pos_before_relative_empty_section,
                        prev_section,
                    ) = get_number_and_section_from_relative_position(
                        payload,
                        connection,
                        version,
                        rulebase,
                        above_relative_position,
                        pos_before_relative_empty_section,
                        api_call_object,
                        prev_section,
                        section_name,
                    )
                    if not keep_searching_rulebase(
                        position,
                        section_name,
                        payload["position"],
                        relative_pos_is_section,
                    ):
                        break

            return position, section_name
    return None, None


# build the show rulebase payload
def build_rulebase_payload(api_call_object, payload, position_number):
    show_rulebase_required_identifiers_payload = get_relevant_show_rulebase_identifier_payload(api_call_object, payload)
    show_rulebase_required_identifiers_payload.update({'offset': position_number - 1, 'limit': 1})
    return show_rulebase_required_identifiers_payload


def build_rulebase_command(api_call_object):
    rulebase_command = "show-" + api_call_object + "base"

    if api_call_object == "threat-exception":
        rulebase_command = "show-threat-rule-exception-rulebase"

    return rulebase_command


# remove from payload unrecognized params (used for cases where add payload differs from that of a set)
def build_payload(api_call_object, payload, params_to_remove):
    if api_call_object in params_to_remove:
        for param in params_to_remove[api_call_object]:
            del payload[param]

    return payload


# extract first rule from given rulebase response and the section it is in.
def extract_rule_and_section_from_rulebase_response(response):
    section_name = None
    rule = response["rulebase"][0]
    i = 0
    # skip empty sections (possible when offset=0)
    while "rulebase" in rule and len(rule["rulebase"]) == 0:
        i += 1
        rule = response["rulebase"][i]

    while "rulebase" in rule:
        section_name = rule["name"]
        rule = rule["rulebase"][0]

    return rule, section_name


def get_relevant_show_rulebase_command(api_call_object):
    if api_call_object == "access-rule":
        return "show-access-rulebase"
    elif api_call_object == "threat-rule":
        return "show-threat-rulebase"
    elif api_call_object == "threat-exception":
        return "show-threat-rule-exception-rulebase"
    elif api_call_object == 'nat-rule':
        return 'show-nat-rulebase'
    elif api_call_object == 'https-rule':
        return 'show-https-rulebase'
    elif api_call_object == 'mobile-access-rule':
        return 'show-mobile-access-rulebase'
    elif api_call_object == 'mobile-access-profile-rule':
        return 'show-mobile-access-profile-rulebase'


# returns the show rulebase payload with the relevant required identifiers params
def get_relevant_show_rulebase_identifier_payload(api_call_object, payload):
    show_rulebase_payload = {}
    if api_call_object == 'nat-rule':
        show_rulebase_payload = {'package': payload['package']}

    # mobile-access-x apis don't have an identifier in show rulebase command
    elif 'mobile-access' not in api_call_object:
        show_rulebase_payload = {'name': payload['layer']}

    if api_call_object == 'threat-exception':
        show_rulebase_payload['rule-name'] = payload['rule-name']

    return show_rulebase_payload


# returns the show section/rule payload with the relevant required identifying package/layer
def get_relevant_layer_or_package_identifier(api_call_object, payload):
    if 'nat' in api_call_object:
        identifier = {'package': payload['package']}

    else:
        identifier = {'layer': payload['layer']}

    return identifier


# is the param position (if the user inserted it) equals between the object and the user input, as well as the section the rule is in
def is_equals_with_position_param(
    payload, connection, version, api_call_object
):
    (
        position_number,
        section_according_to_position,
    ) = get_number_and_section_from_position(
        payload, connection, version, api_call_object
    )

    # In this case the one of the following has occurred:
    # 1) There is no position param, then it's equals in vacuous truth
    # 2) search_entire_rulebase = False so it's possible the relative rule wasn't found in the default limit or maybe doesn't even exist
    # 3) search_entire_rulebase = True and the relative rule/section doesn't exist
    if position_number is None:
        return True

    rulebase_payload = build_rulebase_payload(
        api_call_object, payload, position_number
    )
    rulebase_command = build_rulebase_command(api_call_object)

    code, response = send_request(
        connection, version, rulebase_command, rulebase_payload
    )
    rule, section = extract_rule_and_section_from_rulebase_response(response)

    # if the names of the exist rule and the user input rule are equals, as well as the section they're in, then it
    # means that their positions are equals so I return True. and there is no way that there is another rule with this
    # name cause otherwise the 'equals' command would fail
    if (
        rule["name"] == payload["name"]
        and section_according_to_position == section
    ):
        return True
    else:
        return False


# get copy of the payload without some of the params
def extract_payload_without_some_params(payload, params_to_remove):
    copy_payload = dict(payload)
    for param in params_to_remove:
        if param in copy_payload:
            del copy_payload[param]
    return copy_payload


# get copy of the payload with only some of the params
def extract_payload_with_some_params(payload, params_to_insert):
    copy_payload = {}
    for param in params_to_insert:
        if param in payload:
            copy_payload[param] = payload[param]
    return copy_payload


# is equals with all the params including action and position
def is_equals_with_all_params(
    payload, connection, version, api_call_object, is_access_rule
):
    if is_access_rule and "action" in payload:
        payload_for_show = extract_payload_with_some_params(
            payload, ["name", "uid", "layer"]
        )
        code, response = send_request(
            connection, version, "show-" + api_call_object, payload_for_show
        )
        exist_action = response["action"]["name"]
        if exist_action.lower() != payload["action"].lower():
            if (
                payload["action"].lower() != "Apply Layer".lower()
                or exist_action.lower() != "Inner Layer".lower()
            ):
                return False

    # here the action is equals, so check the position param
    if not is_equals_with_position_param(
        payload, connection, version, api_call_object
    ):
        return False

    return True


# handle api call for rule
def api_call_for_rule(module, api_call_object):
    is_access_rule = True if "access" in api_call_object else False
    payload = get_payload_from_parameters(module.params)
    connection = Connection(module._socket_path)
    version = get_version(module)

    result = {"changed": False}

    if is_access_rule:
        copy_payload_without_some_params = extract_payload_without_some_params(
            payload, ["action", "position", "search_entire_rulebase"]
        )
    else:
        copy_payload_without_some_params = extract_payload_without_some_params(
            payload, ["position"]
        )
    payload_for_equals = {
        "type": api_call_object,
        "params": copy_payload_without_some_params,
    }
    equals_code, equals_response = send_request(
        connection, version, "equals", payload_for_equals
    )
    result["checkpoint_session_uid"] = connection.get_session_uid()
    handle_equals_failure(module, equals_code, equals_response)

    if module.params["state"] == "present":
        if equals_code == 200:
            if equals_response["equals"]:
                if not is_equals_with_all_params(
                    payload,
                    connection,
                    version,
                    api_call_object,
                    is_access_rule,
                ):
                    equals_response["equals"] = False
            # else objects are equals and there is no need for set request
            if not equals_response["equals"]:
                if module.check_mode:
                    return {"changed": True, "message": "This would edit the object"}
                # if user insert param 'position' and needed to use the 'set' command, change the param name to 'new-position'
                if "position" in payload:
                    payload["new-position"] = payload["position"]
                    del payload["position"]
                if "search-entire-rulebase" in payload:
                    del payload["search-entire-rulebase"]
                handle_call_and_set_result(
                    connection,
                    version,
                    "set-" + api_call_object,
                    payload,
                    module,
                    result,
                )
            else:
                if module.check_mode:
                    return {"changed": False, "message": "Object exists with desired configuration"}
        elif equals_code == 404:
            if module.check_mode:
                return {"changed": True, "message": "This would create the object"}
            if "search-entire-rulebase" in payload:
                del payload["search-entire-rulebase"]
            handle_call_and_set_result(
                connection,
                version,
                "add-" + api_call_object,
                payload,
                module,
                result,
            )
    elif module.params["state"] == "absent":
        handle_delete(
            equals_code,
            payload,
            delete_params,
            connection,
            version,
            api_call_object,
            module,
            result,
        )
    if not module.check_mode:
        result["checkpoint_session_uid"] = connection.get_session_uid()
    return result


# check if call is in plural form
def call_is_plural(api_call_object, payload):
    if (
        (payload.get("name") is not None or payload.get("rule-number") is not None)
        and ("nat" in api_call_object or "mobile-access" in api_call_object)
    ):
        return False
    if ((payload.get("layer") is None and ("access" in api_call_object or "threat"
                                           in api_call_object or "https" in api_call_object))
        or
            (payload.get("package") is not None and "nat" in api_call_object)):
        return True
    return False


# handle api call facts for rule
def api_call_facts_for_rule(
    module, api_call_object, api_call_object_plural_version
):
    payload = get_payload_from_parameters(module.params)
    connection = Connection(module._socket_path)
    version = get_version(module)

    # if there is no layer, the API command will be in plural version (e.g. show-https-rulebase instead of show-https-rule)
    if call_is_plural(api_call_object, payload):
        api_call_object = api_call_object_plural_version

    response = handle_call(
        connection,
        version,
        "show-" + api_call_object,
        payload,
        module,
        False,
        False,
    )
    result = {api_call_object: response}
    return result


# The code from here till EOF will be deprecated when Rikis' modules will be deprecated
# checkpoint_argument_spec = dict(
#     auto_publish_session=dict(type="bool", default=True),
#     policy_package=dict(type="str", default="standard"),
#     auto_install_policy=dict(type="bool", default=True),
#     targets=dict(type="list"),
# )


def publish(connection, uid=None):
    payload = None

    if uid:
        payload = {"uid": uid}

    connection.send_request("/web_api/publish", payload)


def discard(connection, uid=None):
    payload = None

    if uid:
        payload = {"uid": uid}

    connection.send_request("/web_api/discard", payload)


def install_policy(connection, policy_package, targets):
    payload = {"policy-package": policy_package, "targets": targets}

    connection.send_request("/web_api/install-policy", payload)


def prepare_rule_params_for_execute_module(
    rule, module_args, position, below_rule_name
):
    rule["layer"] = module_args["layer"]
    if "details_level" in module_args.keys():
        rule["details_level"] = module_args["details_level"]
    if "state" not in rule.keys() or (
        "state" in rule.keys() and rule["state"] != "absent"
    ):
        if below_rule_name:
            relative_position = {
                "relative_position": {"below": below_rule_name}
            }
            rule.update(relative_position)
        else:
            rule["position"] = position
        position = position + 1
        below_rule_name = rule["name"]

    return rule, position, below_rule_name


def check_if_to_publish_for_action(result, module_args):
    to_publish = (
        (
            "auto_publish_session" in module_args.keys()
            and module_args["auto_publish_session"]
        )
        and ("changed" in result.keys() and result["changed"] is True)
        and ("failed" not in result.keys() or result["failed"] is False)
    )
    return to_publish


class CheckPointRequest(object):
    def __init__(
        self,
        module=None,
        connection=None,
        headers=None,
        not_rest_data_keys=None,
        task_vars=None,
    ):
        self.module = module
        if module:
            # This will be removed, once all of the available modules
            # are moved to use action plugin design, as otherwise test
            # would start to complain without the implementation.
            self.connection = Connection(self.module._socket_path)
        elif connection:
            self.connection = connection
            try:
                self.connection.load_platform_plugins(
                    "check_point.mgmt.checkpoint"
                )
                self.connection.set_options(var_options=task_vars)
            except ConnectionError:
                raise
        # This allows us to exclude specific argspec keys from being included by
        # the rest data that don't follow the deepsec_* naming convention
        if not_rest_data_keys:
            self.not_rest_data_keys = not_rest_data_keys
        else:
            self.not_rest_data_keys = []
        self.not_rest_data_keys.append("validate_certs")
        self.headers = headers if headers else BASE_HEADERS

    # wait for task
    def wait_for_task(self, version, connection, task_id):
        task_id_payload = {"task-id": task_id, "details-level": "full"}
        task_complete = False
        minutes_until_timeout = 30
        # if module.params['wait_for_task_timeout'] is not None and module.params['wait_for_task_timeout'] >= 0:
        #     minutes_until_timeout = module.params['wait_for_task_timeout']
        max_num_iterations = minutes_until_timeout * 30
        current_iteration = 0

        # As long as there is a task in progress
        while not task_complete and current_iteration < max_num_iterations:
            current_iteration += 1
            # Check the status of the task
            code, response = send_request(
                connection, version, "show-task", task_id_payload
            )

            attempts_counter = 0
            while code != 200:
                if attempts_counter < 5:
                    attempts_counter += 1
                    time.sleep(2)
                    code, response = send_request(
                        connection, version, "show-task", task_id_payload
                    )
                else:
                    response["message"] = (
                        "ERROR: Failed to handle asynchronous tasks as synchronous, tasks result is"
                        " undefined. " + response["message"]
                    )
                    _fail_json(parse_fail_message(code, response))

            # Count the number of tasks that are not in-progress
            completed_tasks = 0
            for task in response["tasks"]:
                if task["status"] == "failed":
                    _fail_json(
                        "Task {0} with task id {1} failed. Look at the logs for more details".format(
                            task["task-name"], task["task-id"]
                        )
                    )
                if task["status"] == "in progress":
                    break
                completed_tasks += 1

            # Are we done? check if all tasks are completed
            if completed_tasks == len(response["tasks"]):
                task_complete = True
            else:
                time.sleep(2)  # Wait for two seconds
        if not task_complete:
            _fail_json(
                "ERROR: Timeout. Task-id: {0}.".format(
                    task_id_payload["task-id"]
                )
            )
        else:
            return response

    # if failed occurred, in some cases we want to discard changes before exiting. We also notify the user about the `discard`
    def discard_and_fail(
        self, code, response, connection, version, session_uid
    ):
        discard_code, discard_response = send_request(
            connection, version, "discard"
        )
        if discard_code != 200:
            try:
                _fail_json(
                    parse_fail_message(code, response)
                    + " Failed to discard session {0}"
                    " with error {1} with message {2}".format(
                        session_uid,
                        discard_code,
                        discard_response,
                    )
                )
            except Exception:
                # Read-only mode without UID
                _fail_json(
                    parse_fail_message(code, response)
                    + " Failed to discard session"
                    " with error {0} with message {1}".format(
                        discard_code, discard_response
                    )
                )

        _fail_json(
            "Checkpoint session with ID: {0}".format(session_uid)
            + ", "
            + parse_fail_message(code, response)
            + " Unpublished changes were discarded"
        )

    # handle publish command, and wait for it to end if the user asked so
    def handle_publish(self, connection, version, payload):
        publish_code, publish_response = send_request(
            connection, version, "publish"
        )
        if publish_code != 200:
            self.discard_and_fail(
                publish_code, publish_response, connection, version
            )
        if payload.get("wait_for_task"):
            self.wait_for_task(
                version, connection, publish_response["task-id"]
            )

    # handle call
    def handle_call(
            self,
            connection,
            version,
            api_url,
            payload,
            to_discard_on_failure,
            session_uid=None,
            to_publish=False,
    ):
        code, response = send_request(connection, version, api_url, payload)
        if code != 200:
            if to_discard_on_failure:
                self.discard_and_fail(
                    code, response, connection, version, session_uid
                )
            elif "object_not_found" not in response.get(
                    "code"
            ) and "not found" not in response.get("message"):
                raise _fail_json(
                    "Checkpoint session with ID: {0}".format(session_uid)
                    + ", "
                    + parse_fail_message(code, response)
                )
        else:
            if "wait_for_task" in payload and payload["wait_for_task"]:
                if "task-id" in response:
                    response = self.wait_for_task(
                        version, connection, response["task-id"]
                    )
                elif "tasks" in response:
                    for task in response["tasks"]:
                        if "task-id" in task:
                            task_id = task["task-id"]
                            response[task_id] = self.wait_for_task(
                                version, connection, task["task-id"]
                            )
                    del response["tasks"]

        if to_publish:
            self.handle_publish(connection, version, payload)
        return code, response

    # handle the call and set the result with 'changed' and teh response
    def handle_add_and_set_result(
            self,
            connection,
            version,
            api_url,
            payload,
            session_uid,
            auto_publish_session=False,
    ):
        code, response = self.handle_call(
            connection,
            version,
            api_url,
            payload,
            True,
            session_uid,
            auto_publish_session,
        )
        result = {"code": code, "response": response, "changed": True}
        return result

    # handle delete
    def handle_delete(self, connection, payload, api_call_object, version):
        auto_publish = False
        payload_for_equals = {"type": api_call_object, "params": payload}
        equals_code, equals_response = send_request(
            connection, version, "equals", payload_for_equals
        )
        session_uid = connection.get_session_uid()
        if equals_code == 200:
            if payload.get("auto_publish_session"):
                auto_publish = payload["auto_publish_session"]
                del payload["auto_publish_session"]
            code, response = self.handle_call(
                connection,
                version,
                "delete-" + api_call_object,
                payload,
                True,
                session_uid,
                auto_publish,
            )
            result = {"code": code, "response": response, "changed": True}
        else:
            # else equals_code is 404 and no need to delete because object doesn't exist
            result = {"changed": False}
        if result.get("response"):
            result["checkpoint_session_uid"] = session_uid
        return result

    # handle api call facts
    def api_call_facts(self, connection, payload, api_call_object, version):
        if payload.get("auto_publish_session"):
            del payload["auto_publish_session"]
        code, response = self.handle_call(
            connection, version, api_call_object, payload, False
        )
        result = {"code": code, "response": response}
        return result

    # handle api call
    def api_call(
            self,
            connection,
            payload,
            remove_keys,
            api_call_object,
            state,
            equals_response,
            version,
            delete_params,
    ):
        result = {}
        auto_publish_session = False
        if payload.get("auto_publish_session"):
            auto_publish_session = payload["auto_publish_session"]
            del payload["auto_publish_session"]
        session_uid = connection.get_session_uid()
        if state == "merged":
            if equals_response and equals_response.get("equals") is False:
                payload = remove_unwanted_key(payload, remove_keys)
                result = self.handle_add_and_set_result(
                    connection,
                    version,
                    "set-" + api_call_object,
                    payload,
                    session_uid,
                    auto_publish_session,
                )
            elif equals_response.get("code") or equals_response.get("message"):
                result = self.handle_add_and_set_result(
                    connection,
                    version,
                    "add-" + api_call_object,
                    payload,
                    session_uid,
                    auto_publish_session,
                )
        elif state == "replaced":
            if equals_response and equals_response.get("equals") is False:
                code, response = self.handle_call(
                    connection,
                    version,
                    "delete-" + api_call_object,
                    delete_params,
                    True,
                    session_uid,
                    auto_publish_session,
                )
                result = self.handle_add_and_set_result(
                    connection,
                    version,
                    "add-" + api_call_object,
                    payload,
                    session_uid,
                    auto_publish_session,
                )
            elif equals_response.get("code") or equals_response.get("message"):
                result = self.handle_add_and_set_result(
                    connection,
                    version,
                    "add-" + api_call_object,
                    payload,
                    session_uid,
                    auto_publish_session,
                )
        if result.get("response"):
            result["checkpoint_session_uid"] = session_uid

        return result

    # if user insert a specific version, we add it to the url
    def get_version(self, payload):
        return (
            ("v" + payload["version"] + "/") if payload.get("version") else ""
        )

    def _httpapi_error_handle(self, api_obj, state, **kwargs):
        # FIXME - make use of handle_httperror(self, exception) where applicable
        #   https://docs.ansible.com/ansible/latest/network/dev_guide/developing_plugins_network.html#developing-plugins-httpapi
        try:
            result = {}
            version = self.get_version(kwargs["data"])
            if state == "gathered":
                result = self.api_call_facts(
                    self.connection, kwargs["data"], "show-" + api_obj, version
                )
            elif state == "deleted":
                result = self.handle_delete(
                    self.connection, kwargs["data"], api_obj, version
                )
            elif state == "merged" or state == "replaced":
                payload_for_equals = {
                    "type": api_obj,
                    "params": kwargs["data"],
                }
                equals_code, equals_response = send_request(
                    self.connection, version, "equals", payload_for_equals
                )
                if equals_response.get("equals"):
                    result = {
                        "code": equals_code,
                        "response": equals_response,
                        "changed": False,
                    }
                else:
                    result = self.api_call(
                        self.connection,
                        kwargs["data"],
                        kwargs["remove_keys"],
                        api_obj,
                        state,
                        equals_response,
                        version,
                        kwargs["delete_params"],
                    )
        except ConnectionError as e:
            raise _fail_json("connection error occurred: {0}".format(e))
        except ValueError as e:
            raise _fail_json("certificate not found: {0}".format(e))
        # This fn. will return both code and response, once all of the available modules
        # are moved to use action plugin design, as otherwise test
        # would start to complain without the implementation.
        return result

    def post(self, obj, state, **kwargs):
        return self._httpapi_error_handle(obj, state, **kwargs)
