#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_firewall_profile_group
short_description: Configure profile groups in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and profile_group category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    firewall_profile_group:
        description:
            - Configure profile groups.
        default: null
        type: dict
        suboptions:
            application_list:
                description:
                    - Name of an existing Application list. Source application.list.name.
                type: str
            av_profile:
                description:
                    - Name of an existing Antivirus profile. Source antivirus.profile.name.
                type: str
            casb_profile:
                description:
                    - Name of an existing CASB profile. Source casb.profile.name.
                type: str
            cifs_profile:
                description:
                    - Name of an existing CIFS profile. Source cifs.profile.name.
                type: str
            diameter_filter_profile:
                description:
                    - Name of an existing Diameter filter profile. Source diameter-filter.profile.name.
                type: str
            dlp_profile:
                description:
                    - Name of an existing DLP profile. Source dlp.profile.name.
                type: str
            dlp_sensor:
                description:
                    - Name of an existing DLP sensor. Source dlp.sensor.name.
                type: str
            dnsfilter_profile:
                description:
                    - Name of an existing DNS filter profile. Source dnsfilter.profile.name.
                type: str
            emailfilter_profile:
                description:
                    - Name of an existing email filter profile. Source emailfilter.profile.name.
                type: str
            file_filter_profile:
                description:
                    - Name of an existing file-filter profile. Source file-filter.profile.name.
                type: str
            icap_profile:
                description:
                    - Name of an existing ICAP profile. Source icap.profile.name.
                type: str
            ips_sensor:
                description:
                    - Name of an existing IPS sensor. Source ips.sensor.name.
                type: str
            ips_voip_filter:
                description:
                    - Name of an existing VoIP (ips) profile. Source voip.profile.name.
                type: str
            mms_profile:
                description:
                    - Name of an existing MMS profile. Source firewall.mms-profile.name.
                type: str
            name:
                description:
                    - Profile group name.
                required: true
                type: str
            profile_protocol_options:
                description:
                    - Name of an existing Protocol options profile. Source firewall.profile-protocol-options.name.
                type: str
            sctp_filter_profile:
                description:
                    - Name of an existing SCTP filter profile. Source sctp-filter.profile.name.
                type: str
            spamfilter_profile:
                description:
                    - Name of an existing Spam filter profile. Source spamfilter.profile.name.
                type: str
            ssh_filter_profile:
                description:
                    - Name of an existing SSH filter profile. Source ssh-filter.profile.name.
                type: str
            ssl_ssh_profile:
                description:
                    - Name of an existing SSL SSH profile. Source firewall.ssl-ssh-profile.name.
                type: str
            telemetry_profile:
                description:
                    - Name of an existing telemetry profile. Source telemetry-controller.profile.name.
                type: str
            videofilter_profile:
                description:
                    - Name of an existing VideoFilter profile. Source videofilter.profile.name.
                type: str
            virtual_patch_profile:
                description:
                    - Name of an existing virtual-patch profile. Source virtual-patch.profile.name.
                type: str
            voip_profile:
                description:
                    - Name of an existing VoIP (voipd) profile. Source voip.profile.name.
                type: str
            waf_profile:
                description:
                    - Name of an existing Web application firewall profile. Source waf.profile.name.
                type: str
            webfilter_profile:
                description:
                    - Name of an existing Web filter profile. Source webfilter.profile.name.
                type: str
"""

EXAMPLES = """
- name: Configure profile groups.
  fortinet.fortios.fortios_firewall_profile_group:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_profile_group:
          application_list: "<your_own_value> (source application.list.name)"
          av_profile: "<your_own_value> (source antivirus.profile.name)"
          casb_profile: "<your_own_value> (source casb.profile.name)"
          cifs_profile: "<your_own_value> (source cifs.profile.name)"
          diameter_filter_profile: "<your_own_value> (source diameter-filter.profile.name)"
          dlp_profile: "<your_own_value> (source dlp.profile.name)"
          dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
          dnsfilter_profile: "<your_own_value> (source dnsfilter.profile.name)"
          emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
          file_filter_profile: "<your_own_value> (source file-filter.profile.name)"
          icap_profile: "<your_own_value> (source icap.profile.name)"
          ips_sensor: "<your_own_value> (source ips.sensor.name)"
          ips_voip_filter: "<your_own_value> (source voip.profile.name)"
          mms_profile: "<your_own_value> (source firewall.mms-profile.name)"
          name: "default_name_17"
          profile_protocol_options: "<your_own_value> (source firewall.profile-protocol-options.name)"
          sctp_filter_profile: "<your_own_value> (source sctp-filter.profile.name)"
          spamfilter_profile: "<your_own_value> (source spamfilter.profile.name)"
          ssh_filter_profile: "<your_own_value> (source ssh-filter.profile.name)"
          ssl_ssh_profile: "<your_own_value> (source firewall.ssl-ssh-profile.name)"
          telemetry_profile: "<your_own_value> (source telemetry-controller.profile.name)"
          videofilter_profile: "<your_own_value> (source videofilter.profile.name)"
          virtual_patch_profile: "<your_own_value> (source virtual-patch.profile.name)"
          voip_profile: "<your_own_value> (source voip.profile.name)"
          waf_profile: "<your_own_value> (source waf.profile.name)"
          webfilter_profile: "<your_own_value> (source webfilter.profile.name)"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_firewall_profile_group_data(json):
    option_list = [
        "application_list",
        "av_profile",
        "casb_profile",
        "cifs_profile",
        "diameter_filter_profile",
        "dlp_profile",
        "dlp_sensor",
        "dnsfilter_profile",
        "emailfilter_profile",
        "file_filter_profile",
        "icap_profile",
        "ips_sensor",
        "ips_voip_filter",
        "mms_profile",
        "name",
        "profile_protocol_options",
        "sctp_filter_profile",
        "spamfilter_profile",
        "ssh_filter_profile",
        "ssl_ssh_profile",
        "telemetry_profile",
        "videofilter_profile",
        "virtual_patch_profile",
        "voip_profile",
        "waf_profile",
        "webfilter_profile",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def firewall_profile_group(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_profile_group_data = data["firewall_profile_group"]

    filtered_data = filter_firewall_profile_group_data(firewall_profile_group_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "profile-group", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "profile-group", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["firewall_profile_group"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "profile-group",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "profile-group", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "profile-group", mkey=converted_data["name"], vdom=vdom
        )
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_firewall(data, fos, check_mode):

    if data["firewall_profile_group"]:
        resp = firewall_profile_group(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_profile_group"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "profile_protocol_options": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssl_ssh_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "av_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "webfilter_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dnsfilter_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "emailfilter_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "dlp_profile": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "file_filter_profile": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "ips_sensor": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "application_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "voip_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ips_voip_filter": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "sctp_filter_profile": {"v_range": [["v7.0.1", ""]], "type": "string"},
        "diameter_filter_profile": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "virtual_patch_profile": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "icap_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "videofilter_profile": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "waf_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ssh_filter_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "casb_profile": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "telemetry_profile": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "cifs_profile": {"v_range": [["v6.2.0", "v7.6.0"]], "type": "string"},
        "dlp_sensor": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
        "mms_profile": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "spamfilter_profile": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "firewall_profile_group": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_profile_group"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_profile_group"]["options"][attribute_name][
                "required"
            ] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "firewall_profile_group"
        )

        is_error, has_changed, result, diff = fortios_firewall(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
