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
module: fortios_firewall_sniffer
short_description: Configure sniffer in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and sniffer category.
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
    - We highly recommend using your own value as the id instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
       available number for the object, it does have limitations. Please find more details in Q&A.
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
    firewall_sniffer:
        description:
            - Configure sniffer.
        default: null
        type: dict
        suboptions:
            anomaly:
                description:
                    - Configuration method to edit Denial of Service (DoS) anomaly settings.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action taken when the threshold is reached.
                        type: str
                        choices:
                            - 'pass'
                            - 'block'
                            - 'proxy'
                    log:
                        description:
                            - Enable/disable anomaly logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    name:
                        description:
                            - Anomaly name.
                        required: true
                        type: str
                    quarantine:
                        description:
                            - Quarantine method.
                        type: str
                        choices:
                            - 'none'
                            - 'attacker'
                    quarantine_expiry:
                        description:
                            - Duration of quarantine. (Format ###d##h##m, minimum 1m, maximum 364d23h59m). Requires quarantine set to attacker.
                        type: str
                    quarantine_log:
                        description:
                            - Enable/disable quarantine logging.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        description:
                            - Enable/disable this anomaly.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    synproxy_tcp_mss:
                        description:
                            - Determine TCP maximum segment size (MSS) value for packets replied by syn proxy module.
                        type: str
                        choices:
                            - '0'
                            - '256'
                            - '512'
                            - '1024'
                            - '1300'
                            - '1360'
                            - '1460'
                            - '1500'
                    synproxy_tcp_sack:
                        description:
                            - enable/disable TCP selective acknowledage (SACK) for packets replied by syn proxy module.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    synproxy_tcp_timestamp:
                        description:
                            - enable/disable TCP timestamp option for packets replied by syn proxy module.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    synproxy_tcp_window:
                        description:
                            - Determine TCP Window size for packets replied by syn proxy module.
                        type: str
                        choices:
                            - '4096'
                            - '8192'
                            - '16384'
                            - '32768'
                    synproxy_tcp_windowscale:
                        description:
                            - Determine TCP window scale option value for packets replied by syn proxy module.
                        type: str
                        choices:
                            - '0'
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                            - '6'
                            - '7'
                            - '8'
                            - '9'
                            - '10'
                            - '11'
                            - '12'
                            - '13'
                            - '14'
                    synproxy_tos:
                        description:
                            - Determine TCP differentiated services code point value (type of service).
                        type: str
                        choices:
                            - '0'
                            - '10'
                            - '12'
                            - '14'
                            - '18'
                            - '20'
                            - '22'
                            - '26'
                            - '28'
                            - '30'
                            - '34'
                            - '36'
                            - '38'
                            - '40'
                            - '46'
                            - '255'
                    synproxy_ttl:
                        description:
                            - Determine Time to live (TTL) value for packets replied by syn proxy module.
                        type: str
                        choices:
                            - '32'
                            - '64'
                            - '128'
                            - '255'
                    threshold:
                        description:
                            - Anomaly threshold. Number of detected instances (packets per second or concurrent session number) that triggers the anomaly
                               action.
                        type: int
                    threshold_default:
                        description:
                            - Number of detected instances per minute which triggers action (1 - 2147483647). Note that each anomaly has a different threshold
                               value assigned to it.
                        type: int
            application_list:
                description:
                    - Name of an existing application list. Source application.list.name.
                type: str
            application_list_status:
                description:
                    - Enable/disable application control profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            av_profile:
                description:
                    - Name of an existing antivirus profile. Source antivirus.profile.name.
                type: str
            av_profile_status:
                description:
                    - Enable/disable antivirus profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            casb_profile:
                description:
                    - Name of an existing CASB profile. Source casb.profile.name.
                type: str
            casb_profile_status:
                description:
                    - Enable/disable CASB profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dlp_profile:
                description:
                    - Name of an existing DLP profile. Source dlp.profile.name.
                type: str
            dlp_profile_status:
                description:
                    - Enable/disable DLP profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dlp_sensor:
                description:
                    - Name of an existing DLP sensor. Source dlp.sensor.name.
                type: str
            dlp_sensor_status:
                description:
                    - Enable/disable DLP sensor.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dsri:
                description:
                    - Enable/disable DSRI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            emailfilter_profile:
                description:
                    - Name of an existing email filter profile. Source emailfilter.profile.name.
                type: str
            emailfilter_profile_status:
                description:
                    - Enable/disable emailfilter.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            file_filter_profile:
                description:
                    - Name of an existing file-filter profile. Source file-filter.profile.name.
                type: str
            file_filter_profile_status:
                description:
                    - Enable/disable file filter.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            host:
                description:
                    - 'Hosts to filter for in sniffer traffic (Format examples: 1.1.1.1, 2.2.2.0/24, 3.3.3.3/255.255.255.0, 4.4.4.0-4.4.4.240).'
                type: str
            id:
                description:
                    - Sniffer ID (0 - 9999). see <a href='#notes'>Notes</a>.
                required: true
                type: int
            interface:
                description:
                    - Interface name that traffic sniffing will take place on. Source system.interface.name.
                type: str
            ip_threatfeed:
                description:
                    - Name of an existing IP threat feed.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Threat feed name. Source system.external-resource.name.
                        required: true
                        type: str
            ip_threatfeed_status:
                description:
                    - Enable/disable IP threat feed.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ips_dos_status:
                description:
                    - Enable/disable IPS DoS anomaly detection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ips_sensor:
                description:
                    - Name of an existing IPS sensor. Source ips.sensor.name.
                type: str
            ips_sensor_status:
                description:
                    - Enable/disable IPS sensor.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipv6:
                description:
                    - Enable/disable sniffing IPv6 packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            logtraffic:
                description:
                    - Either log all sessions, only sessions that have a security profile applied, or disable all logging for this policy.
                type: str
                choices:
                    - 'all'
                    - 'utm'
                    - 'disable'
            max_packet_count:
                description:
                    - Maximum packet count (1 - 1000000).
                type: int
            non_ip:
                description:
                    - Enable/disable sniffing non-IP packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            port:
                description:
                    - 'Ports to sniff (Format examples: 10, :20, 30:40, 50-, 100-200).'
                type: str
            protocol:
                description:
                    - Integer value for the protocol type as defined by IANA (0 - 255).
                type: str
            scan_botnet_connections:
                description:
                    - Enable/disable scanning of connections to Botnet servers.
                type: str
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            spamfilter_profile:
                description:
                    - Name of an existing spam filter profile. Source spamfilter.profile.name.
                type: str
            spamfilter_profile_status:
                description:
                    - Enable/disable spam filter.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            status:
                description:
                    - Enable/disable the active status of the sniffer.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            vlan:
                description:
                    - List of VLANs to sniff.
                type: str
            webfilter_profile:
                description:
                    - Name of an existing web filter profile. Source webfilter.profile.name.
                type: str
            webfilter_profile_status:
                description:
                    - Enable/disable web filter profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure sniffer.
  fortinet.fortios.fortios_firewall_sniffer:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_sniffer:
          anomaly:
              -
                  action: "pass"
                  log: "enable"
                  name: "default_name_6"
                  quarantine: "none"
                  quarantine_expiry: "<your_own_value>"
                  quarantine_log: "disable"
                  status: "disable"
                  synproxy_tcp_mss: "0"
                  synproxy_tcp_sack: "enable"
                  synproxy_tcp_timestamp: "enable"
                  synproxy_tcp_window: "4096"
                  synproxy_tcp_windowscale: "0"
                  synproxy_tos: "0"
                  synproxy_ttl: "32"
                  threshold: "0"
                  threshold_default: "0"
          application_list: "<your_own_value> (source application.list.name)"
          application_list_status: "enable"
          av_profile: "<your_own_value> (source antivirus.profile.name)"
          av_profile_status: "enable"
          casb_profile: "<your_own_value> (source casb.profile.name)"
          casb_profile_status: "enable"
          dlp_profile: "<your_own_value> (source dlp.profile.name)"
          dlp_profile_status: "enable"
          dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
          dlp_sensor_status: "enable"
          dsri: "enable"
          emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
          emailfilter_profile_status: "enable"
          file_filter_profile: "<your_own_value> (source file-filter.profile.name)"
          file_filter_profile_status: "enable"
          host: "myhostname"
          id: "36"
          interface: "<your_own_value> (source system.interface.name)"
          ip_threatfeed:
              -
                  name: "default_name_39 (source system.external-resource.name)"
          ip_threatfeed_status: "enable"
          ips_dos_status: "enable"
          ips_sensor: "<your_own_value> (source ips.sensor.name)"
          ips_sensor_status: "enable"
          ipv6: "enable"
          logtraffic: "all"
          max_packet_count: "4000"
          non_ip: "enable"
          port: "<your_own_value>"
          protocol: "<your_own_value>"
          scan_botnet_connections: "disable"
          spamfilter_profile: "<your_own_value> (source spamfilter.profile.name)"
          spamfilter_profile_status: "enable"
          status: "enable"
          uuid: "<your_own_value>"
          vlan: "<your_own_value>"
          webfilter_profile: "<your_own_value> (source webfilter.profile.name)"
          webfilter_profile_status: "enable"
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


def filter_firewall_sniffer_data(json):
    option_list = [
        "anomaly",
        "application_list",
        "application_list_status",
        "av_profile",
        "av_profile_status",
        "casb_profile",
        "casb_profile_status",
        "dlp_profile",
        "dlp_profile_status",
        "dlp_sensor",
        "dlp_sensor_status",
        "dsri",
        "emailfilter_profile",
        "emailfilter_profile_status",
        "file_filter_profile",
        "file_filter_profile_status",
        "host",
        "id",
        "interface",
        "ip_threatfeed",
        "ip_threatfeed_status",
        "ips_dos_status",
        "ips_sensor",
        "ips_sensor_status",
        "ipv6",
        "logtraffic",
        "max_packet_count",
        "non_ip",
        "port",
        "protocol",
        "scan_botnet_connections",
        "spamfilter_profile",
        "spamfilter_profile_status",
        "status",
        "uuid",
        "vlan",
        "webfilter_profile",
        "webfilter_profile_status",
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


def valid_attr_to_invalid_attr(data):
    speciallist = {"threshold(default)": "threshold_default"}

    for k, v in speciallist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return valid_attr_to_invalid_attr(data)


def firewall_sniffer(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    firewall_sniffer_data = data["firewall_sniffer"]

    filtered_data = filter_firewall_sniffer_data(firewall_sniffer_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("firewall", "sniffer", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "sniffer", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_sniffer"] = filtered_data
    fos.do_member_operation(
        "firewall",
        "sniffer",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "sniffer", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("firewall", "sniffer", mkey=converted_data["id"], vdom=vdom)
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

    if data["firewall_sniffer"]:
        resp = firewall_sniffer(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("firewall_sniffer"))
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
        "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "uuid": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "logtraffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "all"}, {"value": "utm"}, {"value": "disable"}],
        },
        "ipv6": {
            "v_range": [["v6.0.0", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "non_ip": {
            "v_range": [["v6.0.0", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "host": {"v_range": [["v6.0.0", "v7.0.12"], ["v7.2.1", ""]], "type": "string"},
        "port": {"v_range": [["v6.0.0", "v7.0.12"], ["v7.2.1", ""]], "type": "string"},
        "protocol": {
            "v_range": [["v6.0.0", "v7.0.12"], ["v7.2.1", ""]],
            "type": "string",
        },
        "vlan": {"v_range": [["v6.0.0", "v7.0.12"], ["v7.2.1", ""]], "type": "string"},
        "application_list_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "application_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ips_sensor_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ips_sensor": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dsri": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "av_profile_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "av_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "webfilter_profile_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webfilter_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "emailfilter_profile_status": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "emailfilter_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "dlp_profile_status": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dlp_profile": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "ip_threatfeed_status": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip_threatfeed": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.0", ""]],
        },
        "file_filter_profile_status": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "file_filter_profile": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "ips_dos_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "anomaly": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "action": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "pass"},
                        {"value": "block"},
                        {"value": "proxy"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "attacker"}],
                },
                "quarantine_expiry": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "quarantine_log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "threshold": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "synproxy_ttl": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "32"},
                        {"value": "64"},
                        {"value": "128"},
                        {"value": "255"},
                    ],
                },
                "synproxy_tos": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "0"},
                        {"value": "10"},
                        {"value": "12"},
                        {"value": "14"},
                        {"value": "18"},
                        {"value": "20"},
                        {"value": "22"},
                        {"value": "26"},
                        {"value": "28"},
                        {"value": "30"},
                        {"value": "34"},
                        {"value": "36"},
                        {"value": "38"},
                        {"value": "40"},
                        {"value": "46"},
                        {"value": "255"},
                    ],
                },
                "synproxy_tcp_mss": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "0"},
                        {"value": "256"},
                        {"value": "512"},
                        {"value": "1024"},
                        {"value": "1300"},
                        {"value": "1360"},
                        {"value": "1460"},
                        {"value": "1500"},
                    ],
                },
                "synproxy_tcp_sack": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "synproxy_tcp_timestamp": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "synproxy_tcp_window": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "4096"},
                        {"value": "8192"},
                        {"value": "16384"},
                        {"value": "32768"},
                    ],
                },
                "synproxy_tcp_windowscale": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "0"},
                        {"value": "1"},
                        {"value": "2"},
                        {"value": "3"},
                        {"value": "4"},
                        {"value": "5"},
                        {"value": "6"},
                        {"value": "7"},
                        {"value": "8"},
                        {"value": "9"},
                        {"value": "10"},
                        {"value": "11"},
                        {"value": "12"},
                        {"value": "13"},
                        {"value": "14"},
                    ],
                },
                "threshold_default": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "casb_profile_status": {
            "v_range": [["v7.4.1", "v7.4.1"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "casb_profile": {"v_range": [["v7.4.1", "v7.4.1"]], "type": "string"},
        "dlp_sensor_status": {
            "v_range": [["v6.0.0", "v7.0.12"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dlp_sensor": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
        "max_packet_count": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "integer"},
        "spamfilter_profile_status": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "spamfilter_profile": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "scan_botnet_connections": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "block"}, {"value": "monitor"}],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "id"
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
        "firewall_sniffer": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_sniffer"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_sniffer"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "firewall_sniffer"
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
