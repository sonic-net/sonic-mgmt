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
module: fortios_wireless_controller_hotspot20_hs_profile
short_description: Configure hotspot profile in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller_hotspot20 feature and hs_profile category.
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
    wireless_controller_hotspot20_hs_profile:
        description:
            - Configure hotspot profile.
        default: null
        type: dict
        suboptions:
            plmn_3gpp:
                description:
                    - 3GPP PLMN name. Source wireless-controller.hotspot20.anqp-3gpp-cellular.name.
                type: str
            access_network_asra:
                description:
                    - Enable/disable additional step required for access (ASRA).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            access_network_esr:
                description:
                    - Enable/disable emergency services reachable (ESR).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            access_network_internet:
                description:
                    - Enable/disable connectivity to the Internet.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            access_network_type:
                description:
                    - Access network type.
                type: str
                choices:
                    - 'private-network'
                    - 'private-network-with-guest-access'
                    - 'chargeable-public-network'
                    - 'free-public-network'
                    - 'personal-device-network'
                    - 'emergency-services-only-network'
                    - 'test-or-experimental'
                    - 'wildcard'
            access_network_uesa:
                description:
                    - Enable/disable unauthenticated emergency service accessible (UESA).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            advice_of_charge:
                description:
                    - Advice of charge. Source wireless-controller.hotspot20.h2qp-advice-of-charge.name.
                type: str
            anqp_domain_id:
                description:
                    - ANQP Domain ID (0-65535).
                type: int
            bss_transition:
                description:
                    - Enable/disable basic service set (BSS) transition Support.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            conn_cap:
                description:
                    - Connection capability name. Source wireless-controller.hotspot20.h2qp-conn-capability.name.
                type: str
            deauth_request_timeout:
                description:
                    - Deauthentication request timeout (in seconds).
                type: int
            dgaf:
                description:
                    - Enable/disable downstream group-addressed forwarding (DGAF).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            domain_name:
                description:
                    - Domain name.
                type: str
            gas_comeback_delay:
                description:
                    - GAS comeback delay (0 or 100 - 10000 milliseconds).
                type: int
            gas_fragmentation_limit:
                description:
                    - GAS fragmentation limit (512 - 4096).
                type: int
            hessid:
                description:
                    - Homogeneous extended service set identifier (HESSID).
                type: str
            ip_addr_type:
                description:
                    - IP address type name. Source wireless-controller.hotspot20.anqp-ip-address-type.name.
                type: str
            l2tif:
                description:
                    - Enable/disable Layer 2 traffic inspection and filtering.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            nai_realm:
                description:
                    - NAI realm list name. Source wireless-controller.hotspot20.anqp-nai-realm.name.
                type: str
            name:
                description:
                    - Hotspot profile name.
                required: true
                type: str
            network_auth:
                description:
                    - Network authentication name. Source wireless-controller.hotspot20.anqp-network-auth-type.name.
                type: str
            oper_friendly_name:
                description:
                    - Operator friendly name. Source wireless-controller.hotspot20.h2qp-operator-name.name.
                type: str
            oper_icon:
                description:
                    - Operator icon. Source wireless-controller.hotspot20.icon.name.
                type: str
            osu_provider:
                description:
                    - Manually selected list of OSU provider(s).
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - OSU provider name. Source wireless-controller.hotspot20.h2qp-osu-provider.name.
                        required: true
                        type: str
            osu_provider_nai:
                description:
                    - OSU Provider NAI. Source wireless-controller.hotspot20.h2qp-osu-provider-nai.name.
                type: str
            osu_ssid:
                description:
                    - Online sign up (OSU) SSID.
                type: str
            pame_bi:
                description:
                    - Enable/disable Pre-Association Message Exchange BSSID Independent (PAME-BI).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            proxy_arp:
                description:
                    - Enable/disable Proxy ARP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            qos_map:
                description:
                    - QoS MAP set ID. Source wireless-controller.hotspot20.qos-map.name.
                type: str
            release:
                description:
                    - Hotspot 2.0 Release number (1, 2, 3).
                type: int
            roaming_consortium:
                description:
                    - Roaming consortium list name. Source wireless-controller.hotspot20.anqp-roaming-consortium.name.
                type: str
            terms_and_conditions:
                description:
                    - Terms and conditions. Source wireless-controller.hotspot20.h2qp-terms-and-conditions.name.
                type: str
            venue_group:
                description:
                    - Venue group.
                type: str
                choices:
                    - 'unspecified'
                    - 'assembly'
                    - 'business'
                    - 'educational'
                    - 'factory'
                    - 'institutional'
                    - 'mercantile'
                    - 'residential'
                    - 'storage'
                    - 'utility'
                    - 'vehicular'
                    - 'outdoor'
            venue_name:
                description:
                    - Venue name. Source wireless-controller.hotspot20.anqp-venue-name.name.
                type: str
            venue_type:
                description:
                    - Venue type.
                type: str
                choices:
                    - 'unspecified'
                    - 'arena'
                    - 'stadium'
                    - 'passenger-terminal'
                    - 'amphitheater'
                    - 'amusement-park'
                    - 'place-of-worship'
                    - 'convention-center'
                    - 'library'
                    - 'museum'
                    - 'restaurant'
                    - 'theater'
                    - 'bar'
                    - 'coffee-shop'
                    - 'zoo-or-aquarium'
                    - 'emergency-center'
                    - 'doctor-office'
                    - 'bank'
                    - 'fire-station'
                    - 'police-station'
                    - 'post-office'
                    - 'professional-office'
                    - 'research-facility'
                    - 'attorney-office'
                    - 'primary-school'
                    - 'secondary-school'
                    - 'university-or-college'
                    - 'factory'
                    - 'hospital'
                    - 'long-term-care-facility'
                    - 'rehab-center'
                    - 'group-home'
                    - 'prison-or-jail'
                    - 'retail-store'
                    - 'grocery-market'
                    - 'auto-service-station'
                    - 'shopping-mall'
                    - 'gas-station'
                    - 'private'
                    - 'hotel-or-motel'
                    - 'dormitory'
                    - 'boarding-house'
                    - 'automobile'
                    - 'airplane'
                    - 'bus'
                    - 'ferry'
                    - 'ship-or-boat'
                    - 'train'
                    - 'motor-bike'
                    - 'muni-mesh-network'
                    - 'city-park'
                    - 'rest-area'
                    - 'traffic-control'
                    - 'bus-stop'
                    - 'kiosk'
            venue_url:
                description:
                    - Venue name. Source wireless-controller.hotspot20.anqp-venue-url.name.
                type: str
            wan_metrics:
                description:
                    - WAN metric name. Source wireless-controller.hotspot20.h2qp-wan-metric.name.
                type: str
            wba_charging_currency:
                description:
                    - Three letter currency code.
                type: str
            wba_charging_rate:
                description:
                    - Number of currency units per kilobyte.
                type: int
            wba_data_clearing_provider:
                description:
                    - WBA ID of data clearing provider.
                type: str
            wba_financial_clearing_provider:
                description:
                    - WBA ID of financial clearing provider.
                type: str
            wba_open_roaming:
                description:
                    - Enable/disable WBA open roaming support.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            wnm_sleep_mode:
                description:
                    - Enable/disable wireless network management (WNM) sleep mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure hotspot profile.
  fortinet.fortios.fortios_wireless_controller_hotspot20_hs_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_hotspot20_hs_profile:
          plmn_3gpp: "<your_own_value> (source wireless-controller.hotspot20.anqp-3gpp-cellular.name)"
          access_network_asra: "enable"
          access_network_esr: "enable"
          access_network_internet: "enable"
          access_network_type: "private-network"
          access_network_uesa: "enable"
          advice_of_charge: "<your_own_value> (source wireless-controller.hotspot20.h2qp-advice-of-charge.name)"
          anqp_domain_id: "0"
          bss_transition: "enable"
          conn_cap: "<your_own_value> (source wireless-controller.hotspot20.h2qp-conn-capability.name)"
          deauth_request_timeout: "60"
          dgaf: "enable"
          domain_name: "<your_own_value>"
          gas_comeback_delay: "500"
          gas_fragmentation_limit: "1024"
          hessid: "<your_own_value>"
          ip_addr_type: "<your_own_value> (source wireless-controller.hotspot20.anqp-ip-address-type.name)"
          l2tif: "enable"
          nai_realm: "<your_own_value> (source wireless-controller.hotspot20.anqp-nai-realm.name)"
          name: "default_name_22"
          network_auth: "<your_own_value> (source wireless-controller.hotspot20.anqp-network-auth-type.name)"
          oper_friendly_name: "<your_own_value> (source wireless-controller.hotspot20.h2qp-operator-name.name)"
          oper_icon: "<your_own_value> (source wireless-controller.hotspot20.icon.name)"
          osu_provider:
              -
                  name: "default_name_27 (source wireless-controller.hotspot20.h2qp-osu-provider.name)"
          osu_provider_nai: "<your_own_value> (source wireless-controller.hotspot20.h2qp-osu-provider-nai.name)"
          osu_ssid: "<your_own_value>"
          pame_bi: "disable"
          proxy_arp: "enable"
          qos_map: "<your_own_value> (source wireless-controller.hotspot20.qos-map.name)"
          release: "2"
          roaming_consortium: "<your_own_value> (source wireless-controller.hotspot20.anqp-roaming-consortium.name)"
          terms_and_conditions: "<your_own_value> (source wireless-controller.hotspot20.h2qp-terms-and-conditions.name)"
          venue_group: "unspecified"
          venue_name: "<your_own_value> (source wireless-controller.hotspot20.anqp-venue-name.name)"
          venue_type: "unspecified"
          venue_url: "<your_own_value> (source wireless-controller.hotspot20.anqp-venue-url.name)"
          wan_metrics: "<your_own_value> (source wireless-controller.hotspot20.h2qp-wan-metric.name)"
          wba_charging_currency: "<your_own_value>"
          wba_charging_rate: "0"
          wba_data_clearing_provider: "<your_own_value>"
          wba_financial_clearing_provider: "<your_own_value>"
          wba_open_roaming: "disable"
          wnm_sleep_mode: "enable"
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


def filter_wireless_controller_hotspot20_hs_profile_data(json):
    option_list = [
        "plmn_3gpp",
        "access_network_asra",
        "access_network_esr",
        "access_network_internet",
        "access_network_type",
        "access_network_uesa",
        "advice_of_charge",
        "anqp_domain_id",
        "bss_transition",
        "conn_cap",
        "deauth_request_timeout",
        "dgaf",
        "domain_name",
        "gas_comeback_delay",
        "gas_fragmentation_limit",
        "hessid",
        "ip_addr_type",
        "l2tif",
        "nai_realm",
        "name",
        "network_auth",
        "oper_friendly_name",
        "oper_icon",
        "osu_provider",
        "osu_provider_nai",
        "osu_ssid",
        "pame_bi",
        "proxy_arp",
        "qos_map",
        "release",
        "roaming_consortium",
        "terms_and_conditions",
        "venue_group",
        "venue_name",
        "venue_type",
        "venue_url",
        "wan_metrics",
        "wba_charging_currency",
        "wba_charging_rate",
        "wba_data_clearing_provider",
        "wba_financial_clearing_provider",
        "wba_open_roaming",
        "wnm_sleep_mode",
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
    speciallist = {"3gpp_plmn": "plmn_3gpp"}

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


def wireless_controller_hotspot20_hs_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    wireless_controller_hotspot20_hs_profile_data = data[
        "wireless_controller_hotspot20_hs_profile"
    ]

    filtered_data = filter_wireless_controller_hotspot20_hs_profile_data(
        wireless_controller_hotspot20_hs_profile_data
    )
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey(
            "wireless-controller.hotspot20", "hs-profile", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "wireless-controller.hotspot20", "hs-profile", vdom=vdom, mkey=mkey
        )
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
    data_copy["wireless_controller_hotspot20_hs_profile"] = filtered_data
    fos.do_member_operation(
        "wireless-controller.hotspot20",
        "hs-profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "wireless-controller.hotspot20",
            "hs-profile",
            data=converted_data,
            vdom=vdom,
        )

    elif state == "absent":
        return fos.delete(
            "wireless-controller.hotspot20",
            "hs-profile",
            mkey=converted_data["name"],
            vdom=vdom,
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


def fortios_wireless_controller_hotspot20(data, fos, check_mode):

    if data["wireless_controller_hotspot20_hs_profile"]:
        resp = wireless_controller_hotspot20_hs_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_hotspot20_hs_profile")
        )
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
        "release": {"v_range": [["v7.0.2", ""]], "type": "integer"},
        "access_network_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "private-network"},
                {"value": "private-network-with-guest-access"},
                {"value": "chargeable-public-network"},
                {"value": "free-public-network"},
                {"value": "personal-device-network"},
                {"value": "emergency-services-only-network"},
                {"value": "test-or-experimental"},
                {"value": "wildcard"},
            ],
        },
        "access_network_internet": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "access_network_asra": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "access_network_esr": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "access_network_uesa": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "venue_group": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "unspecified"},
                {"value": "assembly"},
                {"value": "business"},
                {"value": "educational"},
                {"value": "factory"},
                {"value": "institutional"},
                {"value": "mercantile"},
                {"value": "residential"},
                {"value": "storage"},
                {"value": "utility"},
                {"value": "vehicular"},
                {"value": "outdoor"},
            ],
        },
        "venue_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "unspecified"},
                {"value": "arena"},
                {"value": "stadium"},
                {"value": "passenger-terminal"},
                {"value": "amphitheater"},
                {"value": "amusement-park"},
                {"value": "place-of-worship"},
                {"value": "convention-center"},
                {"value": "library"},
                {"value": "museum"},
                {"value": "restaurant"},
                {"value": "theater"},
                {"value": "bar"},
                {"value": "coffee-shop"},
                {"value": "zoo-or-aquarium"},
                {"value": "emergency-center"},
                {"value": "doctor-office"},
                {"value": "bank"},
                {"value": "fire-station"},
                {"value": "police-station"},
                {"value": "post-office"},
                {"value": "professional-office"},
                {"value": "research-facility"},
                {"value": "attorney-office"},
                {"value": "primary-school"},
                {"value": "secondary-school"},
                {"value": "university-or-college"},
                {"value": "factory"},
                {"value": "hospital"},
                {"value": "long-term-care-facility"},
                {"value": "rehab-center"},
                {"value": "group-home"},
                {"value": "prison-or-jail"},
                {"value": "retail-store"},
                {"value": "grocery-market"},
                {"value": "auto-service-station"},
                {"value": "shopping-mall"},
                {"value": "gas-station"},
                {"value": "private"},
                {"value": "hotel-or-motel"},
                {"value": "dormitory"},
                {"value": "boarding-house"},
                {"value": "automobile"},
                {"value": "airplane"},
                {"value": "bus"},
                {"value": "ferry"},
                {"value": "ship-or-boat"},
                {"value": "train"},
                {"value": "motor-bike"},
                {"value": "muni-mesh-network"},
                {"value": "city-park"},
                {"value": "rest-area"},
                {"value": "traffic-control"},
                {"value": "bus-stop"},
                {"value": "kiosk"},
            ],
        },
        "hessid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "proxy_arp": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "l2tif": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pame_bi": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "anqp_domain_id": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "domain_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "osu_ssid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "gas_comeback_delay": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "gas_fragmentation_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dgaf": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "deauth_request_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "wnm_sleep_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "bss_transition": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "venue_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "venue_url": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "roaming_consortium": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "nai_realm": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "oper_friendly_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "oper_icon": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "advice_of_charge": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "osu_provider_nai": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "terms_and_conditions": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "osu_provider": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "wan_metrics": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "network_auth": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "conn_cap": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "qos_map": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip_addr_type": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wba_open_roaming": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "wba_financial_clearing_provider": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
        },
        "wba_data_clearing_provider": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "wba_charging_currency": {"v_range": [["v7.6.0", ""]], "type": "string"},
        "wba_charging_rate": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "plmn_3gpp": {"v_range": [["v6.0.0", ""]], "type": "string"},
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
        "wireless_controller_hotspot20_hs_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_hotspot20_hs_profile"]["options"][
            attribute_name
        ] = module_spec["options"][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_hotspot20_hs_profile"]["options"][
                attribute_name
            ]["required"] = True

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
            fos, versioned_schema, "wireless_controller_hotspot20_hs_profile"
        )

        is_error, has_changed, result, diff = fortios_wireless_controller_hotspot20(
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
