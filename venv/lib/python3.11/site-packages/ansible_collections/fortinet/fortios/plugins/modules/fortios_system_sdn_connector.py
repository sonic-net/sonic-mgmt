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
module: fortios_system_sdn_connector
short_description: Configure connection to SDN Connector in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and sdn_connector category.
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
    system_sdn_connector:
        description:
            - Configure connection to SDN Connector.
        default: null
        type: dict
        suboptions:
            access_key:
                description:
                    - AWS / ACS access key ID.
                type: str
            alt_resource_ip:
                description:
                    - Enable/disable AWS alternative resource IP.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            api_key:
                description:
                    - IBM cloud API key or service ID API key.
                type: str
            azure_region:
                description:
                    - Azure server region.
                type: str
                choices:
                    - 'global'
                    - 'china'
                    - 'germany'
                    - 'usgov'
                    - 'local'
            client_id:
                description:
                    - Azure client ID (application ID).
                type: str
            client_secret:
                description:
                    - Azure client secret (application key).
                type: str
            compartment_id:
                description:
                    - Compartment ID.
                type: str
            compartment_list:
                description:
                    - Configure OCI compartment list.
                type: list
                elements: dict
                suboptions:
                    compartment_id:
                        description:
                            - OCI compartment ID.
                        required: true
                        type: str
            compute_generation:
                description:
                    - Compute generation for IBM cloud infrastructure.
                type: int
            domain:
                description:
                    - Domain name.
                type: str
            external_account_list:
                description:
                    - Configure AWS external account list.
                type: list
                elements: dict
                suboptions:
                    external_id:
                        description:
                            - AWS external ID.
                        type: str
                    region_list:
                        description:
                            - AWS region name list.
                        type: list
                        elements: dict
                        suboptions:
                            region:
                                description:
                                    - AWS region name.
                                required: true
                                type: str
                    role_arn:
                        description:
                            - AWS role ARN to assume.
                        required: true
                        type: str
            external_ip:
                description:
                    - Configure GCP external IP.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - External IP name.
                        required: true
                        type: str
            forwarding_rule:
                description:
                    - Configure GCP forwarding rule.
                type: list
                elements: dict
                suboptions:
                    rule_name:
                        description:
                            - Forwarding rule name.
                        required: true
                        type: str
                    target:
                        description:
                            - Target instance name.
                        type: str
            gcp_project:
                description:
                    - GCP project name.
                type: str
            gcp_project_list:
                description:
                    - Configure GCP project list.
                type: list
                elements: dict
                suboptions:
                    gcp_zone_list:
                        description:
                            - Configure GCP zone list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - GCP zone name.
                                required: true
                                type: str
                    id:
                        description:
                            - GCP project ID.
                        required: true
                        type: str
            group_name:
                description:
                    - Full path group name of computers.
                type: str
            ha_status:
                description:
                    - Enable/disable use for FortiGate HA service.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ibm_region:
                description:
                    - IBM cloud region name.
                type: str
                choices:
                    - 'dallas'
                    - 'washington-dc'
                    - 'london'
                    - 'frankfurt'
                    - 'sydney'
                    - 'tokyo'
                    - 'osaka'
                    - 'toronto'
                    - 'sao-paulo'
                    - 'madrid'
                    - 'us-south'
                    - 'us-east'
                    - 'germany'
                    - 'great-britain'
                    - 'japan'
                    - 'australia'
            ibm_region_gen1:
                description:
                    - IBM cloud compute generation 1 region name.
                type: str
                choices:
                    - 'us-south'
                    - 'us-east'
                    - 'germany'
                    - 'great-britain'
                    - 'japan'
                    - 'australia'
            ibm_region_gen2:
                description:
                    - IBM cloud compute generation 2 region name.
                type: str
                choices:
                    - 'us-south'
                    - 'us-east'
                    - 'great-britain'
            key_passwd:
                description:
                    - Private key password.
                type: str
            login_endpoint:
                description:
                    - Azure Stack login endpoint.
                type: str
            message_server_port:
                description:
                    - HTTP port number of the SAP message server.
                type: int
            microsoft_365:
                description:
                    - Enable to use as Microsoft 365 connector.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - SDN connector name.
                required: true
                type: str
            nic:
                description:
                    - Configure Azure network interface.
                type: list
                elements: dict
                suboptions:
                    ip:
                        description:
                            - Configure IP configuration.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - IP configuration name.
                                required: true
                                type: str
                            private_ip:
                                description:
                                    - Private IP address.
                                type: str
                            public_ip:
                                description:
                                    - Public IP name.
                                type: str
                            resource_group:
                                description:
                                    - Resource group of Azure public IP.
                                type: str
                    name:
                        description:
                            - Network interface name.
                        required: true
                        type: str
                    peer_nic:
                        description:
                            - Peer network interface name.
                        type: str
            oci_cert:
                description:
                    - OCI certificate. Source certificate.local.name.
                type: str
            oci_fingerprint:
                description:
                    - OCI pubkey fingerprint.
                type: str
            oci_region:
                description:
                    - OCI server region.
                type: str
                choices:
                    - 'phoenix'
                    - 'ashburn'
                    - 'frankfurt'
                    - 'london'
            oci_region_list:
                description:
                    - Configure OCI region list.
                type: list
                elements: dict
                suboptions:
                    region:
                        description:
                            - OCI region.
                        required: true
                        type: str
            oci_region_type:
                description:
                    - OCI region type.
                type: str
                choices:
                    - 'commercial'
                    - 'government'
            password:
                description:
                    - Password of the remote SDN connector as login credentials.
                type: str
            private_key:
                description:
                    - Private key of GCP service account.
                type: str
            proxy:
                description:
                    - SDN proxy. Source system.sdn-proxy.name.
                type: str
            region:
                description:
                    - AWS / ACS region name.
                type: str
            resource_group:
                description:
                    - Azure resource group.
                type: str
            resource_url:
                description:
                    - Azure Stack resource URL.
                type: str
            route:
                description:
                    - Configure GCP route.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Route name.
                        required: true
                        type: str
            route_table:
                description:
                    - Configure Azure route table.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Route table name.
                        required: true
                        type: str
                    resource_group:
                        description:
                            - Resource group of Azure route table.
                        type: str
                    route:
                        description:
                            - Configure Azure route.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Route name.
                                required: true
                                type: str
                            next_hop:
                                description:
                                    - Next hop address.
                                type: str
                    subscription_id:
                        description:
                            - Subscription ID of Azure route table.
                        type: str
            secret_key:
                description:
                    - AWS / ACS secret access key.
                type: str
            secret_token:
                description:
                    - Secret token of Kubernetes service account.
                type: str
            server:
                description:
                    - Server address of the remote SDN connector.
                type: str
            server_ca_cert:
                description:
                    - Trust only those servers whose certificate is directly/indirectly signed by this certificate. Source certificate.remote.name certificate
                      .ca.name.
                type: str
            server_cert:
                description:
                    - Trust servers that contain this certificate only. Source certificate.remote.name.
                type: str
            server_list:
                description:
                    - Server address list of the remote SDN connector.
                type: list
                elements: dict
                suboptions:
                    ip:
                        description:
                            - IPv4 address.
                        required: true
                        type: str
            server_port:
                description:
                    - Port number of the remote SDN connector.
                type: int
            service_account:
                description:
                    - GCP service account email.
                type: str
            status:
                description:
                    - Enable/disable connection to the remote SDN connector.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            subscription_id:
                description:
                    - Azure subscription ID.
                type: str
            tenant_id:
                description:
                    - Tenant ID (directory ID).
                type: str
            type:
                description:
                    - Type of SDN connector.
                type: str
                choices:
                    - 'aci'
                    - 'alicloud'
                    - 'aws'
                    - 'azure'
                    - 'gcp'
                    - 'nsx'
                    - 'nuage'
                    - 'oci'
                    - 'openstack'
                    - 'kubernetes'
                    - 'vmware'
                    - 'sepm'
                    - 'aci-direct'
                    - 'ibm'
                    - 'nutanix'
                    - 'sap'
            update_interval:
                description:
                    - Dynamic object update interval (30 - 3600 sec).
                type: int
            use_metadata_iam:
                description:
                    - Enable/disable use of IAM role from metadata to call API.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            user_id:
                description:
                    - User ID.
                type: str
            username:
                description:
                    - Username of the remote SDN connector as login credentials.
                type: str
            vcenter_password:
                description:
                    - vCenter server password for NSX quarantine.
                type: str
            vcenter_server:
                description:
                    - vCenter server address for NSX quarantine.
                type: str
            vcenter_username:
                description:
                    - vCenter server username for NSX quarantine.
                type: str
            vdom:
                description:
                    - Virtual domain name of the remote SDN connector. Source system.vdom.name.
                type: str
            verify_certificate:
                description:
                    - Enable/disable server certificate verification.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            vpc_id:
                description:
                    - AWS VPC ID.
                type: str
"""

EXAMPLES = """
- name: Configure connection to SDN Connector.
  fortinet.fortios.fortios_system_sdn_connector:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_sdn_connector:
          access_key: "<your_own_value>"
          alt_resource_ip: "disable"
          api_key: "<your_own_value>"
          azure_region: "global"
          client_id: "<your_own_value>"
          client_secret: "<your_own_value>"
          compartment_id: "<your_own_value>"
          compartment_list:
              -
                  compartment_id: "<your_own_value>"
          compute_generation: "2"
          domain: "<your_own_value>"
          external_account_list:
              -
                  external_id: "<your_own_value>"
                  region_list:
                      -
                          region: "<your_own_value>"
                  role_arn: "<your_own_value>"
          external_ip:
              -
                  name: "default_name_20"
          forwarding_rule:
              -
                  rule_name: "<your_own_value>"
                  target: "<your_own_value>"
          gcp_project: "<your_own_value>"
          gcp_project_list:
              -
                  gcp_zone_list:
                      -
                          name: "default_name_27"
                  id: "28"
          group_name: "<your_own_value>"
          ha_status: "disable"
          ibm_region: "dallas"
          ibm_region_gen1: "us-south"
          ibm_region_gen2: "us-south"
          key_passwd: "<your_own_value>"
          login_endpoint: "<your_own_value>"
          message_server_port: "0"
          microsoft_365: "disable"
          name: "default_name_38"
          nic:
              -
                  ip:
                      -
                          name: "default_name_41"
                          private_ip: "<your_own_value>"
                          public_ip: "<your_own_value>"
                          resource_group: "<your_own_value>"
                  name: "default_name_45"
                  peer_nic: "<your_own_value>"
          oci_cert: "<your_own_value> (source certificate.local.name)"
          oci_fingerprint: "<your_own_value>"
          oci_region: "phoenix"
          oci_region_list:
              -
                  region: "<your_own_value>"
          oci_region_type: "commercial"
          password: "<your_own_value>"
          private_key: "<your_own_value>"
          proxy: "<your_own_value> (source system.sdn-proxy.name)"
          region: "<your_own_value>"
          resource_group: "<your_own_value>"
          resource_url: "<your_own_value>"
          route:
              -
                  name: "default_name_60"
          route_table:
              -
                  name: "default_name_62"
                  resource_group: "<your_own_value>"
                  route:
                      -
                          name: "default_name_65"
                          next_hop: "<your_own_value>"
                  subscription_id: "<your_own_value>"
          secret_key: "<your_own_value>"
          secret_token: "<your_own_value>"
          server: "192.168.100.40"
          server_ca_cert: "<your_own_value> (source certificate.remote.name certificate.ca.name)"
          server_cert: "<your_own_value> (source certificate.remote.name)"
          server_list:
              -
                  ip: "<your_own_value>"
          server_port: "0"
          service_account: "<your_own_value>"
          status: "disable"
          subscription_id: "<your_own_value>"
          tenant_id: "<your_own_value>"
          type: "aci"
          update_interval: "60"
          use_metadata_iam: "disable"
          user_id: "<your_own_value>"
          username: "<your_own_value>"
          vcenter_password: "<your_own_value>"
          vcenter_server: "<your_own_value>"
          vcenter_username: "<your_own_value>"
          vdom: "<your_own_value> (source system.vdom.name)"
          verify_certificate: "disable"
          vpc_id: "<your_own_value>"
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


def filter_system_sdn_connector_data(json):
    option_list = [
        "access_key",
        "alt_resource_ip",
        "api_key",
        "azure_region",
        "client_id",
        "client_secret",
        "compartment_id",
        "compartment_list",
        "compute_generation",
        "domain",
        "external_account_list",
        "external_ip",
        "forwarding_rule",
        "gcp_project",
        "gcp_project_list",
        "group_name",
        "ha_status",
        "ibm_region",
        "ibm_region_gen1",
        "ibm_region_gen2",
        "key_passwd",
        "login_endpoint",
        "message_server_port",
        "microsoft_365",
        "name",
        "nic",
        "oci_cert",
        "oci_fingerprint",
        "oci_region",
        "oci_region_list",
        "oci_region_type",
        "password",
        "private_key",
        "proxy",
        "region",
        "resource_group",
        "resource_url",
        "route",
        "route_table",
        "secret_key",
        "secret_token",
        "server",
        "server_ca_cert",
        "server_cert",
        "server_list",
        "server_port",
        "service_account",
        "status",
        "subscription_id",
        "tenant_id",
        "type",
        "update_interval",
        "use_metadata_iam",
        "user_id",
        "username",
        "vcenter_password",
        "vcenter_server",
        "vcenter_username",
        "vdom",
        "verify_certificate",
        "vpc_id",
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


def system_sdn_connector(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_sdn_connector_data = data["system_sdn_connector"]

    filtered_data = filter_system_sdn_connector_data(system_sdn_connector_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "sdn-connector", filtered_data, vdom=vdom)
        current_data = fos.get("system", "sdn-connector", vdom=vdom, mkey=mkey)
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
    data_copy["system_sdn_connector"] = filtered_data
    fos.do_member_operation(
        "system",
        "sdn-connector",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "sdn-connector", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "sdn-connector", mkey=converted_data["name"], vdom=vdom
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


def fortios_system(data, fos, check_mode):

    if data["system_sdn_connector"]:
        resp = system_sdn_connector(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_sdn_connector"))
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
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "aci"},
                {"value": "alicloud", "v_range": [["v6.2.0", ""]]},
                {"value": "aws"},
                {"value": "azure"},
                {"value": "gcp"},
                {"value": "nsx"},
                {"value": "nuage"},
                {"value": "oci"},
                {"value": "openstack"},
                {"value": "kubernetes", "v_range": [["v6.2.0", ""]]},
                {"value": "vmware", "v_range": [["v6.2.0", ""]]},
                {"value": "sepm", "v_range": [["v6.2.0", ""]]},
                {"value": "aci-direct", "v_range": [["v6.4.0", ""]]},
                {"value": "ibm", "v_range": [["v6.4.0", ""]]},
                {"value": "nutanix", "v_range": [["v7.0.0", ""]]},
                {"value": "sap", "v_range": [["v7.2.1", ""]]},
            ],
        },
        "proxy": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "use_metadata_iam": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "microsoft_365": {
            "v_range": [["v7.6.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ha_status": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "verify_certificate": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "vdom": {"v_range": [["v7.6.3", ""]], "type": "string"},
        "server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "server_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {"v_range": [["v6.4.4", ""]], "type": "string", "required": True}
            },
            "v_range": [["v6.4.4", ""]],
        },
        "server_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "message_server_port": {"v_range": [["v7.6.1", ""]], "type": "integer"},
        "username": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "vcenter_server": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "vcenter_username": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "vcenter_password": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "access_key": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "secret_key": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "region": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "vpc_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "alt_resource_ip": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "external_account_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "role_arn": {
                    "v_range": [["v7.0.4", ""]],
                    "type": "string",
                    "required": True,
                },
                "external_id": {
                    "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", ""]],
                    "type": "string",
                },
                "region_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "region": {
                            "v_range": [["v7.0.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.0.4", ""]],
                },
            },
            "v_range": [["v7.0.4", ""]],
        },
        "tenant_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "client_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "client_secret": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "subscription_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "resource_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "login_endpoint": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "resource_url": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "azure_region": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "global"},
                {"value": "china"},
                {"value": "germany"},
                {"value": "usgov"},
                {"value": "local"},
            ],
        },
        "nic": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "peer_nic": {"v_range": [["v7.6.1", ""]], "type": "string"},
                "ip": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "private_ip": {"v_range": [["v7.6.1", ""]], "type": "string"},
                        "public_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                        "resource_group": {
                            "v_range": [["v6.2.0", ""]],
                            "type": "string",
                        },
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "route_table": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "subscription_id": {
                    "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
                    "type": "string",
                },
                "resource_group": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "route": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "next_hop": {"v_range": [["v6.0.0", ""]], "type": "string"},
                    },
                    "v_range": [["v6.0.0", ""]],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "user_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "compartment_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "compartment_id": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.0", ""]],
        },
        "oci_region_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "region": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.0", ""]],
        },
        "oci_region_type": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "commercial"}, {"value": "government"}],
        },
        "oci_cert": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "external_ip": {
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
        "route": {
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
        "gcp_project_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {"v_range": [["v7.0.4", ""]], "type": "string", "required": True},
                "gcp_zone_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.0.4", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.0.4", ""]],
                },
            },
            "v_range": [["v7.0.4", ""]],
        },
        "forwarding_rule": {
            "type": "list",
            "elements": "dict",
            "children": {
                "rule_name": {
                    "v_range": [["v7.0.2", ""]],
                    "type": "string",
                    "required": True,
                },
                "target": {"v_range": [["v7.0.2", ""]], "type": "string"},
            },
            "v_range": [["v7.0.2", ""]],
        },
        "service_account": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "private_key": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "secret_token": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "domain": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "group_name": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "server_cert": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "server_ca_cert": {"v_range": [["v7.2.4", ""]], "type": "string"},
        "api_key": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "ibm_region": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "dallas", "v_range": [["v7.0.4", ""]]},
                {"value": "washington-dc", "v_range": [["v7.0.4", ""]]},
                {"value": "london", "v_range": [["v7.0.4", ""]]},
                {"value": "frankfurt", "v_range": [["v7.0.4", ""]]},
                {"value": "sydney", "v_range": [["v7.0.4", ""]]},
                {"value": "tokyo", "v_range": [["v7.0.4", ""]]},
                {"value": "osaka", "v_range": [["v7.0.4", ""]]},
                {"value": "toronto", "v_range": [["v7.0.4", ""]]},
                {"value": "sao-paulo", "v_range": [["v7.0.4", ""]]},
                {"value": "madrid", "v_range": [["v7.6.1", ""]]},
                {
                    "value": "us-south",
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.3"]],
                },
                {
                    "value": "us-east",
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.3"]],
                },
                {
                    "value": "germany",
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.3"]],
                },
                {
                    "value": "great-britain",
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.3"]],
                },
                {
                    "value": "japan",
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.3"]],
                },
                {
                    "value": "australia",
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.0.3"]],
                },
            ],
        },
        "update_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "compute_generation": {"v_range": [["v6.4.0", "v7.6.0"]], "type": "integer"},
        "compartment_id": {"v_range": [["v6.0.0", "v7.2.4"]], "type": "string"},
        "oci_region": {
            "v_range": [["v6.0.0", "v7.2.4"]],
            "type": "string",
            "options": [
                {"value": "phoenix", "v_range": [["v6.0.0", "v6.0.11"]]},
                {"value": "ashburn", "v_range": [["v6.0.0", "v6.0.11"]]},
                {"value": "frankfurt", "v_range": [["v6.0.0", "v6.0.11"]]},
                {"value": "london", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
        },
        "oci_fingerprint": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "gcp_project": {"v_range": [["v6.0.0", "v7.0.3"]], "type": "string"},
        "ibm_region_gen1": {
            "v_range": [["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [
                {"value": "us-south"},
                {"value": "us-east"},
                {"value": "germany"},
                {"value": "great-britain"},
                {"value": "japan"},
                {"value": "australia"},
            ],
        },
        "ibm_region_gen2": {
            "v_range": [["v6.4.1", "v6.4.1"]],
            "type": "string",
            "options": [
                {"value": "us-south"},
                {"value": "us-east"},
                {"value": "great-britain"},
            ],
        },
        "key_passwd": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
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
        "system_sdn_connector": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_sdn_connector"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_sdn_connector"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_sdn_connector"
        )

        is_error, has_changed, result, diff = fortios_system(
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
