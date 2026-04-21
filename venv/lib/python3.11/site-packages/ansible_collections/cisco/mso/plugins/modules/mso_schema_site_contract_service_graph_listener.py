#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}


DOCUMENTATION = r"""
---
module: mso_schema_site_contract_service_graph_listener
short_description: Manage the listener for Azure site contract service graph in schema sites
description:
- Manage the listener for Azure site contract service graph in schema sites on Cisco ACI Multi-Site.
- This module is only compatible with NDO versions 3.7 and 4.2+. NDO versions 4.0 and 4.1 are not supported.
author:
- Sabari Jaganathan (@sajagana)
options:
  tenant:
    description:
    - The name of the tenant.
    type: str
  device:
    description:
    - The name of the device.
    type: str
    aliases: [ device_name ]
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  contract:
    description:
    - The name of the contract.
    type: str
    required: true
  site:
    description:
    - The name of the site.
    type: str
    required: true
  service_node_index:
    description:
    - The index of the service node in the site contract service graph. The value starts from 0.
    type: int
  listener:
    description:
    - The name of the listener.
    type: str
    aliases: [ name, listener_name ]
  listener_protocol:
    description:
    - The protocol of the listener.
    type: str
    choices: [ http, https, tcp, udp, tls, inherit ]
  listener_port:
    description:
    - The port of the listener.
    type: int
  security_policy:
    description:
    - The security policy of the listener.
    type: str
    choices: [
        default,
        elb_sec_2016_18,
        elb_sec_fs_2018_06,
        elb_sec_tls_1_2_2017_01,
        elb_sec_tls_1_2_ext_2018_06,
        elb_sec_tls_1_1_2017_01,
        elb_sec_2015_05,
        elb_sec_tls_1_0_2015_04,
        app_gw_ssl_default,
        app_gw_ssl_2015_501,
        app_gw_ssl_2017_401,
        app_gw_ssl_2017_401s
      ]
  ssl_certificates:
    description:
    - The ssl certificates of the listener.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the ssl certificate.
        type: str
        required: true
      certificate_store:
        description:
        - The certificate store of the ssl certificate.
        type: str
        required: true
        choices: [ default, iam, acm ]
  frontend_ip:
    description:
    - The frontend ip of the listener. Only supported for Network load balancers.
    type: str
  rules:
    description:
    - The rules of the listener.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the rule.
        type: str
        required: true
      floating_ip:
        description:
        - The floating ip of the rule.
        type: str
      priority:
        description:
        - The priority of the rule.
        type: int
        required: true
      host:
        description:
        - The host of the rule.
        type: str
      path:
        description:
        - The path of the rule.
        type: str
      action:
        description:
        - The action of the rule.
        type: str
      action_type:
        description:
        - The action type of the rule.
        type: str
        required: true
        choices: [ fixed_response, forward, redirect, ha_port ]
      content_type:
        description:
        - The content type of the rule.
        type: str
        choices: [ text_plain, text_css, text_html, app_js, app_json ]
      port:
        description:
        - The port of the rule.
        type: int
      protocol:
        description:
        - The protocol of the rule.
        type: str
        choices: [ http, https, tcp, udp, tls, inherit ]
      provider_epg:
        description:
        - The provider epg of the rule.
        type: dict
        suboptions:
          schema:
            description:
            - The schema name of the provider epg reference.
            type: str
          template:
            description:
            - The template name of the provider epg reference.
            type: str
          anp_name:
            description:
            - The application profile name of the provider epg reference.
            type: str
            required: true
            aliases: [ anp ]
          epg_name:
            description:
            - The epg (Endpoint Group) name of the provider epg reference.
            type: str
            required: true
            aliases: [ epg ]
      url_type:
        description:
        - The url type of the rule.
        type: str
        choices: [ original, custom ]
      custom_url:
        description:
        - The custom url of the rule.
        type: str
      redirect_host_name:
        description:
        - The redirect host name of the rule.
        type: str
      redirect_path:
        description:
        - The redirect path of the rule.
        type: str
      redirect_query:
        description:
        - The redirect query of the rule.
        type: str
      response_code:
        description:
        - The response code of the rule.
        type: str
      response_body:
        description:
        - The response body of the rule.
        type: str
      redirect_protocol:
        description:
        - The redirect protocol of the rule.
        type: str
        choices: [ http, https, tcp, udp, tls, inherit ]
      redirect_port:
        description:
        - The redirect port of the rule.
        type: int
      redirect_code:
        description:
        - The redirect code of the rule.
        type: str
        choices: [ unknown, permanently_moved, found, see_other, temporary_redirect ]
      health_check:
        description:
        - The health check of the rule.
        type: dict
        suboptions:
          port:
            description:
            - The port of the health check.
            type: int
          protocol:
            description:
            - The protocol of the health check.
            type: str
            choices: [ http, https, tcp, udp, tls, inherit ]
          path:
            description:
            - The path of the health check.
            type: str
          interval:
            description:
            - The interval of the health check.
            type: int
          timeout:
            description:
            - The timeout of the health check.
            type: int
          unhealthy_threshold:
            description:
            - The unhealthy threshold of the health check.
            type: int
          use_host_from_rule:
            description:
            - The use host from rule of the health check.
            type: bool
          host:
            description:
            - The host of the health check. The host attribute will be enabled when the I(use_host_from_rule) is false.
            type: str
          success_code:
            description:
            - The success code of the health check.
            type: str
      target_ip_type:
        description:
        - The target ip type of the rule.
        type: str
        choices: [ unspecified, primary, secondary ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
seealso:
- module: cisco.mso.mso_schema_template_contract_service_graph
extends_documentation_fragment: cisco.mso.modules
"""


EXAMPLES = r"""
- name: Add a listener for Network Load-Balancer
  cisco.mso.mso_schema_site_contract_service_graph_listener:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    contract: "Contract2"
    schema: mso_schema
    template: ansible_template1
    site: mso_site
    service_node_index: 0
    listener: nlb_li_tcp
    listener_port: 80
    listener_protocol: tcp
    tenant: mso_tenant
    frontend_ip: "10.10.10.10"
    device: ans_test_nlb
    security_policy: default
    rules:
      - name: rule1
        priority: 1
        action_type: forward
        port: 80
        protocol: tcp
        health_check:
          port: 80
          protocol: tcp
          interval: 5
          unhealthy_threshold: 2
          success_code: 200-399

- name: Add a listener for Application Load-Balancer
  cisco.mso.mso_schema_site_contract_service_graph_listener:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    contract: "Contract2"
    schema: mso_schema
    template: ansible_template1
    site: mso_site
    service_node_index: 1
    listener: aplb_li_https
    tenant: mso_tenant
    device: ans_test_aplb
    listener_port: 443
    listener_protocol: https
    security_policy: default
    ssl_certificates:
      - name: ans_test_keyring
        certificate_store: default
    rules:
      - name: rule1
        priority: 1
        action_type: forward
        port: 80
        protocol: http
        provider_epg:
          anp_name: AP1
          epg_name: EPG1
        health_check:
          port: 80
          protocol: http
          path: "health_check_path"
          interval: 30
          timeout: 30
          unhealthy_threshold: 3
          use_host_from_rule: true
          success_code: "200"
        target_ip_type: unspecified

- name: Query all listeners
  cisco.mso.mso_schema_site_contract_service_graph_listener:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    contract: "Contract2"
    schema: mso_schema
    template: ansible_template1
    site: mso_site
    state: query
  register: query_all_listeners

- name: Query all listeners with name ans_li_common
  cisco.mso.mso_schema_site_contract_service_graph_listener:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    contract: "Contract2"
    schema: mso_schema
    template: ansible_template1
    site: mso_site
    listener: ans_li_common
    state: query
  register: query_all_ans_li_common

- name: Query a listener with name - aplb_li_https
  cisco.mso.mso_schema_site_contract_service_graph_listener:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    contract: "Contract2"
    schema: mso_schema
    template: ansible_template1
    site: mso_site
    service_node_index: 1
    listener: aplb_li_https
    state: query
  register: query_aplb_li_https

- name: Remove an existing listener - ans_li_common
  cisco.mso.mso_schema_site_contract_service_graph_listener:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    contract: "Contract2"
    schema: mso_schema
    template: ansible_template1
    site: mso_site
    service_node_index: 1
    listener: aplb_li_https
    state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
    listener_ssl_certificates_spec,
    listener_rules_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.constants import (
    LISTENER_REDIRECT_CODE_MAP,
    LISTENER_CONTENT_TYPE_MAP,
    LISTENER_ACTION_TYPE_MAP,
    LISTENER_SECURITY_POLICY_MAP,
    LISTENER_PROTOCOLS,
    YES_OR_NO_TO_BOOL_STRING_MAP,
)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        tenant=dict(type="str"),
        device=dict(type="str", aliases=["device_name"]),
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        contract=dict(type="str", required=True),
        site=dict(type="str", required=True),
        service_node_index=dict(type="int"),
        listener=dict(type="str", aliases=["name", "listener_name"]),
        listener_protocol=dict(type="str", choices=LISTENER_PROTOCOLS),
        listener_port=dict(type="int"),
        security_policy=dict(type="str", choices=list(LISTENER_SECURITY_POLICY_MAP)),
        ssl_certificates=dict(type="list", elements="dict", options=listener_ssl_certificates_spec()),
        frontend_ip=dict(type="str"),
        rules=dict(type="list", elements="dict", options=listener_rules_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["listener"]],
            ["state", "present", ["listener", "listener_protocol", "listener_port", "rules"]],
        ],
    )

    mso = MSOModule(module)
    site = module.params.get("site")

    # Get site id
    site_id = mso.lookup_site(site)

    if mso.site_type == "on-premise" or mso.cloud_provider_type != "azure":
        mso.fail_json(msg="The Site Contract Service Graph Listener is not supported for the site: {0}.".format(site))

    schema = module.params.get("schema")
    template = module.params.get("template")
    contract = module.params.get("contract")
    service_node_index = module.params.get("service_node_index")
    listener = module.params.get("listener")
    tenant = module.params.get("tenant")
    device = module.params.get("device")
    listener_protocol = module.params.get("listener_protocol")
    listener_port = module.params.get("listener_port")
    security_policy = LISTENER_SECURITY_POLICY_MAP.get(module.params.get("security_policy"))
    ssl_certificates = module.params.get("ssl_certificates")
    frontend_ip = module.params.get("frontend_ip")
    rules = module.params.get("rules")
    state = module.params.get("state")

    if listener_protocol == "https":
        mso.input_validation("listener_protocol", "https", ["security_policy", "ssl_certificates"], module.params, None, object_name=listener)

    mso_schema = MSOSchema(mso, schema, template)
    mso_schema.set_template(template)
    schema_id = mso.lookup_schema(schema, True)
    mso_schema.set_site(template, site)
    mso_schema.set_site_contract(contract, False)

    service_graph_ref = mso_schema.schema_objects["site_contract"].details.get("serviceGraphRelationship", {}).get("serviceGraphRef")
    service_nodes = mso_schema.schema_objects["site_contract"].details.get("serviceGraphRelationship", {}).get("serviceNodesRelationship", [])

    parent_present = False

    if service_graph_ref is None:
        mso.fail_json(msg="The site contract: {0} is not associated with a service graph.".format(contract))
    # Parent object present check
    else:
        if service_node_index is not None and service_node_index >= 0:
            if len(service_nodes) > 0 and len(service_nodes) > service_node_index:
                service_node = service_nodes[service_node_index]
                # Query all listeners under a contract service node
                # The below condition was never false if the service graph was created properly, but condition is required to avoid error
                if service_node.get("serviceNodeRef") and service_node.get("serviceNodeRef").split("/")[-1] == "node{0}".format(service_node_index + 1):
                    listeners = service_node.get("deviceConfiguration", {}).get("cloudLoadBalancer", {}).get("listeners", [])
                    if listeners:
                        parent_present = True
                        if listener:
                            for listener_data in listeners:
                                if listener_data.get("name") == listener:
                                    mso.existing = listener_data
                                    break
                        else:
                            mso.existing = listeners
                else:
                    mso.fail_json(
                        msg="The service_node_index: {0} is not matching with the service node reference: {1}.".format(
                            service_node_index, service_node.get("serviceNodeRef")
                        )
                    )
            else:
                mso.fail_json(msg="The service_node_index: {0} is out of range.".format(service_node_index))

        # Query all listeners under a contract does not require service_node_index, so the below condition is required
        elif state == "query":
            # Query all listeners under a contract
            for service_node in service_nodes:
                listeners = service_node.get("deviceConfiguration", {}).get("cloudLoadBalancer", {}).get("listeners", [])
                if listener:
                    for listener_data in listeners:
                        # Query a listener under a contract service node
                        if listener_data.get("name") == listener:
                            mso.existing = ([listener_data] + mso.existing) if mso.existing else [listener_data]
                            break
                else:
                    mso.existing = (listeners + mso.existing) if mso.existing else listeners

        else:
            mso.fail_json(msg="The service_node_index: {0} is not valid.".format(service_node_index))

    if state == "query":
        mso.exit_json()

    ops = []
    mso.previous = mso.existing

    parent_object = {}

    if state == "present":
        # Parent object creation logic begins
        if device is None and parent_present is False:
            mso.fail_json(msg="The 'device' name is required to initialize the parent object.")

        elif device is not None and parent_present is False:
            query_device_data = mso.lookup_service_node_device(site_id, tenant, device_name=device)

            if query_device_data.get("deviceVendorType") == "NATIVELB" and (
                query_device_data.get("devType") == "application" or query_device_data.get("devType") == "network"
            ):
                mso_schema.set_site_service_graph(service_graph_ref.split("/")[-1])

                for sg in mso_schema.schema_objects["site_service_graph"].details.get("serviceNodes", []):
                    if device == sg.get("device").get("dn").split("/")[-1].split("-")[-1]:
                        parent_object = dict(deviceConfiguration=dict(cloudLoadBalancer=dict(listeners=[])), serviceNodeRef=sg.get("serviceNodeRef"))
                        break
            else:
                mso.fail_json(
                    msg="Listener is not supported for the 'service_node_index': {0} is associated with the Third-Party {1} device.".format(
                        service_node_index, "Load Balancer" if query_device_data.get("deviceVendorType") == "ADC" else "Firewall"
                    )
                )
        # Parent object creation logic ends

        # Listener object creation logic begins
        listener_object = dict(
            name=listener,
            protocol=listener_protocol,
            port=listener_port,
            secPolicy=security_policy,
        )

        if frontend_ip:
            mso.input_validation("frontend_ip", frontend_ip, ["tenant", "device"], module.params, None, object_name=listener)
            listener_object["nlbDevIp"] = dict(name=frontend_ip, dn="uni/tn-{0}/clb-{1}/vip-{2}".format(tenant, device, frontend_ip))

        if ssl_certificates:
            listener_object["certificates"] = [
                {
                    "name": ssl_certificate.get("name"),
                    "tDn": "uni/tn-{0}/certstore".format(tenant),
                    "default": True,
                    "store": ssl_certificate.get("certificate_store"),
                }
                for ssl_certificate in ssl_certificates
            ]

        # Rules object creation logic
        rules_data = []

        for position, rule in enumerate(rules, 0):
            if (listener_protocol == "http" and rule.get("protocol") == "http") or (listener_protocol == "https" and rule.get("protocol") == "https"):
                mso.fail_json(msg="When the 'listener_protocol' is '{0}', the rule 'protocol' must be '{1}'".format(listener_protocol, rule.get("protocol")))

            if rule.get("action_type") == "redirect":
                mso.input_validation(
                    "action_type", "redirect", ["redirect_protocol", "redirect_port", "url_type", "redirect_code"], rule, position, rule.get("name")
                )
            elif rule.get("action_type") == "forward":
                mso.input_validation("action_type", "forward", ["protocol", "port", "health_check"], rule, position, rule.get("name"))

            if rule.get("url_type") == "custom":
                mso.input_validation(
                    "url_type", "custom", ["redirect_host_name", "redirect_path", "redirect_query", "response_code"], rule, position, rule.get("name")
                )

            rule_data = dict(
                name=rule.get("name"),
                floatingIp=rule.get("floating_ip"),
                index=rule.get("priority"),
                host=rule.get("host"),
                path=rule.get("path"),
                action=rule.get("action"),
                actionType=LISTENER_ACTION_TYPE_MAP.get(rule.get("action_type")),
                contentType=LISTENER_CONTENT_TYPE_MAP.get(rule.get("content_type")),
                port=rule.get("port"),
                protocol=rule.get("protocol"),
                urlType=rule.get("url_type"),
                customURL=rule.get("custom_url"),
                redirectHostName=rule.get("redirect_host_name"),
                redirectPath=rule.get("redirect_path"),
                redirectQuery=rule.get("redirect_query"),
                responseCode=rule.get("response_code"),
                responseBody=rule.get("response_body"),
                redirectProtocol=rule.get("redirect_protocol"),
                redirectPort=rule.get("redirect_port"),
                redirectCode=LISTENER_REDIRECT_CODE_MAP.get(rule.get("redirect_code")),
                targetIpType=rule.get("target_ip_type"),
            )

            if listener_protocol in ["tcp", "udp"]:
                mso.input_validation("listener_protocol", "tcp/udp", ["health_check"], rule)

            provider_epg = rule.get("provider_epg")
            if provider_epg:
                rule_data["providerEpgRef"] = "/schemas/{0}/templates/{1}/anps/{2}/epgs/{3}".format(
                    provider_epg.get("schema") or schema_id,
                    provider_epg.get("template_name") or template,
                    provider_epg.get("anp_name"),
                    provider_epg.get("epg_name"),
                )

            health_check = rule.get("health_check")
            if health_check:
                if listener_protocol in ["tcp", "udp"]:
                    if health_check.get("protocol") == "tcp":
                        mso.input_validation("health_check - 'protocol'", "tcp", ["port", "unhealthy_threshold", "interval"], health_check)
                    elif health_check.get("protocol") in ["http", "https"]:
                        mso.input_validation("health_check - 'protocol'", "http/https", ["port", "path", "unhealthy_threshold", "interval"], health_check)
                elif (listener_protocol == "http" and health_check.get("protocol") == "https") or (
                    listener_protocol == "https" and health_check.get("protocol") == "http"
                ):
                    mso.input_validation(
                        "health_check - 'protocol'", "http/https", ["port", "path", "unhealthy_threshold", "timeout", "interval"], health_check
                    )
                else:
                    mso.fail_json(
                        msg=(
                            "The 'listener_protocol': {0} and the health_check protocol: {1} "
                            + "is not a valid configuration at the object position: {2} and the object name: {3}"
                        ).format(listener_protocol, health_check.get("protocol"), position, rule.get("name"))
                    )

                health_check_data = dict(
                    port=health_check.get("port"),
                    protocol=health_check.get("protocol"),
                    path=health_check.get("path"),
                    interval=health_check.get("interval"),
                    timeout=health_check.get("timeout"),
                    unhealthyThreshold=health_check.get("unhealthy_threshold"),
                    successCode=health_check.get("success_code"),
                    useHostFromRule=YES_OR_NO_TO_BOOL_STRING_MAP.get(health_check.get("use_host_from_rule")),
                    host=health_check.get("host"),
                )

                rule_data["healthCheck"] = health_check_data

            rules_data.append(rule_data)

        listener_object["rules"] = rules_data

        if parent_present:
            # Update an existing listener
            if mso.existing:
                listener_path = (
                    "/sites/{0}-{1}/contracts/{2}/serviceGraphRelationship/serviceNodesRelationship/{3}/deviceConfiguration/cloudLoadBalancer/listeners/{4}"
                ).format(site_id, template, contract, service_node_index, listener)
                op = "replace"
            else:
                # Create a new listener
                listener_path = (
                    "/sites/{0}-{1}/contracts/{2}/serviceGraphRelationship/serviceNodesRelationship/{3}/deviceConfiguration/cloudLoadBalancer/listeners/-"
                ).format(site_id, template, contract, service_node_index)
                op = "add"
            parent_object = listener_object
        else:
            # Create a new listener with parent object
            listener_path = "/sites/{0}-{1}/contracts/{2}/serviceGraphRelationship/serviceNodesRelationship/{3}".format(
                site_id, template, contract, service_node_index
            )
            op = "replace"
            parent_object["deviceConfiguration"]["cloudLoadBalancer"]["listeners"].append(listener_object)

        mso.sanitize(parent_object, collate=True)
        ops.append(dict(op=op, path=listener_path, value=mso.sent))

    elif state == "absent":
        if mso.existing:
            listener_path = (
                "/sites/{0}-{1}/contracts/{2}/serviceGraphRelationship/serviceNodesRelationship/{3}/deviceConfiguration/cloudLoadBalancer/listeners/{4}"
            ).format(site_id, template, contract, service_node_index, listener)
            ops.append(dict(op="remove", path=listener_path))

    mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(mso_schema.path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
