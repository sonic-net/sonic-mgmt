#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_template
short_description: Manage Templates on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Templates on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the template.
    type: str
    aliases: [ name ]
  template_id:
    description:
    - The id of the template.
    - This parameter is required when the O(template) needs to be updated.
    type: str
    aliases: [ id ]
  template_type:
    description:
    - The type of the template.
    - The O(template_type=application) is only intended for retrieving the Application template using O(template_id) and does not support template creation.
    type: str
    aliases: [ type ]
    choices:
      - application
      - tenant
      - l3out
      - fabric_policy
      - fabric_resource
      - monitoring_tenant
      - monitoring_access
      - service_device
  tenant:
    description:
    - The name of the tenant attached to the template.
    - Required when O(type=tenant), O(type=l3out), O(type=monitoring_tenant) or O(type=service_device).
    type: str
  sites:
    description:
    - The list of sites attached to the template.
    - Required when O(type=l3out), O(type=monitoring_tenant) or O(type=monitoring_access).
    - Set to an empty list O(sites=[]) to remove all sites attached from the template.
    - Set to null O(sites=null) or do not provide O(sites) to avoid making changes to sites attached to the template.
    aliases: [ site ]
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the site attached to the template.
        type: str
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new tenant policy template
  cisco.mso.ndo_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy
    template_type: tenant
    tenant: ansible_test_tenant
    sites:
      - name: ansible_test_site
    state: present

- name: Create a new l3out policy template
  cisco.mso.ndo_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_l3out_policy_template
    template_type: l3out
    tenant: ansible_test_tenant
    sites:
      - name: ansible_test_site
    state: present

- name: Query a tenant policy template
  cisco.mso.ndo_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy
    template_type: tenant
    state: query
  register: query_new_tenant_policy_template

- name: Query all tenant policy templates
  cisco.mso.ndo_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_type: tenant
    state: query
  register: query_all

- name: Query all templates
  cisco.mso.ndo_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
  register: query_all

- name: Delete a tenant policy template
  cisco.mso.ndo_template:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_policy
    template_type: tenant
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate
from ansible_collections.cisco.mso.plugins.module_utils.constants import TEMPLATE_TYPES


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", aliases=["name"]),
        template_id=dict(type="str", aliases=["id"]),
        template_type=dict(type="str", aliases=["type"], choices=list(TEMPLATE_TYPES)),
        tenant=dict(type="str"),
        sites=dict(type="list", elements="dict", aliases=["site"], options=dict(name=dict(type="str"))),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["template", "template_type"]],
            ["state", "present", ["template", "template_type"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    template_id = module.params.get("template_id")
    template_type = module.params.get("template_type")
    tenant_id = mso.lookup_tenant(module.params.get("tenant"))
    site_ids = [mso.lookup_site(site.get("name")) for site in module.params.get("sites", [])] if module.params.get("sites") else []
    state = module.params.get("state")

    if state != "query" and template_type == "application":
        mso.fail_json(msg="The template_type: application is only intended for retrieving the Application template.")

    mso_template = MSOTemplate(mso, template_type, template, template_id)

    mso.existing = mso.previous = copy.deepcopy(mso_template.template)

    if state == "present":
        if tenant_id and not TEMPLATE_TYPES[template_type]["tenant"]:
            mso.fail_json(msg="Tenant cannot be attached to template of type {0}.".format(template_type))

        if not tenant_id and TEMPLATE_TYPES[template_type]["tenant"]:
            mso.fail_json(msg="Tenant must be provided for template of type {0}.".format(template_type))

        if not site_ids and TEMPLATE_TYPES[template_type]["site_amount"] == 1:
            mso.fail_json(msg="Site must be provided for template of type {0}.".format(template_type))

        if len(site_ids) > 1 and TEMPLATE_TYPES[template_type]["site_amount"] == 1:
            mso.fail_json(msg="Only one site can be attached to template of type {0}.".format(template_type))

        if mso_template.template:
            if mso_template.template.get("templateType") != TEMPLATE_TYPES[template_type]["template_type"]:
                mso.fail_json(msg="Template type cannot be changed.")

            if TEMPLATE_TYPES[template_type]["tenant"] and changed(
                mso_template.template, template_type, tenant_id, "tenantId" if TEMPLATE_TYPES[template_type] != "monitoring_acces" else "tenant"
            ):
                mso.fail_json(msg="Tenant cannot be changed.")

            if TEMPLATE_TYPES[template_type]["site_amount"] == 1 and changed(mso_template.template, template_type, site_ids[0], "siteId"):
                mso.fail_json(msg="Site cannot be changed.")

            ops = []
            if mso_template.template.get("displayName") != template:
                ops.append(dict(op="replace", path="/displayName", value=template))
                # Changing in existing object to set correctly in proposed/current output
                mso_template.template["displayName"] = template

            # When more then 1 site can be provided the sites can be added and/or removed with PATCH operations
            # This is done to avoid config loss within sites during a single replace operation on the sites container
            if TEMPLATE_TYPES[template_type]["site_amount"] > 1 and module.params.get("sites") is not None:
                append_site_config_to_ops(ops, TEMPLATE_TYPES[template_type]["template_type_container"], mso_template.template, site_ids)

            mso.sanitize(mso_template.template)

            if not module.check_mode and ops:
                mso.existing = mso.request(mso_template.template_path, method="PATCH", data=ops)

        else:
            payload = {
                "displayName": template,
                "templateType": TEMPLATE_TYPES[template_type]["template_type"],
                TEMPLATE_TYPES[template_type]["template_type_container"]: {},
            }

            # Set template specific payload in functions to increase readability due to the amount of different templates with small differences
            if template_type == "tenant":
                set_tenant_template_payload(payload, template_type, tenant_id, site_ids)
            elif template_type == "l3out":
                set_l3out_template_payload(payload, template_type, tenant_id, site_ids[0])
            elif template_type == "fabric_policy":
                set_fabric_policy_template_payload(payload, template_type, site_ids)
            elif template_type == "fabric_resource":
                set_fabric_resource_template_payload(payload, template_type, site_ids)
            elif template_type == "monitoring_tenant":
                set_monitoring_tenant_template_payload(payload, template_type, tenant_id, site_ids)
            elif template_type == "monitoring_access":
                set_monitoring_acces_template_payload(payload, template_type, site_ids)
            elif template_type == "service_device":
                set_service_device_template_payload(payload, template_type, tenant_id, site_ids)

            if not module.check_mode:
                mso.existing = mso.request(mso_template.templates_path, method="POST", data=payload)
                payload["templateId"] = mso.existing.get("templateId")

            mso.sanitize(payload)

        if module.check_mode:
            mso.existing = mso.proposed

    elif state == "absent":
        if mso.previous and not module.check_mode:
            mso.request(mso_template.template_path, method="DELETE")
        mso.existing = {}

    mso.exit_json()


def set_tenant_template_payload(payload, template_type, tenant_id, site_ids):
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"template": {"tenantId": tenant_id}})
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"sites": [{"siteId": site_id} for site_id in site_ids]})


def set_l3out_template_payload(payload, template_type, tenant_id, site_id):
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"tenantId": tenant_id})
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"siteId": site_id})


def set_fabric_policy_template_payload(payload, template_type, site_ids):
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"sites": [{"siteId": site_id} for site_id in site_ids]})


def set_fabric_resource_template_payload(payload, template_type, site_ids):
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"sites": [{"siteId": site_id} for site_id in site_ids]})


def set_monitoring_tenant_template_payload(payload, template_type, tenant_id, site_ids):
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"template": {"mtType": "tenant", "tenant": tenant_id}})
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"sites": [{"siteId": site_id} for site_id in site_ids]})


def set_monitoring_acces_template_payload(payload, template_type, site_ids):
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"template": {"mtType": "access"}})
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"sites": [{"siteId": site_id} for site_id in site_ids]})


def set_service_device_template_payload(payload, template_type, tenant_id, site_ids):
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"template": {"tenantId": tenant_id}})
    payload[TEMPLATE_TYPES[template_type]["template_type_container"]].update({"sites": [{"siteId": site_id} for site_id in site_ids]})


def changed(config, template_type, value, key):
    if TEMPLATE_TYPES[template_type]["template_container"]:
        config_value = config.get(TEMPLATE_TYPES[template_type]["template_type_container"], {}).get("template", {}).get(key)
    else:
        config_value = config.get(TEMPLATE_TYPES[template_type]["template_type_container"], {}).get(key)
    return config_value != value


def append_site_config_to_ops(ops, template_type_container, config, site_ids):
    template_container = config.get(template_type_container, {})

    existing_site_ids = [site.get("siteId") for site in template_container.get("sites", [])]

    index_list = [index for index, site_id in enumerate(existing_site_ids) if site_id not in site_ids]

    if index_list:
        # Sort in reverse to remove from the end of the list first, this way the indexes are not shifting during removal operations
        index_list.sort(reverse=True)
        for index in index_list:
            ops.append(dict(op="remove", path="/{0}/sites/{1}".format(template_type_container, index)))
            # Changing in existing object to set correctly in proposed/current output
            template_container["sites"].pop(index)

    for site_id in [site_id for site_id in site_ids if site_id not in existing_site_ids]:
        payload = {"siteId": site_id}
        ops.append(dict(op="add", path="/{0}/sites/-".format(template_type_container), value=payload))
        # Changing in existing object to set correctly in proposed/current output
        if template_container.get("sites") is None:
            template_container["sites"] = []
        template_container["sites"].append(payload)


if __name__ == "__main__":
    main()
