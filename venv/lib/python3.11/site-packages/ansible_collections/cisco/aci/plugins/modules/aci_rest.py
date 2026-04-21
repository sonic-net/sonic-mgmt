#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2020, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# Copyright: (c) 2023, Samita Bhattacharjee (@samitab) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_rest
short_description: Direct access to the Cisco APIC REST API
description:
- Enables the management of the Cisco ACI fabric through direct access to the Cisco APIC REST API.
- Thanks to the idempotent nature of the APIC, this module is idempotent and reports changes.
requirements:
- lxml (when using XML payload)
- xmljson >= 0.1.8 (when using XML payload)
- python 2.7+ (when using xmljson)
options:
  method:
    description:
    - The HTTP method of the request.
    - Using C(delete) is typically used for deleting objects.
    - Using C(get) is typically used for querying objects.
    - Using C(post) is typically used for modifying objects.
    type: str
    choices: [ delete, get, post ]
    default: get
    aliases: [ action ]
  path:
    description:
    - URI being used to execute API calls.
    - Must end in C(.xml) or C(.json).
    type: str
    required: true
    aliases: [ uri ]
  content:
    description:
    - When used instead of C(src), sets the payload of the API request directly.
    - This may be convenient to template simple requests.
    - For anything complex use the C(template) lookup plugin (see examples)
      or the C(template) module with parameter C(src).
    type: raw
  src:
    description:
    - Name of the absolute path of the filename that includes the body
      of the HTTP request being sent to the ACI fabric.
    - If you require a templated payload, use the C(content) parameter
      together with the C(template) lookup plugin, or use C(template).
    type: path
    aliases: [ config_file ]
  rsp_subtree_preserve:
    description:
    - Preserve the response for the provided path.
    type: bool
    default: false
  page_size:
    description:
    - The number of items to return in a single page.
    type: int
  page:
    description:
    - The page number to return.
    type: int
  normalize_payload_values:
    description:
    - If this parameter is not specified in the task, the value of environment variable ACI_NORMALIZE_PAYLOAD_VALUES will be used instead.
    - This parameter enforces the conversion of integer and float values to strings in Ansible Core v2.19.0 and later, as well as Jinja2 v3.1.6 and later.
    - To disable this conversion, set O(normalize_payload_values=false) or unset the ACI_NORMALIZE_PAYLOAD_VALUES environment variable.
    type: bool
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

notes:
- Certain payloads are known not to be idempotent, so be careful when constructing payloads,
  e.g. using C(status="created") will cause idempotency issues, use C(status="modified") instead.
  More information in :ref:`the ACI documentation <aci_guide_known_issues>`.
- Certain payloads (and used paths) are known to report no changes happened when changes did happen.
  This is a known APIC problem and has been reported to the vendor. A workaround for this issue exists.
  More information in :ref:`the ACI documentation <aci_guide_known_issues>`.
- XML payloads require the C(lxml) and C(xmljson) python libraries. For JSON payloads nothing special is needed.
- If you do not have any attributes, it may be necessary to add the "attributes" key with an empty dictionnary "{}" for value
  as the APIC does expect the entry to precede any children.
- Annotation set directly in c(src) or C(content) will take precedent over the C(annotation) parameter.
seealso:
- module: cisco.aci.aci_tenant
- name: Cisco APIC REST API Configuration Guide
  description: More information about the APIC REST API.
  link: http://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/2-x/rest_cfg/2_1_x/b_Cisco_APIC_REST_API_Configuration_Guide.html
author:
- Dag Wieers (@dagwieers)
- Cindy Zhao (@cizhao)
- Samita Bhattacharjee (@samitab)
"""

EXAMPLES = r"""
- name: Add a tenant using certificate authentication
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    method: post
    path: /api/mo/uni.xml
    src: /home/cisco/ansible/aci/configs/aci_config.xml
  delegate_to: localhost

- name: Add a tenant from a templated payload file from templates/
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    method: post
    path: /api/mo/uni.xml
    content: "{{ lookup('template', 'aci/tenant.xml.j2') }}"
  delegate_to: localhost

- name: Add a tenant using inline YAML
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    validate_certs: false
    path: /api/mo/uni.json
    method: post
    content:
      fvTenant:
        attributes:
          name: Sales
          descr: Sales department
  delegate_to: localhost

- name: Add a tenant using a JSON string
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    validate_certs: false
    path: /api/mo/uni.json
    method: post
    content:
      {
        "fvTenant": {
          "attributes": {
            "name": "Sales",
            "descr": "Sales department"
          }
        }
      }
  delegate_to: localhost

- name: Add a tenant using an XML string
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/{{ aci_username }}.key
    validate_certs: false
    path: /api/mo/uni.xml
    method: post
    content: '<fvTenant name="Sales" descr="Sales departement"/>'
  delegate_to: localhost

- name: Get tenants using password authentication
  cisco.aci.aci_rest:
    host: apic
    username: admin
    password: SomeSecretPassword
    method: get
    path: /api/node/class/fvTenant.json
  delegate_to: localhost
  register: query_result

- name: Get first 5 tenants using password authentication and pagination
  cisco.aci.aci_rest:
    host: apic
    username: admin
    password: SomeSecretPassword
    method: get
    page_size: 5
    path: /api/node/class/fvTenant.json
  delegate_to: localhost
  register: query_result

- name: Configure contracts
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    method: post
    path: /api/mo/uni.xml
    src: /home/cisco/ansible/aci/configs/contract_config.xml
  delegate_to: localhost

- name: Register leaves and spines
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    validate_certs: false
    method: post
    path: /api/mo/uni/controller/nodeidentpol.xml
    content:
      <fabricNodeIdentPol>
        <fabricNodeIdentP name="{{ item.name }}" nodeId="{{ item.nodeid }}" status="{{ item.status }}" serial="{{ item.serial }}"/>
      </fabricNodeIdentPol>
  with_items:
    - '{{ apic_leavesspines }}'
  delegate_to: localhost

- name: Wait for all controllers to become ready
  cisco.aci.aci_rest:
    host: apic
    username: admin
    private_key: pki/admin.key
    validate_certs: false
    path: /api/node/class/topSystem.json?query-target-filter=eq(topSystem.role,"controller")
  register: apics
  until: "'totalCount' in apics and apics.totalCount|int >= groups['apic']|count"
  retries: 120
  delay: 30
  delegate_to: localhost
  run_once: true
"""

RETURN = r"""
error_code:
  description: The REST ACI return code, useful for troubleshooting on failure
  returned: always
  type: int
  sample: 122
error_text:
  description: The REST ACI descriptive text, useful for troubleshooting on failure
  returned: always
  type: str
  sample: unknown managed object class foo
imdata:
  description: Converted output returned by the APIC REST (register this for post-processing)
  returned: always
  type: str
  sample: [{"error": {"attributes": {"code": "122", "text": "unknown managed object class foo"}}}]
payload:
  description: The (templated) payload send to the APIC REST API (xml or json)
  returned: always
  type: str
  sample: '<foo bar="boo"/>'
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
response:
  description: HTTP response string
  returned: always
  type: str
  sample: 'HTTP Error 400: Bad Request'
status:
  description: HTTP status code
  returned: always
  type: int
  sample: 400
totalCount:
  description: Number of items in the imdata array
  returned: always
  type: str
  sample: '0'
url:
  description: URL used for APIC REST call
  returned: success
  type: str
  sample: https://1.2.3.4/api/mo/uni/tn-[Dag].json?rsp-subtree=modified
"""

import json
import os
import re

try:
    from ansible.module_utils.six.moves.urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    HAS_URLPARSE = True
except Exception:
    HAS_URLPARSE = False

# Optional, only used for XML payload
try:
    from lxml import etree  # noqa

    HAS_LXML_ETREE = True
except ImportError:
    HAS_LXML_ETREE = False

# Optional, only used for XML payload
try:
    from xmljson import cobra  # noqa

    HAS_XMLJSON_COBRA = True
except ImportError:
    HAS_XMLJSON_COBRA = False

# Optional, only used for YAML validation
try:
    import yaml

    HAS_YAML = True
except Exception:
    HAS_YAML = False

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible_collections.cisco.aci.plugins.module_utils.aci import (
    ACIModule,
    aci_argument_spec,
    aci_annotation_spec,
    convert_numbers_and_none_values_to_string,
)
from ansible.module_utils._text import to_text
from ansible_collections.cisco.aci.plugins.module_utils.annotation_unsupported import (
    ANNOTATION_UNSUPPORTED,
)


def update_qsl(url, params):
    """Add or update a URL query string"""

    if HAS_URLPARSE:
        url_parts = list(urlparse(url))
        query = dict(parse_qsl(url_parts[4]))
        query.update(params)
        url_parts[4] = urlencode(query)
        return urlunparse(url_parts)
    elif "?" in url:
        return url + "&" + "&".join(["%s=%s" % (k, v) for k, v in params.items()])
    else:
        return url + "?" + "&".join(["%s=%s" % (k, v) for k, v in params.items()])


def add_annotation(annotation, payload):
    """Add annotation to payload only if it has not already been added"""
    if annotation and isinstance(payload, dict):
        for key, val in payload.items():
            if key in ANNOTATION_UNSUPPORTED:
                continue
            if isinstance(val, dict):
                att = val.get("attributes", {})
                if "annotation" not in att.keys():
                    att["annotation"] = annotation
                # Recursively add annotation to children
                children = val.get("children", None)
                if children:
                    for child in children:
                        add_annotation(annotation, child)


def add_annotation_xml(annotation, tree):
    """Add annotation to payload xml only if it has not already been added"""
    if annotation:
        for element in tree.iter():
            if element.tag in ANNOTATION_UNSUPPORTED:
                continue
            ann = element.get("annotation")
            if ann is None:
                element.set("annotation", annotation)


class ACIRESTModule(ACIModule):
    def changed(self, d):
        """Check ACI response for changes"""

        if isinstance(d, dict):
            for k, v in d.items():
                if k == "status" and v in ("created", "modified", "deleted"):
                    return True
                elif self.changed(v) is True:
                    return True
        elif isinstance(d, list):
            for i in d:
                if self.changed(i) is True:
                    return True

        return False

    def response_type(self, rawoutput, rest_type="xml"):
        """Handle APIC response output"""

        if rest_type == "json":
            self.response_json(rawoutput)
        else:
            self.response_xml(rawoutput)

        # Use APICs built-in idempotency
        if HAS_URLPARSE:
            self.result["changed"] = self.changed(self.imdata)


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        path=dict(type="str", required=True, aliases=["uri"]),
        method=dict(type="str", default="get", choices=["delete", "get", "post"], aliases=["action"]),
        src=dict(type="path", aliases=["config_file"]),
        content=dict(type="raw"),
        rsp_subtree_preserve=dict(type="bool", default=False),
        page_size=dict(type="int"),
        page=dict(type="int"),
        # To support Ansible Core 2.19.0 and later, Jinja2 3.1.6 and later versions.
        normalize_payload_values=dict(
            type="bool",
            fallback=(env_fallback, ["ACI_NORMALIZE_PAYLOAD_VALUES"]),
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["content", "src"]],
    )

    content = module.params.get("content")
    path = module.params.get("path")
    src = module.params.get("src")
    rsp_subtree_preserve = module.params.get("rsp_subtree_preserve")
    annotation = module.params.get("annotation")
    page_size = module.params.get("page_size")
    page = module.params.get("page")
    normalize_payload_values = module.params.get("normalize_payload_values")
    if module.params.get("method") != "get" and page_size:
        module.fail_json(msg="Pagination parameters (page and page_size) are only valid for GET method")

    # Report missing file
    file_exists = False
    if src:
        if os.path.isfile(src):
            file_exists = True
        else:
            module.fail_json(msg="Cannot find/access src '{0}'".format(src))

    # Find request type
    if path.find(".xml") != -1:
        rest_type = "xml"
        if not HAS_LXML_ETREE:
            module.fail_json(msg="The lxml python library is missing, or lacks etree support.")
        if not HAS_XMLJSON_COBRA:
            module.fail_json(msg="The xmljson python library is missing, or lacks cobra support.")
    elif path.find(".json") != -1:
        rest_type = "json"
    else:
        module.fail_json(msg="Failed to find REST API payload type (neither .xml nor .json).")

    aci = ACIRESTModule(module)
    aci.result["status"] = -1  # Ensure we always return a status

    # We include the payload as it may be templated
    payload = content
    if file_exists:
        with open(src, "r") as config_object:
            # TODO: Would be nice to template this, requires action-plugin
            payload = config_object.read()

    # Validate payload
    if rest_type == "json" and payload:
        if isinstance(payload, str) and HAS_YAML:
            try:
                payload = yaml.safe_load(payload)
            except Exception as e:
                module.fail_json(msg="Failed to parse provided JSON/YAML payload: {0}".format(to_text(e)), exception=to_text(e), payload=payload)
        add_annotation(annotation, payload)
        payload = json.dumps(convert_numbers_and_none_values_to_string(payload) if normalize_payload_values else payload)

    elif rest_type == "xml" and HAS_LXML_ETREE:
        if payload and isinstance(payload, dict) and HAS_XMLJSON_COBRA:
            # Validate inline YAML/JSON
            add_annotation(annotation, payload)
            payload = etree.tostring(cobra.etree(payload)[0], encoding="unicode")
        elif payload and isinstance(payload, str):
            try:
                # Validate XML string
                payload = etree.fromstring(payload)
                add_annotation_xml(annotation, payload)
                payload = etree.tostring(payload, encoding="unicode")
            except Exception as e:
                module.fail_json(msg="Failed to parse provided XML payload: {0}".format(to_text(e)), payload=payload)

    # Perform actual request using auth cookie (Same as aci.request(), but also supports XML)
    # NOTE By setting aci.path we ensure that Ansible displays accurate URL info when the plugin and the aci_rest module are used.
    aci.path = path.lstrip("/")
    aci.url = "{0}/{1}".format(aci.base_url, aci.path)

    if aci.params.get("method") == "get" and page_size:
        aci.path = update_qsl(aci.path, {"page": page, "page-size": page_size})
        aci.url = update_qsl(aci.url, {"page": page, "page-size": page_size})
    if aci.params.get("method") != "get" and not rsp_subtree_preserve:
        aci.path = "{0}?rsp-subtree=modified".format(aci.path)
        aci.url = update_qsl(aci.url, {"rsp-subtree": "modified"})

    method = aci.params.get("method").upper()
    # Perform request
    if not aci.module.check_mode:
        resp, info = aci.api_call(method, aci.url, data=payload, return_response=True)
        # Report failure
        if info.get("status") != 200:
            try:
                # APIC error
                aci.response_type(info["body"], rest_type)
                aci.fail_json(msg="APIC Error {code}: {text}".format_map(aci.error))
            except KeyError:
                # Connection error
                aci.fail_json(msg="Connection failed for {url}. {msg}".format_map(info))

        try:
            aci.response_type(resp.read(), rest_type)
        except AttributeError:
            aci.response_type(info.get("body"), rest_type)

        aci.result["status"] = aci.status
        aci.result["imdata"] = aci.imdata
        aci.result["totalCount"] = aci.totalCount

    else:
        # NOTE A case when aci_rest is used with check mode and the apic host is used directly from the inventory
        if aci.connection is not None and aci.params.get("host") is None:
            aci.url = urlunparse(urlparse(aci.url)._replace(netloc=re.sub(r"[[\]]", "", aci.connection.get_option("host")).split(",")[0]))
        aci.method = method
        # Set changed to true so check_mode changed result is behaving similar to non aci_rest modules
        aci.result["changed"] = True

    # Only set proposed if we have a payload and thus also only allow output_path if we have a payload
    # DELETE and GET do not have a payload
    if payload and method == "POST":
        if rest_type == "json":
            payload = json.loads(payload)

        aci.result["proposed"] = payload

        output_path = aci.params.get("output_path")
        if output_path is not None:
            with open(output_path, "a") as output_file:
                if rest_type == "json":
                    json.dump([payload], output_file)
                else:
                    output_file.write(str(payload))

    # Report success
    aci.exit_json(**aci.result)


if __name__ == "__main__":
    main()
