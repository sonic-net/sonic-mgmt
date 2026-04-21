# -*- coding: utf-8 -*-

# This code is part of Ansible, but is an independent component

# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.

# Copyright: (c) 2017, Dag Wieers <dag@wieers.com>
# Copyright: (c) 2017, Jacob McGill (@jmcgill298)
# Copyright: (c) 2017, Swetha Chunduri (@schunduri)
# Copyright: (c) 2019, Rob Huelga (@RobW3LGA)
# Copyright: (c) 2020, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# Copyright: (c) 2020, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# Copyright: (c) 2023, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# Copyright: (c) 2024, Samita Bhattacharjee (@samiib) <samitab@cisco.com>
# All rights reserved.

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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import json
import os
from copy import deepcopy

from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_bytes, to_native
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.connection import Connection

# Optional, only used for APIC signature-based authentication
try:
    from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign

    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False

# Signature-based authentication using cryptography
try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# Optional, only used for XML payload
try:
    import lxml.etree

    HAS_LXML_ETREE = True
except ImportError:
    HAS_LXML_ETREE = False

# Optional, only used for XML payload
try:
    from xmljson import cobra

    HAS_XMLJSON_COBRA = True
except ImportError:
    HAS_XMLJSON_COBRA = False

try:
    from ansible.module_utils.six.moves.urllib.parse import urlparse

    HAS_URLPARSE = True
except Exception:
    HAS_URLPARSE = False


def aci_argument_spec():
    return dict(
        host=dict(
            type="str",
            aliases=["hostname"],
            fallback=(env_fallback, ["ACI_HOST"]),
        ),
        port=dict(type="int", required=False, fallback=(env_fallback, ["ACI_PORT"])),
        username=dict(
            type="str",
            aliases=["user"],
            fallback=(env_fallback, ["ACI_USERNAME", "ANSIBLE_NET_USERNAME"]),
        ),
        password=dict(
            type="str",
            no_log=True,
            fallback=(env_fallback, ["ACI_PASSWORD", "ANSIBLE_NET_PASSWORD"]),
        ),
        # Beware, this is not the same as client_key !
        private_key=dict(
            type="str",
            aliases=["cert_key"],
            no_log=True,
            fallback=(env_fallback, ["ACI_PRIVATE_KEY", "ANSIBLE_NET_SSH_KEYFILE"]),
        ),
        # Beware, this is not the same as client_cert !
        certificate_name=dict(
            type="str",
            aliases=["cert_name"],
            fallback=(env_fallback, ["ACI_CERTIFICATE_NAME"]),
        ),
        output_level=dict(
            type="str",
            default="normal",
            choices=["debug", "info", "normal"],
            fallback=(env_fallback, ["ACI_OUTPUT_LEVEL"]),
        ),
        timeout=dict(type="int", fallback=(env_fallback, ["ACI_TIMEOUT"])),
        use_proxy=dict(type="bool", fallback=(env_fallback, ["ACI_USE_PROXY"])),
        use_ssl=dict(type="bool", fallback=(env_fallback, ["ACI_USE_SSL"])),
        validate_certs=dict(type="bool", fallback=(env_fallback, ["ACI_VALIDATE_CERTS"])),
        output_path=dict(type="str", fallback=(env_fallback, ["ACI_OUTPUT_PATH"])),
        suppress_verification=dict(
            type="bool",
            aliases=["no_verification", "no_verify", "suppress_verify", "ignore_verify", "ignore_verification"],
            fallback=(env_fallback, ["ACI_SUPPRESS_VERIFICATION"]),
        ),
        suppress_previous=dict(type="bool", aliases=["no_previous", "ignore_previous"], fallback=(env_fallback, ["ACI_SUPPRESS_PREVIOUS"])),
    )


def aci_annotation_spec():
    return dict(
        annotation=dict(
            type="str",
            default="orchestrator:ansible",
            fallback=(env_fallback, ["ACI_ANNOTATION"]),
        ),
    )


def aci_owner_spec():
    return dict(
        owner_key=dict(type="str", no_log=False, fallback=(env_fallback, ["ACI_OWNER_KEY"])),
        owner_tag=dict(type="str", fallback=(env_fallback, ["ACI_OWNER_TAG"])),
    )


def enhanced_lag_spec(name_is_required=True):
    return dict(
        name=dict(type="str", required=name_is_required),
        lacp_mode=dict(type="str", choices=["active", "passive"]),
        load_balancing_mode=dict(
            type="str",
            choices=[
                "dst-ip",
                "dst-ip-l4port",
                "dst-ip-vlan",
                "dst-ip-l4port-vlan",
                "dst-mac",
                "dst-l4port",
                "src-ip",
                "src-ip-l4port",
                "src-ip-vlan",
                "src-ip-l4port-vlan",
                "src-mac",
                "src-l4port",
                "src-dst-ip",
                "src-dst-ip-l4port",
                "src-dst-ip-vlan",
                "src-dst-ip-l4port-vlan",
                "src-dst-mac",
                "src-dst-l4port",
                "src-port-id",
                "vlan",
            ],
        ),
        number_uplinks=dict(type="int"),
    )


def netflow_spec():
    return dict(
        name=dict(type="str", required=True),
        active_flow_timeout=dict(type="int"),
        idle_flow_timeout=dict(type="int"),
        sampling_rate=dict(type="int"),
    )


def expression_spec():
    return dict(
        key=dict(type="str", required=True, no_log=False),
        operator=dict(
            type="str",
            choices=[
                "not_in",
                "in",
                "equals",
                "not_equals",
                "has_key",
                "does_not_have_key",
            ],
            required=True,
        ),
        value=dict(type="str"),
    )


def aci_contract_qos_spec():
    return dict(type="str", choices=["level1", "level2", "level3", "unspecified"])


def aci_contract_dscp_spec(direction=None):
    return dict(
        type="str",
        aliases=["target" if not direction else "target_{0}".format(direction)],
        choices=[
            "AF11",
            "AF12",
            "AF13",
            "AF21",
            "AF22",
            "AF23",
            "AF31",
            "AF32",
            "AF33",
            "AF41",
            "AF42",
            "AF43",
            "CS0",
            "CS1",
            "CS2",
            "CS3",
            "CS4",
            "CS5",
            "CS6",
            "CS7",
            "EF",
            "VA",
            "unspecified",
        ],
    )


def route_control_profile_spec():
    return dict(
        profile=dict(type="str", required=True),
        l3out=dict(type="str"),
        direction=dict(type="str", required=True),
        tenant=dict(type="str", required=True),
    )


def destination_epg_spec():
    return dict(
        tenant=dict(type="str", required=True, aliases=["tenant_name"]),
        ap=dict(type="str", required=True, aliases=["ap_name", "app_profile", "app_profile_name"]),
        epg=dict(type="str", required=True, aliases=["epg_name"]),
        source_ip=dict(type="str", required=True),
        destination_ip=dict(type="str", required=True),
        span_version=dict(type="str", choices=["version_1", "version_2"]),
        version_enforced=dict(type="bool"),
        flow_id=dict(type="int"),
        ttl=dict(type="int"),
        mtu=dict(type="int"),
        dscp=dict(
            type="str",
            choices=[
                "CS0",
                "CS1",
                "CS2",
                "CS3",
                "CS4",
                "CS5",
                "CS6",
                "CS7",
                "EF",
                "VA",
                "AF11",
                "AF12",
                "AF13",
                "AF21",
                "AF22",
                "AF23",
                "AF31",
                "AF32",
                "AF33",
                "AF41",
                "AF42",
                "AF43",
                "unspecified",
            ],
        ),
    )


def ospf_spec():
    return dict(
        area_cost=dict(type="int"),
        area_ctrl=dict(type="list", elements="str", choices=["redistribute", "summary", "suppress-fa", "unspecified"]),
        area_id=dict(type="str"),
        area_type=dict(type="str", choices=["nssa", "regular", "stub"]),
        description=dict(type="str", aliases=["descr"]),
        multipod_internal=dict(type="str", choices=["no", "yes"]),
        name_alias=dict(type="str"),
    )


def integrate_url(httpapi_url, local_path):
    parse_url = urlparse(httpapi_url)
    return {"protocol": parse_url.scheme, "host": parse_url.netloc, "path": local_path}


def action_rule_set_comm_spec():
    return dict(
        community=dict(type="str"),
        criteria=dict(type="str", choices=["append", "none", "replace"]),
    )


def action_rule_set_dampening_spec():
    return dict(
        half_life=dict(type="int"),
        max_suppress_time=dict(type="int"),
        reuse=dict(type="int"),
        suppress=dict(type="int"),
    )


def associated_netflow_exporter_epg_spec():
    return dict(
        tenant=dict(type="str"),
        ap=dict(type="str"),
        epg=dict(type="str"),
    )


def associated_netflow_exporter_extepg_spec():
    return dict(
        tenant=dict(type="str"),
        l3out=dict(type="str"),
        extepg=dict(type="str"),
    )


def associated_netflow_exporter_vrf_spec():
    return dict(
        tenant=dict(type="str"),
        vrf=dict(type="str"),
    )


def pim_interface_profile_spec():
    return dict(
        tenant=dict(type="str", aliases=["tenant_name"]),
        pim=dict(type="str", aliases=["pim_interface_policy", "name"]),
    )


def igmp_interface_profile_spec():
    return dict(tenant=dict(type="str", aliases=["tenant_name"]), igmp=dict(type="str", aliases=["igmp_interface_policy", "name"]))


def storm_control_policy_rate_spec():
    return dict(
        rate=dict(type="str"),
        burst_rate=dict(type="str"),
        rate_type=dict(type="str", choices=["percentage", "pps"], required=True),
    )


def switch_config_spec(policy_type):
    return dict(
        node_type=dict(type="str", aliases=["type", "switch_type"], choices=["leaf", "spine"]),
        node=dict(type="int", aliases=["node_id"]),
        policy_group=dict(
            type="str",
            aliases=[
                "{0}_policy".format(policy_type),
                "{0}_policy_group".format(policy_type),
            ],
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )


def convert_numbers_and_none_values_to_string(data):
    """
    Recursively converts None, int, and float values within dictionaries, lists, and other iterable structures to their string representations.
    Boolean and string values are returned as-is.
    None values are converted to an empty string "".
    Integers and floats are converted using `str()`.

    :param data: The input data structure, which can be a dictionary, list, tuple, set, int, float, str, bool, or None.
    :return: A new data structure with None, int, and float values converted to strings.
    """
    if isinstance(data, (bool, str)):
        return data
    elif isinstance(data, (int, float)):
        return str(data)
    elif isinstance(data, dict):
        return {k: convert_numbers_and_none_values_to_string(v) for k, v in data.items()}
    elif hasattr(data, "__iter__"):  # Handles lists, tuples, sets, etc.
        return [convert_numbers_and_none_values_to_string(item) for item in data]
    elif data is None:
        return ""
    else:
        # For any other types not explicitly handled (e.g., custom objects), return as is
        return data


class ACIModule(object):
    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.result = dict(changed=False)
        self.headers = dict()
        self.child_classes = set()
        self.connection = None

        # error output
        self.error = dict(code=None, text=None)

        # normal output
        self.existing = None

        # info output
        self.config = dict()
        self.original = None
        self.proposed = dict()
        self.stdout = None

        # debug output
        self.filter_string = ""
        self.obj_filter = None
        self.method = None
        self.path = None
        self.parent_path = None
        self.response = None
        self.status = None
        self.url = None
        self.httpapi_logs = list()

        # aci_rest output
        self.imdata = None
        self.totalCount = None

        # get no verify flag
        self.suppress_verification = self.params.get("suppress_verification")

        # get suppress previous flag
        self.suppress_previous = self.params.get("suppress_previous")

        # Ensure protocol is set
        self.define_protocol()

        # Set Connection plugin
        self.set_connection()

        # Get the current working directory
        self.params["working_directory"] = os.getcwd()

        if self.module._debug:
            self.module.warn("Enable debug output because ANSIBLE_DEBUG was set.")
            self.params["output_level"] = "debug"

        if self.params.get("port") is not None:
            self.base_url = "{protocol}://{host}:{port}".format_map(self.params)
        else:
            self.base_url = "{protocol}://{host}".format_map(self.params)

        if self.params.get("private_key"):
            # Perform signature-based authentication, no need to log on separately
            if not HAS_CRYPTOGRAPHY and not HAS_OPENSSL:
                self.module.fail_json(msg="Cannot use signature-based authentication because cryptography (preferred) or pyopenssl are not available")
            elif self.params.get("password") is not None:
                self.module.warn("When doing ACI signatured-based authentication, providing parameter 'password' is not required")
        elif self.connection is None:
            if self.params.get("password"):
                # Perform password-based authentication, log on using password
                self.login()
            else:
                self.module.fail_json(msg="Either parameter 'password' or 'private_key' is required for authentication")

    def boolean(self, value, true="yes", false="no"):
        """Return an acceptable value back"""

        # When we expect value is of type=bool
        if value is None:
            return None
        elif value is True:
            return true
        elif value is False:
            return false

        # If all else fails, escalate back to user
        self.module.fail_json(msg="Boolean value '%s' is an invalid ACI boolean value.")

    def iso8601_format(self, dt):
        """Return an ACI-compatible ISO8601 formatted time: 2123-12-12T00:00:00.000+00:00"""
        try:
            return dt.isoformat(timespec="milliseconds")
        except Exception:
            tz = dt.strftime("%z")
            return "%s.%03d%s:%s" % (
                dt.strftime("%Y-%m-%dT%H:%M:%S"),
                dt.microsecond / 1000,
                tz[:3],
                tz[3:],
            )

    def define_protocol(self):
        """Set protocol based on use_ssl parameter"""

        # Set protocol for further use
        self.params["protocol"] = "https" if self.params.get("use_ssl") or self.params.get("use_ssl") is None else "http"

    def set_connection(self):
        if self.connection is None and self.module._socket_path:
            self.connection = Connection(self.module._socket_path)

    def login(self):
        """Log in to APIC"""

        # Perform login request
        url = "{0}/api/aaaLogin.json".format(self.base_url)
        payload = {
            "aaaUser": {
                "attributes": {
                    "name": "admin" if self.params.get("username") is None else self.params.get("username"),
                    "pwd": self.params.get("password"),
                }
            }
        }
        resp, auth = self.api_call("POST", url, data=json.dumps(payload), return_response=True)

        # Handle APIC response
        if auth.get("status") != 200:
            self.response = auth.get("msg")
            self.status = auth.get("status")
            try:
                # APIC error
                self.response_json(auth["body"])
                self.fail_json(msg="Authentication failed: {code} {text}".format_map(self.error))
            except KeyError:
                # Connection error
                self.fail_json(msg="Connection failed for {url}. {msg}".format_map(auth))

        # Retain cookie for later use
        self.headers["Cookie"] = resp.headers.get("Set-Cookie")

    def cert_auth(self, path=None, payload="", method=None):
        """Perform APIC signature-based authentication, not the expected SSL client certificate authentication."""

        if method is None:
            method = self.params.get("method").upper()

        # NOTE: ACI documentation incorrectly uses complete URL
        if path is None:
            path = self.path
        path = "/" + path.lstrip("/")

        if payload is None:
            payload = ""

        # Check if we got a private key. This allows the use of vaulting the private key.
        try:
            if HAS_CRYPTOGRAPHY:
                key = self.params.get("private_key").encode()
                sig_key = serialization.load_pem_private_key(
                    key,
                    password=None,
                    backend=default_backend(),
                )
            else:
                sig_key = load_privatekey(FILETYPE_PEM, self.params.get("private_key"))
        except Exception:
            if os.path.exists(self.params.get("private_key")):
                try:
                    permission = "r"
                    if HAS_CRYPTOGRAPHY:
                        permission = "rb"
                    with open(self.params.get("private_key"), permission) as fh:
                        private_key_content = fh.read()
                except Exception:
                    self.module.fail_json(msg="Cannot open private key file '{private_key}'.".format_map(self.params))
                try:
                    if HAS_CRYPTOGRAPHY:
                        sig_key = serialization.load_pem_private_key(
                            private_key_content,
                            password=None,
                            backend=default_backend(),
                        )
                    else:
                        sig_key = load_privatekey(FILETYPE_PEM, private_key_content)
                except Exception:
                    self.module.fail_json(msg="Cannot load private key file '{private_key}'.".format_map(self.params))
                if self.params.get("certificate_name") is None:
                    self.params["certificate_name"] = os.path.basename(os.path.splitext(self.params.get("private_key"))[0])
            else:
                self.module.fail_json(
                    msg="Provided private key {private_key} does not appear to be a private key or provided file does not exist.".format_map(self.params)
                )

        if self.params.get("certificate_name") is None:
            self.params["certificate_name"] = "admin" if self.params.get("username") is None else self.params.get("username")
        # NOTE: ACI documentation incorrectly adds a space between method and path
        sig_request = method + path + payload
        if HAS_CRYPTOGRAPHY:
            sig_signature = sig_key.sign(sig_request.encode(), padding.PKCS1v15(), hashes.SHA256())
        else:
            sig_signature = sign(sig_key, sig_request, "sha256")
        sig_dn = "uni/userext/user-{username}/usercert-{certificate_name}".format_map(self.params)
        self.headers["Cookie"] = (
            "APIC-Certificate-Algorithm=v1.0; "
            + "APIC-Certificate-DN={0}; ".format(sig_dn)
            + "APIC-Certificate-Fingerprint=fingerprint; "
            + "APIC-Request-Signature={0}".format(to_native(base64.b64encode(sig_signature)))
        )

    def response_json(self, rawoutput):
        """Handle APIC JSON response output"""
        try:
            jsondata = json.loads(rawoutput)
        except Exception as e:
            # Expose RAW output for troubleshooting
            self.error = dict(code=-1, text="Unable to parse output as JSON, see 'raw' output. {0}".format(e))
            self.result["raw"] = rawoutput
            return

        # Extract JSON API output
        if isinstance(jsondata, list):
            self.imdata = jsondata
            self.totalCount = len(jsondata)
        else:
            self.imdata = jsondata.get("imdata", {})
            total_count = jsondata.get("totalCount")
            if total_count is not None:
                self.totalCount = int(total_count)

        # Handle possible APIC error information
        self.response_error()

    def response_xml(self, rawoutput):
        """Handle APIC XML response output"""

        # NOTE: The XML-to-JSON conversion is using the "Cobra" convention
        try:
            xml = lxml.etree.fromstring(to_bytes(rawoutput))
            xmldata = cobra.data(xml)
        except Exception as e:
            # Expose RAW output for troubleshooting
            self.error = dict(code=-1, text="Unable to parse output as XML, see 'raw' output. {0}".format(e))
            self.result["raw"] = rawoutput
            return

        # Reformat as ACI does for JSON API output
        self.imdata = xmldata.get("imdata", {}).get("children")
        if self.imdata is None:
            self.imdata = dict()
        self.totalCount = int(xmldata.get("imdata", {}).get("attributes", {}).get("totalCount", -1))

        # Handle possible APIC error information
        self.response_error()

    def response_error(self):
        """Set error information when found"""

        # Handle possible APIC error information
        if self.totalCount != "0":
            try:
                self.error = self.imdata[0].get("error").get("attributes")
            except (AttributeError, IndexError, KeyError):
                pass

    # TODO: This could be designed to update existing keys
    def update_qs(self, params):
        """Append key-value pairs to self.filter_string"""
        accepted_params = dict((k, v) for (k, v) in params.items() if v is not None)
        if accepted_params:
            if self.filter_string:
                self.filter_string += "&"
            else:
                self.filter_string = "?"
            self.filter_string += "&".join(["%s=%s" % (k, v) for (k, v) in accepted_params.items()])

    # TODO: This could be designed to accept multiple obj_classes and keys
    def build_filter(self, obj_class, params):
        """Build an APIC filter based on obj_class and key-value pairs"""
        accepted_params = dict((k, v) for (k, v) in params.items() if v is not None)
        if len(accepted_params) == 1:
            return ",".join('eq({0}.{1},"{2}")'.format(obj_class, k, v) for (k, v) in accepted_params.items())
        elif len(accepted_params) > 1:
            return "and(" + ",".join(['eq({0}.{1},"{2}")'.format(obj_class, k, v) for (k, v) in accepted_params.items()]) + ")"

    def _deep_url_path_builder(self, obj):
        target_class = obj.get("target_class")
        target_filter = obj.get("target_filter")
        subtree_class = obj.get("subtree_class")
        subtree_filter = obj.get("subtree_filter")
        object_rn = obj.get("object_rn")
        mo = obj.get("module_object")
        add_subtree_filter = obj.get("add_subtree_filter")
        add_target_filter = obj.get("add_target_filter")

        if self.module.params.get("state") in ("absent", "present") and mo is not None:
            self.path = "api/mo/uni/{0}.json".format(object_rn)
            self.update_qs({"rsp-prop-include": "config-only"})

        else:
            # State is 'query'
            if object_rn is not None:
                # Query for a specific object in the module's class
                self.path = "api/mo/uni/{0}.json".format(object_rn)
            else:
                self.path = "api/class/{0}.json".format(target_class)

            if add_target_filter:
                self.update_qs({"query-target-filter": self.build_filter(target_class, target_filter)})

            if add_subtree_filter:
                self.update_qs({"rsp-subtree-filter": self.build_filter(subtree_class, subtree_filter)})

        if self.params.get("port") is not None:
            self.url = "{protocol}://{host}:{port}/{path}".format(path=self.path, **self.module.params)

        else:
            self.url = "{protocol}://{host}/{path}".format(path=self.path, **self.module.params)

        if self.child_classes:
            self.update_qs(
                {
                    "rsp-subtree": "full",
                    "rsp-subtree-class": ",".join(sorted(self.child_classes)),
                }
            )

    def _deep_url_parent_object(self, parent_objects, parent_class):
        for parent_object in parent_objects:
            if parent_object.get("aci_class") is parent_class:
                return parent_object

        return None

    def construct_deep_url(self, target_object, parent_objects=None, child_classes=None):
        """
        This method is used to retrieve the appropriate URL path and filter_string to make the request to the APIC.

        :param target_object: The target class dictionary containing parent_class, aci_class, aci_rn, target_filter, and module_object keys.
        :param parent_objects: The parent class list of dictionaries containing parent_class, aci_class, aci_rn, target_filter, and module_object keys.
        :param child_classes: The list of child classes that the module supports along with the object.
        :type target_object: dict
        :type parent_objects: list[dict]
        :type child_classes: list[string]
        :return: The path and filter_string needed to build the full URL.
        """

        self.filter_string = ""
        rn_builder = None
        subtree_classes = None
        add_subtree_filter = False
        add_target_filter = False
        has_target_query = False
        has_target_query_compare = False
        has_target_query_difference = False
        has_target_query_called = False

        if child_classes is None:
            self.child_classes = set()
        else:
            self.child_classes = set(child_classes)

        target_parent_class = target_object.get("parent_class")
        target_class = target_object.get("aci_class")
        target_rn = target_object.get("aci_rn")
        target_filter = target_object.get("target_filter")
        target_module_object = target_object.get("module_object")

        url_path_object = dict(
            target_class=target_class,
            target_filter=target_filter,
            subtree_class=target_class,
            subtree_filter=target_filter,
            module_object=target_module_object,
        )

        if target_module_object is not None:
            rn_builder = target_rn
        else:
            has_target_query = True
            has_target_query_compare = True

        if parent_objects is not None:
            current_parent_class = target_parent_class
            has_parent_query_compare = False
            has_parent_query_difference = False
            is_first_parent = True
            is_single_parent = None
            search_classes = set()

            while current_parent_class != "uni":
                parent_object = self._deep_url_parent_object(parent_objects=parent_objects, parent_class=current_parent_class)

                if parent_object is not None:
                    parent_parent_class = parent_object.get("parent_class")
                    parent_class = parent_object.get("aci_class")
                    parent_rn = parent_object.get("aci_rn")
                    parent_filter = parent_object.get("target_filter")
                    parent_module_object = parent_object.get("module_object")

                    if is_first_parent:
                        is_single_parent = True
                    else:
                        is_single_parent = False
                    is_first_parent = False

                    if parent_parent_class != "uni":
                        search_classes.add(parent_class)

                    if parent_module_object is not None:
                        if rn_builder is not None:
                            rn_builder = "{0}/{1}".format(parent_rn, rn_builder)
                        else:
                            rn_builder = parent_rn

                        url_path_object["target_class"] = parent_class
                        url_path_object["target_filter"] = parent_filter

                        has_target_query = False
                    else:
                        rn_builder = None
                        subtree_classes = search_classes

                        has_target_query = True
                        if is_single_parent:
                            has_parent_query_compare = True

                    current_parent_class = parent_parent_class
                else:
                    raise ValueError("Reference error for parent_class '{0}'. Each parent_class must reference a valid object".format(current_parent_class))

                if not has_target_query_difference and not has_target_query_called:
                    if has_target_query is not has_target_query_compare:
                        has_target_query_difference = True
                else:
                    if not has_parent_query_difference and has_target_query is not has_parent_query_compare:
                        has_parent_query_difference = True
                has_target_query_called = True

            if not has_parent_query_difference and has_parent_query_compare and target_module_object is not None:
                add_target_filter = True

            elif has_parent_query_difference and target_module_object is not None:
                add_subtree_filter = True
                self.child_classes.add(target_class)

                if has_target_query:
                    add_target_filter = True

            elif has_parent_query_difference and not has_target_query and target_module_object is None:
                self.child_classes.add(target_class)
                self.child_classes.update(subtree_classes)

            elif not has_parent_query_difference and not has_target_query and target_module_object is None:
                self.child_classes.add(target_class)

            elif not has_target_query and is_single_parent and target_module_object is None:
                self.child_classes.add(target_class)

        url_path_object["object_rn"] = rn_builder
        url_path_object["add_subtree_filter"] = add_subtree_filter
        url_path_object["add_target_filter"] = add_target_filter

        self._deep_url_path_builder(url_path_object)

    def construct_url(
        self,
        root_class,
        subclass_1=None,
        subclass_2=None,
        subclass_3=None,
        subclass_4=None,
        subclass_5=None,
        subclass_6=None,
        child_classes=None,
        config_only=True,
        rsp_subtree="full",
    ):
        """
        This method is used to retrieve the appropriate URL path and filter_string to make the request to the APIC.

        :param root_class: The top-level class dictionary containing aci_class, aci_rn, target_filter, and module_object keys.
        :param sublass_1: The second-level class dictionary containing aci_class, aci_rn, target_filter, and module_object keys.
        :param sublass_2: The third-level class dictionary containing aci_class, aci_rn, target_filter, and module_object keys.
        :param sublass_3: The fourth-level class dictionary containing aci_class, aci_rn, target_filter, and module_object keys.
        :param child_classes: The list of child classes that the module supports along with the object.
        :type root_class: dict
        :type subclass_1: dict
        :type subclass_2: dict
        :type subclass_3: dict
        :type subclass_4: dict
        :type subclass_5: dict
        :type subclass_6: dict
        :type child_classes: list
        :return: The path and filter_string needed to build the full URL.
        """
        self.filter_string = ""

        if child_classes is None:
            self.child_classes = set()
        else:
            self.child_classes = set(child_classes)

        if subclass_6 is not None:
            self._construct_url_7(root_class, subclass_1, subclass_2, subclass_3, subclass_4, subclass_5, subclass_6, config_only)
        elif subclass_5 is not None:
            self._construct_url_6(root_class, subclass_1, subclass_2, subclass_3, subclass_4, subclass_5, config_only)
        elif subclass_4 is not None:
            self._construct_url_5(root_class, subclass_1, subclass_2, subclass_3, subclass_4, config_only)
        elif subclass_3 is not None:
            self._construct_url_4(root_class, subclass_1, subclass_2, subclass_3, config_only)
        elif subclass_2 is not None:
            self._construct_url_3(root_class, subclass_1, subclass_2, config_only)
        elif subclass_1 is not None:
            self._construct_url_2(root_class, subclass_1, config_only)
        else:
            self._construct_url_1(root_class, config_only)

        if self.params.get("port") is not None:
            self.url = "{protocol}://{host}:{port}/{path}".format(path=self.path, **self.module.params)
        else:
            self.url = "{protocol}://{host}/{path}".format(path=self.path, **self.module.params)

        if self.child_classes:
            # Append child_classes to filter_string if filter string is empty
            self.update_qs(
                {
                    "rsp-subtree": rsp_subtree,
                    "rsp-subtree-class": ",".join(sorted(self.child_classes)),
                }
            )
        elif rsp_subtree == "children":
            self.update_qs({"rsp-subtree": rsp_subtree})

    def _construct_url_1(self, obj, config_only=True):
        """
        This method is used by construct_url when the object is the top-level class.
        """
        obj_class = obj.get("aci_class")
        obj_rn = obj.get("aci_rn")
        obj_filter = obj.get("target_filter")
        mo = obj.get("module_object")

        if self.module.params.get("state") in ("absent", "present"):
            # State is absent or present
            self.path = "api/mo/uni/{0}.json".format(obj_rn)
            self.parent_path = "api/mo/uni.json"
            if config_only:
                self.update_qs({"rsp-prop-include": "config-only"})
            self.obj_filter = obj_filter
        elif mo is None:
            # Query for all objects of the module's class (filter by properties)
            self.path = "api/class/{0}.json".format(obj_class)
            if obj_filter is not None:
                self.update_qs({"query-target-filter": self.build_filter(obj_class, obj_filter)})
        else:
            # Query for a specific object in the module's class
            self.path = "api/mo/uni/{0}.json".format(obj_rn)

    def _construct_url_2(self, parent, obj, config_only=True):
        """
        This method is used by construct_url when the object is the second-level class.
        """
        parent_rn = parent.get("aci_rn")
        parent_obj = parent.get("module_object")
        obj_class = obj.get("aci_class")
        obj_rn = obj.get("aci_rn")
        obj_filter = obj.get("target_filter")
        mo = obj.get("module_object")

        if self.module.params.get("state") in ("absent", "present"):
            # State is absent or present
            self.path = "api/mo/uni/{0}/{1}.json".format(parent_rn, obj_rn)
            self.parent_path = "api/mo/uni/{0}.json".format(parent_rn)
            if config_only:
                self.update_qs({"rsp-prop-include": "config-only"})
            self.obj_filter = obj_filter
        elif parent_obj is None and mo is None:
            # Query for all objects of the module's class
            self.path = "api/class/{0}.json".format(obj_class)
            self.update_qs({"query-target-filter": self.build_filter(obj_class, obj_filter)})
        elif parent_obj is None:  # mo is known
            # Query for all objects of the module's class that match the provided ID value
            self.path = "api/class/{0}.json".format(obj_class)
            self.update_qs({"query-target-filter": self.build_filter(obj_class, obj_filter)})
        elif mo is None:  # parent_obj is known
            # Query for all object's of the module's class that belong to a specific parent object
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}.json".format(parent_rn)
        else:
            # Query for specific object in the module's class
            self.path = "api/mo/uni/{0}/{1}.json".format(parent_rn, obj_rn)

    def _construct_url_3(self, root, parent, obj, config_only=True):
        """
        This method is used by construct_url when the object is the third-level class.
        """
        root_rn = root.get("aci_rn")
        root_obj = root.get("module_object")
        parent_class = parent.get("aci_class")
        parent_rn = parent.get("aci_rn")
        parent_filter = parent.get("target_filter")
        parent_obj = parent.get("module_object")
        obj_class = obj.get("aci_class")
        obj_rn = obj.get("aci_rn")
        obj_filter = obj.get("target_filter")
        mo = obj.get("module_object")

        if self.module.params.get("state") in ("absent", "present"):
            # State is absent or present
            self.path = "api/mo/uni/{0}/{1}/{2}.json".format(root_rn, parent_rn, obj_rn)
            self.parent_path = "api/mo/uni/{0}/{1}.json".format(root_rn, parent_rn)
            if config_only:
                self.update_qs({"rsp-prop-include": "config-only"})
            self.obj_filter = obj_filter
        elif root_obj is None and parent_obj is None and mo is None:
            # Query for all objects of the module's class
            self.path = "api/class/{0}.json".format(obj_class)
            self.update_qs({"query-target-filter": self.build_filter(obj_class, obj_filter)})
        elif root_obj is None and parent_obj is None:  # mo is known
            # Query for all objects of the module's class matching the provided ID value of the object
            self.path = "api/class/{0}.json".format(obj_class)
            self.update_qs({"query-target-filter": self.build_filter(obj_class, obj_filter)})
        elif root_obj is None and mo is None:  # parent_obj is known
            # Query for all objects of the module's class that belong to any parent class
            # matching the provided ID value for the parent object
            self.child_classes.add(obj_class)
            self.path = "api/class/{0}.json".format(parent_class)
            self.update_qs({"query-target-filter": self.build_filter(parent_class, parent_filter)})
        elif parent_obj is None and mo is None:  # root_obj is known
            # Query for all objects of the module's class that belong to a specific root object
            self.child_classes.update([parent_class, obj_class])
            self.path = "api/mo/uni/{0}.json".format(root_rn)
            # NOTE: No need to select by root_filter
            # self.update_qs({'query-target-filter': self.build_filter(root_class, root_filter)})
        elif root_obj is None:  # mo and parent_obj are known
            # Query for all objects of the module's class that belong to any parent class
            # matching the provided ID values for both object and parent object
            self.child_classes.add(obj_class)
            self.path = "api/class/{0}.json".format(parent_class)
            self.update_qs({"query-target-filter": self.build_filter(parent_class, parent_filter)})
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif parent_obj is None:  # mo and root_obj are known
            # Query for all objects of the module's class that match the provided ID value and belong to a specific root object
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}.json".format(root_rn)
            # NOTE: No need to select by root_filter
            # self.update_qs({'query-target-filter': self.build_filter(root_class, root_filter)})
            # TODO: Filter by parent_filter and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif mo is None:  # root_obj and parent_obj are known
            # Query for all objects of the module's class that belong to a specific parent object
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}.json".format(root_rn, parent_rn)
            # NOTE: No need to select by parent_filter
            # self.update_qs({'query-target-filter': self.build_filter(parent_class, parent_filter)})
        else:
            # Query for a specific object of the module's class
            self.path = "api/mo/uni/{0}/{1}/{2}.json".format(root_rn, parent_rn, obj_rn)

    def _construct_url_4(self, root, sec, parent, obj, config_only=True):
        """
        This method is used by construct_url when the object is the fourth-level class.
        """
        root_rn = root.get("aci_rn")
        root_obj = root.get("module_object")
        sec_rn = sec.get("aci_rn")
        sec_obj = sec.get("module_object")
        parent_rn = parent.get("aci_rn")
        parent_obj = parent.get("module_object")
        obj_class = obj.get("aci_class")
        obj_rn = obj.get("aci_rn")
        obj_filter = obj.get("target_filter")
        mo = obj.get("module_object")

        if self.child_classes is None:
            self.child_classes = [obj_class]

        if self.module.params.get("state") in ("absent", "present"):
            # State is absent or present
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}.json".format(root_rn, sec_rn, parent_rn, obj_rn)
            self.parent_path = "api/mo/uni/{0}/{1}/{2}.json".format(root_rn, sec_rn, parent_rn)
            if config_only:
                self.update_qs({"rsp-prop-include": "config-only"})
            self.obj_filter = obj_filter
        # TODO: Add all missing cases
        elif root_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/class/{0}.json".format(obj_class)
            self.update_qs({"query-target-filter": self.build_filter(obj_class, obj_filter)})
        elif sec_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}.json".format(root_rn)
            # NOTE: No need to select by root_filter
            # self.update_qs({'query-target-filter': self.build_filter(root_class, root_filter)})
            # TODO: Filter by sec_filter, parent and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif parent_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}.json".format(root_rn, sec_rn)
            # NOTE: No need to select by sec_filter
            # self.update_qs({'query-target-filter': self.build_filter(sec_class, sec_filter)})
            # TODO: Filter by parent_filter and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif mo is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}/{2}.json".format(root_rn, sec_rn, parent_rn)
            # NOTE: No need to select by parent_filter
            # self.update_qs({'query-target-filter': self.build_filter(parent_class, parent_filter)})
        else:
            # Query for a specific object of the module's class
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}.json".format(root_rn, sec_rn, parent_rn, obj_rn)

    def _construct_url_5(self, root, ter, sec, parent, obj, config_only=True):
        """
        This method is used by construct_url when the object is the fourth-level class.
        """

        root_rn = root.get("aci_rn")
        root_obj = root.get("module_object")
        ter_rn = ter.get("aci_rn")
        ter_obj = ter.get("module_object")
        sec_rn = sec.get("aci_rn")
        sec_obj = sec.get("module_object")
        parent_rn = parent.get("aci_rn")
        parent_obj = parent.get("module_object")
        obj_class = obj.get("aci_class")
        obj_rn = obj.get("aci_rn")
        obj_filter = obj.get("target_filter")
        mo = obj.get("module_object")

        if self.child_classes is None:
            self.child_classes = [obj_class]

        if self.module.params.get("state") in ("absent", "present"):
            # State is absent or present
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}/{4}.json".format(root_rn, ter_rn, sec_rn, parent_rn, obj_rn)
            self.parent_path = "api/mo/uni/{0}/{1}/{2}/{3}.json".format(root_rn, ter_rn, sec_rn, parent_rn)
            if config_only:
                self.update_qs({"rsp-prop-include": "config-only"})
            self.obj_filter = obj_filter
        # TODO: Add all missing cases
        elif root_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/class/{0}.json".format(obj_class)
            self.update_qs({"query-target-filter": self.build_filter(obj_class, obj_filter)})
        elif ter_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}.json".format(root_rn)
            # NOTE: No need to select by root_filter
            # self.update_qs({'query-target-filter': self.build_filter(root_class, root_filter)})
            # TODO: Filter by ter_filter, parent and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif sec_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}.json".format(root_rn, ter_rn)
            # NOTE: No need to select by ter_filter
            # self.update_qs({'query-target-filter': self.build_filter(ter_class, ter_filter)})
            # TODO: Filter by sec_filter, parent and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif parent_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}/{2}.json".format(root_rn, ter_rn, sec_rn)
            # NOTE: No need to select by sec_filter
            # self.update_qs({'query-target-filter': self.build_filter(sec_class, sec_filter)})
            # TODO: Filter by parent_filter and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif mo is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}.json".format(root_rn, ter_rn, sec_rn, parent_rn)
            # NOTE: No need to select by parent_filter
            # self.update_qs({'query-target-filter': self.build_filter(parent_class, parent_filter)})
        else:
            # Query for a specific object of the module's class
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}/{4}.json".format(root_rn, ter_rn, sec_rn, parent_rn, obj_rn)

    def _construct_url_6(self, root, quad, ter, sec, parent, obj, config_only=True):
        """
        This method is used by construct_url when the object is the fifth-level class.
        """
        root_rn = root.get("aci_rn")
        root_obj = root.get("module_object")
        quad_rn = quad.get("aci_rn")
        quad_obj = quad.get("module_object")
        ter_rn = ter.get("aci_rn")
        ter_obj = ter.get("module_object")
        sec_rn = sec.get("aci_rn")
        sec_obj = sec.get("module_object")
        parent_rn = parent.get("aci_rn")
        parent_obj = parent.get("module_object")
        obj_class = obj.get("aci_class")
        obj_rn = obj.get("aci_rn")
        obj_filter = obj.get("target_filter")
        mo = obj.get("module_object")

        if self.child_classes is None:
            self.child_classes = [obj_class]

        if self.module.params.get("state") in ("absent", "present"):
            # State is absent or present
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}/{4}/{5}.json".format(root_rn, quad_rn, ter_rn, sec_rn, parent_rn, obj_rn)
            if config_only:
                self.update_qs({"rsp-prop-include": "config-only"})
            self.obj_filter = obj_filter
        # TODO: Add all missing cases
        elif root_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/class/{0}.json".format(obj_class)
            self.update_qs({"query-target-filter": self.build_filter(obj_class, obj_filter)})
        elif quad_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}.json".format(root_rn)
            # NOTE: No need to select by root_filter
            # self.update_qs({'query-target-filter': self.build_filter(root_class, root_filter)})
            # TODO: Filter by quad_filter, parent and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif ter_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}.json".format(root_rn, quad_rn)
            # NOTE: No need to select by quad_filter
            # self.update_qs({'query-target-filter': self.build_filter(quad_class, quad_filter)})
            # TODO: Filter by ter_filter, parent and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif sec_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}/{2}.json".format(root_rn, quad_rn, ter_rn)
            # NOTE: No need to select by ter_filter
            # self.update_qs({'query-target-filter': self.build_filter(ter_class, ter_filter)})
            # TODO: Filter by sec_filter, parent and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif parent_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}.json".format(root_rn, quad_rn, ter_rn, sec_rn)
            # NOTE: No need to select by sec_filter
            # self.update_qs({'query-target-filter': self.build_filter(sec_class, sec_filter)})
            # TODO: Filter by parent_filter and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif mo is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}/{4}.json".format(root_rn, quad_rn, ter_rn, sec_rn, parent_rn)
            # NOTE: No need to select by parent_filter
            # self.update_qs({'query-target-filter': self.build_filter(parent_class, parent_filter)})
        else:
            # Query for a specific object of the module's class
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}/{4}/{5}.json".format(root_rn, quad_rn, ter_rn, sec_rn, parent_rn, obj_rn)

    def _construct_url_7(self, root, quin, quad, ter, sec, parent, obj, config_only=True):
        """
        This method is used by construct_url when the object is the sixth-level class.
        """
        root_rn = root.get("aci_rn")
        root_obj = root.get("module_object")
        quin_rn = quin.get("aci_rn")
        quin_obj = quin.get("module_object")
        quad_rn = quad.get("aci_rn")
        quad_obj = quad.get("module_object")
        ter_rn = ter.get("aci_rn")
        ter_obj = ter.get("module_object")
        sec_rn = sec.get("aci_rn")
        sec_obj = sec.get("module_object")
        parent_rn = parent.get("aci_rn")
        parent_obj = parent.get("module_object")
        obj_class = obj.get("aci_class")
        obj_rn = obj.get("aci_rn")
        obj_filter = obj.get("target_filter")
        mo = obj.get("module_object")

        if self.child_classes is None:
            self.child_classes = [obj_class]

        if self.module.params.get("state") in ("absent", "present"):
            # State is absent or present
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}/{4}/{5}/{6}.json".format(root_rn, quin_rn, quad_rn, ter_rn, sec_rn, parent_rn, obj_rn)
            if config_only:
                self.update_qs({"rsp-prop-include": "config-only"})
            self.obj_filter = obj_filter
        # TODO: Add all missing cases
        elif root_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/class/{0}.json".format(obj_class)
            self.update_qs({"query-target-filter": self.build_filter(obj_class, obj_filter)})
        elif quin_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}.json".format(root_rn)
            # NOTE: No need to select by root_filter
            # self.update_qs({'query-target-filter': self.build_filter(root_class, root_filter)})
            # TODO: Filter by quin_filter, parent and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif quad_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}.json".format(root_rn, quin_rn)
            # NOTE: No need to select by root_filter
            # self.update_qs({'query-target-filter': self.build_filter(root_class, root_filter)})
            # TODO: Filter by quin_filter, parent and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif ter_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}/{2}.json".format(root_rn, quin_rn, quad_rn)
            # NOTE: No need to select by quad_filter
            # self.update_qs({'query-target-filter': self.build_filter(quin_class, quin_filter)})
            # TODO: Filter by ter_filter, parent and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif sec_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}.json".format(root_rn, quin_rn, quad_rn, ter_rn)
            # NOTE: No need to select by ter_filter
            # self.update_qs({'query-target-filter': self.build_filter(ter_class, ter_filter)})
            # TODO: Filter by sec_filter, parent and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif parent_obj is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}/{4}.json".format(root_rn, quin_rn, quad_rn, ter_rn, sec_rn)
            # NOTE: No need to select by sec_filter
            # self.update_qs({'query-target-filter': self.build_filter(sec_class, sec_filter)})
            # TODO: Filter by parent_filter and obj_filter
            self.update_qs({"rsp-subtree-filter": self.build_filter(obj_class, obj_filter)})
        elif mo is None:
            self.child_classes.add(obj_class)
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}/{4}/{5}.json".format(root_rn, quin_rn, quad_rn, ter_rn, sec_rn, parent_rn)
            # NOTE: No need to select by parent_filter
            # self.update_qs({'query-target-filter': self.build_filter(parent_class, parent_filter)})
        else:
            # Query for a specific object of the module's class
            self.path = "api/mo/uni/{0}/{1}/{2}/{3}/{4}/{5}/{6}.json".format(root_rn, quin_rn, quad_rn, ter_rn, sec_rn, parent_rn, obj_rn)

    def delete_config(self):
        """
        This method is used to handle the logic when the modules state is equal to absent. The method only pushes a change if
        the object exists, and if check_mode is False. A successful change will mark the module as changed.
        """
        self.proposed = dict()

        if not self.existing and not self.suppress_previous:
            return
        elif not self.module.check_mode:
            # Sign and encode request as to APIC's wishes
            self.api_call("DELETE", self.url, None, return_response=False)
        else:
            self.result["changed"] = True
            self.method = "DELETE"

    def get_diff(self, aci_class, required_properties=None):
        """
        This method is used to get the difference between the proposed and existing configurations. Each module
        should call the get_existing method before this method, and add the proposed config to the module results
        using the module's config parameters. The new config will added to the self.result dictionary.
        :param aci_class: Type str.
                          This is the root dictionary key for the MO's configuration body, or the ACI class of the MO.
        """
        proposed_config = self.proposed[aci_class]["attributes"]
        if self.existing:
            existing_config = self.existing[0][aci_class]["attributes"]
            config = {}

            # values are strings, so any diff between proposed and existing can be a straight replace
            for key, value in proposed_config.items():
                existing_field = existing_config.get(key)
                if value != existing_field:
                    config[key] = value

            # add name back to config only if the configs do not match
            if config:
                # TODO: If URLs are built with the object's name, then we should be able to leave off adding the name back
                if required_properties and isinstance(required_properties, dict):
                    config.update(required_properties)
                config = {aci_class: {"attributes": config}}

            # check for updates to child configs and update new config dictionary
            children = self.get_diff_children(aci_class)

            if children and config:
                config[aci_class].update({"children": children})
            elif children:
                config = {aci_class: {"attributes": {}, "children": children}}

        else:
            config = self.proposed
        self.config = config

    @staticmethod
    def get_diff_child(child_class, proposed_child, existing_child):
        """
        This method is used to get the difference between a proposed and existing child configs. The get_nested_config()
        method should be used to return the proposed and existing config portions of child.
        :param child_class: Type str.
                            The root class (dict key) for the child dictionary.
        :param proposed_child: Type dict.
                               The config portion of the proposed child dictionary.
        :param existing_child: Type dict.
                               The config portion of the existing child dictionary.
        :return: The child config with only values that are updated. If the proposed dictionary has no updates to make
                 to what exists on the APIC, then None is returned.
        """
        update_config = {child_class: {"attributes": {}}}
        for key, value in proposed_child.items():
            existing_field = existing_child.get(key)
            if value != existing_field:
                update_config[child_class]["attributes"][key] = value

        if not update_config[child_class]["attributes"]:
            return None

        return update_config

    def get_diff_children(self, aci_class, proposed_obj=None, existing_obj=None):
        """
        This method is used to retrieve the updated child configs by comparing the proposed children configs
        against the objects existing children configs.
        :param aci_class: Type str.
                          This is the root dictionary key for the MO's configuration body, or the ACI class of the MO.
        :return: The list of updated child config dictionaries. None is returned if there are no changes to the child
                 configurations.
        """
        if proposed_obj is None:
            proposed_children = self.proposed[aci_class].get("children")
        else:
            proposed_children = proposed_obj

        if proposed_children:
            child_updates = []
            if existing_obj is None:
                existing_children = self.existing[0][aci_class].get("children", [])
            else:
                existing_children = existing_obj

            # Loop through proposed child configs and compare against existing child configuration
            for child in proposed_children:
                child_class, proposed_child, existing_child = self.get_nested_config(child, existing_children)
                (
                    proposed_child_children,
                    existing_child_children,
                ) = self.get_nested_children(child, existing_children)

                if existing_child is None:
                    child_update = child
                else:
                    child_update = self.get_diff_child(child_class, proposed_child, existing_child)
                    if proposed_child_children:
                        child_update_children = self.get_diff_children(aci_class, proposed_child_children, existing_child_children)

                        if child_update_children:
                            child_update = child

                # Update list of updated child configs only if the child config is different than what exists
                if child_update:
                    child_updates.append(child_update)
        else:
            return None

        return child_updates

    def get_existing(self):
        """
        This method is used to get the existing object(s) based on the path specified in the module. Each module should
        build the URL so that if the object's name is supplied, then it will retrieve the configuration for that particular
        object, but if no name is supplied, then it will retrieve all MOs for the class. Following this method will ensure
        that this method can be used to supply the existing configuration when using the get_diff method. The response, status,
        and existing configuration will be added to the self.result dictionary.
        """
        if self.suppress_previous:
            self.existing = []
            return

        uri = self.url + self.filter_string
        self.api_call("GET", uri, data=None, return_response=False)

    def __get_existing_validation(self, changed):
        """
        This method is used to get the existing object(s) state after a config change has been completed.
        It will not get the object(s) state if there is no change or suppress_verification is enabled.
        When suppress_verification is enabled, the existing will be set to proposed if there was a change or suppress_previous is enabled.
        """
        if self.suppress_verification:
            if changed or self.suppress_previous:
                self.result["current_verified"] = False
                self.existing = [self.proposed] if self.proposed != {} else []
            else:
                # existing already equals the previous
                self.result["current_verified"] = True
        elif changed:
            uri = self.url + self.filter_string
            self.api_call("GET", uri, data=None, return_response=False)

    @staticmethod
    def get_nested_config(proposed_child, existing_children):
        """
        This method is used for stiping off the outer layers of the child dictionaries so only the configuration
        key, value pairs are returned.
        :param proposed_child: Type dict.
                               The dictionary that represents the child config.
        :param existing_children: Type list.
                                  The list of existing child config dictionaries.
        :return: The child's class as str (root config dict key), the child's proposed config dict, and the child's
                 existing configuration dict.
        """
        for key in proposed_child.keys():
            child_class = key
            proposed_config = proposed_child[key]["attributes"]
            existing_config = None

            # FIXME: Design causes issues for repeated child_classes
            # get existing dictionary from the list of existing to use for comparison
            for child in existing_children:
                if child.get(child_class):
                    existing_config = child[key]["attributes"]
                    # NOTE: This is an ugly fix
                    # Return the one that is a subset match
                    if set(proposed_config.items()).issubset(set(existing_config.items())):
                        break
                    existing_config = None

        return child_class, proposed_config, existing_config

    @staticmethod
    def get_nested_children(proposed_child, existing_children):
        """
        This method is used for stiping off the outer layers of the child dictionaries so only the children are returned.
        :param proposed_child: Type dict.
                               The dictionary that represents the child config.
        :param existing_children: Type list.
                                  The list of existing child config dictionaries.
        :return: The child's class as str (root config dict key), the child's proposed children as a list and the child's
                 existing children as a list.
        """
        for key in proposed_child.keys():
            child_class = key
            proposed_config = proposed_child[key]["attributes"]
            existing_config = None
            proposed_children = proposed_child[key].get("children")
            existing_child_children = None

            # FIXME: Design causes issues for repeated child_classes
            # get existing dictionary from the list of existing to use for comparison
            for child in existing_children:
                if child.get(child_class):
                    existing_config = child[key]["attributes"]
                    existing_child_children = child[key].get("children")
                    # NOTE: This is an ugly fix
                    # Return the one that is a subset match
                    if set(proposed_config.items()).issubset(set(existing_config.items())):
                        break
                    existing_child_children = None
                    existing_config = None

        return proposed_children, existing_child_children

    def payload(self, aci_class, class_config, child_configs=None):
        """
        This method is used to dynamically build the proposed configuration dictionary from the config related parameters
        passed into the module. All values that were not passed values from the playbook task will be removed so as to not
        inadvertently change configurations.
        :param aci_class: Type str
                          This is the root dictionary key for the MO's configuration body, or the ACI class of the MO.
        :param class_config: Type dict
                             This is the configuration of the MO using the dictionary keys expected by the API
        :param child_configs: Type list
                              This is a list of child dictionaries associated with the MOs config. The list should only
                              include child objects that are used to associate two MOs together. Children that represent
                              MOs should have their own module.
        """
        proposed = dict((k, str(v)) for k, v in class_config.items() if v is not None)
        if self.params.get("annotation") is not None:
            proposed["annotation"] = self.params.get("annotation")
        if self.params.get("owner_key") is not None:
            proposed["ownerKey"] = self.params.get("owner_key")
        if self.params.get("owner_tag") is not None:
            proposed["ownerTag"] = self.params.get("owner_tag")
        self.proposed = {aci_class: {"attributes": proposed}}

        # add child objects to proposed
        if child_configs:
            children = self.handle_child_configs(child_configs)

            if children:
                self.proposed[aci_class].update(dict(children=children))

    def handle_child_configs(self, child_configs):
        children = []
        for child in child_configs:
            child_copy = deepcopy(child)
            has_value = False
            for class_name in child_copy.keys():
                for attribute, value in child_copy[class_name]["attributes"].items():
                    if value is None:
                        child[class_name]["attributes"].pop(attribute)
                    else:
                        child[class_name]["attributes"][attribute] = str(value)
                        has_value = True
                if child_copy[class_name].get("children") is not None:
                    has_value = True
                    child[class_name]["children"] = self.handle_child_configs(child_copy[class_name]["children"])
            if has_value:
                children.append(child)
        return children

    def post_config(self, parent_class=None):
        """
        This method is used to handle the logic when the modules state is equal to present. The method only pushes a change if
        the object has differences than what exists on the APIC, and if check_mode is False. A successful change will mark the
        module as changed.
        """
        if not self.config:
            return
        elif not self.module.check_mode:
            # Sign and encode request as to APIC's wishes
            url = self.url
            if parent_class is not None:
                if self.params.get("port") is not None:
                    url = "{protocol}://{host}:{port}/{path}".format(path=self.parent_path, **self.module.params)
                else:
                    url = "{protocol}://{host}/{path}".format(path=self.parent_path, **self.module.params)
                self.config = {parent_class: {"attributes": {}, "children": [self.config]}}
            self.api_call("POST", url, json.dumps(self.config), return_response=False)
        else:
            self.result["changed"] = True
            self.method = "POST"

    def exit_json(self, filter_existing=None, **kwargs):
        """
        :param filter_existing: tuple consisting of the function at (index 0) and the args at (index 1)
        CAUTION: the function should always take in self.existing in its first parameter
        :param kwargs: kwargs to be passed to ansible module exit_json()
        filter_existing is not passed via kwargs since it cant handle function type and should not be exposed to user
        """

        if "state" in self.params:
            if self.params.get("state") in ("absent", "present"):
                if self.params.get("output_level") in ("debug", "info"):
                    self.result["previous"] = self.existing if not filter_existing else filter_existing[0](self.existing, filter_existing[1])

        # Return the gory details when we need it
        if self.params.get("output_level") == "debug":
            if "state" in self.params:
                self.result["filter_string"] = self.filter_string
            self.result["method"] = self.method
            # self.result['path'] = self.path  # Adding 'path' in result causes state: absent in output
            self.result["response"] = self.response
            self.result["status"] = self.status
            self.result["url"] = self.url
            if self.httpapi_logs is not None:
                self.result["httpapi_logs"] = self.httpapi_logs
        if self.stdout:
            self.result["stdout"] = self.stdout

        if "state" in self.params:
            self.original = self.existing
            if self.params.get("state") in ("absent", "present"):
                self.__get_existing_validation(self.result["changed"])

            # if self.module._diff and self.original != self.existing:
            #     self.result['diff'] = dict(
            #         before=json.dumps(self.original, sort_keys=True, indent=4),
            #         after=json.dumps(self.existing, sort_keys=True, indent=4),
            #     )
            self.result["current"] = self.existing if not filter_existing else filter_existing[0](self.existing, filter_existing[1])

            if self.params.get("output_level") in ("debug", "info"):
                self.result["sent"] = self.config
                self.result["proposed"] = self.proposed

        self.dump_json()
        self.result.update(**kwargs)
        self.module.exit_json(**self.result)

    def fail_json(self, msg, **kwargs):
        # Return error information, if we have it
        if self.error.get("code") is not None and self.error.get("text") is not None:
            self.result["error"] = self.error

        if self.stdout:
            self.result["stdout"] = self.stdout

        if "state" in self.params:
            if self.params.get("state") in ("absent", "present"):
                if self.params.get("output_level") in ("debug", "info"):
                    self.result["previous"] = self.existing

            # Return the gory details when we need it
            if self.params.get("output_level") == "debug":
                if self.imdata is not None:
                    self.result["imdata"] = self.imdata
                    self.result["totalCount"] = self.totalCount

        if self.params.get("output_level") == "debug":
            if self.url is not None:
                if "state" in self.params:
                    self.result["filter_string"] = self.filter_string
                self.result["method"] = self.method
                # self.result['path'] = self.path  # Adding 'path' in result causes state: absent in output
                self.result["response"] = self.response
                self.result["status"] = self.status
                self.result["url"] = self.url
            if self.httpapi_logs is not None:
                self.result["httpapi_logs"] = self.httpapi_logs

        if "state" in self.params:
            if self.params.get("output_level") in ("debug", "info"):
                self.result["sent"] = self.config
                self.result["proposed"] = self.proposed

        self.result.update(**kwargs)
        self.module.fail_json(msg=msg, **self.result)

    def dump_json(self):
        if self.params.get("state") in ("absent", "present"):
            dn_path = self.url.rsplit("/mo/", maxsplit=1)[-1]
            if dn_path[-5:] == ".json":
                dn_path = dn_path[:-5]
            mo = {}
            if self.proposed:
                mo = self.proposed
                for aci_class in mo:
                    mo[aci_class]["attributes"]["dn"] = dn_path
                    if self.obj_filter is not None:
                        if "tDn" in self.obj_filter:
                            mo[aci_class]["attributes"]["tDn"] = self.obj_filter["tDn"]

            elif self.params.get("state") == "absent" and self.existing:
                for aci_class in self.existing[0]:
                    mo[aci_class] = dict(attributes=dict(dn=dn_path, status="deleted"))

            self.result["mo"] = mo
            output_path = self.params.get("output_path")
            if output_path is not None:
                with open(output_path, "a") as output_file:
                    if self.result.get("changed") is True:
                        json.dump([mo], output_file)

    def parsed_url_path(self, url):
        if not HAS_URLPARSE:
            self.fail_json(msg="urlparse is not installed")
        parse_result = urlparse(url)
        if parse_result.query == "":
            return parse_result.path
        else:
            return parse_result.path + "?" + parse_result.query

    def api_call(self, method, url, data=None, return_response=False):
        resp = None
        if self.connection is not None:
            self.connection.set_params(self.params)
            info = self.connection.send_request(method, self.parsed_url_path(url), data)
            self.url = "{protocol}://{host}/{path}".format_map(integrate_url(info.get("url"), self.path))
            self.error = info.get("error")
            self.httpapi_logs.extend(self.connection.pop_messages())
        else:
            if self.params.get("private_key"):
                self.cert_auth(path=self.parsed_url_path(url), payload=data, method=method)
            resp, info = fetch_url(
                self.module,
                url,
                data=data,
                headers=self.headers,
                method=method,
                timeout=30 if self.params.get("timeout") is None else self.params.get("timeout"),
                use_proxy=True if self.params.get("use_proxy") is None else self.params.get("use_proxy"),
            )

        self.response = info.get("msg")
        self.status = info.get("status")
        self.method = method

        if return_response:
            return resp, info
        else:
            # Handle APIC response
            if info.get("status") == 200:
                if method == "POST" or method == "DELETE":
                    self.result["changed"] = True
                try:
                    if method == "GET":
                        self.existing = json.loads(resp.read())["imdata"]
                    else:
                        self.response_json(resp.read())
                except AttributeError:
                    if method == "GET":
                        self.existing = json.loads(info.get("body"))["imdata"]
                    else:
                        self.response_json(info.get("body"))
            else:
                try:
                    # APIC error
                    self.response_json(info["body"])
                    self.fail_json(msg="APIC Error {code}: {text}".format_map(self.error))
                except KeyError:
                    # Connection error
                    self.fail_json(msg="Connection failed for {url}. {msg}".format_map(info))
