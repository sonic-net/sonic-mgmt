# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy
import re
import os
import ast
import datetime
import shutil
import tempfile
from ansible.module_utils.basic import json
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.six import PY3
from ansible.module_utils.six.moves import filterfalse
from ansible.module_utils.six.moves.urllib.parse import urlencode, urljoin
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_native, to_text
from ansible.module_utils.connection import Connection
from ansible_collections.cisco.mso.plugins.module_utils.constants import (
    NDO_API_VERSION_PATH_FORMAT,
    AZURE_L4L7_CONNECTOR_TYPE_MAP,
    LISTENER_REDIRECT_CODE_MAP,
    LISTENER_CONTENT_TYPE_MAP,
    LISTENER_ACTION_TYPE_MAP,
    LISTENER_PROTOCOLS,
)


try:
    from requests_toolbelt.multipart.encoder import MultipartEncoder

    HAS_MULTIPART_ENCODER = True
except ImportError:
    HAS_MULTIPART_ENCODER = False


if PY3:

    def cmp(a, b):
        return (a > b) - (a < b)


def issubset(subset, superset):
    """Recurse through nested dictionary and compare entries"""

    # Both objects are the same object
    if subset is superset:
        return True

    # Both objects are identical
    if subset == superset:
        return True

    # Both objects have a different type
    if type(subset) is not type(superset):
        return False

    for key, value in subset.items():
        # Ignore empty values
        if value is None:
            return True

        # Item from subset is missing from superset
        if key not in superset:
            return False

        # Item has different types in subset and superset
        if not isinstance(superset.get(key), type(value)):
            return False

        # Compare if item values are subset
        if isinstance(value, dict):
            if not issubset(superset.get(key), value):
                return False
        elif isinstance(value, list):
            try:
                # NOTE: Fails for lists of dicts
                if not set(value) <= set(superset.get(key)):
                    return False
            except TypeError:
                # Fall back to exact comparison for lists of dicts
                diff = list(filterfalse(lambda i: i in value, superset.get(key))) + list(filterfalse(lambda j: j in superset.get(key), value))
                if diff:
                    return False
        elif isinstance(value, set):
            if not value <= superset.get(key):
                return False
        else:
            if not value == superset.get(key):
                return False

    return True


def update_qs(params):
    """Append key-value pairs to self.filter_string"""
    accepted_params = dict((k, v) for (k, v) in params.items() if v is not None)
    return "?" + urlencode(accepted_params)


def mso_argument_spec():
    return dict(
        host=dict(type="str", required=False, aliases=["hostname"], fallback=(env_fallback, ["MSO_HOST"])),
        port=dict(type="int", required=False, fallback=(env_fallback, ["MSO_PORT"])),
        username=dict(type="str", required=False, fallback=(env_fallback, ["MSO_USERNAME", "ANSIBLE_NET_USERNAME"])),
        password=dict(type="str", required=False, no_log=True, fallback=(env_fallback, ["MSO_PASSWORD", "ANSIBLE_NET_PASSWORD"])),
        output_level=dict(type="str", default="normal", choices=["debug", "info", "normal"], fallback=(env_fallback, ["MSO_OUTPUT_LEVEL"])),
        timeout=dict(type="int", fallback=(env_fallback, ["MSO_TIMEOUT"])),
        use_proxy=dict(type="bool", fallback=(env_fallback, ["MSO_USE_PROXY"])),
        use_ssl=dict(type="bool", fallback=(env_fallback, ["MSO_USE_SSL"])),
        validate_certs=dict(type="bool", fallback=(env_fallback, ["MSO_VALIDATE_CERTS"])),
        login_domain=dict(type="str", fallback=(env_fallback, ["MSO_LOGIN_DOMAIN"])),
    )


def mso_reference_spec():
    return dict(
        name=dict(type="str", required=True),
        schema=dict(type="str"),
        template=dict(type="str"),
    )


def mso_l3out_reference_spec():
    return dict(
        name=dict(type="str", required=True),
        schema=dict(type="str"),
        template=dict(type="str"),
        tenant=dict(type="str"),
    )


def mso_epg_subnet_spec():
    return dict(
        subnet=dict(type="str", required=True, aliases=["ip"]),
        description=dict(type="str"),
        scope=dict(type="str", default="private", choices=["private", "public"]),
        shared=dict(type="bool", default=False),
        no_default_gateway=dict(type="bool", default=False),
    )


def mso_subnet_spec():
    subnet_spec = mso_epg_subnet_spec()
    subnet_spec.update(dict(querier=dict(type="bool", default=False)))
    return subnet_spec


def mso_bd_subnet_spec():
    subnet_spec = mso_epg_subnet_spec()
    subnet_spec.update(dict(querier=dict(type="bool", default=False)))
    subnet_spec.update(dict(primary=dict(type="bool", default=False)))
    subnet_spec.update(dict(virtual=dict(type="bool", default=False)))
    return subnet_spec


def mso_dhcp_spec():
    return dict(
        dhcp_option_policy=dict(type="dict", options=mso_dhcp_option_spec()),
        name=dict(type="str", required=True),
        version=dict(type="int", required=True),
    )


def mso_dhcp_option_spec():
    return dict(
        name=dict(type="str", required=True),
        version=dict(type="int", required=True),
    )


def mso_contractref_spec():
    return dict(
        name=dict(type="str", required=True),
        schema=dict(type="str"),
        template=dict(type="str"),
        type=dict(type="str", required=True, choices=["consumer", "provider"]),
    )


def mso_expression_spec():
    return dict(
        type=dict(type="str", required=True, aliases=["tag"]),
        operator=dict(type="str", choices=["not_in", "in", "equals", "not_equals", "has_key", "does_not_have_key"], required=True),
        value=dict(type="str"),
    )


def mso_expression_spec_ext_epg():
    return dict(
        type=dict(type="str", choices=["ip_address"], required=True),
        operator=dict(type="str", choices=["equals"], required=True),
        value=dict(type="str", required=True),
    )


def mso_hub_network_spec():
    return dict(
        name=dict(type="str", required=True),
        tenant=dict(type="str", required=True),
    )


def mso_object_migrate_spec():
    return dict(
        epg=dict(type="str", required=True),
        anp=dict(type="str", required=True),
    )


def mso_service_graph_node_spec():
    return dict(
        type=dict(type="str", required=True),
    )


def mso_service_graph_node_device_spec():
    return dict(
        device_name=dict(type="str", aliases=["name"], required=True),
        provider_connector_type=dict(type="str", choices=list(AZURE_L4L7_CONNECTOR_TYPE_MAP.keys())),
        provider_interface=dict(type="str"),
        consumer_connector_type=dict(type="str", choices=["none", "redirect"]),
        consumer_interface=dict(type="str"),
    )


def mso_service_graph_connector_spec():
    return dict(
        provider=dict(type="str", required=True),
        consumer=dict(type="str", required=True),
        # Only connectorType bd with value "general" is supported for now thus fixed in code
        #  when connectorType externalEpg is supported "route-peering" should be added
        #  also change SERVICE_NODE_CONNECTOR_TYPE_MAP in constants.py
        #  also verify if connector type is specific to provider or always same for both
        connector_object_type=dict(type="str", default="bd", choices=["bd"]),
        provider_schema=dict(type="str"),
        provider_template=dict(type="str"),
        consumer_schema=dict(type="str"),
        consumer_template=dict(type="str"),
    )


def mso_site_anp_epg_bulk_staticport_spec():
    return dict(
        type=dict(type="str", choices=["port", "vpc", "dpc"]),
        pod=dict(type="str"),  # This parameter is not required for querying all objects
        leaf=dict(type="str"),  # This parameter is not required for querying all objects
        fex=dict(type="str"),  # This parameter is not required for querying all objects
        path=dict(type="str"),  # This parameter is not required for querying all objects
        vlan=dict(type="int"),  # This parameter is not required for querying all objects
        primary_micro_segment_vlan=dict(type="int"),  # This parameter is not required for querying all objects
        deployment_immediacy=dict(type="str", choices=["immediate", "lazy"]),
        mode=dict(type="str", choices=["native", "regular", "untagged"]),
    )


def ndo_remote_user_spec():
    return dict(
        name=dict(type="str", required=True),
        login_domain=dict(type="str", required=True),
    )


def ndo_bfd_multi_hop_settings_spec():
    return dict(
        type="dict",
        options=dict(
            state=dict(type="str", choices=["enabled", "disabled"]),
            admin_state=dict(type="str", choices=["enabled", "disabled"]),
            detection_multiplier=dict(type="int"),
            min_receive_interval=dict(type="int"),  # msec
            min_transmit_interval=dict(type="int"),  # msec
        ),
    )


def ndo_template_object_spec(aliases=None):
    return dict(
        type="dict",
        options=dict(
            name=dict(type="str", aliases=aliases) if aliases else dict(type="str"),
            template=dict(type="str"),
            template_id=dict(type="str"),
        ),
        required_by={
            "template": "name",
            "template_id": "name",
        },
        mutually_exclusive=[
            ["template", "template_id"],
        ],
    )


def ndo_l3out_ptp_spec(aliases=None):
    return dict(
        type="dict",
        options=dict(
            mode=dict(type="str", choices=["multicast_dynamic", "multicast_master", "unicast_master"]),
            source_address=dict(type="str"),
            unicast_destinations=dict(type="list", elements="str"),
            user_profile=dict(
                type="dict",
                options=dict(
                    uuid=dict(type="str"),
                    reference=dict(
                        type="dict",
                        aliases=["ref"],
                        options=dict(
                            name=dict(type="str", required=True),
                            template=dict(type="str"),
                            template_id=dict(type="str"),
                        ),
                        required_one_of=[
                            ["template", "template_id"],
                        ],
                        mutually_exclusive=[
                            ("template", "template_id"),
                        ],
                    ),
                ),
                required_one_of=[
                    ["reference", "uuid"],
                ],
                mutually_exclusive=[
                    ("reference", "uuid"),
                ],
            ),
        ),
    )


def ndo_l3out_virtual_port_channel_spec(side_b=True, secondary_address=False):
    virtual_port_channel_spec = dict(
        type="dict",
        aliases=["vpc"],
        options=dict(
            uuid=dict(type="str"),
            reference=dict(
                type="dict",
                aliases=["ref"],
                options=dict(
                    name=dict(type="str", required=True),
                    template=dict(type="str"),
                    template_id=dict(type="str"),
                ),
                required_one_of=[
                    ["template", "template_id"],
                ],
                mutually_exclusive=[
                    ("template", "template_id"),
                ],
            ),
        ),
        required_one_of=[
            ["reference", "uuid"],
        ],
        mutually_exclusive=[
            ("reference", "uuid"),
        ],
    )

    if side_b:
        virtual_port_channel_spec["options"]["side_b_ipv4_address"] = dict(type="str")
        virtual_port_channel_spec["options"]["side_b_ipv6_address"] = dict(type="str")
        virtual_port_channel_spec["options"]["side_b_ipv6_link_local_address"] = dict(type="str")
        virtual_port_channel_spec["options"]["side_b_ipv6_dad"] = dict(type="str", choices=["enabled", "disabled"])
        virtual_port_channel_spec["options"]["side_b_node_group_policy"] = dict(type="str")
        virtual_port_channel_spec["options"]["side_b_node_router_id"] = dict(type="str", aliases=["router_id"])
        virtual_port_channel_spec["options"]["side_b_use_router_id_as_loopback"] = dict(type="bool")
        virtual_port_channel_spec["options"]["side_b_node_loopback_ip"] = dict(type="str", aliases=["loopback_ip"])
    if secondary_address:
        # enforcing default for clarity of module behaviour, this value is not send to API but is just for calculation of VPC path
        virtual_port_channel_spec["options"]["side_b"] = dict(type="bool", default=False)

    return virtual_port_channel_spec


def ndo_l3out_port_channel_spec(micro_bfd=True):
    port_channel_spec = dict(
        type="dict",
        aliases=["pc"],
        options=dict(
            uuid=dict(type="str"),
            reference=dict(
                type="dict",
                aliases=["ref"],
                options=dict(
                    name=dict(type="str", required=True),
                    template=dict(type="str"),
                    template_id=dict(type="str"),
                ),
                required_one_of=[
                    ["template", "template_id"],
                ],
                mutually_exclusive=[
                    ("template", "template_id"),
                ],
            ),
        ),
        required_one_of=[
            ["reference", "uuid"],
        ],
        mutually_exclusive=[
            ("reference", "uuid"),
        ],
    )

    if micro_bfd:
        port_channel_spec["options"]["micro_bfd_enabled"] = dict(type="bool")
        port_channel_spec["options"]["micro_bfd_address"] = dict(type="str")
        port_channel_spec["options"]["micro_bfd_start_timer"] = dict(type="int")

    return port_channel_spec


# Copied from ansible's module uri.py (url): https://github.com/ansible/ansible/blob/cdf62edc65f564fff6b7e575e084026fa7faa409/lib/ansible/modules/uri.py
def write_file(module, url, dest, content, resp, tmpsrc=None):
    # create a tempfile with some test content

    if tmpsrc is None and content is not None:
        fd, tmpsrc = tempfile.mkstemp(dir=module.tmpdir)
        f = open(tmpsrc, "wb")
        try:
            f.write(content)
        except Exception as e:
            os.remove(tmpsrc)
            module.fail_json(msg="Failed to create temporary content file: {0}".format(to_native(e)))
        f.close()

    checksum_src = None
    checksum_dest = None

    # raise an error if there is no tmpsrc file
    if not os.path.exists(tmpsrc):
        os.remove(tmpsrc)
        module.fail_json(msg="Source '{0}' does not exist".format(tmpsrc))
    if not os.access(tmpsrc, os.R_OK):
        os.remove(tmpsrc)
        module.fail_json(msg="Source '{0}' is not readable".format(tmpsrc))
    checksum_src = module.sha1(tmpsrc)

    # check if there is no dest file
    if os.path.exists(dest):
        # raise an error if copy has no permission on dest
        if not os.access(dest, os.W_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination '{0}' not writable".format(dest))
        if not os.access(dest, os.R_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination '{0}' not readable".format(dest))
        checksum_dest = module.sha1(dest)
    else:
        if not os.access(os.path.dirname(dest), os.W_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination dir '{0}' not writable".format(os.path.dirname(dest)))

    if checksum_src != checksum_dest:
        try:
            shutil.copyfile(tmpsrc, dest)
        except Exception as e:
            os.remove(tmpsrc)
            module.fail_json(msg="failed to copy {0} to {1}: {2}".format(tmpsrc, dest, to_native(e)))

    os.remove(tmpsrc)


def format_interface_descriptions(mso, interface_descriptions, node=None):
    if interface_descriptions:

        def format_range_interfaces(format_dict):
            ids = format_dict.get("interfaceID")
            if re.fullmatch(r"((\d+/)+\d+$)", ids):
                yield format_dict
            elif re.fullmatch(r"((\d+/)+\d+-\d+$)", ids):
                slots = ids.rsplit("/", 1)[0]
                range_start, range_stop = ids.rsplit("/", 1)[1].split("-")
                if int(range_stop) > int(range_start):
                    for x in range(int(range_start), int(range_stop) + 1):
                        copy_format_dict = deepcopy(format_dict)
                        copy_format_dict.update(interfaceID="{0}/{1}".format(slots, x))
                        yield copy_format_dict
                else:
                    mso.fail_json(msg="Range start is greater than or equal to range stop for range of IDs '{0}'".format(ids))
            else:
                mso.fail_json(msg="Incorrect interface ID or range of IDs. Got '{0}'".format(ids))

        return [
            item
            for interface_description in interface_descriptions
            for item in format_range_interfaces(
                {
                    "nodeID": node if node is not None else interface_description.get("node"),
                    "interfaceID": interface_description.get("interface_id", interface_description.get("interfaceID")),
                    "description": interface_description.get("description"),
                }
            )
        ]
    return []


class MSOModule(object):
    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.result = dict(changed=False)
        self.headers = {"Content-Type": "text/json"}
        self.platform = "local"

        # normal output
        self.existing = dict()

        # mso_rest output
        self.jsondata = None
        self.error = dict(code=None, message=None, info=None)

        # info output
        self.previous = dict()
        self.proposed = dict()
        self.sent = dict()
        self.stdout = None
        self.patch_operation = None

        # debug output
        self.has_modified = False
        self.filter_string = ""
        self.method = None
        self.path = None
        self.response = None
        self.status = None
        self.url = None
        self.httpapi_logs = list()
        self.site_type = None  # on-premise or cloud
        self.cloud_provider_type = None  # aws or azure or gcp

        if self.module._debug:
            self.module.warn("Enable debug output because ANSIBLE_DEBUG was set.")
            self.params["output_level"] = "debug"

        if self.module._socket_path is None:
            if self.params.get("use_ssl") is None:
                self.params["use_ssl"] = True
            if self.params.get("use_proxy") is None:
                self.params["use_proxy"] = True
            if self.params.get("validate_certs") is None:
                self.params["validate_certs"] = True
            if self.params.get("timeout") is None:
                self.params["timeout"] = 30

            # Ensure protocol is set
            self.params["protocol"] = "https" if self.params.get("use_ssl", True) else "http"

            # Set base_uri
            if self.params.get("port") is not None:
                self.base_only_uri = "{protocol}://{host}:{port}/".format(**self.params)
                self.baseuri = "{0}api/v1/".format(self.base_only_uri)
            else:
                self.base_only_uri = "{protocol}://{host}/".format(**self.params)
                self.baseuri = "{0}api/v1/".format(self.base_only_uri)

            if self.params.get("host") is None:
                self.fail_json(msg="Parameter 'host' is required when not using the HTTP API connection plugin")

            if self.params.get("password"):
                # Perform password-based authentication, log on using password
                self.login()
            else:
                self.fail_json(msg="Parameter 'password' is required for authentication")
        else:
            self.connection = Connection(self.module._socket_path)
            if self.connection.get_platform() == "cisco.nd":
                self.platform = "nd"
            elif self.connection.get_platform() == "cisco.mso":
                self.platform = "mso"
            else:
                self.fail_json(msg="Connection must be identified as platform 'cisco.nd' or 'cisco.mso'")

    def get_login_domain_id(self, domain):
        """Get a domain and return its id"""
        if domain is None:
            return domain
        d = self.get_obj("auth/login-domains", key="domains", name=domain)
        if not d:
            self.fail_json(msg="Login domain '%s' is not a valid domain name." % domain)
        if "id" not in d:
            self.fail_json(msg="Login domain lookup failed for domain '%s': %s" % (domain, d))
        return d["id"]

    def login(self):
        """Log in to MSO"""

        # Perform login request
        if (self.params.get("login_domain") is not None) and (self.params.get("login_domain") != "Local"):
            domain_id = self.get_login_domain_id(self.params.get("login_domain"))
            payload = {"username": self.params.get("username", "admin"), "password": self.params.get("password"), "domainId": domain_id}
        else:
            payload = {"username": self.params.get("username", "admin"), "password": self.params.get("password")}
        self.url = urljoin(self.baseuri, "auth/login")
        resp, auth = fetch_url(
            self.module,
            self.url,
            data=json.dumps(payload),
            method="POST",
            headers=self.headers,
            timeout=self.params.get("timeout"),
            use_proxy=self.params.get("use_proxy"),
        )

        # Handle MSO response
        if auth.get("status") not in [200, 201]:
            self.response = auth.get("msg")
            self.status = auth.get("status")
            self.fail_json(msg="Authentication failed: {msg}".format(**auth))

        payload = json.loads(resp.read())

        self.headers["Authorization"] = "Bearer {token}".format(**payload)

    def response_json(self, rawoutput):
        """Handle MSO JSON response output"""
        try:
            self.jsondata = json.loads(rawoutput)
        except Exception as e:
            # Expose RAW output for troubleshooting
            self.error = dict(code=-1, message="Unable to parse output as JSON, see 'raw' output. %s" % e)
            self.result["raw"] = rawoutput
            return

        # Handle possible MSO error information
        if self.status not in [200, 201, 202, 204]:
            self.error = self.jsondata

    def request_download(self, path, destination=None, method="GET", api_version="v1"):
        if self.platform != "nd":
            self.url = urljoin(self.baseuri, path)

        redirected = False
        redir_info = {}
        redirect = {}
        content = None
        data = None

        src = self.params.get("src")
        if src:
            try:
                self.headers.update({"Content-Length": os.stat(src).st_size})
                data = open(src, "rb")
            except OSError:
                self.fail_json(msg="Unable to open source file %s" % src, elapsed=0)

        kwargs = {}
        if destination is not None and os.path.isdir(destination):
            # first check if we are redirected to a file download
            if self.platform == "nd":
                redir_info = self.connection.get_remote_file_io_stream(
                    NDO_API_VERSION_PATH_FORMAT.format(api_version=api_version, path=path), self.module.tmpdir, method
                )
                # In place of Content-Disposition, NDO get_remote_file_io_stream returns content-disposition.
                content_disposition = redir_info.get("content-disposition")
            else:
                check, redir_info = fetch_url(self.module, self.url, headers=self.headers, method=method, timeout=self.params.get("timeout"))
                content_disposition = check.headers.get("Content-Disposition")

            if content_disposition:
                file_name = content_disposition.split("filename=")[1]
            else:
                self.fail_json(msg="Failed to fetch {0} backup information from MSO/NDO, response: {1}".format(self.params.get("backup"), redir_info))

            # if we are redirected, update the url with the location header and update dest with the new url filename
            if redir_info["status"] in (301, 302, 303, 307):
                self.url = redir_info.get("location")
                redirected = True
            destination = os.path.join(destination, file_name)

        # if destination file already exist, only download if file newer
        if os.path.exists(destination):
            kwargs["last_mod_time"] = datetime.datetime.utcfromtimestamp(os.path.getmtime(destination))

        if self.platform == "nd":
            if redir_info["status"] == 200 and redirected is False:
                info = redir_info
            else:
                info = self.connection.get_remote_file_io_stream("/mso/{0}".format(self.url.split("/mso/", 1)), self.module.tmpdir, method)
        else:
            resp, info = fetch_url(
                self.module,
                self.url,
                data=data,
                headers=self.headers,
                method=method,
                timeout=self.params.get("timeout"),
                unix_socket=self.params.get("unix_socket"),
                **kwargs
            )

            try:
                content = resp.read()
            except AttributeError:
                # there was no content, but the error read() may have been stored in the info as 'body'
                content = info.pop("body", "")

            if src:
                # Try to close the open file handle
                try:
                    data.close()
                except Exception:
                    pass

        redirect["redirected"] = redirected or info.get("url") != self.url
        redirect.update(redir_info)
        redirect.update(info)

        write_file(self.module, self.url, destination, content, redirect, info.get("tmpsrc"))

        return redirect, destination

    def request_upload(self, path, fields=None, method="POST", api_version="v1"):
        """Generic HTTP MultiPart POST method for MSO uploads."""
        self.path = path
        if self.platform != "nd":
            self.url = urljoin(self.baseuri, path)

        info = dict()

        if self.platform == "nd":
            try:
                if os.path.exists(self.params.get("backup")):
                    info = self.connection.send_file_request(
                        method,
                        NDO_API_VERSION_PATH_FORMAT.format(api_version=api_version, path=path),
                        file=self.params.get("backup"),
                        remote_path=self.params.get("remote_path"),
                    )
                else:
                    self.fail_json(msg="Upload failed due to: No such file or directory, Backup file: '{0}'".format(self.params.get("backup")))
            except Exception as error:
                self.fail_json("NDO upload failed due to: {0}".format(error))
        else:
            if not HAS_MULTIPART_ENCODER:
                self.fail_json(msg="requests-toolbelt is required for the upload state of this module")

            mp_encoder = MultipartEncoder(fields=fields)
            self.headers["Content-Type"] = mp_encoder.content_type
            self.headers["Accept-Encoding"] = "gzip, deflate, br"

            resp, info = fetch_url(
                self.module,
                self.url,
                headers=self.headers,
                data=mp_encoder,
                method=method,
                timeout=self.params.get("timeout"),
                use_proxy=self.params.get("use_proxy"),
            )

        self.response = info.get("msg")
        self.status = info.get("status")

        # Get change status from HTTP headers
        if "modified" in info:
            self.has_modified = True
            if info.get("modified") == "false":
                self.result["changed"] = False
            elif info.get("modified") == "true":
                self.result["changed"] = True

        # 200: OK, 201: Created, 202: Accepted, 204: No Content
        if self.status in (200, 201, 202, 204):
            if self.platform == "nd":
                return info
            else:
                output = resp.read()
                if output:
                    return json.loads(output)

        # 400: Bad Request, 401: Unauthorized, 403: Forbidden,
        # 405: Method Not Allowed, 406: Not Acceptable
        # 500: Internal Server Error, 501: Not Implemented
        elif self.status:
            if self.status >= 400:
                try:
                    if self.platform == "nd":
                        payload = info.get("body")
                    else:
                        payload = json.loads(resp.read())
                except (ValueError, AttributeError):
                    try:
                        payload = json.loads(info.get("body"))
                    except Exception:
                        self.fail_json(msg="MSO Error:", info=info)
                if "code" in payload:
                    self.fail_json(msg="MSO Error {code}: {message}".format(**payload), info=info, payload=payload)
                else:
                    self.fail_json(msg="MSO Error:".format(**payload), info=info, payload=payload)
        else:
            self.fail_json(msg="Backup file upload failed due to: {0}".format(info))
        return {}

    def request(self, path, method=None, data=None, qs=None, api_version="v1", ignore_errors=None):
        """Generic HTTP method for MSO requests."""
        self.path = path

        if method is not None:
            self.method = method

        # If we PATCH with empty operations, return
        if method == "PATCH" and not data:
            return {}
        else:
            self.patch_operation = data

        # if method in ['PATCH', 'PUT']:
        #     if qs is not None:
        #         qs['enableVersionCheck'] = 'true'
        #     else:
        #         qs = dict(enableVersionCheck='true')

        if method in ["PATCH"]:
            if qs is not None:
                qs["validate"] = "false"
            else:
                qs = dict(validate="false")

        resp = None
        if self.module._socket_path:
            self.connection.set_params(self.params)
            if api_version is not None:
                if self.platform == "nd":
                    uri = NDO_API_VERSION_PATH_FORMAT.format(api_version=api_version, path=self.path)
                else:
                    uri = "/api/{0}/{1}".format(api_version, self.path)
            else:
                uri = self.path

            if qs is not None:
                uri = uri + update_qs(qs)

            try:
                info = self.connection.send_request(method, uri, json.dumps(data))
                self.url = info.get("url")
                self.httpapi_logs.extend(self.connection.pop_messages())
                info.pop("date", None)
            except Exception as e:
                try:
                    error_obj = json.loads(to_text(e))
                except Exception:
                    error_obj = dict(
                        error=dict(code=-1, message="Unable to parse error output as JSON. Raw error message: {0}".format(e), exception=to_text(e))
                    )
                    pass
                self.httpapi_logs.extend(self.connection.pop_messages())
                self.fail_json(msg=error_obj["error"]["message"])

        else:
            if api_version is not None:
                self.url = "{0}api/{1}/{2}".format(self.base_only_uri, api_version, self.path.lstrip("/"))
            else:
                self.url = "{0}{1}".format(self.base_only_uri, self.path.lstrip("/"))

            if qs is not None:
                self.url = self.url + update_qs(qs)
            resp, info = fetch_url(
                self.module,
                self.url,
                headers=self.headers,
                data=json.dumps(data),
                method=self.method,
                timeout=self.params.get("timeout"),
                use_proxy=self.params.get("use_proxy"),
            )

        self.response = info.get("msg")
        self.status = info.get("status", -1)

        # Get change status from HTTP headers
        if "modified" in info:
            self.has_modified = True
            if info.get("modified") == "false":
                self.result["changed"] = False
            elif info.get("modified") == "true":
                self.result["changed"] = True

        # 200: OK, 201: Created, 202: Accepted
        if self.status in (200, 201, 202):
            try:
                output = resp.read()
                if output:
                    try:
                        return json.loads(output)
                    except Exception as e:
                        self.error = dict(code=-1, message="Unable to parse output as JSON, see 'raw' output. {0}".format(e))
                        self.result["raw"] = output
                        return
            except AttributeError:
                return info.get("body")

        # 204: No Content
        elif self.status == 204:
            return {}

        # 404: Not Found
        elif self.method == "DELETE" and self.status == 404:
            return {}

        # 400: Bad Request, 401: Unauthorized, 403: Forbidden,
        # 405: Method Not Allowed, 406: Not Acceptable
        # 500: Internal Server Error, 501: Not Implemented
        elif self.status >= 400:
            self.result["status"] = self.status
            body = info.get("body")
            if body is not None:
                try:
                    if isinstance(body, dict):
                        payload = body
                    else:
                        payload = json.loads(body)

                    if ignore_errors:
                        for error in ignore_errors:
                            if error in payload.get("message", ""):
                                return error
                except Exception as e:
                    self.error = dict(code=-1, message="Unable to parse output as JSON, see 'raw' output. %s" % e)
                    self.result["raw"] = body
                    self.fail_json(msg="MSO Error:", data=data, info=info)
                self.error = payload
                if "code" in payload:
                    self.fail_json(msg="MSO Error {code}: {message}".format(**payload), data=data, info=info, payload=payload)
                else:
                    self.fail_json(msg="MSO Error:".format(**payload), data=data, info=info, payload=payload)
            else:
                # Connection error
                msg = "Connection failed for {0}. {1}".format(info.get("url"), info.get("msg"))
                self.error = msg
                self.fail_json(msg=msg)
            return {}

    def l3out_interface_request(self, mso_l3out_template, ops, ignore_errors, state, remove_operations):
        """
        Wrapper function to handle the L3Out interface requests and node error responses.
        L3Out node configuration requires an interface to be present for that node.
        When the response fails with an error that indicates the node configuration is invalid, this function will retry
        the request including the removal node configuration.
        The function will retry only once to avoid potential infinite loops.
        :param mso_l3out_template: MSOTemplate instance for the L3Out template
        :param ops: List of operations to send to the API
        :param ignore_errors: List of error strings to ignore
        :param state: Desired state of the L3Out interface (present, absent)
        :param remove_operations: Dictionary of Remove Operations to remove the node configuration if the interface is absent
            The key in this dictionary is set the error string that indicates which node configuration is invalid.
            The value is set to the PATCH operation to remove the node configuration.
        :return: Response from the MSO request
        """

        if state == "absent":
            # When the last interface from a node is deleted the node configuration must also be removed
            response = self.request(mso_l3out_template.template_path, method="PATCH", data=ops, ignore_errors=ignore_errors)
            # When the response matches an error string from the ignore errors we need to remove the node configuration
            if response in ignore_errors:
                # Pop the operation from the remove_operations dictionary so it won't be used again
                # For VPC configurations the remove operations could potentially be multiple
                remove_op = remove_operations.pop(response)
                # 1. Insert the remove operation at the beginning of the ops list when no node removal operation is present in ops
                # 2. Insert the second node operation before the first node operation if index of the node is greater than the first node operation
                # Example: if ops are:
                # ["/l3outTemplate/l3outs/0/nodes/0", "/l3outTemplate/l3outs/0/sviInterfaces/0"]
                # and the remove operation is:
                # "/l3outTemplate/l3outs/0/nodes/1"
                # then the ops will be updated to:
                # ["/l3outTemplate/l3outs/0/nodes/1", "/l3outTemplate/l3outs/0/nodes/0", "/l3outTemplate/l3outs/0/sviInterfaces/0"]
                # because "/l3outTemplate/l3outs/0/nodes/1" > "/l3outTemplate/l3outs/0/nodes/0" == True
                # 3. Insert the second node operation after the first node operation if index of the node is smaller than the first node operation
                # Example: if ops are:
                # ["/l3outTemplate/l3outs/0/nodes/1", "/l3outTemplate/l3outs/0/sviInterfaces/0"]
                # and the remove operation is:
                # "/l3outTemplate/l3outs/0/nodes/0"
                # then the ops will be updated to:
                # ["/l3outTemplate/l3outs/0/nodes/1", "/l3outTemplate/l3outs/0/nodes/0", "/l3outTemplate/l3outs/0/sviInterfaces/0"]
                # because "/l3outTemplate/l3outs/0/nodes/0" > "/l3outTemplate/l3outs/0/nodes/1" == False
                # Scenario 3 is currently not possible because the API orders the node error by the node index.
                # This logic is put into place in case the ordering of the nodes in the API changes in the future.
                if len(ops) == 1 or remove_op.get("path", "") > ops[0].get("path", ""):
                    ops.insert(0, remove_op)
                else:
                    ops.insert(1, remove_op)

                # Remove the error from the ignore_errors list so it won't be retried again
                ignore_errors.remove(response)

                # Retry the request with the remove operation when there are still remove operations left
                # If there are no remove operations left, the request will be executed without the remove operation
                # and the response will be returned as is.
                if len(remove_operations) != 0:
                    return self.l3out_interface_request(mso_l3out_template, ops, ignore_errors, state, remove_operations)
            else:
                return response

        return self.request(mso_l3out_template.template_path, method="PATCH", data=ops)

    def query_objs(self, path, key=None, api_version="v1", **kwargs):
        """Query the MSO REST API for objects in a path"""
        found = []
        objs = self.request(path, api_version=api_version, method="GET")

        if not objs:
            return found

        if key is None:
            key = path

        if isinstance(objs, dict):
            if key not in objs:
                self.fail_json(msg="Key '{0}' missing from data".format(key), data=objs)
            objs_list = objs.get(key)
        else:
            objs_list = objs
        for obj in objs_list:
            for kw_key, kw_value in kwargs.items():
                if kw_value is None:
                    continue
                if isinstance(kw_value, dict):
                    obj_value = obj.get(kw_key)
                    if obj_value is not None and isinstance(obj_value, dict):
                        breakout = False
                        for kw_key_lvl2, kw_value_lvl2 in kw_value.items():
                            if obj_value.get(kw_key_lvl2) != kw_value_lvl2:
                                breakout = True
                                break
                        if breakout:
                            break
                    else:
                        break
                elif obj.get(kw_key) != kw_value:
                    break
            else:
                found.append(obj)

        return found

    def query_obj(self, path, api_version="v1", **kwargs):
        """Query the MSO REST API for the whole object at a path"""
        obj = self.request(path, api_version=api_version, method="GET")
        if obj == {}:
            return {}
        for kw_key, kw_value in kwargs.items():
            if kw_value is None:
                continue
            if isinstance(kw_value, dict):
                obj_value = obj.get(kw_key)
                if obj_value is not None and isinstance(obj_value, dict):
                    for kw_key_lvl2, kw_value_lvl2 in kw_value.items():
                        if obj_value.get(kw_key_lvl2) != kw_value_lvl2:
                            return {}
            elif obj.get(kw_key) != kw_value:
                return {}
        return obj

    def get_obj(self, path, api_version="v1", **kwargs):
        """Get a specific object from a set of MSO REST objects"""
        objs = self.query_objs(path, api_version=api_version, **kwargs)
        if len(objs) == 0:
            return {}
        if len(objs) > 1:
            self.fail_json(msg="More than one object matches unique filter: {0}".format(kwargs))
        return objs[0]

    def lookup_schema(self, schema, ignore_not_found_error=False):
        """Look up schema and return its id"""
        if schema is None:
            return schema

        schema_summary = self.query_objs("schemas/list-identity", key="schemas", displayName=schema)
        if not schema_summary and not ignore_not_found_error:
            self.fail_json(msg="Provided schema '{0}' does not exist.".format(schema))
        elif (not schema_summary or not schema_summary[0].get("id")) and ignore_not_found_error:
            self.module.warn("Provided schema '{0}' does not exist.".format(schema))
            return None
        schema_id = schema_summary[0].get("id")
        if not schema_id:
            self.fail_json(msg="Schema lookup failed for schema '{0}': '{1}'".format(schema, schema_id))
        return schema_id

    def lookup_domain(self, domain, ignore_not_found_error=False):
        """Look up a domain and return its id"""
        if domain is None:
            return domain

        d = self.get_obj("auth/domains", key="domains", name=domain)
        if not d and not ignore_not_found_error:
            self.fail_json(msg="Domain '{0}' is not a valid domain name.".format(domain))
        elif (not d or "id" not in d) and ignore_not_found_error:
            self.module.warn("Domain '{0}' is not a valid domain name.".format(domain))
            return None
        if "id" not in d:
            self.fail_json(msg="Domain lookup failed for domain '{0}': {1}".format(domain, d))
        return d.get("id")

    def lookup_roles(self, roles, ignore_not_found_error=False):
        """Look up roles and return their ids"""
        if roles is None:
            return roles

        ids = []
        for role in roles:
            access_type = "readWrite"
            try:
                role = ast.literal_eval(role)
                if isinstance(role, dict) and "name" in role:
                    name = role.get("name")
                    if role.get("access_type") == "read":
                        access_type = "readOnly"
            except ValueError:
                name = role

            r = self.get_obj("roles", name=name)
            if not r and not ignore_not_found_error:
                self.fail_json(msg="Role '{0}' is not a valid role name.".format(name))
            elif (not r or "id" not in r) and ignore_not_found_error:
                self.module.warn("Role '{0}' is not a valid role name.".format(name))
                return ids
            if "id" not in r:
                self.fail_json(msg="Role lookup failed for role '{0}': {1}".format(name, r))
            ids.append(dict(roleId=r.get("id"), accessType=access_type))
        return ids

    def lookup_site_type(self, site_data):
        """Get site type(AWS, AZURE or physical)"""
        site_type = site_data.get("platform")
        if site_type == "cloud":
            self.cloud_provider_type = site_data.get("cloudProviders")[0]
        self.site_type = site_type

    def lookup_site(self, site, ignore_not_found_error=False):
        """Look up a site and return its id"""
        if site is None:
            return site

        s = self.get_obj("sites", name=site)
        if not s and not ignore_not_found_error:
            self.fail_json(msg="Site '{0}' is not a valid site name.".format(site))
        elif (not s or "id" not in s) and ignore_not_found_error:
            self.module.warn("Site '{0}' is not a valid site name.".format(site))
            return None
        if "id" not in s:
            self.fail_json(msg="Site lookup failed for site '{0}': {1}".format(site, s))

        self.lookup_site_type(s)
        return s.get("id")

    def lookup_sites(self, sites, ignore_not_found_error=False):
        """Look up sites and return their ids"""
        if sites is None:
            return sites

        ids = []
        for site in sites:
            s = self.get_obj("sites", name=site)
            if not s and not ignore_not_found_error:
                self.fail_json(msg="Site '{0}' is not a valid site name.".format(site))
            elif (not s or "id" not in s) and ignore_not_found_error:
                self.module.warn("Site '{0}' is not a valid site name.".format(site))
                return ids
            if "id" not in s:
                self.fail_json(msg="Site lookup failed for site '{0}': {1}".format(site, s))
            ids.append(dict(siteId=s.get("id"), securityDomains=[]))
        return ids

    def lookup_tenant(self, tenant, ignore_not_found_error=False):
        """Look up a tenant and return its id"""
        if tenant is None:
            return tenant

        t = self.get_obj("tenants", key="tenants", name=tenant)
        if not t and not ignore_not_found_error:
            self.fail_json(msg="Tenant '{0}' is not valid tenant name.".format(tenant))
        elif (not t or "id" not in t) and ignore_not_found_error:
            self.module.warn("Tenant '{0}' is not valid tenant name.".format(tenant))
            return None
        if "id" not in t:
            self.fail_json(msg="Tenant lookup failed for tenant '{0}': {1}".format(tenant, t))
        return t.get("id")

    def lookup_remote_location(self, remote_location, ignore_not_found_error=False):
        """Look up a remote location and return its path and id"""
        if remote_location is None:
            return None

        remote = self.get_obj("platform/remote-locations", key="remoteLocations", name=remote_location)
        if "id" not in remote and not ignore_not_found_error:
            self.fail_json(msg="No remote location found for remote '{0}'".format(remote_location))
        elif "id" not in remote and ignore_not_found_error:
            self.module.warn("No remote location found for remote '{0}'".format(remote_location))
            return dict()
        remote_info = dict(id=remote.get("id"), path=remote.get("credential")["remotePath"])
        return remote_info

    def lookup_users(self, users, ignore_not_found_error=False):
        """Look up users and return their ids"""
        # Ensure tenant has at least admin user
        if users is None:
            users = ["admin"]
        elif "admin" not in users:
            users.append("admin")

        ids = []
        if self.platform == "nd":
            remote_users = self.nd_request("/nexus/infra/api/aaa/v4/remoteusers", method="GET", ignore_not_found_error=True)
            local_users = self.nd_request("/nexus/infra/api/aaa/v4/localusers", method="GET", ignore_not_found_error=True)

            # To handle the issue in ND 4.0 related to querying local and remote users, new API endpoints have been introduced.
            # These endpoints should be removed once the official ND API endpoints become operational.
            if remote_users == {} and local_users == {}:
                remote_users = self.nd_request("/api/config/class/remoteusers", method="GET")
                local_users = self.nd_request("/api/config/class/localusers", method="GET")

        for user in users:
            user_dict = dict()
            if self.platform == "nd":
                user_dict = self.get_user_from_list_of_users(user, local_users)
                if user_dict is None:
                    user_dict = self.get_user_from_list_of_users(user, remote_users)
            else:
                user_dict = self.get_obj("users", username=user)
            if not user_dict and not ignore_not_found_error:
                self.fail_json(msg="User '{0}' is not a valid user name.".format(user))
            elif (not user_dict or "id" not in user_dict) and ignore_not_found_error:
                self.module.warn("User '{0}' is not a valid user name.".format(user))
                return ids
            if "id" not in user_dict:
                if "userID" not in user_dict:
                    self.fail_json(msg="User lookup failed for user '{0}': {1}".format(user, user_dict))
                id = dict(userId=user_dict.get("userID"))
            else:
                id = dict(userId=user_dict.get("id"))
            if id in ids:
                self.fail_json(msg="User '{0}' is duplicate.".format(user))
            ids.append(id)
        return ids

    def get_user_from_list_of_users(self, user_name, users, login_domain=""):
        """Get user from the ND users API response object"""
        if isinstance(users, dict):
            for user in users.get("items"):
                if (
                    user.get("spec")
                    and user.get("spec").get("loginID") == user_name
                    and ((login_domain == "" and user.get("spec").get("loginDomain") is None) or user.get("spec").get("loginDomain") == login_domain)
                ):
                    return user.get("spec")
        else:
            # Handling a list of user objects is a temporary workaround that should be removed.
            # Once the ND official local and remote user API endpoints are operational.
            for user in users:
                if (user.get("loginid") == user_name or user.get("loginID") == user_name) and (
                    (login_domain == "" and user.get("logindomain") is None) or user.get("logindomain") == login_domain
                ):
                    return user
        return None

    def lookup_remote_users(self, remote_users, ignore_not_found_error=False):
        ids = []
        if self.platform == "nd":
            remote_users_data = self.nd_request("/nexus/infra/api/aaa/v4/remoteusers", method="GET", ignore_not_found_error=True)

            # To handle the issue in ND 4.0 related to querying local and remote users, new API endpoints have been introduced.
            # These endpoints should be removed once the official ND API endpoints become operational.
            if remote_users_data == {}:
                remote_users_data = self.nd_request("/api/config/class/remoteusers", method="GET")

        for remote_user in remote_users:
            user_dict = dict()
            if self.platform == "nd":
                user_dict = self.get_user_from_list_of_users(remote_user.get("name"), remote_users_data, remote_user.get("login_domain"))
            if not user_dict and not ignore_not_found_error:
                self.fail_json(msg="User '{0}' is not a valid user name.".format(remote_user.get("name")))
            elif (not user_dict or "id" not in user_dict) and ignore_not_found_error:
                self.module.warn("User '{0}' is not a valid user name.".format(remote_user.get("name")))
                return ids
            if "id" not in user_dict:
                if "userID" not in user_dict:
                    self.fail_json(msg="User lookup failed for user '{0}': {1}".format(remote_user.get("name"), user_dict))
                id = dict(userId=user_dict.get("userID"))
            else:
                id = dict(userId=user_dict.get("id"))
            if id in ids:
                self.fail_json(msg="User '{0}' is duplicate.".format(remote_user.get("name")))
            ids.append(id)
        return ids

    def create_label(self, label, label_type):
        """Create a new label"""
        return self.request("labels", method="POST", data=dict(displayName=label, type=label_type))

    def lookup_labels(self, labels, label_type, ignore_not_found_error=False):
        """Look up labels and return their ids (create if necessary)"""
        if labels is None:
            return None

        ids = []
        for label in labels:
            label_obj = self.get_obj("labels", displayName=label)
            if not label_obj:
                label_obj = self.create_label(label, label_type)
            if "id" not in label_obj and not ignore_not_found_error:
                self.fail_json(msg="Label lookup failed for label '{0}': {1}".format(label, label_obj))
            elif "id" not in label_obj and ignore_not_found_error:
                self.module.warn("Label lookup failed for label '{0}': {1}".format(label, label_obj))
                return ids
            ids.append(label_obj.get("id"))
        return ids

    def anp_ref(self, **data):
        """Create anpRef string"""
        return "/schemas/{schema_id}/templates/{template}/anps/{anp}".format(**data)

    def epg_ref(self, **data):
        """Create epgRef string"""
        return "/schemas/{schema_id}/templates/{template}/anps/{anp}/epgs/{epg}".format(**data)

    def bd_ref(self, **data):
        """Create bdRef string"""
        return "/schemas/{schema_id}/templates/{template}/bds/{bd}".format(**data)

    def contract_ref(self, **data):
        """Create contractRef string"""
        # Support the contract argspec
        if "name" in data:
            data["contract"] = data.get("name")
        return "/schemas/{schema_id}/templates/{template}/contracts/{contract}".format(**data)

    def filter_ref(self, **data):
        """Create a filterRef string"""
        return "/schemas/{schema_id}/templates/{template}/filters/{filter}".format(**data)

    def vrf_ref(self, **data):
        """Create vrfRef string"""
        return "/schemas/{schema_id}/templates/{template}/vrfs/{vrf}".format(**data)

    def l3out_ref(self, **data):
        """Create l3outRef string"""
        return "/schemas/{schema_id}/templates/{template}/l3outs/{l3out}".format(**data)

    def ext_epg_ref(self, **data):
        """Create extEpgRef string"""
        return "/schemas/{schema_id}/templates/{template}/externalEpgs/{external_epg}".format(**data)

    def service_graph_ref(self, **data):
        """Create serviceGraphRef string"""
        return "/schemas/{schema_id}/templates/{template}/serviceGraphs/{service_graph}".format(**data)

    def vrf_dict_from_ref(self, data):
        vrf_ref_regex = re.compile(r"\/schemas\/(.*)\/templates\/(.*)\/vrfs\/(.*)")
        vrf_dict = vrf_ref_regex.search(data)
        return {
            "vrfName": vrf_dict.group(3),
            "schemaId": vrf_dict.group(1),
            "templateName": vrf_dict.group(2),
        }

    def dict_from_ref(self, data):
        if data and data != "":
            ref_regex = re.compile(r"\/schemas\/(.*)\/templates\/(.*?)\/(.*?)\/(.*)")
            dic = ref_regex.search(data)
            if dic is not None:
                schema_id = dic.group(1)
                template_name = dic.group(2)
                category = dic.group(3)
                name = dic.group(4)
                uri_map = {
                    "vrfs": ["vrfName", "schemaId", "templateName"],
                    "bds": ["bdName", "schemaId", "templateName"],
                    "filters": ["filterName", "schemaId", "templateName"],
                    "contracts": ["contractName", "schemaId", "templateName"],
                    "l3outs": ["l3outName", "schemaId", "templateName"],
                    "anps": ["anpName", "schemaId", "templateName"],
                    "serviceGraphs": ["serviceGraphName", "schemaId", "templateName"],
                    "serviceNode": ["serviceNodeName", "schemaId", "templateName", "serviceGraphName"],
                }
                result = {
                    uri_map[category][1]: schema_id,
                    uri_map[category][2]: template_name,
                }

                self.recursive_dict_from_ref_regex(name, result, uri_map[category][0])

                return result
            else:
                ref_regex = re.compile(r"uni\/tn-(.*)\/out-(.*)")
                dic = ref_regex.search(data)
                if dic is not None:
                    return {"l3outName": dic.group(2), "tenant": dic.group(1)}
                self.fail_json(msg="There was no group in search: {data}".format(data=data))

    def recursive_dict_from_ref_regex(self, data, result, category):
        continued_ref_regex = re.compile(r"(.*?)\/([a-zA-Z]+.*)")
        section_ref_regex = re.compile(r"([a-zA-Z]+)\/(.*)")
        dic_name = continued_ref_regex.search(data)
        if dic_name is not None:
            result[category] = dic_name.group(1)
            next_section = dic_name.group(2)
            dic_next_section = section_ref_regex.search(next_section)
            if dic_next_section is not None:
                next_name = dic_next_section.group(2)
                self.recursive_dict_from_ref_regex(next_name, result, dic_next_section.group(1).rstrip("s") + "Name")
        else:
            result[category] = data

    def recursive_dict_from_ref(self, data):
        for key in data:
            if key.endswith("Ref"):
                data[key] = self.dict_from_ref(data.get(key))
            if isinstance(data[key], list):
                for item in data[key]:
                    self.recursive_dict_from_ref(item)
        return data

    def make_reference(self, data, reftype, schema_id, template):
        """Create a reference from a dictionary"""
        # Removes entry from payload
        if data is None:
            return None

        if data.get("schema") is not None:
            schema_obj = self.get_obj("schemas", displayName=data.get("schema"))
            if not schema_obj:
                self.fail_json(msg="Referenced schema '{schema}' in {reftype}ref does not exist".format(reftype=reftype, **data))
            schema_id = schema_obj.get("id")

        if data.get("template") is not None:
            template = data.get("template")

        refname = "%sName" % reftype

        return {
            refname: data.get("name"),
            "schemaId": schema_id,
            "templateName": template,
        }

    def make_subnets(self, data, is_bd_subnet=True):
        """Create a subnets list from input"""
        if data is None:
            return None

        subnets = []
        for subnet in data:
            if "subnet" in subnet:
                subnet["ip"] = subnet.get("subnet")
            if subnet.get("description") is None:
                subnet["description"] = subnet.get("subnet")
            subnet_payload = dict(
                ip=subnet.get("ip"),
                description=str(subnet.get("description")),
                scope=subnet.get("scope"),
                shared=subnet.get("shared"),
                noDefaultGateway=subnet.get("no_default_gateway"),
            )
            if is_bd_subnet:
                subnet_payload.update(dict(querier=subnet.get("querier"), primary=subnet.get("primary"), virtual=subnet.get("virtual")))
            subnets.append(subnet_payload)

        return subnets

    def make_dhcp_label(self, data):
        """Create a DHCP policy from input"""
        if data is None:
            return None
        if isinstance(data, list):
            dhcps = []
            for dhcp in data:
                if "dhcp_option_policy" in dhcp:
                    dhcp["dhcpOptionLabel"] = dhcp.get("dhcp_option_policy")
                    del dhcp["dhcp_option_policy"]
                dhcps.append(dhcp)
            return dhcps
        if "version" in data:
            data["version"] = int(data.get("version"))
        if data and "dhcp_option_policy" in data:
            dhcp_option_policy = data.get("dhcp_option_policy")
            if dhcp_option_policy is not None and "version" in dhcp_option_policy:
                dhcp_option_policy["version"] = int(dhcp_option_policy.get("version"))
            data["dhcpOptionLabel"] = dhcp_option_policy
            del data["dhcp_option_policy"]
        return data

    def sanitize(self, updates, collate=False, required=None, unwanted=None):
        """Clean up unset keys from a request payload"""
        if required is None:
            required = []
        if unwanted is None:
            unwanted = []
        self.proposed = deepcopy(self.existing)
        self.sent = deepcopy(self.existing)

        if isinstance(self.existing, dict):
            for key in self.existing:
                # Remove References
                if key.endswith("Ref"):
                    if key in required:
                        continue
                    self.proposed.pop(key, None)
                    self.sent.pop(key, None)
                    continue

                # Removed unwanted keys
                elif key in unwanted:
                    self.proposed.pop(key, None)
                    self.sent.pop(key, None)
                    continue

        if isinstance(updates, dict):
            # Clean up self.sent
            for key in updates:
                # Always retain 'id'
                if key in required:
                    if key in self.existing or updates.get(key) is not None:
                        self.sent[key] = updates.get(key)
                    continue

                # Remove unspecified values
                elif not collate and updates.get(key) is None:
                    if key in self.existing:
                        self.sent.pop(key, None)
                    continue

                # Remove identical values
                elif not collate and updates.get(key) == self.existing.get(key):
                    self.sent.pop(key, None)
                    continue

                # Add everything else
                if updates.get(key) is not None:
                    self.sent[key] = updates.get(key)

            # Update self.proposed
            self.proposed.update(self.sent)

        elif updates is not None:
            self.sent = updates
            # Update self.proposed
            self.proposed = self.sent

    def delete_keys_from_dict(self, dict_to_sanitize, keys):
        # TODO investigate combine this method above sanitize method
        copy = deepcopy(dict_to_sanitize)
        for (
            k,
            v,
        ) in copy.items():
            if k in keys:
                del dict_to_sanitize[k]
            elif isinstance(v, dict):
                dict_to_sanitize[k] = self.delete_keys_from_dict(v, keys)
            elif isinstance(v, list):
                for index, item in enumerate(v):
                    if isinstance(item, dict):
                        dict_to_sanitize[k][index] = self.delete_keys_from_dict(item, keys)
        return dict_to_sanitize

    def exit_json(self, **kwargs):
        """Custom written method to exit from module."""

        if self.params.get("state") in ("absent", "present", "upload", "restore", "download", "move", "clone"):
            if self.params.get("output_level") in ("debug", "info"):
                self.result["previous"] = self.previous
            # FIXME: Modified header only works for PATCH
            if not self.has_modified and self.previous != self.existing:
                self.result["changed"] = True
        if self.stdout:
            self.result["stdout"] = self.stdout

        # Return the gory details when we need it
        if self.params.get("output_level") == "debug":
            self.result["method"] = self.method
            self.result["response"] = self.response
            self.result["status"] = self.status
            self.result["url"] = self.url
            self.result["httpapi_logs"] = self.httpapi_logs
            self.result["socket"] = self.module._socket_path

            if self.params.get("state") in ("absent", "present"):
                self.result["sent"] = self.sent
                self.result["proposed"] = self.proposed

                if self.method == "PATCH":
                    self.result["patch_operation"] = self.patch_operation

        self.result["current"] = self.existing

        if self.module._diff and self.result.get("changed") is True:
            self.result["diff"] = dict(
                before=self.previous,
                after=self.existing,
            )

        self.result.update(**kwargs)
        self.module.exit_json(**self.result)

    def fail_json(self, msg, **kwargs):
        """Custom written method to return info on failure."""

        if self.params.get("state") in ("absent", "present"):
            if self.params.get("output_level") in ("debug", "info"):
                self.result["previous"] = self.previous
            # FIXME: Modified header only works for PATCH
            if not self.has_modified and self.previous != self.existing:
                self.result["changed"] = True
        if self.stdout:
            self.result["stdout"] = self.stdout

        # Return the gory details when we need it
        if self.params.get("output_level") == "debug":
            if self.url is not None:
                self.result["method"] = self.method
                self.result["response"] = self.response
                self.result["status"] = self.status
                self.result["url"] = self.url
                self.result["httpapi_logs"] = self.httpapi_logs
                self.result["socket"] = self.module._socket_path

            if self.params.get("state") in ("absent", "present"):
                self.result["sent"] = self.sent
                self.result["proposed"] = self.proposed

                if self.method == "PATCH":
                    self.result["patch_operation"] = self.patch_operation

        self.result["current"] = self.existing

        self.result.update(**kwargs)
        self.module.fail_json(msg=msg, **self.result)

    def check_changed(self):
        """Check if changed by comparing new values from existing"""
        existing = self.existing
        if "password" in existing:
            existing["password"] = self.sent.get("password")

        existing = self.remove_keys_from_dict_when_value_empty(existing)
        self.stdout = json.dumps(existing)

        return not issubset(self.sent, existing)

    def update_service_graph_obj(self, service_graph_obj):
        """update filter with more information"""
        service_graph_obj["serviceGraphRef"] = self.dict_from_ref(service_graph_obj.get("serviceGraphRef"))
        for service_node in service_graph_obj["serviceNodesRelationship"]:
            service_node.get("consumerConnector")["bdRef"] = self.dict_from_ref(service_node.get("consumerConnector").get("bdRef"))
            service_node.get("providerConnector")["bdRef"] = self.dict_from_ref(service_node.get("providerConnector").get("bdRef"))
            service_node["serviceNodeRef"] = self.dict_from_ref(service_node.get("serviceNodeRef"))
        if service_graph_obj.get("serviceGraphContractRelationRef"):
            del service_graph_obj["serviceGraphContractRelationRef"]

    def update_filter_obj(self, contract_obj, filter_obj, filter_type, contract_display_name=None, update_filter_ref=True):
        """update filter with more information"""
        if update_filter_ref:
            filter_obj["filterRef"] = self.dict_from_ref(filter_obj.get("filterRef"))
        if contract_display_name:
            filter_obj["displayName"] = contract_display_name
        else:
            filter_obj["displayName"] = contract_obj.get("displayName")
        filter_obj["filterType"] = filter_type
        filter_obj["contractScope"] = contract_obj.get("scope")
        filter_obj["contractFilterType"] = contract_obj.get("filterType")
        # Conditional statement 'description == ""' is needed to set empty string.
        if contract_obj.get("description") or contract_obj.get("description") == "":
            filter_obj["description"] = contract_obj.get("description")
        # Conditional statement is needed to determine if "prio" exist in contract object.
        # Same reason as described mso_schema_template_contract_filter.py.
        if contract_obj.get("prio"):
            filter_obj["prio"] = contract_obj.get("prio")

    def query_schema(self, schema):
        schema_id = self.lookup_schema(schema)
        schema_path = "schemas/{0}".format(schema_id)
        schema_obj = self.query_obj(schema_path, displayName=schema)
        if not schema_obj:
            self.module.fail_json(msg="Schema '{0}' is not a valid schema name.".format(schema))
        return schema_id, schema_path, schema_obj

    def query_schema_by_id(self, schema_id):
        schema_path = "schemas/{0}".format(schema_id)
        schema_obj = self.query_obj(schema_path)
        if not schema_obj:
            self.module.fail_json(msg="Schema '{0}' is not a valid schema ID.".format(schema_id))
        return schema_id, schema_path, schema_obj

    def query_service_node_types(self):
        node_objs = self.query_objs("schemas/service-node-types", key="serviceNodeTypes")
        if not node_objs:
            self.module.fail_json(msg="Service node types do not exist")
        return node_objs

    def lookup_service_node_device(self, site_id, tenant, device_name=None, service_node_type=None, ignore_not_found_error=False):
        if self.site_type == "cloud":
            tenant = "{0}/{1}".format(tenant, self.site_type)

        if service_node_type is None:
            node_devices = self.query_objs("sites/{0}/aci/tenants/{1}/devices".format(site_id, tenant), key="devices")
        else:
            node_devices = self.query_objs("sites/{0}/aci/tenants/{1}/devices?deviceType={2}".format(site_id, tenant, service_node_type), key="devices")
        if device_name is not None:
            for device in node_devices:
                if device_name == device.get("name"):
                    return device
            if ignore_not_found_error:
                self.module.warn("Provided device '{0}' of type '{1}' does not exist.".format(device_name, service_node_type))
                return node_devices
            else:
                self.module.fail_json(msg="Provided device '{0}' of type '{1}' does not exist.".format(device_name, service_node_type))
        return node_devices

    # Workaround function due to inconsistency in attributes REQUEST/RESPONSE API
    # Fix for MSO Error 400: Bad Request: (0)(0)(0)(0)/deploymentImmediacy error.path.missing
    def find_dicts_with_target_key(self, target_dict, target, replace, result=None):
        if result is None:
            result = []

        for key, value in target_dict.items():
            if key == target:
                result.append(target_dict)
            if isinstance(value, dict):
                self.find_dicts_with_target_key(value, target, replace, result)
            if isinstance(value, list):
                for entry in value:
                    if isinstance(entry, dict):
                        self.find_dicts_with_target_key(entry, target, replace, result)

        return result

    # Workaround function due to inconsistency in attributes REQUEST/RESPONSE API
    # Fix for MSO Error 400: Bad Request: (0)(0)(0)(0)/deploymentImmediacy error.path.missing
    def replace_keys_in_dict(self, target, replace, target_dict=None):
        if target_dict is None:
            target_dict = self.existing

        key_list = self.find_dicts_with_target_key(target_dict, target, replace)
        for item in key_list:
            item[replace] = item.get(target)
            del item[target]

    # Workaround function to remove null/None fields returned by API RESPONSE
    def remove_keys_from_dict_when_value_empty(self, target_dict, modified_target=None):
        if modified_target is None:
            modified_target = deepcopy(target_dict)

        for key, value in target_dict.items():
            if value is None:
                del modified_target[key]
            elif isinstance(value, dict):
                self.remove_keys_from_dict_when_value_empty(value, modified_target[key])
            elif isinstance(value, list):
                for entry_index, entry in enumerate(value):
                    if isinstance(entry, dict):
                        self.remove_keys_from_dict_when_value_empty(entry, modified_target[key][entry_index])

        return modified_target

    def validate_schema(self, schema_id):
        return self.request("schemas/{id}/validate".format(id=schema_id), method="GET")

    def input_validation(self, attr_name, attr_value, required_attributes, target_object, object_position=None, object_name=None):
        if attr_name in (None, "") or attr_value in (None, ""):
            self.module.fail_json(msg="The attribute and value must be set")

        empty_attributes = [attribute for attribute in required_attributes if target_object.get(attribute) in (None, "", [], {}, 0)]

        if object_position is not None and object_name is not None and empty_attributes:
            self.module.fail_json(
                msg="When the '{0}' is '{1}', the {2} attributes must be set at the object position: {3} and the object name: {4}".format(
                    attr_name, attr_value, empty_attributes, object_position, object_name
                )
            )
        elif object_position is not None and object_name is None and empty_attributes:
            self.module.fail_json(
                msg="When the '{0}' is '{1}', the {2} attributes must be set at the object position: {3}".format(
                    attr_name, attr_value, empty_attributes, object_position
                )
            )
        elif object_position is None and object_name is not None and empty_attributes:
            self.module.fail_json(
                msg="When the '{0}' is '{1}', the {2} attributes must be set and the object name: {3}".format(
                    attr_name, attr_value, empty_attributes, object_name
                )
            )
        elif empty_attributes:
            self.module.fail_json(msg="When the '{0}' is '{1}', the {2} attributes must be set".format(attr_name, attr_value, empty_attributes))

    # Temporarily introduced method to handle nd specific query without introducing a dependency on the nd collection in code
    # Copied method from the nd collection: https://github.com/CiscoDevNet/ansible-nd/blob/master/plugins/module_utils/nd.py#L221
    # TODO: Refactor the code for bundled nd collection
    def nd_request(self, path, method=None, data=None, file=None, qs=None, prefix="", file_key="file", output_format="json", ignore_not_found_error=False):
        """Generic HTTP method for ND requests."""
        self.path = path

        if method is not None:
            self.method = method

        # If we PATCH with empty operations, return
        if method == "PATCH" and not data:
            return {}

        conn = Connection(self.module._socket_path)
        conn.set_params(self.params)
        uri = self.path
        if prefix != "":
            uri = "{0}/{1}".format(prefix, self.path)
        if qs is not None:
            uri = uri + update_qs(qs)
        try:
            if file is not None:
                info = conn.send_file_request(method, uri, file, data, None, file_key)
            else:
                if data:
                    info = conn.send_request(method, uri, json.dumps(data))
                else:
                    info = conn.send_request(method, uri)
            self.result["data"] = data

            self.url = info.get("url")
            self.httpapi_logs.extend(conn.pop_messages())
            info.pop("date", None)
        except Exception as e:
            try:
                error_obj = json.loads(to_text(e))
            except Exception:
                error_obj = dict(error=dict(code=-1, message="Unable to parse error output as JSON. Raw error message: {0}".format(e), exception=to_text(e)))
                pass
            self.fail_json(msg=error_obj["error"]["message"])

        self.response = info.get("msg")
        self.status = info.get("status", -1)

        self.result["socket"] = self.module._socket_path

        # Get change status from HTTP headers
        if "modified" in info:
            self.has_modified = True
            if info.get("modified") == "false":
                self.result["changed"] = False
            elif info.get("modified") == "true":
                self.result["changed"] = True

        # 200: OK, 201: Created, 202: Accepted, 204: No Content
        if self.status in (200, 201, 202, 204):
            if output_format == "raw":
                return info.get("raw")
            return info.get("body")

        # 404: Not Found
        elif self.method == "DELETE" and self.status == 404:
            return {}

        # 400: Bad Request, 401: Unauthorized, 403: Forbidden,
        # 405: Method Not Allowed, 406: Not Acceptable
        # 500: Internal Server Error, 501: Not Implemented
        elif self.status >= 400:
            self.result["status"] = self.status
            body = info.get("body")
            if body is not None:
                try:
                    if isinstance(body, dict):
                        payload = body
                    else:
                        payload = json.loads(body)
                except Exception as e:
                    self.error = dict(code=-1, message="Unable to parse output as JSON, see 'raw' output. {0}".format(e))
                    self.result["raw"] = body
                    self.fail_json(msg="ND Error: {0}".format(self.error.get("message")), data=data, info=info)
                self.error = payload
                if "code" in payload:
                    self.fail_json(msg="ND Error {code}: {message}".format(**payload), data=data, info=info, payload=payload)
                elif "messages" in payload and len(payload.get("messages")) > 0:
                    self.fail_json(msg="ND Error {code} ({severity}): {message}".format(**payload["messages"][0]), data=data, info=info, payload=payload)
                else:
                    if ignore_not_found_error:
                        return {}
                    self.fail_json(msg="ND Error: Unknown error no error code in decoded payload".format(**payload), data=data, info=info, payload=payload)
            elif not ignore_not_found_error:
                self.result["raw"] = info.get("raw")
                # Connection error
                msg = "Connection failed for {0}. {1}".format(info.get("url"), info.get("msg"))
                self.error = msg
                self.fail_json(msg=msg)
            return {}

    def verify_time_format(self, date_time):
        if date_time != "now" or date_time != "infinite":
            try:
                formatted_date_time = datetime.datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S")
                return str(formatted_date_time)
            except ValueError:
                return self.fail_json(msg="ERROR: The time must be in 'YYYY-MM-DD HH:MM:SS' format.")

    def get_site_interface_details(self, site_id=None, uuid=None, node=None, port=None, port_channel_uuid=None, virtual_port_channel_uuid=None):
        if port_channel_uuid:
            path = "/pcsummary/site/{0}?uuid={1}".format(site_id, port_channel_uuid)
        elif virtual_port_channel_uuid:
            path = "/vpcsummary/site/{0}?uuid={1}".format(site_id, virtual_port_channel_uuid)
        elif uuid:
            path = "/sitephysifsummary/site/{0}?uuid={1}".format(site_id, uuid)
        elif node:
            path = "/sitephysifsummary/site/{0}?node={1}".format(site_id, node)

        site_data = self.request(path, method="GET")

        if port_channel_uuid:
            if site_data.get("spec", {}).get("pcs"):
                return site_data.get("spec", {}).get("pcs")[0]
            self.fail_json(msg="The site port channel interface not found. Site ID: {0} and UUID: {1}".format(site_id, port_channel_uuid))
        elif virtual_port_channel_uuid:
            if site_data.get("spec", {}).get("vpcs"):
                return site_data.get("spec", {}).get("vpcs")[0]
            self.fail_json(msg="The site virtual port channel interface not found. Site ID: {0} and UUID: {1}".format(site_id, virtual_port_channel_uuid))
        elif uuid:
            if site_data.get("spec", {}).get("monitoringTemplateInterfaces"):
                return site_data.get("spec", {}).get("monitoringTemplateInterfaces", [])[0]
            else:
                self.fail_json(msg="The site port interface not found. Site ID: {0} and UUID: {1}".format(site_id, uuid))
        elif node and port:
            for interface in site_data.get("spec", {}).get("interfaces", []):
                # To ensure consistency between the API response data and the input data by converting the node to a string
                if interface.get("port") == port and str(interface.get("node")) == str(node):
                    return interface
            self.fail_json(msg="The site port interface not found. Site ID: {0}, Node: {1} and Path: {2}".format(site_id, node, port))
        elif node:
            pod_ids = list(set([interface.get("pod") for interface in site_data.get("spec", {}).get("interfaces", [])]))
            if len(pod_ids) == 1:
                # All physical interfaces of a node should belong to the same POD.
                return pod_ids[0]
            elif len(pod_ids) == 0:
                self.fail_json(msg="The site and node not found. Site ID: {0} and Node: {1}".format(site_id, node))
            elif len(pod_ids) > 1:
                # This scenario should never be possible but is added in case of faulty return data.
                self.fail_json(msg="The site and node are found with multiple POD IDs. Site ID: {0}, Node: {1}, POD IDs: {2}".format(site_id, node, pod_ids))

        return {}

    def check_template_when_name_is_provided(self, parameter):
        if parameter and parameter.get("name") and not (parameter.get("template") or parameter.get("template_id")):
            self.fail_json(msg="Either 'template' or 'template_id' associated with '{}' must be provided".format(parameter.get("name")))


def service_node_ref_str_to_dict(serviceNodeRefStr):
    serviceNodeRefTokens = serviceNodeRefStr.split("/")
    return dict(
        schemaId=serviceNodeRefTokens[2],
        serviceGraphName=serviceNodeRefTokens[6],
        serviceNodeName=serviceNodeRefTokens[8],
        templateName=serviceNodeRefTokens[4],
    )


def mso_schema_site_contract_service_graph_spec():
    return dict(
        cluster_interface_device=dict(type="str", required=True, aliases=["cluster_device", "device", "device_name"]),
        provider_connector_cluster_interface=dict(
            type="str", required=True, aliases=["provider_cluster_interface", "provider_interface", "provider_interface_name"]
        ),
        provider_connector_redirect_policy_tenant=dict(type="str", aliases=["provider_redirect_policy_tenant", "provider_tenant"]),
        provider_connector_redirect_policy=dict(type="str", aliases=["provider_redirect_policy", "provider_policy"]),
        consumer_connector_cluster_interface=dict(
            type="str", required=True, aliases=["consumer_cluster_interface", "consumer_interface", "consumer_interface_name"]
        ),
        consumer_connector_redirect_policy_tenant=dict(type="str", aliases=["consumer_redirect_policy_tenant", "consumer_tenant"]),
        consumer_connector_redirect_policy=dict(type="str", aliases=["consumer_redirect_policy", "consumer_policy"]),
        consumer_subnet_ips=dict(type="list", elements="str"),
    )


def listener_ssl_certificates_spec():
    return dict(
        name=dict(type="str", required=True),
        certificate_store=dict(type="str", choices=["default", "iam", "acm"], required=True),
    )


def listener_rules_provider_epg_ref_spec():
    return dict(
        schema=dict(type="str"),
        template=dict(type="str"),
        anp_name=dict(type="str", required=True, aliases=["anp"]),
        epg_name=dict(type="str", required=True, aliases=["epg"]),
    )


def listener_rules_health_check_spec():
    return dict(
        port=dict(type="int"),
        protocol=dict(type="str", choices=LISTENER_PROTOCOLS),
        path=dict(type="str"),
        interval=dict(type="int"),
        timeout=dict(type="int"),
        unhealthy_threshold=dict(type="int"),
        use_host_from_rule=dict(type="bool"),
        success_code=dict(type="str"),
        host=dict(type="str"),
    )


def listener_rules_spec():
    return dict(
        name=dict(type="str", required=True),
        floating_ip=dict(type="str"),
        priority=dict(type="int", required=True),
        host=dict(type="str"),
        path=dict(type="str"),
        action=dict(type="str"),
        action_type=dict(type="str", required=True, choices=list(LISTENER_ACTION_TYPE_MAP)),
        content_type=dict(type="str", choices=list(LISTENER_CONTENT_TYPE_MAP)),
        port=dict(type="int"),
        protocol=dict(type="str", choices=LISTENER_PROTOCOLS),
        provider_epg=dict(
            type="dict",
            options=listener_rules_provider_epg_ref_spec(),
        ),
        url_type=dict(type="str", choices=["original", "custom"]),
        custom_url=dict(type="str"),
        redirect_host_name=dict(type="str"),
        redirect_path=dict(type="str"),
        redirect_query=dict(type="str"),
        response_code=dict(type="str"),
        response_body=dict(type="str"),
        redirect_protocol=dict(type="str", choices=LISTENER_PROTOCOLS),
        redirect_port=dict(type="int"),
        redirect_code=dict(type="str", choices=list(LISTENER_REDIRECT_CODE_MAP)),
        health_check=dict(
            type="dict",
            options=listener_rules_health_check_spec(),
        ),
        target_ip_type=dict(type="str", choices=["unspecified", "primary", "secondary"]),
    )


def epg_object_reference_spec(aliases=None):
    epg_reference_spec = dict(
        type="dict",
        options=dict(
            name=dict(type="str", required=True),
            template=dict(type="str"),
            template_id=dict(type="str"),
            schema=dict(type="str"),
            schema_id=dict(type="str"),
            anp=dict(type="str"),
            anp_uuid=dict(type="str"),
        ),
        required_one_of=[
            ["template", "template_id"],
            ["schema", "schema_id"],
            ["anp", "anp_uuid"],
        ],
        mutually_exclusive=[
            ("schema", "schema_id"),
            ("template", "template_id"),
            ("anp", "anp_uuid"),
        ],
    )
    if aliases:
        epg_reference_spec["aliases"] = aliases
    return epg_reference_spec
