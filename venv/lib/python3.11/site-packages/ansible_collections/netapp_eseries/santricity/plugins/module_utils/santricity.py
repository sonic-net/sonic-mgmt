# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import random
import mimetypes

from pprint import pformat
from ansible.module_utils import six
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.urls import open_url
from ansible.module_utils.api import basic_auth_argument_spec
from ansible.module_utils._text import to_native
try:
    from ansible.module_utils.ansible_release import __version__ as ansible_version
except ImportError:
    ansible_version = 'unknown'

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


def eseries_host_argument_spec():
    """Retrieve a base argument specification common to all NetApp E-Series modules"""
    argument_spec = basic_auth_argument_spec()
    argument_spec.update(dict(
        api_username=dict(type="str", required=True),
        api_password=dict(type="str", required=True, no_log=True),
        api_url=dict(type="str", required=True),
        ssid=dict(type="str", required=False, default="1"),
        validate_certs=dict(type="bool", required=False, default=True)
    ))
    return argument_spec


def eseries_proxy_argument_spec():
    """Retrieve a base argument specification common to all NetApp E-Series modules for proxy specific tasks"""
    argument_spec = basic_auth_argument_spec()
    argument_spec.update(dict(
        api_username=dict(type="str", required=True),
        api_password=dict(type="str", required=True, no_log=True),
        api_url=dict(type="str", required=True),
        validate_certs=dict(type="bool", required=False, default=True)
    ))
    return argument_spec


class NetAppESeriesModule(object):
    """Base class for all NetApp E-Series modules.

    Provides a set of common methods for NetApp E-Series modules, including version checking, mode (proxy, embedded)
    verification, http requests, secure http redirection for embedded web services, and logging setup.

    Be sure to add the following lines in the module's documentation section:
    extends_documentation_fragment:
        - santricity

    :param dict(dict) ansible_options: dictionary of ansible option definitions
    :param str web_services_version: minimally required web services rest api version (default value: "02.00.0000.0000")
    :param bool supports_check_mode: whether the module will support the check_mode capabilities (default=False)
    :param list(list) mutually_exclusive: list containing list(s) of mutually exclusive options (optional)
    :param list(list) required_if: list containing list(s) containing the option, the option value, and then a list of
        required options. (optional)
    :param list(list) required_one_of: list containing list(s) of options for which at least one is required. (optional)
    :param list(list) required_together: list containing list(s) of options that are required together. (optional)
    :param bool log_requests: controls whether to log each request (default: True)
    :param bool proxy_specific_task: controls whether ssid is a default option (default: False)
    """
    DEFAULT_TIMEOUT = 300
    DEFAULT_SECURE_PORT = "8443"
    DEFAULT_BASE_PATH = "devmgr/"
    DEFAULT_REST_API_PATH = "devmgr/v2/"
    DEFAULT_REST_API_ABOUT_PATH = "devmgr/utils/about"
    DEFAULT_HEADERS = {"Content-Type": "application/json", "Accept": "application/json",
                       "netapp-client-type": "Ansible-%s" % ansible_version}
    HTTP_AGENT = "Ansible / %s" % ansible_version
    SIZE_UNIT_MAP = dict(bytes=1, b=1, kb=1024, mb=1024**2, gb=1024**3, tb=1024**4,
                         pb=1024**5, eb=1024**6, zb=1024**7, yb=1024**8)

    HOST_TYPE_INDEXES = {"aix mpio": 9, "avt 4m": 5, "hp-ux": 15, "linux atto": 24, "linux dm-mp": 28, "linux pathmanager": 25, "solaris 10 or earlier": 2,
                         "solaris 11 or later": 17, "svc": 18, "ontap": 26, "mac": 22, "vmware": 10, "windows": 1, "windows atto": 23, "windows clustered": 8}

    def __init__(self, ansible_options, web_services_version=None, supports_check_mode=False,
                 mutually_exclusive=None, required_if=None, required_one_of=None, required_together=None,
                 log_requests=True, proxy_specific_task=False):

        if proxy_specific_task:
            argument_spec = eseries_proxy_argument_spec()
        else:
            argument_spec = eseries_host_argument_spec()

        argument_spec.update(ansible_options)

        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=supports_check_mode,
                                    mutually_exclusive=mutually_exclusive, required_if=required_if,
                                    required_one_of=required_one_of, required_together=required_together)

        args = self.module.params
        self.web_services_version = web_services_version if web_services_version else "02.00.0000.0000"

        if proxy_specific_task:
            self.ssid = "0"
        else:
            self.ssid = args["ssid"]
        self.url = args["api_url"]
        self.log_requests = log_requests
        self.creds = dict(url_username=args["api_username"],
                          url_password=args["api_password"],
                          validate_certs=args["validate_certs"])

        if not self.url.endswith("/"):
            self.url += "/"

        self.is_proxy_used_cache = None
        self.is_embedded_available_cache = None
        self.is_web_services_valid_cache = None

    def _check_ssid(self):
        """Verify storage system identifier exist on the proxy and, if not, then update to match storage system name."""
        try:
            rc, data = self._request(url=self.url + self.DEFAULT_REST_API_ABOUT_PATH, **self.creds)

            if data["runningAsProxy"]:
                if self.ssid.lower() not in ["proxy", "0"]:
                    try:
                        rc, systems = self._request(url=self.url + self.DEFAULT_REST_API_PATH + "storage-systems", **self.creds)
                        alternates = []
                        for system in systems:
                            if system["id"] == self.ssid:
                                break
                            elif system["name"] == self.ssid:
                                alternates.append(system["id"])
                        else:
                            if len(alternates) == 1:
                                self.module.warn("Array Id does not exist on Web Services Proxy instance! "
                                                 "However, there is a storage system with a matching name. "
                                                 "Updating Identifier. Array Name: [%s], Array Id [%s]." % (self.ssid, alternates[0]))
                                self.ssid = alternates[0]
                            else:
                                self.module.fail_json(msg="Array identifier does not exist on Web Services Proxy "
                                                          "instance! Array ID [%s]." % self.ssid)

                    except Exception as error:
                        self.module.fail_json(msg="Failed to determine Web Services Proxy storage systems! "
                                                  "Array [%s]. Error [%s]" % (self.ssid, to_native(error)))
        except Exception as error:
            # Don't fail here, if the ssid is wrong then it will fail on the next request. Causes issues for
            # na_santricity_auth module.
            pass

    def _check_web_services_version(self):
        """Verify proxy or embedded web services meets minimum version required for module.

        The minimum required web services version is evaluated against version supplied through the web services rest
        api. AnsibleFailJson exception will be raised when the minimum is not met or exceeded.

        This helper function will update the supplied api url if secure http is not used for embedded web services

        :raise AnsibleFailJson: raised when the contacted api service does not meet the minimum required version.
        """
        if not self.is_web_services_valid_cache:

            url_parts = urlparse(self.url)
            if not url_parts.scheme or not url_parts.netloc:
                self.module.fail_json(msg="Failed to provide valid API URL. "
                                          "Example: https://192.168.1.100:8443/devmgr/v2. URL [%s]." % self.url)

            if url_parts.scheme not in ["http", "https"]:
                self.module.fail_json(msg="Protocol must be http or https. URL [%s]." % self.url)

            self.url = "%s://%s/" % (url_parts.scheme, url_parts.netloc)
            about_url = self.url + self.DEFAULT_REST_API_ABOUT_PATH
            rc, data = request(about_url, timeout=self.DEFAULT_TIMEOUT, headers=self.DEFAULT_HEADERS, ignore_errors=True, force_basic_auth=False, **self.creds)

            if rc != 200:
                self.module.warn("Failed to retrieve web services about information! Retrying with secure ports. "
                                 "Array Id [%s]." % self.ssid)
                self.url = "https://%s:8443/" % url_parts.netloc.split(":")[0]
                about_url = self.url + self.DEFAULT_REST_API_ABOUT_PATH
                try:
                    rc, data = request(about_url, timeout=self.DEFAULT_TIMEOUT, headers=self.DEFAULT_HEADERS, **self.creds)
                except Exception as error:
                    self.module.fail_json(msg="Failed to retrieve the webservices about information! Array Id [%s]. "
                                              "Error [%s]." % (self.ssid, to_native(error)))

            if len(data["version"].split(".")) == 4:
                major, minor, other, revision = data["version"].split(".")
                minimum_major, minimum_minor, other, minimum_revision = self.web_services_version.split(".")

                if not (major > minimum_major or
                        (major == minimum_major and minor > minimum_minor) or
                        (major == minimum_major and minor == minimum_minor and revision >= minimum_revision)):
                    self.module.fail_json(msg="Web services version does not meet minimum version required. "
                                              "Current version: [%s]."
                                              " Version required: [%s]." % (data["version"], self.web_services_version))
                self.module.log("Web services rest api version met the minimum required version.")
            else:
                self.module.warn("Web services rest api version unknown!")

            self._check_ssid()
            self.is_web_services_valid_cache = True

    def is_web_services_version_met(self, version):
        """Determines whether a particular web services version has been satisfied."""
        split_version = version.split(".")
        if len(split_version) != 4 or not split_version[0].isdigit() or not split_version[1].isdigit() or not split_version[3].isdigit():
            self.module.fail_json(msg="Version is not a valid Web Services version. Version [%s]." % version)

        url_parts = urlparse(self.url)
        if not url_parts.scheme or not url_parts.netloc:
            self.module.fail_json(msg="Failed to provide valid API URL. "
                                      "Example: https://192.168.1.100:8443/devmgr/v2. URL [%s]." % self.url)

        if url_parts.scheme not in ["http", "https"]:
            self.module.fail_json(msg="Protocol must be http or https. URL [%s]." % self.url)

        self.url = "%s://%s/" % (url_parts.scheme, url_parts.netloc)
        about_url = self.url + self.DEFAULT_REST_API_ABOUT_PATH
        rc, data = request(about_url, timeout=self.DEFAULT_TIMEOUT, headers=self.DEFAULT_HEADERS, ignore_errors=True, **self.creds)

        if rc != 200:
            self.module.warn("Failed to retrieve web services about information! Retrying with secure ports. "
                             "Array Id [%s]." % self.ssid)
            self.url = "https://%s:8443/" % url_parts.netloc.split(":")[0]
            about_url = self.url + self.DEFAULT_REST_API_ABOUT_PATH
            try:
                rc, data = request(about_url, timeout=self.DEFAULT_TIMEOUT, headers=self.DEFAULT_HEADERS, **self.creds)
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve the webservices about information! Array Id [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(error)))

        if len(data["version"].split(".")) == 4:
            major, minor, other, revision = data["version"].split(".")
            minimum_major, minimum_minor, other, minimum_revision = split_version
            if not (major > minimum_major or
                    (major == minimum_major and minor > minimum_minor) or
                    (major == minimum_major and minor == minimum_minor and revision >= minimum_revision)):
                return False
        else:
            return False
        return True

    def is_embedded_available(self):
        """Determine whether the storage array has embedded services available."""
        self._check_web_services_version()

        if self.is_embedded_available_cache is None:

            if self.is_proxy():
                if self.ssid == "0" or self.ssid.lower() == "proxy":
                    self.is_embedded_available_cache = False
                else:
                    try:
                        rc, bundle = self.request("storage-systems/%s/graph/xpath-filter?query=/sa/saData/extendedSAData/codeVersions[codeModule='bundle']"
                                                  % self.ssid)
                        self.is_embedded_available_cache = False
                        if bundle:
                            self.is_embedded_available_cache = True
                    except Exception as error:
                        self.module.fail_json(msg="Failed to retrieve information about storage system [%s]. "
                                                  "Error [%s]." % (self.ssid, to_native(error)))
            else:   # Contacted using embedded web services
                self.is_embedded_available_cache = True

            self.module.log("embedded_available: [%s]" % ("True" if self.is_embedded_available_cache else "False"))
        return self.is_embedded_available_cache

    def is_embedded(self):
        """Determine whether web services server is the embedded web services."""
        return not self.is_proxy()

    def is_proxy(self):
        """Determine whether web services server is the proxy web services.

        :raise AnsibleFailJson: raised when web services about endpoint failed to be contacted.
        :return bool: whether contacted web services is running from storage array (embedded) or from a proxy.
        """
        self._check_web_services_version()

        if self.is_proxy_used_cache is None:
            about_url = self.url + self.DEFAULT_REST_API_ABOUT_PATH
            try:
                rc, data = request(about_url, timeout=self.DEFAULT_TIMEOUT, headers=self.DEFAULT_HEADERS, force_basic_auth=False, **self.creds)
                self.is_proxy_used_cache = data["runningAsProxy"]

                self.module.log("proxy: [%s]" % ("True" if self.is_proxy_used_cache else "False"))
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve the webservices about information! Array Id [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(error)))

        return self.is_proxy_used_cache

    def request(self, path, rest_api_path=DEFAULT_REST_API_PATH, rest_api_url=None, data=None, method='GET', headers=None, ignore_errors=False, timeout=None,
                force_basic_auth=True, log_request=None, json_response=True):
        """Issue an HTTP request to a url, retrieving an optional JSON response.

        :param str path: web services rest api endpoint path (Example: storage-systems/1/graph).
            Note that when the full url path is specified then that will be used without supplying the protocol,
            hostname, port and rest path.
        :param str rest_api_path: override the class DEFAULT_REST_API_PATH which is used to build the request URL.
        :param str rest_api_url: override the class url member which contains the base url for web services.
        :param data: data required for the request (data may be json or any python structured data)
        :param str method: request method such as GET, POST, DELETE.
        :param dict headers: dictionary containing request headers.
        :param bool ignore_errors: forces the request to ignore any raised exceptions.
        :param int timeout: duration of seconds before request finally times out.
        :param bool force_basic_auth: Ensure that basic authentication is being used.
        :param bool log_request: Log the request and response
        :param bool json_response: Whether the response should be loaded as JSON, otherwise the response is return raw.
        """
        self._check_web_services_version()

        if rest_api_url is None:
            rest_api_url = self.url
        if headers is None:
            headers = self.DEFAULT_HEADERS
        if timeout is None:
            timeout = self.DEFAULT_TIMEOUT
        if log_request is None:
            log_request = self.log_requests

        if not isinstance(data, str) and "Content-Type" in headers and headers["Content-Type"] == "application/json":
            data = json.dumps(data)

        if path.startswith("/"):
            path = path[1:]
        request_url = rest_api_url + rest_api_path + path

        if log_request:
            self.module.log(pformat(dict(url=request_url, data=data, method=method, headers=headers)))

        response = self._request(url=request_url, data=data, method=method, headers=headers, last_mod_time=None,
                                 timeout=timeout, http_agent=self.HTTP_AGENT, force_basic_auth=force_basic_auth,
                                 ignore_errors=ignore_errors, json_response=json_response, **self.creds)
        if log_request:
            self.module.log(pformat(response))

        return response

    @staticmethod
    def _request(url, data=None, headers=None, method='GET', use_proxy=True, force=False, last_mod_time=None,
                 timeout=10, validate_certs=True, url_username=None, url_password=None, http_agent=None,
                 force_basic_auth=True, ignore_errors=False, json_response=True):
        """Issue an HTTP request to a url, retrieving an optional JSON response."""

        if headers is None:
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers.update({"netapp-client-type": "Ansible-%s" % ansible_version})

        if not http_agent:
            http_agent = "Ansible / %s" % ansible_version

        try:
            r = open_url(url=url, data=data, headers=headers, method=method, use_proxy=use_proxy, force=force,
                         last_mod_time=last_mod_time, timeout=timeout, validate_certs=validate_certs,
                         url_username=url_username, url_password=url_password, http_agent=http_agent,
                         force_basic_auth=force_basic_auth)
            rc = r.getcode()
            response = r.read()
            if json_response and response:
                response = json.loads(response)

        except HTTPError as error:
            rc = error.code
            response = error.fp.read()
            try:
                if json_response:
                    response = json.loads(response)
            except Exception:
                pass

            if not ignore_errors:
                raise Exception(rc, response)
        except ValueError as error:
            pass

        return rc, response


def create_multipart_formdata(files, fields=None, send_8kb=False):
    """Create the data for a multipart/form request.

    :param list(list) files: list of lists each containing (name, filename, path).
    :param list(list) fields: list of lists each containing (key, value).
    :param bool send_8kb: only sends the first 8kb of the files (default: False).
    """
    boundary = "---------------------------" + "".join([str(random.randint(0, 9)) for x in range(27)])
    data_parts = list()
    data = None

    if six.PY2:  # Generate payload for Python 2
        newline = "\r\n"
        if fields is not None:
            for key, value in fields:
                data_parts.extend(["--%s" % boundary,
                                   'Content-Disposition: form-data; name="%s"' % key,
                                   "",
                                   value])

        for name, filename, path in files:
            with open(path, "rb") as fh:
                value = fh.read(8192) if send_8kb else fh.read()

                data_parts.extend(["--%s" % boundary,
                                   'Content-Disposition: form-data; name="%s"; filename="%s"' % (name, filename),
                                   "Content-Type: %s" % (mimetypes.guess_type(path)[0] or "application/octet-stream"),
                                   "",
                                   value])
        data_parts.extend(["--%s--" % boundary, ""])
        data = newline.join(data_parts)

    else:
        newline = six.b("\r\n")
        if fields is not None:
            for key, value in fields:
                data_parts.extend([six.b("--%s" % boundary),
                                   six.b('Content-Disposition: form-data; name="%s"' % key),
                                   six.b(""),
                                   six.b(value)])

        for name, filename, path in files:
            with open(path, "rb") as fh:
                value = fh.read(8192) if send_8kb else fh.read()

                data_parts.extend([six.b("--%s" % boundary),
                                   six.b('Content-Disposition: form-data; name="%s"; filename="%s"' % (name, filename)),
                                   six.b("Content-Type: %s" % (mimetypes.guess_type(path)[0] or "application/octet-stream")),
                                   six.b(""),
                                   value])
        data_parts.extend([six.b("--%s--" % boundary), b""])
        data = newline.join(data_parts)

    headers = {
        "Content-Type": "multipart/form-data; boundary=%s" % boundary,
        "Content-Length": str(len(data))}

    return headers, data


def request(url, data=None, headers=None, method='GET', use_proxy=True,
            force=False, last_mod_time=None, timeout=10, validate_certs=True,
            url_username=None, url_password=None, http_agent=None, force_basic_auth=True, ignore_errors=False):
    """Issue an HTTP request to a url, retrieving an optional JSON response."""

    if headers is None:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers.update({"netapp-client-type": "Ansible-%s" % ansible_version})

    if not http_agent:
        http_agent = "Ansible / %s" % ansible_version

    try:
        r = open_url(url=url, data=data, headers=headers, method=method, use_proxy=use_proxy,
                     force=force, last_mod_time=last_mod_time, timeout=timeout, validate_certs=validate_certs,
                     url_username=url_username, url_password=url_password, http_agent=http_agent,
                     force_basic_auth=force_basic_auth)
    except HTTPError as err:
        r = err.fp

    try:
        raw_data = r.read()
        if raw_data:
            data = json.loads(raw_data)
        else:
            raw_data = None
    except Exception:
        if ignore_errors:
            pass
        else:
            raise Exception(raw_data)

    resp_code = r.getcode()

    if resp_code >= 400 and not ignore_errors:
        raise Exception(resp_code, data)
    else:
        return resp_code, data
