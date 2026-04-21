# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2017, Sumit Kumar <sumit4@netapp.com>
# Copyright (c) 2017, Michael Price <michael.price@netapp.com>
# Copyright (c) 2017-2025, NetApp, Inc
# All rights reserved.
#
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

'''
netapp.py
'''

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import json
import logging
import os
import ssl
import time
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils._text import to_native

try:
    from ansible.module_utils.ansible_release import __version__ as ANSIBLE_VERSION
except ImportError:
    ANSIBLE_VERSION = 'unknown'

COLLECTION_VERSION = "23.2.0"
CLIENT_APP_VERSION = "%s/%s" % ("%s", COLLECTION_VERSION)
IMPORT_EXCEPTION = None

try:
    from netapp_lib.api.zapi import zapi
    HAS_NETAPP_LIB = True
except ImportError as exc:
    HAS_NETAPP_LIB = False
    IMPORT_EXCEPTION = exc

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

HAS_SF_SDK = False
SF_BYTE_MAP = dict(
    # Management GUI displays 1024 ** 3 as 1.1 GB, thus use 1000.
    bytes=1,
    b=1,
    kb=1000,
    mb=1000 ** 2,
    gb=1000 ** 3,
    tb=1000 ** 4,
    pb=1000 ** 5,
    eb=1000 ** 6,
    zb=1000 ** 7,
    yb=1000 ** 8
)

POW2_BYTE_MAP = dict(
    # Here, 1 kb = 1024
    bytes=1,
    b=1,
    k=1024,
    m=1024 ** 2,
    g=1024 ** 3,
    t=1024 ** 4,
    p=1024 ** 5,
    e=1024 ** 6,
    z=1024 ** 7,
    y=1024 ** 8,
    kb=1024,
    mb=1024 ** 2,
    gb=1024 ** 3,
    tb=1024 ** 4,
    pb=1024 ** 5,
    eb=1024 ** 6,
    zb=1024 ** 7,
    yb=1024 ** 8,
)

ERROR_MSG = dict(
    no_cserver='This module is expected to run as cluster admin'
)

LOG = logging.getLogger(__name__)
LOG_FILE = '/tmp/ontap_apis.log'
ZAPI_DEPRECATION_MESSAGE = "The 'netapp-lib' library is no longer maintained. Proceed at your own risk.  "\
                           "While the original deprecation date has been deferred due to continued consumer usage and feedback,  "\
                           "ONTAPI (ZAPI) are considered legacy.  "\
                           "All new features, fixes, and improvements will be developed for the modules having REST API support.  "\
                           "To ensure continued support, please migrate to the REST API."

try:
    from solidfire.factory import ElementFactory
    HAS_SF_SDK = True
except ImportError:
    HAS_SF_SDK = False


def has_netapp_lib():
    return HAS_NETAPP_LIB


def netapp_lib_is_required():
    return "Error: the python NetApp-Lib module is required.  Import error: %s" % str(IMPORT_EXCEPTION)


def has_sf_sdk():
    return HAS_SF_SDK


def na_ontap_zapi_only_spec():
    # This is used for Zapi only Modules.

    return dict(
        hostname=dict(required=True, type='str'),
        username=dict(required=False, type='str', aliases=['user']),
        password=dict(required=False, type='str', aliases=['pass'], no_log=True),
        https=dict(required=False, type='bool', default=False),
        validate_certs=dict(required=False, type='bool', default=True),
        http_port=dict(required=False, type='int'),
        ontapi=dict(required=False, type='int'),
        use_rest=dict(required=False, type='str', default='never'),
        feature_flags=dict(required=False, type='dict'),
        cert_filepath=dict(required=False, type='str'),
        key_filepath=dict(required=False, type='str', no_log=False),
    )


def na_ontap_host_argument_spec():
    # This is used for Zapi + REST Modules.

    return dict(
        hostname=dict(required=True, type='str'),
        username=dict(required=False, type='str', aliases=['user']),
        password=dict(required=False, type='str', aliases=['pass'], no_log=True),
        https=dict(required=False, type='bool', default=False),
        validate_certs=dict(required=False, type='bool', default=True),
        http_port=dict(required=False, type='int'),
        ontapi=dict(required=False, type='int'),
        use_rest=dict(required=False, type='str', default='always'),
        feature_flags=dict(required=False, type='dict'),
        cert_filepath=dict(required=False, type='str'),
        key_filepath=dict(required=False, type='str', no_log=False),
        force_ontap_version=dict(required=False, type='str'),
        use_lambda=dict(required=False, type='bool', default=False)
    )


def na_ontap_rest_only_spec():
    # This is used for REST only Modules.

    return dict(
        hostname=dict(required=True, type='str'),
        username=dict(required=False, type='str', aliases=['user']),
        password=dict(required=False, type='str', aliases=['pass'], no_log=True),
        https=dict(required=False, type='bool', default=False),
        validate_certs=dict(required=False, type='bool', default=True),
        http_port=dict(required=False, type='int'),
        use_rest=dict(required=False, type='str', default='always'),
        feature_flags=dict(required=False, type='dict'),
        cert_filepath=dict(required=False, type='str'),
        key_filepath=dict(required=False, type='str', no_log=False),
        force_ontap_version=dict(required=False, type='str')
    )


def na_ontap_host_argument_spec_peer():
    spec = na_ontap_host_argument_spec()
    spec.pop('feature_flags')
    spec.pop('use_lambda')
    # get rid of default values, as we'll use source values
    for value in spec.values():
        if 'default' in value:
            value.pop('default')
    return spec


def na_ontap_lambda_argument_spec():
    # This is used for modules that support Lambda proxy functionality.
    return dict(
        lambda_config=dict(required=False, type='dict', options=dict(
            function_name=dict(required=True, type='str'),
            aws_region=dict(required=True, type='str'),
            aws_profile=dict(required=False, type='str')
        ))
    )


def has_feature(module, feature_name):
    feature = get_feature(module, feature_name)
    if isinstance(feature, bool):
        return feature
    module.fail_json(msg="Error: expected bool type for feature flag: %s" % feature_name)


def get_feature(module, feature_name):
    ''' if the user has configured the feature, use it
        otherwise, use our default
    '''
    default_flags = dict(
        strict_json_check=True,                 # when true, fail if response.content in not empty and is not valid json
        trace_apis=False,                       # when true, append ZAPI and REST requests/responses to /tmp/ontap_zapi.txt
        trace_headers=False,                    # when true, headers are not redacted in send requests
        trace_auth_args=False,                  # when true, auth_args are not redacted in send requests
        check_required_params_for_none=True,
        classic_basic_authorization=False,      # use ZAPI wrapper to send Authorization header
        deprecation_warning=True,
        sanitize_xml=True,
        sanitize_code_points=[8],               # unicode values, 8 is backspace
        show_modified=True,
        always_wrap_zapi=True,                  # for better error reporting
        flexcache_delete_return_timeout=5,      # ONTAP bug if too big?
        # for SVM, whch protocols can be allowed
        svm_allowable_protocols_rest=['cifs', 'fcp', 'iscsi', 'nvme', 'nfs', 'ndmp', 's3'],
        svm_allowable_protocols_zapi=['cifs', 'fcp', 'iscsi', 'nvme', 'nfs', 'ndmp', 'http'],
        max_files_change_threshold=1,           # percentage of increase/decrease required to trigger a modify action
        warn_or_fail_on_fabricpool_backend_change='fail',
        no_cserver_ems=False                    # when True, don't attempt to find cserver and don't send cserver EMS
    )

    if module.params['feature_flags'] is not None and feature_name in module.params['feature_flags']:
        return module.params['feature_flags'][feature_name]
    if feature_name in default_flags:
        return default_flags[feature_name]
    module.fail_json(msg="Internal error: unexpected feature flag: %s" % feature_name)


def create_sf_connection(module, port=None, host_options=None):
    if not HAS_SF_SDK:
        module.fail_json(msg="the python SolidFire SDK module is required")

    if host_options is None:
        host_options = module.params
    msg, msg2 = None, None
    missing_options = [option for option in ('hostname', 'username', 'password') if not host_options.get(option)]
    if missing_options:
        verb = 'are' if len(missing_options) > 1 else 'is'
        msg = "%s %s required for ElementSW connection." % (', '.join(missing_options), verb)
    extra_options = [option for option in ('cert_filepath', 'key_filepath') if host_options.get(option)]
    if extra_options:
        verb = 'are' if len(extra_options) > 1 else 'is'
        msg2 = "%s %s not supported for ElementSW connection." % (', '.join(extra_options), verb)
    msg = "%s  %s" % (msg, msg2) if msg and msg2 else msg or msg2
    if msg:
        module.fail_json(msg=msg)
    hostname = host_options.get('hostname')
    username = host_options.get('username')
    password = host_options.get('password')

    try:
        return ElementFactory.create(hostname, username, password, port=port)
    except Exception as exc:
        raise Exception("Unable to create SF connection: %s" % exc)


def set_auth_method(module, username, password, cert_filepath, key_filepath):
    error = None
    auth_method = None
    # defaults to cert authentication if both basic and client certificate authentication parameters are given
    if cert_filepath is not None:
        auth_method = 'single_cert' if key_filepath is None else 'cert_key'
    else:
        if password is None and username is None:
            error = ('Error: cannot have a key file without a cert file' if key_filepath is not None
                     else 'Error: ONTAP module requires username/password or SSL certificate file(s)')
        elif password is not None and username is not None:
            auth_method = 'basic_auth' if has_feature(module, 'classic_basic_authorization') else 'speedy_basic_auth'
        else:
            error = 'Error: username and password have to be provided together'
    if error:
        module.fail_json(msg=error)
    return auth_method


def setup_host_options_from_module_params(host_options, module, keys):
    '''if an option is not set, use primary value.
       but don't mix up basic and certificate authentication methods

       host_options is updated in place
       option values are read from module.params
       keys is a list of keys that need to be added/updated/left alone in host_options
    '''
    password_keys = ['username', 'password']
    certificate_keys = ['cert_filepath', 'key_filepath']
    use_password = any(host_options.get(x) is not None for x in password_keys)
    use_certificate = any(host_options.get(x) is not None for x in certificate_keys)
    if use_password and use_certificate:
        module.fail_json(
            msg='Error: host cannot have both basic authentication (username/password) and certificate authentication (cert/key files).')
    if use_password:
        exclude_keys = certificate_keys
    elif use_certificate:
        exclude_keys = password_keys
    else:
        exclude_keys = []
    for key in keys:
        if host_options.get(key) is None and key not in exclude_keys:
            # use same value as source if no value is given for dest
            host_options[key] = module.params[key]


def set_zapi_port_and_transport(server, https, port, validate_certs):
    # default is HTTP
    if https:
        if port is None:
            port = 443
        transport_type = 'HTTPS'
        # HACK to bypass certificate verification
        if validate_certs is False and not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
            ssl._create_default_https_context = ssl._create_unverified_context
    else:
        if port is None:
            port = 80
        transport_type = 'HTTP'
    server.set_transport_type(transport_type)
    server.set_port(port)


def should_use_lambda(module):
    """
    Determine if the module should use Lambda proxy for ONTAP API calls.
    :param module: Ansible module instance.
    :return: Boolean indicating whether to use Lambda.
    """
    return module.params.get('use_lambda', False)


def setup_na_ontap_lambda(module):
    """
    Set up a Lambda proxy for ONTAP operations based on module parameters.
    :param module: Ansible module instance.
    :return: AwsLambda instance or None if Lambda is not enabled.
    """
    lambda_config = module.params.get('lambda_config', {})

    if not HAS_BOTO3:
        module.fail_json(msg="boto3 is required for Lambda functionality. Install with: pip install boto3")

    try:
        return AwsLambda(module, lambda_config)
    except Exception as exc:
        module.fail_json("Failed to create Lambda proxy: %s" % exc)


def setup_na_ontap_zapi(module, vserver=None, wrap_zapi=False, host_options=None):
    module.warn(ZAPI_DEPRECATION_MESSAGE)
    if host_options is None:
        host_options = module.params
    hostname = host_options.get('hostname')
    username = host_options.get('username')
    password = host_options.get('password')
    cert_filepath = host_options.get('cert_filepath')
    key_filepath = host_options.get('key_filepath')
    https = host_options.get('https')
    validate_certs = host_options.get('validate_certs')
    port = host_options.get('http_port')
    version = host_options.get('ontapi')
    trace = has_feature(module, 'trace_apis')
    if trace:
        logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s')
    wrap_zapi |= has_feature(module, 'always_wrap_zapi')
    auth_method = set_auth_method(module, username, password, cert_filepath, key_filepath)

    if not HAS_NETAPP_LIB:
        module.fail_json(msg=netapp_lib_is_required())

    # set up zapi
    if auth_method in ('single_cert', 'cert_key'):
        # override NaServer in netapp-lib to enable certificate authentication
        server = OntapZAPICx(hostname, module=module, username=username, password=password,
                             validate_certs=validate_certs, cert_filepath=cert_filepath,
                             key_filepath=key_filepath, style=zapi.NaServer.STYLE_CERTIFICATE,
                             auth_method=auth_method, trace=trace)
        # SSL certificate authentication requires SSL
        https = True
    elif auth_method == 'speedy_basic_auth' or wrap_zapi:
        # override NaServer in netapp-lib to add Authorization header preemptively
        # use wrapper to handle parse error (mostly for na_ontap_command)
        server = OntapZAPICx(hostname, module=module, username=username, password=password,
                             validate_certs=validate_certs, auth_method=auth_method, trace=trace)
    else:
        # legacy netapp-lib
        server = zapi.NaServer(hostname, username=username, password=password, trace=trace)
    if vserver:
        server.set_vserver(vserver)
    if host_options.get('use_rest') == 'always':
        note = '' if https else '  Note: https is set to false.'
        module.warn("Using ZAPI for %s, ignoring 'use_rest: always'.%s" % (module._name, note))

    set_zapi_port_and_transport(server, https, port, validate_certs)
    server.set_api_version(major=1, minor=(version or 110))
    server.set_server_type('FILER')
    return server


def is_zapi_connection_error(message):
    ''' return True if it is a connection issue '''
    # netapp-lib message may contain a tuple or a str!
    try:
        if isinstance(message, tuple) and isinstance(message[0], ConnectionError):
            return True
    except NameError:
        # python 2.7 does not know about ConnectionError
        pass
    return isinstance(message, str) and message.startswith(('URLError', 'Unauthorized'))


def is_zapi_write_access_error(message):
    ''' return True if it is a write access error '''
    # netapp-lib message may contain a tuple or a str!
    if isinstance(message, str) and message.startswith('Insufficient privileges:'):
        return 'does not have write access' in message
    return False


def is_zapi_missing_vserver_error(message):
    ''' return True if it is a missing vserver error '''
    # netapp-lib message may contain a tuple or a str!
    return isinstance(message, str) and message in ('Vserver API missing vserver parameter.', 'Specified vserver not found')


def get_cserver_zapi(server):
    ''' returns None if not run on the management or cluster IP '''
    vserver_info = zapi.NaElement('vserver-get-iter')
    query_details = zapi.NaElement.create_node_with_children('vserver-info', **{'vserver-type': 'admin'})
    query = zapi.NaElement('query')
    query.add_child_elem(query_details)
    vserver_info.add_child_elem(query)
    try:
        result = server.invoke_successfully(vserver_info,
                                            enable_tunneling=False)
    except zapi.NaApiError as exc:
        # Do not fail if we can't connect to the server.
        # The module will report a better error when trying to get some data from ONTAP.
        if is_zapi_connection_error(exc.message):
            return None
        # raise on other errors, as it may be a bug in calling the ZAPI
        raise exc
    attribute_list = result.get_child_by_name('attributes-list')
    if attribute_list is not None:
        vserver_list = attribute_list.get_child_by_name('vserver-info')
        if vserver_list is not None:
            return vserver_list.get_child_content('vserver-name')
    return None


def classify_zapi_exception(error):
    ''' return type of error '''
    try:
        # very unlikely to fail, but don't take any chance
        err_code = int(error.code)
    except (AttributeError, ValueError):
        err_code = 0
    try:
        # very unlikely to fail, but don't take any chance
        err_msg = error.message
    except AttributeError:
        err_msg = ""
    if err_code == 13005 and err_msg.startswith('Unable to find API:') and 'data vserver' in err_msg:
        return 'missing_vserver_api_error', 'Most likely running a cluster level API as vserver: %s' % to_native(error)
    if err_code == 13001 and err_msg.startswith("RPC: Couldn't make connection"):
        return 'rpc_error', to_native(error)
    return "other_error", to_native(error)


def get_cserver(connection, is_rest=False):
    if not is_rest:
        return get_cserver_zapi(connection)

    params = {'fields': 'type'}
    api = "private/cli/vserver"
    json, error = connection.get(api, params)
    if json is None or error is not None:
        # exit if there is an error or no data
        return None
    vservers = json.get('records')
    if vservers is not None:
        for vserver in vservers:
            if vserver['type'] == 'admin':     # cluster admin
                return vserver['vserver']
        if len(vservers) == 1:                  # assume vserver admin
            return vservers[0]['vserver']

    return None


def generate_result(changed, actions=None, modify=None, response=None, extra_responses=None):
    result = dict(changed=changed)
    if response is not None:
        result['response'] = response
    if modify:
        result['modify'] = modify
    if actions:
        result['actions'] = actions
    if extra_responses:
        result.update(extra_responses)
    return result


if HAS_NETAPP_LIB:
    class OntapZAPICx(zapi.NaServer):
        ''' override zapi NaServer class to:
        - enable SSL certificate authentication
        - ignore invalid XML characters in ONTAP output (when using CLI module)
        - add Authorization header when using basic authentication
        '''
        def __init__(self, hostname=None, server_type=zapi.NaServer.SERVER_TYPE_FILER,
                     transport_type=zapi.NaServer.TRANSPORT_TYPE_HTTP,
                     style=zapi.NaServer.STYLE_LOGIN_PASSWORD, username=None,
                     password=None, port=None, trace=False, module=None,
                     cert_filepath=None, key_filepath=None, validate_certs=None,
                     auth_method=None):
            # python 2.x syntax, but works for python 3 as well
            super(OntapZAPICx, self).__init__(hostname, server_type=server_type,
                                              transport_type=transport_type,
                                              style=style, username=username,
                                              password=password, port=port, trace=trace)
            self.cert_filepath = cert_filepath
            self.key_filepath = key_filepath
            self.validate_certs = validate_certs
            self.module = module
            self.base64_creds = None
            if auth_method == 'speedy_basic_auth':
                auth = '%s:%s' % (username, password)
                self.base64_creds = base64.b64encode(auth.encode()).decode()

        def _create_certificate_auth_handler(self):
            try:
                context = ssl.create_default_context()
            except AttributeError as exc:
                self._fail_with_exc_info('SSL certificate authentication requires python 2.7 or later.', exc)

            if not self.validate_certs:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            try:
                context.load_cert_chain(self.cert_filepath, keyfile=self.key_filepath)
            except IOError as exc:
                self._fail_with_exc_info('Cannot load SSL certificate, check files exist.', exc)

            return zapi.urllib.request.HTTPSHandler(context=context)

        def _fail_with_exc_info(self, arg0, exc):
            msg = arg0
            msg += '  More info: %s' % repr(exc)
            self.module.fail_json(msg=msg)

        def sanitize_xml(self, response):
            # some ONTAP CLI commands return BEL on error
            new_response = response.replace(b'\x07\n', b'')
            # And 9.1 uses \r\n rather than \n !
            new_response = new_response.replace(b'\x07\r\n', b'')
            # And 9.7 may send backspaces
            for code_point in get_feature(self.module, 'sanitize_code_points'):
                if bytes([8]) == b'\x08':   # python 3
                    byte = bytes([code_point])
                elif chr(8) == b'\x08':     # python 2
                    byte = chr(code_point)
                else:                       # very unlikely, noop
                    byte = b'.'
                new_response = new_response.replace(byte, b'.')
            return new_response

        def _parse_response(self, response):
            ''' handling XML parsing exception '''
            try:
                return super(OntapZAPICx, self)._parse_response(response)
            except zapi.etree.XMLSyntaxError as exc:
                if has_feature(self.module, 'sanitize_xml'):
                    try:
                        return super(OntapZAPICx, self)._parse_response(self.sanitize_xml(response))
                    except Exception:
                        # ignore a second exception, we'll report the first one
                        pass
                try:
                    # report first exception, but include full response
                    exc.msg += ".  Received: %s" % response
                except Exception:
                    # in case the response is very badly formatted, ignore it
                    pass
                raise exc

        def _create_request(self, na_element, enable_tunneling=False):
            ''' intercept newly created request to add Authorization header '''
            request, netapp_element = super(OntapZAPICx, self)._create_request(na_element, enable_tunneling=enable_tunneling)
            request.add_header('X-Dot-Client-App', CLIENT_APP_VERSION % self.module._name)
            if self.base64_creds is not None:
                request.add_header('Authorization', 'Basic %s' % self.base64_creds)
            return request, netapp_element

        # as is from latest version of netapp-lib
        def invoke_elem(self, na_element, enable_tunneling=False):
            """Invoke the API on the server."""
            if not na_element or not isinstance(na_element, zapi.NaElement):
                raise ValueError('NaElement must be supplied to invoke API')

            request, request_element = self._create_request(na_element,
                                                            enable_tunneling)

            if self._trace:
                zapi.LOG.debug("Request: %s", request_element.to_string(pretty=True))

            if not hasattr(self, '_opener') or not self._opener \
                    or self._refresh_conn:
                self._build_opener()
            try:
                if hasattr(self, '_timeout'):
                    response = self._opener.open(request, timeout=self._timeout)
                else:
                    response = self._opener.open(request)
            except zapi.urllib.error.HTTPError as exc:
                raise zapi.NaApiError(exc.code, exc.reason)
            except zapi.urllib.error.URLError as exc:
                msg = 'URL error'
                error = repr(exc)
                try:
                    # ConnectionRefusedError is not defined in python 2.7
                    if isinstance(exc.reason, ConnectionRefusedError):
                        msg = 'Unable to connect'
                        error = exc.args
                except Exception:
                    pass
                raise zapi.NaApiError(msg, error)
            except Exception as exc:
                raise zapi.NaApiError('Unexpected error', repr(exc))

            response_xml = response.read()
            response_element = self._get_result(response_xml)

            if self._trace:
                zapi.LOG.debug("Response: %s", response_element.to_string(pretty=True))

            return response_element


class OntapRestAPI(object):
    ''' wrapper to send requests to ONTAP REST APIs '''
    def __init__(self, module, timeout=60, host_options=None):
        self.host_options = module.params if host_options is None else host_options
        self.module = module
        # either username/password or a certifcate with/without a key are used for authentication
        self.username = self.host_options.get('username')
        self.password = self.host_options.get('password')
        self.hostname = self.host_options['hostname']
        self.use_rest = self.host_options['use_rest'].lower()
        self.cert_filepath = self.host_options.get('cert_filepath')
        self.key_filepath = self.host_options.get('key_filepath')
        self.verify = self.host_options['validate_certs']
        self.timeout = timeout
        port = self.host_options['http_port']
        self.force_ontap_version = self.host_options.get('force_ontap_version')
        if port is None:
            self.url = 'https://%s/api/' % self.hostname
        else:
            self.url = 'https://%s:%d/api/' % (self.hostname, port)
        self.is_rest_error = None
        self.fallback_to_zapi_reason = None
        self.ontap_version = dict(
            full='unknown',
            generation=-1,
            major=-1,
            minor=-1,
            valid=False
        )
        self.errors = []
        self.debug_logs = []
        self.auth_method = set_auth_method(self.module, self.username, self.password, self.cert_filepath, self.key_filepath)
        self.check_required_library()
        if has_feature(module, 'trace_apis'):
            logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s')
        self.log_headers = has_feature(module, 'trace_headers')
        self.log_auth_args = has_feature(module, 'trace_auth_args')

        # Initialize Lambda proxy if configured
        self.lambda_proxy = None
        if should_use_lambda(module):
            self.lambda_proxy = setup_na_ontap_lambda(module)

    def requires_ontap_9_6(self, module_name):
        return self.requires_ontap_version(module_name)

    def requires_ontap_version(self, module_name, version='9.6'):
        suffix = " - %s" % self.is_rest_error if self.is_rest_error is not None else ""
        return "%s only supports REST, and requires ONTAP %s or later.%s" % (module_name, version, suffix)

    def options_require_ontap_version(self, options, version='9.6', use_rest=None):
        current_version = self.get_ontap_version()
        suffix = " - %s" % self.is_rest_error if self.is_rest_error is not None else ""
        if current_version != (-1, -1, -1):
            suffix += " - ONTAP version: %s.%s.%s" % current_version
        if use_rest is not None:
            suffix += " - using %s" % ('REST' if use_rest else 'ZAPI')
        if isinstance(options, list) and len(options) > 1:
            tag = "any of %s" % options
        elif isinstance(options, list) and len(options) == 1:
            tag = str(options[0])
        else:
            tag = str(options)
        return 'using %s requires ONTAP %s or later and REST must be enabled%s.' % (tag, version, suffix)

    def meets_rest_minimum_version(self, use_rest, minimum_generation, minimum_major, minimum_minor=0):
        return use_rest and self.get_ontap_version() >= (minimum_generation, minimum_major, minimum_minor)

    def fail_if_not_rest_minimum_version(self, module_name, minimum_generation, minimum_major, minimum_minor=0):
        status_code = self.get_ontap_version_using_rest()
        msgs = []
        if self.use_rest == 'never':
            msgs.append('Error: REST is required for this module, found: "use_rest: %s".' % self.use_rest)
        # The module only supports REST, so make it required
        self.use_rest = 'always'
        if self.is_rest_error:
            msgs.append('Error using REST for version, error: %s.' % self.is_rest_error)
        if status_code != 200:
            msgs.append('Error using REST for version, status_code: %s.' % status_code)
        if msgs:
            self.module.fail_json(msg='  '.join(msgs))
        version = self.get_ontap_version()
        if version < (minimum_generation, minimum_major, minimum_minor):
            msg = 'Error: ' + self.requires_ontap_version(module_name, '%d.%d.%d' % (minimum_generation, minimum_major, minimum_minor))
            msg += '  Found: %s.%s.%s.' % version
            self.module.fail_json(msg=msg)

    def check_required_library(self):
        if not HAS_REQUESTS:
            self.module.fail_json(msg=missing_required_lib('requests'))

    def build_headers(self, accept=None, vserver_name=None, vserver_uuid=None):
        headers = {'X-Dot-Client-App': CLIENT_APP_VERSION % self.module._name}
        # accept is used to turn on/off HAL linking
        if accept is not None:
            headers['accept'] = accept
        # vserver tunneling using vserver name and/or UUID
        if vserver_name is not None:
            headers['X-Dot-SVM-Name'] = vserver_name
        if vserver_uuid is not None:
            headers['X-Dot-SVM-UUID'] = vserver_uuid
        return headers

    def send_request(self, method, api, params, json=None, headers=None, files=None):
        ''' send http request and process reponse, including error conditions '''
        if self.lambda_proxy:
            status_code, json_dict, error_details = self.lambda_proxy._send_request(method, api, params, json, headers, files)
            self.log_debug("proxy:", status_code)
            self.log_debug("json_dict:", json_dict)
            return status_code, json_dict, error_details

        def get_auth_args():
            if self.auth_method == 'single_cert':
                kwargs = dict(cert=self.cert_filepath)
            elif self.auth_method == 'cert_key':
                kwargs = dict(cert=(self.cert_filepath, self.key_filepath))
            elif self.auth_method in ('basic_auth', 'speedy_basic_auth'):
                # For Unicode passwords: Check if password contains non-ASCII characters
                # If so, UTF-8 encoding is used instead of requests default (Latin-1)
                def is_ascii_compatible(s):
                    try:
                        s.encode('ascii')
                        return True
                    except UnicodeEncodeError:
                        return False

                if not (is_ascii_compatible(self.username) and is_ascii_compatible(self.password)):
                    auth_string = '%s:%s' % (self.username, self.password)
                    auth_bytes = base64.b64encode(auth_string.encode('utf-8')).decode('ascii')
                    kwargs = dict(headers={'Authorization': 'Basic %s' % auth_bytes})
                else:
                    # Standard requests auth for ASCII-only passwords
                    kwargs = dict(auth=(self.username, self.password))
            else:
                raise KeyError(self.auth_method)
            return kwargs

        url = self.url + api
        status_code, json_dict, error_details = self._send_request(method, url, params, json, headers, files, get_auth_args())

        return status_code, json_dict, error_details

    def _send_request(self, method, url, params, json, headers, files, auth_args):
        status_code = None
        json_dict = None
        json_error = None
        error_details = None
        if headers is None:
            headers = self.build_headers()

        # Handles authentication headers from auth_args
        if 'headers' in auth_args:
            # Merge authentication headers with existing headers
            headers.update(auth_args['headers'])
            # Remove headers from auth_args to avoid passing them twice to request function
            auth_args = {k: v for k, v in auth_args.items() if k != 'headers'}

        def fail_on_non_empty_value(response):
            '''json() may fail on an empty value, but it's OK if no response is expected.
               To avoid false positives, only report an issue when we expect to read a value.
               The first get will see it.
            '''
            if method == 'GET' and has_feature(self.module, 'strict_json_check'):
                contents = response.content
                if len(contents) > 0:
                    raise ValueError("Expecting json, got: %s" % contents)

        def get_json(response):
            ''' extract json, and error message if present '''
            try:
                json = response.json()
            except ValueError:
                fail_on_non_empty_value(response)
                return None, None
            return json, json.get('error')

        self.log_debug('sending', repr(dict(method=method, url=url, verify=self.verify, params=params,
                                            timeout=self.timeout, json=json,
                                            headers=headers if self.log_headers else 'redacted',
                                            auth_args=auth_args if self.log_auth_args else 'redacted')))
        try:
            response = requests.request(method, url, verify=self.verify, params=params,
                                        timeout=self.timeout, json=json, headers=headers, files=files, **auth_args)
            status_code = response.status_code
            self.log_debug(status_code, response.content)
            # If the response was successful, no Exception will be raised
            response.raise_for_status()
            json_dict, json_error = get_json(response)
        except requests.exceptions.HTTPError as err:
            try:
                __, json_error = get_json(response)
            except (AttributeError, ValueError):
                json_error = None
            if json_error is None:
                self.log_error(status_code, 'HTTP error: %s' % err)
                error_details = str(err)

            # If an error was reported in the json payload, it is handled below
        except requests.exceptions.ConnectionError as err:
            self.log_error(status_code, 'Connection error: %s' % err)
            error_details = str(err)
        except Exception as err:
            self.log_error(status_code, 'Other error: %s' % err)
            error_details = str(err)
        if json_error is not None:
            self.log_error(status_code, 'Endpoint error: %d: %s' % (status_code, json_error))
            error_details = json_error
        if not error_details and not json_dict:
            if json_dict is None:
                json_dict = {}
            if method == 'OPTIONS':
                # OPTIONS provides the list of supported verbs
                json_dict['Allow'] = response.headers.get('Allow')
            if response.headers.get('Content-Type', '').startswith("multipart/form-data"):
                json_dict['text'] = response.text
        return status_code, json_dict, error_details

    def _is_job_done(self, job_json, job_state, job_error, timed_out):
        """ return (done, message, error)
            done is True to indicate that the job is complete, or failed, or timed out
            done is False when the job is still running
        """
        # a job looks like this
        # {
        #   "uuid": "cca3d070-58c6-11ea-8c0c-005056826c14",
        #   "description": "POST /api/cluster/metrocluster",
        #   "state": "failure",
        #   "message": "There are not enough disks in Pool1.",   **OPTIONAL**
        #   "code": 2432836,
        #   "start_time": "2020-02-26T10:35:44-08:00",
        #   "end_time": "2020-02-26T10:47:38-08:00",
        #   "_links": {
        #     "self": {
        #       "href": "/api/cluster/jobs/cca3d070-58c6-11ea-8c0c-005056826c14"
        #     }
        #   }
        # }
        done, error = False, None
        message = job_json.get('message', '') if job_json else None
        if job_state == 'failure':
            # if the job has failed, return message as error
            error = message
            message = None
            done = True
        elif job_state not in ('queued', 'running', None):
            error = job_error
            done = True
        elif timed_out:
            # Would like to post a message to user (not sure how)
            self.log_error(0, 'Timeout error: Process still running')
            error = 'Timeout error: Process still running'
            if job_error is not None:
                error += ' - %s' % job_error
            done = True
        return done, message, error

    def wait_on_job(self, job, timeout=600, increment=60):
        try:
            url = job['_links']['self']['href'].split('api/')[1]
        except Exception as err:
            self.log_error(0, 'URL Incorrect format: %s - Job: %s' % (err, job))
            return None, 'URL Incorrect format: %s - Job: %s' % (err, job)
        # Expecting job to be in the following format
        # {'job':
        #     {'uuid': 'fde79888-692a-11ea-80c2-005056b39fe7',
        #     '_links':
        #         {'self':
        #             {'href': '/api/cluster/jobs/fde79888-692a-11ea-80c2-005056b39fe7'}
        #         }
        #     }
        # }
        error = None
        errors = []
        message = None
        runtime = 0
        retries = 0
        max_retries = 3
        done = False
        while not done:
            # Will run every <increment> seconds for <timeout> seconds
            job_json, job_error = self.get(url, None)
            job_state = job_json.get('state', None) if job_json else None
            # ignore error if status is provided in the job
            if job_error and job_state is None:
                errors.append(str(job_error))
                retries += 1
                if retries > max_retries:
                    error = " - ".join(errors)
                    self.log_error(0, 'Job error: Reached max retries.')
                    done = True
            else:
                retries = 0
                done, message, error = self._is_job_done(job_json, job_state, job_error, runtime >= timeout)
            if not done:
                time.sleep(increment)
                runtime += increment
        return message, error

    def get(self, api, params=None, headers=None):
        method = 'GET'
        dummy, message, error = self.send_request(method, api, params, json=None, headers=headers)
        return message, error

    def post(self, api, body, params=None, headers=None, files=None):
        method = 'POST'
        retry = 3
        while retry > 0:
            dummy, message, error = self.send_request(method, api, params, json=body, headers=headers, files=files)
            if error and isinstance(error, dict) and 'temporarily locked' in error.get('message', ''):
                time.sleep(30)
                retry = retry - 1
                continue
            break
        return message, error

    def patch(self, api, body, params=None, headers=None, files=None):
        method = 'PATCH'
        retry = 3
        while retry > 0:
            dummy, message, error = self.send_request(method, api, params, json=body, headers=headers, files=files)
            if error and isinstance(error, dict) and 'temporarily locked' in error.get('message', ''):
                time.sleep(30)
                retry = retry - 1
                continue
            break
        return message, error

    def delete(self, api, body=None, params=None, headers=None):
        method = 'DELETE'
        dummy, message, error = self.send_request(method, api, params, json=body, headers=headers)
        return message, error

    def options(self, api, params=None, headers=None):
        method = 'OPTIONS'
        dummy, message, error = self.send_request(method, api, params, json=None, headers=headers)
        return message, error

    def set_version(self, message):
        try:
            version = message.get('version', 'not found')
        except AttributeError:
            self.ontap_version['valid'] = False
            self.ontap_version['full'] = 'unreadable message'
            return
        for key in self.ontap_version:
            try:
                self.ontap_version[key] = version.get(key, -1)
            except AttributeError:
                self.ontap_version[key] = -1
        self.ontap_version['valid'] = all(
            self.ontap_version[key] != -1 for key in self.ontap_version if key != 'valid'
        )

    def get_ontap_version(self):
        if self.ontap_version['valid']:
            return self.ontap_version['generation'], self.ontap_version['major'], self.ontap_version['minor']
        return -1, -1, -1

    def get_node_version_using_rest(self):
        # using GET rather than HEAD because the error messages are different,
        # and we need the version as some REST options are not available in earlier versions
        method = 'GET'
        api = 'cluster/nodes'
        if should_use_lambda(self.module):
            params = {'fields': 'version'}
        else:
            params = {'fields': ['version']}
        status_code, message, error = self.send_request(method, api, params=params)
        if message and 'records' in message and len(message['records']) > 0:
            message = message['records'][0]
        return status_code, message, error

    def get_ontap_version_from_params(self):
        """ Provide a way to override the current version
            This is required when running a custom vsadmin role as ONTAP does not currently allow access to /api/cluster.
            This may also be interesting for testing :)
            Report a warning if API call failed to report version.
            Report a warning if current version could be fetched and is different.
        """
        try:
            version = [int(x) for x in self.force_ontap_version.split('.')]
            if len(version) == 2:
                version.append(0)
            gen, major, minor = version
        except (TypeError, ValueError) as exc:
            self.module.fail_json(
                msg='Error: unexpected format in force_ontap_version, expecting G.M.m or G.M, as in 9.10.1, got: %s, error: %s'
                    % (self.force_ontap_version, exc))

        warning = ''
        read_version = self.get_ontap_version()
        if read_version == (-1, -1, -1):
            warning = ', unable to read current version:'
        elif read_version != (gen, major, minor):
            warning = ' but current version is %s' % self.ontap_version['full']
        if warning:
            warning = 'Forcing ONTAP version to %s%s' % (self.force_ontap_version, warning)
            self.set_version({'version': {
                'generation': gen,
                'major': major,
                'minor': minor,
                'full': 'set by user to %s' % self.force_ontap_version,
            }})
        return warning

    def get_ontap_version_using_rest(self):
        # using GET rather than HEAD because the error messages are different,
        # and we need the version as some REST options are not available in earlier versions
        method = 'GET'
        api = 'cluster'
        if should_use_lambda(self.module):
            params = {'fields': 'version'}
        else:
            params = {'fields': ['version']}
        status_code, message, error = self.send_request(method, api, params=params)
        try:
            if error and 'are available in precluster.' in error.get('message', ''):
                # in precluster mode, version is not available :(
                status_code, message, error = self.get_node_version_using_rest()
            if error and 'User is not authorized.' in error.get('message', ''):
                self.module.fail_json('User is not authorized.')
        except AttributeError:
            pass
        self.set_version(message)
        if error:
            self.log_error(status_code, str(error))
        if self.force_ontap_version:
            warning = self.get_ontap_version_from_params()
            if error:
                warning += ' error: %s, status_code: %s' % (error, status_code)
            if warning:
                self.module.warn(warning)
                msg = 'Forcing ONTAP version to %s' % self.force_ontap_version
                if error:
                    self.log_error('INFO', msg)
                else:
                    self.log_debug('INFO', msg)
            error = None
            status_code = 200
        self.is_rest_error = str(error) if error else None
        return status_code

    def convert_parameter_keys_to_dot_notation(self, parameters):
        """ Get all variable set in a list and add them to a dict so that partially_supported_rest_properties works correctly """
        if isinstance(parameters, dict):
            temp = {}
            for parameter in parameters:
                if isinstance(parameters[parameter], list):
                    if parameter not in temp:
                        temp[parameter] = {}
                    for adict in parameters[parameter]:
                        if isinstance(adict, dict):
                            for key in adict:
                                temp[parameter + '.' + key] = 0
            parameters.update(temp)
        return parameters

    def _is_rest(self, used_unsupported_rest_properties=None, partially_supported_rest_properties=None, parameters=None):
        if self.use_rest not in ['always', 'auto', 'never']:
            error = "use_rest must be one of: never, always, auto. Got: '%s'" % self.use_rest
            return False, error
        if self.use_rest == "always" and used_unsupported_rest_properties:
            error = "REST API currently does not support '%s'" % ', '.join(used_unsupported_rest_properties)
            return True, error
        if self.use_rest == 'never':
            # force ZAPI if requested
            return False, None
        # Check if ONTAP version is already known
        if self.ontap_version['valid']:
            status_code = 200
        else:
            status_code = self.get_ontap_version_using_rest()
        if self.use_rest == "always" and partially_supported_rest_properties:
            # If a variable is on a list we need to move it to a dict for this check to work correctly.
            temp_parameters = parameters.copy()
            temp_parameters = self.convert_parameter_keys_to_dot_notation(temp_parameters)
            error = '\n'.join(
                "Minimum version of ONTAP for %s is %s." % (property[0], str(property[1]))
                for property in partially_supported_rest_properties
                if self.get_ontap_version()[:3] < property[1] and property[0] in temp_parameters
            )
            if error != '':
                return True, 'Error: %s  Current version: %s.' % (error, self.get_ontap_version())
        if self.use_rest == 'always':
            # ignore error, it will show up later when calling another REST API
            return True, None
        # we're now using 'auto'
        if used_unsupported_rest_properties:
            # force ZAPI if some parameter requires it
            if self.get_ontap_version()[:2] > (9, 5):
                self.fallback_to_zapi_reason =\
                    'because of unsupported option(s) or option value(s) in REST: %s' % used_unsupported_rest_properties
                self.module.warn('Falling back to ZAPI %s' % self.fallback_to_zapi_reason)
            return False, None
        if partially_supported_rest_properties:
            # if ontap version is lower than partially_supported_rest_properties version, force ZAPI, only if the paramater is used
            # If a variable is on a list we need to move it to a dict for this check to work correctly.
            temp_parameters = parameters.copy()
            temp_parameters = self.convert_parameter_keys_to_dot_notation(temp_parameters)
            for property in partially_supported_rest_properties:
                if self.get_ontap_version()[:3] < property[1] and property[0] in temp_parameters:
                    self.fallback_to_zapi_reason =\
                        'because of unsupported option(s) or option value(s) "%s" in REST require %s' % (property[0], str(property[1]))
                    self.module.warn('Falling back to ZAPI %s' % self.fallback_to_zapi_reason)
                    return False, None
        if self.get_ontap_version()[:2] in ((9, 4), (9, 5)):
            # we can't trust REST support on 9.5, and not at all on 9.4
            return False, None
        return (True, None) if status_code == 200 else (False, None)

    def is_rest_supported_properties(self, parameters, unsupported_rest_properties=None, partially_supported_rest_properties=None, report_error=False):
        used_unsupported_rest_properties = None
        if unsupported_rest_properties:
            used_unsupported_rest_properties = [x for x in unsupported_rest_properties if x in parameters]
        use_rest, error = self.is_rest(used_unsupported_rest_properties, partially_supported_rest_properties, parameters)
        if report_error:
            return use_rest, error
        if error:
            self.module.fail_json(msg=error)
        return use_rest

    def is_rest(self, used_unsupported_rest_properties=None, partially_supported_rest_properties=None, parameters=None):
        ''' only return error if there is a reason to '''
        use_rest, error = self._is_rest(used_unsupported_rest_properties, partially_supported_rest_properties, parameters)
        if used_unsupported_rest_properties is None and partially_supported_rest_properties is None:
            return use_rest
        return use_rest, error

    def log_error(self, status_code, message):
        LOG.error("%s: %s", status_code, message)
        self.errors.append(message)
        self.debug_logs.append((status_code, message))

    def log_debug(self, status_code, content):
        LOG.debug("%s: %s", status_code, content)
        self.debug_logs.append((status_code, content))

    def write_to_file(self, tag, data=None, filepath=None, append=True):
        '''
        This function is only for debug purposes, all calls to write_to_file should be removed
        before submitting.
        If data is None, tag is considered as data
        else tag is a label, and data is data.
        '''
        if filepath is None:
            filepath = '/tmp/ontap_log'
        mode = 'a' if append else 'w'
        with open(filepath, mode) as afile:
            if data is not None:
                afile.write("%s: %s\n" % (str(tag), str(data)))
            else:
                afile.write(str(tag))
                afile.write('\n')

    def write_errors_to_file(self, tag=None, filepath=None, append=True):
        if tag is None:
            tag = 'Error'
        for error in self.errors:
            self.write_to_file(tag, error, filepath, append)
            if not append:
                append = True

    def write_debug_log_to_file(self, tag=None, filepath=None, append=True):
        if tag is None:
            tag = 'Debug'
        for status_code, message in self.debug_logs:
            self.write_to_file(tag, status_code, filepath, append)
            if not append:
                append = True
            self.write_to_file(tag, message, filepath, append)


class AwsLambda(OntapRestAPI):
    """
    AWS Lambda client for ONTAP API operations.
    Handles AWS Lambda invocation and ONTAP API request formatting.
    """

    def __init__(self, module, lambda_config):
        """
        Initialize the Lambda proxy client.
        :param module: Ansible module instance.
        :param lambda_config: Dictionary containing Lambda configuration.
        """
        self.module = module
        self.lambda_config = lambda_config
        self.lambda_client = None
        self.debug_logs = []

        if not HAS_BOTO3:
            module.fail_json(msg="boto3 is required for Lambda functionality. Install with: pip install boto3")
        self._setup_lambda_client()

    def _setup_lambda_client(self):
        """Set up the AWS Lambda client with proper configuration."""
        region_name = self.lambda_config.get('aws_region')
        profile_name = self.lambda_config.get('aws_profile')

        try:
            if profile_name:
                boto3.setup_default_session(profile_name=profile_name)
            self.lambda_client = boto3.client("lambda", region_name=region_name)
        except Exception as exc:
            self.module.fail_json("Failed to create Lambda client: %s" % exc)

    def is_enabled(self):
        """Check if Lambda proxy is enabled and properly configured."""
        return (self.lambda_config.get('use_lambda', False) and
                self.lambda_config.get('function_name'))

    def invoke_lambda_function(self, function_name, payload):
        """
        Invoke a Lambda function with the specified payload.
        :param function_name: Name of the Lambda function to invoke.
        :param payload: The payload to send to the Lambda function.
        :return: Response from the Lambda function.
        """
        try:
            response = self.lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse',  # Synchronous invocation
                Payload=json.dumps(payload)
            )
            return response
        except Exception as exc:
            self.module.fail_json("Error invoking Lambda function %s: %s" % (function_name, exc))

    def _send_request(self, method, url, params, json_data, headers, files):
        """
        Send an HTTP request through Lambda proxy (compatible with OntapRestAPI._send_request signature).
        :param method: HTTP method (GET, POST, PATCH, DELETE).
        :param url: Full URL or API path.
        :param params: Optional query parameters.
        :param json_data: Optional JSON data for POST/PATCH requests.
        :param headers: Optional headers.
        :param files: Optional files (not supported in Lambda proxy).
        :return: Tuple of (status_code, json_response, error_details).
        """

        # Extract API path from URL if it's a full URL
        if url.startswith('https://'):
            # Extract just the API path part
            api_path = url.split('/api/')[-1]
        else:
            # Already an API path
            api_path = url

        function_name = self.lambda_config.get('function_name')
        hostname = self.module.params.get('hostname')
        username = self.module.params.get('username')
        password = self.module.params.get('password')

        if not function_name:
            return None, None, "lambda_config.function_name is required when using Lambda proxy"

        if not all([hostname, username, password]):
            return None, None, "hostname, username, and password are required for Lambda ONTAP operations"

        # Build the request URL with API path
        if api_path.startswith('/'):
            api_path = api_path[1:]  # Remove leading slash
        api_url = "/api/%s" % api_path

        # Add query parameters if provided
        if params:
            query_string = '&'.join(["%s=%s" % (k, v) for k, v in params.items()])
            api_url += "?%s" % query_string

        # Prepare authentication
        credential = "%s:%s" % (username, password)
        base64_credential = base64.b64encode(credential.encode("utf-8")).decode("utf-8")

        # Build Lambda payload
        payload = {
            "body": {
                "endpoint": hostname,
                "url": api_url,
                "method": method.upper(),
                "headers": {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Authorization": "Basic %s" % base64_credential
                },
                "requestType": "https"
            }
        }

        # Add custom headers if provided
        if headers:
            payload["body"]["headers"].update(headers)

        # Add data for POST/PATCH requests
        if json_data and method.upper() in ['POST', 'PATCH', 'PUT']:
            payload["body"]["data"] = json_data

        try:
            # Invoke Lambda function
            lambda_response = self.invoke_lambda_function(function_name, payload)
            self.log_debug("lambda_response: ", lambda_response)
            # Parse Lambda response
            if lambda_response and 'Payload' in lambda_response:
                response_data = json.loads(lambda_response['Payload'].read())
                self.log_debug("response_data: ", response_data)

                # Extract status code, JSON response, and error from Lambda response
                status_code = response_data.get('status', 500)

                # Try to parse the body as JSON
                body = response_data.get('data', '{}')
                if isinstance(body, str):
                    try:
                        json_response = json.loads(body)
                    except json.JSONDecodeError:
                        json_response = {"raw_response": body}
                else:
                    json_response = body

                # Check for errors
                error_details = None
                if status_code >= 400:
                    error_details = json_response.get('error', "HTTP %d error" % status_code)
                elif 'error' in json_response:
                    error_details = json_response['error']

                return status_code, json_response, error_details
            else:
                return 500, None, "Invalid Lambda response format"

        except Exception as exc:
            return 500, None, "Lambda request failed: %s" % exc
