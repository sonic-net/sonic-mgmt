# Copyright: (c) 2024, Ansible Cloud Team
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import ssl
import atexit
import traceback

try:
    # requests is required for exception handling of the ConnectionError
    import requests
    REQUESTS_IMP_ERR = None
except ImportError:
    REQUESTS_IMP_ERR = traceback.format_exc()

try:
    from pyVim import connect
    from pyVmomi import vim, vmodl
    PYVMOMI_IMP_ERR = None
except ImportError:
    PYVMOMI_IMP_ERR = traceback.format_exc()

from ansible_collections.vmware.vmware.plugins.module_utils.clients.errors import (
    ApiAccessError,
    MissingLibError
)


class PyvmomiClient():
    def __init__(
        self, hostname, username, password, port=443, validate_certs=True,
        proxy_host=None, proxy_port=None, http_proxy_host=None, http_proxy_port=None,
        **_
    ):
        self.check_requirements()
        self.hostname = hostname
        self.username = username
        self.port = port
        self.validate_certs = validate_certs
        # http_proxy_* args are maintained for compatibility for other projects.
        # They should be considered deprecated and dropped with the next major release
        # https://github.com/ansible-collections/vmware.vmware/issues/262
        self.proxy_host = proxy_host or http_proxy_host
        self.proxy_port = proxy_port or http_proxy_port
        self.si, self.content = self.connect_to_api(password=password, return_si=True)
        self.custom_field_mgr = []
        if self.content.customFieldsManager:  # not an ESXi
            self.custom_field_mgr = self.content.customFieldsManager.field

    def connect_to_api(self, password, disconnect_atexit=True, return_si=False):
        """
        Connect to the vCenter/ESXi client using the pyvmomi SDK. This creates a service instance
        which can then be used programmatically to make calls to the vCenter or ESXi
        Args:
            connection_params: dict, A dictionary with different authentication or connection parameters like
                               username, password, hostname, etc. The full list is found in the method below.
            disconnect_atexit: bool, If true, disconnect the client when the module or plugin finishes.
            return_si: bool, If true, return the service instance and the content manager objects. If false, just
                       return the content manager. There really is no need to set this to false since you can
                       just ignore the extra return values. This option is here for legacy compatibility
        Returns:
            If return_si is true
                service_instance, service_instance.RetrieveContent()
            If return_si is false
                service_instance.RetrieveContent()

        """
        self._password = password
        self.__validate_required_connection_params()
        ssl_context = self.__set_ssl_context()

        service_instance = None

        connection_args = dict(
            host=self.hostname,
            port=self.port,
        )
        if ssl_context:
            connection_args.update(sslContext=ssl_context)

        service_instance = self.__create_service_instance(connection_args)
        self._password = None

        # Disabling atexit should be used in special cases only.
        # Such as IP change of the ESXi host which removes the connection anyway.
        # Also removal significantly speeds up the return of the module
        if disconnect_atexit:
            atexit.register(connect.Disconnect, service_instance)
        if return_si:
            return service_instance, service_instance.RetrieveContent()
        return service_instance.RetrieveContent()

    def __validate_required_connection_params(self):
        """
        Validate the user provided the required connection parameters and throw an error
        if they were not found. Usually the module/plugin validation will do this first so
        this is more of a safety/sanity check.
        """
        if not self.hostname:
            raise ApiAccessError((
                "Hostname parameter is missing. Please specify this parameter in task or "
                "export environment variable like 'export VMWARE_HOST=ESXI_HOSTNAME'"
            ))

        if not self.username:
            raise ApiAccessError((
                "Username parameter is missing. Please specify this parameter in task or "
                "export environment variable like 'export VMWARE_USER=ESXI_USERNAME'"
            ))

        if not self._password:
            raise ApiAccessError((
                "Password parameter is missing. Please specify this parameter in task or "
                "export environment variable like 'export VMWARE_PASSWORD=ESXI_PASSWORD'"
            ))

    def __set_ssl_context(self):
        """
        Configure SSL context settings, depending on user inputs
        """
        if self.validate_certs and not hasattr(ssl, 'SSLContext'):
            raise ApiAccessError((
                'pyVim does not support changing verification mode with python < 2.7.9. '
                'Either update python or use validate_certs=false.'
            ))
        elif self.validate_certs:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.check_hostname = True
            ssl_context.load_default_certs()
        elif hasattr(ssl, 'SSLContext'):
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.check_hostname = False
        else:  # Python < 2.7.9 or RHEL/Centos < 7.4
            ssl_context = None

        return ssl_context

    def __create_service_instance(self, connection_args):
        """
        Attempt to connect to the vCenter/ESXi host and pass the resulting service instance back
        """
        error_msg_suffix = ''
        try:
            if self.proxy_host:
                error_msg_suffix = " [proxy: %s:%s]" % (self.proxy_host, self.proxy_port)
                connection_args.update(httpProxyHost=self.proxy_host, httpProxyPort=self.proxy_port)
                smart_stub = connect.SmartStubAdapter(**connection_args)
                session_stub = connect.VimSessionOrientedStub(
                    smart_stub, connect.VimSessionOrientedStub.makeUserLoginMethod(self.username, self._password)
                )
                service_instance = vim.ServiceInstance('ServiceInstance', session_stub)
            else:
                connection_args.update(user=self.username, pwd=self._password)
                service_instance = connect.SmartConnect(**connection_args)
        except vim.fault.InvalidLogin as e:
            raise ApiAccessError((
                "Unable to log on to the vCenter or ESXi API at %s:%s as %s: %s" %
                (connection_args['host'], connection_args['port'], self.username, e.msg) +
                error_msg_suffix
            ))
        except vim.fault.NoPermission as e:
            raise ApiAccessError((
                "User %s does not have the required permissions to log on to the vCenter or ESXi API at %s:%s : %s" %
                (self.username, connection_args['host'], connection_args['port'], e.msg)
            ))
        except (requests.ConnectionError, ssl.SSLError) as e:
            raise ApiAccessError((
                "Unable to connect to the vCenter or ESXi API at %s on TCP/%s: %s" %
                (connection_args['host'], connection_args['port'], e)
            ))
        except vmodl.fault.InvalidRequest as e:
            raise ApiAccessError((
                "Failed to get a response from server %s:%s as request is malformed: %s" %
                (connection_args['host'], connection_args['port'], e.msg) +
                error_msg_suffix
            ))
        except Exception as e:
            raise ApiAccessError((
                "Unknown error while connecting to the vCenter or ESXi API at %s:%s : %s" %
                (connection_args['host'], connection_args['port'], str(e)) +
                error_msg_suffix
            ))

        if service_instance is None:
            raise ApiAccessError((
                "Unknown error while connecting to the vCenter or ESXi API at %s:%s" %
                (connection_args['host'], connection_args['port']) +
                error_msg_suffix
            ))

        return service_instance

    def check_requirements(self):
        """
        Check all requirements for this client are satisfied
        """
        if REQUESTS_IMP_ERR:
            raise MissingLibError('requests', REQUESTS_IMP_ERR)
        if PYVMOMI_IMP_ERR:
            raise MissingLibError('pyvmomi', PYVMOMI_IMP_ERR)

    def get_all_objs_by_type(self, vimtype, folder=None, recurse=True):
        """
            Returns a list of all objects matching a given VMware type.
            This is much slower than get_managed_object_references because it gets all properties for all
            objects found during the search.
            You can also limit the search by folder and recurse if desired
            Args:
                vimtype: The type of object to search for
                folder: vim.Folder, the folder object to use as a base for the search. If
                        none is provided, the datacenter root will be used
                recurse: If true, the search will recurse through the folder structure
            Returns:
                A list of matching objects.
        """
        if not folder:
            folder = self.content.rootFolder

        objs = []
        container = self.content.viewManager.CreateContainerView(folder, vimtype, recurse)
        for managed_object_ref in container.view:
            try:
                objs += [managed_object_ref]
            except vmodl.fault.ManagedObjectNotFound:
                pass
        return objs

    def get_managed_object_references(self, vimtype, properties=None, folder=None, recurse=True):
        """
            Use the property collector to create a list of managed object references with select properties.
            By default, this will return light weight objects with the _moid and the name property. You
            can then filter the list down and fully populate the remaining objects with
            create_vim_object_from_moid.
            Args:
                vimtype: The type of object to search for
                properties: A list of properties that should be included in the managed object reference. The more
                            properties you use, the longer the search will take.
                folder: vim.Folder, the folder object to use as a base for the search. If
                        none is provided, the datacenter root will be used
                recurse: If true, the search will recurse through the folder structure
            Returns:
                list(managed object references). MORs are not full objects, they are reference objects that have
                a moid corresponding to an object, and select properties from said object.
        """
        if not folder:
            folder = self.content.rootFolder
        if not properties:
            properties = ['name']

        container_view = self.content.viewManager.CreateContainerView(folder, [vimtype], recurse)
        prop_spec = vim.PropertyCollector.PropertySpec(type=vimtype, pathSet=properties, all=False)
        obj_spec = vim.PropertyCollector.ObjectSpec(
            obj=container_view,
            skip=True,
            selectSet=[
                vim.PropertyCollector.TraversalSpec(
                    type=vim.view.ContainerView,  # Must be ContainerView
                    path="view",
                    skip=False
                )
            ]
        )
        filter_spec = vim.PropertyCollector.FilterSpec(
            propSet=[prop_spec],
            objectSet=[obj_spec],
            reportMissingObjectsInResults=False
        )

        retrieve_result = self.content.propertyCollector.RetrieveContents([filter_spec])
        container_view.Destroy()
        return retrieve_result

    def create_vim_object_from_moid(self, moid, vimtype):
        """
            Given an object MOID, create a fully populated vim object. This is useful
            to pair with get_managed_object_references. That method will return a list of object
            references, with the _moid attribute. You can then fully populate the object properties
            using this method
            Args:
                moid: The MOID of the object to create
                vimtype: The type of object to search for
            Returns:
                list(vim objects)
        """
        # Construct the actual objects by MOID
        obj = vimtype(moid, self.si._stub)
        try:
            # Force a property fetch to confirm validity
            _ = obj.name    # pylint: disable=disallowed-name
        except vmodl.fault.ManagedObjectNotFound:
            return None

        return obj
