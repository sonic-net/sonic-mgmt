#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: na_santricity_global
short_description: NetApp E-Series manage global settings configuration
description:
    - Allow the user to configure several of the global settings associated with an E-Series storage-system
author:
    - Michael Price (@lmprice)
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    name:
        description:
            - Set the name of the E-Series storage-system
            - This label/name doesn't have to be unique.
            - May be up to 30 characters in length.
        type: str
        aliases:
            - label
    cache_block_size:
        description:
            - Size of the cache's block size.
            - All volumes on the storage system share the same cache space; therefore, the volumes can have only one
              cache block size.
            - See M(netapp_eseries.santricity.na_santricity_facts) for available sizes.
        type: int
        required: False
    cache_flush_threshold:
        description:
            - This is the percentage threshold of the amount of unwritten data that is allowed to remain on the storage
              array's cache before flushing.
        type: int
        required: False
    default_host_type:
        description:
            - Default host type for the storage system.
            - Either one of the following names can be specified, Linux DM-MP, VMWare, Windows, Windows Clustered, or a
              host type index which can be found in M(netapp_eseries.santricity.na_santricity_facts)
        type: str
        required: False
    automatic_load_balancing:
        description:
            - Enable automatic load balancing to allow incoming traffic from the hosts to be dynamically managed and
              balanced across both controllers.
            - Automatic load balancing requires host connectivity reporting to be enabled.
        type: str
        choices:
            - enabled
            - disabled
        required: False
    host_connectivity_reporting:
        description:
            - Enable host connectivity reporting to allow host connections to be monitored for connection and multipath
              driver problems.
            - When I(automatic_load_balancing==enabled) then M(netapp_eseries.santricity.host_connectivity_reporting)
              must be enabled.
        type: str
        choices:
            - enabled
            - disabled
        required: False
    login_banner_message:
        description:
            - Text message that appears prior to the login page.
            - I(login_banner_message=="") will delete any existing banner message.
        type: str
        required: False
    controller_shelf_id:
        description:
            - This is the identifier for the drive enclosure containing the controllers.
        type: int
        required: false
        default: 0
notes:
    - Check mode is supported.
    - This module requires Web Services API v1.3 or newer.
"""

EXAMPLES = """
    - name: Set the storage-system name
      na_santricity_global:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        name: myArrayName
        cache_block_size: 32768
        cache_flush_threshold: 80
        automatic_load_balancing: enabled
        default_host_type: Linux DM-MP
    - name: Set the storage-system name
      na_santricity_global:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        name: myOtherArrayName
        cache_block_size: 8192
        cache_flush_threshold: 60
        automatic_load_balancing: disabled
        default_host_type: 28
"""

RETURN = """
changed:
    description: Whether global settings were changed
    returned: on success
    type: bool
    sample: true
array_name:
    description: Current storage array's name
    returned: on success
    type: str
    sample: arrayName
automatic_load_balancing:
    description: Whether automatic load balancing feature has been enabled
    returned: on success
    type: str
    sample: enabled
host_connectivity_reporting:
    description: Whether host connectivity reporting feature has been enabled
    returned: on success
    type: str
    sample: enabled
cache_settings:
    description: Current cache block size and flushing threshold values
    returned: on success
    type: dict
    sample: {"cache_block_size": 32768, "cache_flush_threshold": 80}
default_host_type_index:
    description: Current default host type index
    returned: on success
    type: int
    sample: 28
login_banner_message:
    description: Current banner message
    returned: on success
    type: str
    sample: "Banner message here!"
controller_shelf_id:
    description: Identifier for the drive enclosure containing the controllers.
    returned: on success
    type: int
    sample: 99
"""
import random
import sys

from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils import six
from ansible.module_utils._text import to_native
try:
    from ansible.module_utils.ansible_release import __version__ as ansible_version
except ImportError:
    ansible_version = 'unknown'


class NetAppESeriesGlobalSettings(NetAppESeriesModule):
    MAXIMUM_LOGIN_BANNER_SIZE_BYTES = 5 * 1024
    LAST_AVAILABLE_CONTROLLER_SHELF_ID = 99

    def __init__(self):
        version = "02.00.0000.0000"
        ansible_options = dict(cache_block_size=dict(type="int", required=False),
                               cache_flush_threshold=dict(type="int", required=False),
                               default_host_type=dict(type="str", required=False),
                               automatic_load_balancing=dict(type="str", choices=["enabled", "disabled"], required=False),
                               host_connectivity_reporting=dict(type="str", choices=["enabled", "disabled"], required=False),
                               name=dict(type='str', required=False, aliases=['label']),
                               login_banner_message=dict(type='str', required=False),
                               controller_shelf_id=dict(type="int", required=False, default=0))

        super(NetAppESeriesGlobalSettings, self).__init__(ansible_options=ansible_options,
                                                          web_services_version=version,
                                                          supports_check_mode=True)
        args = self.module.params
        self.name = args["name"]
        self.cache_block_size = args["cache_block_size"]
        self.cache_flush_threshold = args["cache_flush_threshold"]
        self.host_type_index = args["default_host_type"]
        self.controller_shelf_id = args["controller_shelf_id"]

        self.login_banner_message = None
        if args["login_banner_message"] is not None:
            self.login_banner_message = args["login_banner_message"].rstrip("\n")

        self.autoload_enabled = None
        if args["automatic_load_balancing"]:
            self.autoload_enabled = args["automatic_load_balancing"] == "enabled"

        self.host_connectivity_reporting_enabled = None
        if args["host_connectivity_reporting"]:
            self.host_connectivity_reporting_enabled = args["host_connectivity_reporting"] == "enabled"
        elif self.autoload_enabled:
            self.host_connectivity_reporting_enabled = True

        if self.autoload_enabled and not self.host_connectivity_reporting_enabled:
            self.module.fail_json(msg="Option automatic_load_balancing requires host_connectivity_reporting to be "
                                      "enabled. Array [%s]." % self.ssid)

        self.current_configuration_cache = None

    def get_current_configuration(self, update=False):
        """Retrieve the current storage array's global configuration."""
        if self.current_configuration_cache is None or update:
            self.current_configuration_cache = dict()

            # Get the storage array's capabilities and available options
            try:
                rc, capabilities = self.request("storage-systems/%s/capabilities" % self.ssid)
                self.current_configuration_cache["autoload_capable"] = \
                    "capabilityAutoLoadBalancing" in capabilities["productCapabilities"]
                self.current_configuration_cache["cache_block_size_options"] = \
                    capabilities["featureParameters"]["cacheBlockSizes"]
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve storage array capabilities. Array [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(error)))

            try:
                rc, host_types = self.request("storage-systems/%s/host-types" % self.ssid)
                self.current_configuration_cache["host_type_options"] = dict()
                for host_type in host_types:
                    self.current_configuration_cache["host_type_options"].update({host_type["code"].lower(): host_type["index"]})
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve storage array host options. Array [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(error)))

            # Get the current cache settings
            try:
                rc, settings = self.request("storage-systems/%s/graph/xpath-filter?query=/sa" % self.ssid)
                self.current_configuration_cache["cache_settings"] = {
                    "cache_block_size": settings[0]["cache"]["cacheBlkSize"],
                    "cache_flush_threshold": settings[0]["cache"]["demandFlushThreshold"]
                }
                self.current_configuration_cache["default_host_type_index"] = settings[0]["defaultHostTypeIndex"]
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve cache settings. Array [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(error)))

            try:
                rc, array_info = self.request("storage-systems/%s" % self.ssid)
                self.current_configuration_cache["autoload_enabled"] = array_info["autoLoadBalancingEnabled"]
                self.current_configuration_cache["host_connectivity_reporting_enabled"] = \
                    array_info["hostConnectivityReportingEnabled"]
                self.current_configuration_cache["name"] = array_info['name']
            except Exception as error:
                self.module.fail_json(msg="Failed to determine current configuration. Array [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(error)))

            try:
                rc, login_banner_message = self.request("storage-systems/%s/login-banner?asFile=false" % self.ssid,
                                                        ignore_errors=True, json_response=False,
                                                        headers={"Accept": "application/octet-stream", "netapp-client-type": "Ansible-%s" % ansible_version})
                self.current_configuration_cache["login_banner_message"] = \
                    login_banner_message.decode("utf-8").rstrip("\n")
            except Exception as error:
                self.module.fail_json(msg="Failed to determine current login banner message. Array [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(error)))

            try:
                rc, hardware_inventory = self.request("storage-systems/%s/hardware-inventory" % self.ssid)
                self.current_configuration_cache["controller_shelf_reference"] = \
                    hardware_inventory["trays"][0]["trayRef"]
                self.current_configuration_cache["controller_shelf_id"] = hardware_inventory["trays"][0]["trayId"]
                self.current_configuration_cache["used_shelf_ids"] = \
                    [tray["trayId"] for tray in hardware_inventory["trays"]]
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve controller shelf identifier. Array [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(error)))

        return self.current_configuration_cache

    def change_cache_block_size_required(self):
        """Determine whether cache block size change is required."""
        if self.cache_block_size is None:
            return False

        current_configuration = self.get_current_configuration()
        current_available_block_sizes = current_configuration["cache_block_size_options"]
        if self.cache_block_size not in current_available_block_sizes:
            self.module.fail_json(msg="Invalid cache block size. Array [%s]. "
                                      "Available cache block sizes [%s]." % (self.ssid, current_available_block_sizes))

        return self.cache_block_size != current_configuration["cache_settings"]["cache_block_size"]

    def change_cache_flush_threshold_required(self):
        """Determine whether cache flush percentage change is required."""
        if self.cache_flush_threshold is None:
            return False

        current_configuration = self.get_current_configuration()
        if self.cache_flush_threshold <= 0 or self.cache_flush_threshold >= 100:
            self.module.fail_json(msg="Invalid cache flushing threshold, it must be equal to or between 0 and 100. "
                                      "Array [%s]" % self.ssid)

        return self.cache_flush_threshold != current_configuration["cache_settings"]["cache_flush_threshold"]

    def change_host_type_required(self):
        """Determine whether default host type change is required."""
        if self.host_type_index is None:
            return False

        current_configuration = self.get_current_configuration()
        current_available_host_types = current_configuration["host_type_options"]
        if isinstance(self.host_type_index, str):
            self.host_type_index = self.host_type_index.lower()

        if self.host_type_index in self.HOST_TYPE_INDEXES.keys():
            self.host_type_index = self.HOST_TYPE_INDEXES[self.host_type_index]
        elif self.host_type_index in current_available_host_types.keys():
            self.host_type_index = current_available_host_types[self.host_type_index]

        if self.host_type_index not in current_available_host_types.values():
            self.module.fail_json(msg="Invalid host type index! Array [%s]. "
                                      "Available host options [%s]." % (self.ssid, current_available_host_types))

        return int(self.host_type_index) != current_configuration["default_host_type_index"]

    def change_autoload_enabled_required(self):
        """Determine whether automatic load balancing state change is required."""
        if self.autoload_enabled is None:
            return False

        change_required = False
        current_configuration = self.get_current_configuration()
        if self.autoload_enabled and not current_configuration["autoload_capable"]:
            self.module.fail_json(msg="Automatic load balancing is not available. Array [%s]." % self.ssid)

        if self.autoload_enabled:
            if not current_configuration["autoload_enabled"] or \
                    not current_configuration["host_connectivity_reporting_enabled"]:
                change_required = True
        elif current_configuration["autoload_enabled"]:
            change_required = True

        return change_required

    def change_host_connectivity_reporting_enabled_required(self):
        """Determine whether host connectivity reporting state change is required."""
        if self.host_connectivity_reporting_enabled is None:
            return False

        current_configuration = self.get_current_configuration()
        return self.host_connectivity_reporting_enabled != current_configuration["host_connectivity_reporting_enabled"]

    def change_name_required(self):
        """Determine whether storage array name change is required."""
        if self.name is None:
            return False

        current_configuration = self.get_current_configuration()
        if self.name and len(self.name) > 30:
            self.module.fail_json(msg="The provided name is invalid. It must be less than or equal to 30 characters "
                                      "in length. Array [%s]" % self.ssid)

        return self.name != current_configuration["name"]

    def change_login_banner_message_required(self):
        """Determine whether storage array name change is required."""
        if self.login_banner_message is None:
            return False

        current_configuration = self.get_current_configuration()
        if self.login_banner_message and sys.getsizeof(self.login_banner_message) > self.MAXIMUM_LOGIN_BANNER_SIZE_BYTES:
            self.module.fail_json(msg="The banner message is too long! It must be %s bytes. "
                                      "Array [%s]" % (self.MAXIMUM_LOGIN_BANNER_SIZE_BYTES, self.ssid))
        return self.login_banner_message != current_configuration["login_banner_message"]

    def change_controller_shelf_id_required(self):
        """Determine whether storage array tray identifier change is required."""
        current_configuration = self.get_current_configuration()
        if self.controller_shelf_id is not None and \
                self.controller_shelf_id != current_configuration["controller_shelf_id"]:

            if self.controller_shelf_id in current_configuration["used_shelf_ids"]:
                used_shelf_ids = ", ".join([str(id) for id in self.get_current_configuration()["used_shelf_ids"]])
                self.module.fail_json(msg="The controller_shelf_id is currently being used by another shelf. "
                                          "Used Identifiers: [%s]. Array [%s]." % (used_shelf_ids, self.ssid))

            if self.controller_shelf_id < 0 or self.controller_shelf_id > self.LAST_AVAILABLE_CONTROLLER_SHELF_ID:
                used_shelf_ids = ", ".join([str(id) for id in self.get_current_configuration()["used_shelf_ids"]])
                self.module.fail_json(msg="The controller_shelf_id must be 0-99 and not already used by another shelf. "
                                          "Used Identifiers: [%s]. Array [%s]." % (used_shelf_ids, self.ssid))

            return True
        return False

    def update_cache_settings(self):
        """Update cache block size and/or flushing threshold."""
        current_configuration = self.get_current_configuration()
        block_size = self.cache_block_size if self.cache_block_size else current_configuration["cache_settings"]["cache_block_size"]
        threshold = self.cache_flush_threshold if self.cache_flush_threshold else \
            current_configuration["cache_settings"]["cache_flush_threshold"]
        try:
            rc, cache_settings = \
                self.request("storage-systems/%s/symbol/setSACacheParams?verboseErrorResponse=true" % self.ssid,
                             method="POST",
                             data={"cacheBlkSize": block_size,
                                   "demandFlushAmount": threshold,
                                   "demandFlushThreshold": threshold})
        except Exception as error:
            self.module.fail_json(msg="Failed to set cache settings. Array [%s]. "
                                      "Error [%s]." % (self.ssid, to_native(error)))

    def update_host_type(self):
        """Update default host type."""
        try:
            rc, default_host_type = \
                self.request(
                    "storage-systems/%s/symbol/setStorageArrayProperties?verboseErrorResponse=true" % self.ssid,
                    method="POST",
                    data={"settings": {"defaultHostTypeIndex": self.host_type_index}}
                )
        except Exception as error:
            self.module.fail_json(msg="Failed to set default host type. Array [%s]. "
                                      "Error [%s]" % (self.ssid, to_native(error)))

    def update_autoload(self):
        """Update automatic load balancing state."""
        current_configuration = self.get_current_configuration()
        if self.autoload_enabled and not current_configuration["host_connectivity_reporting_enabled"]:
            try:
                rc, host_connectivity_reporting = \
                    self.request(
                        "storage-systems/%s/symbol/setHostConnectivityReporting?verboseErrorResponse=true" % self.ssid,
                        method="POST",
                        data={"enableHostConnectivityReporting": self.autoload_enabled}
                    )
            except Exception as error:
                self.module.fail_json(msg="Failed to enable host connectivity reporting which is needed for "
                                          "automatic load balancing state. Array [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(error)))

        try:
            rc, autoload = \
                self.request("storage-systems/%s/symbol/setAutoLoadBalancing?verboseErrorResponse=true" % self.ssid,
                             method="POST", data={"enableAutoLoadBalancing": self.autoload_enabled})
        except Exception as error:
            self.module.fail_json(msg="Failed to set automatic load balancing state. Array [%s]. "
                                      "Error [%s]." % (self.ssid, to_native(error)))

    def update_host_connectivity_reporting_enabled(self):
        """Update automatic load balancing state."""
        try:
            rc, host_connectivity_reporting = \
                self.request(
                    "storage-systems/%s/symbol/setHostConnectivityReporting?verboseErrorResponse=true" % self.ssid,
                    method="POST",
                    data={"enableHostConnectivityReporting": self.host_connectivity_reporting_enabled}
                )
        except Exception as error:
            self.module.fail_json(msg="Failed to enable host connectivity reporting. Array [%s]. "
                                      "Error [%s]." % (self.ssid, to_native(error)))

    def update_name(self):
        """Update storage array's name."""
        try:
            rc, result = \
                self.request("storage-systems/%s/configuration" % self.ssid, method="POST", data={"name": self.name})
        except Exception as err:
            self.module.fail_json(msg="Failed to set the storage array name! Array Id [%s]. "
                                      "Error [%s]." % (self.ssid, to_native(err)))

    def update_login_banner_message(self):
        """Update storage login banner message."""
        if self.login_banner_message:
            boundary = "---------------------------" + "".join([str(random.randint(0, 9)) for x in range(27)])
            data_parts = list()
            data = None

            if six.PY2:  # Generate payload for Python 2
                newline = "\r\n"
                data_parts.extend(["--%s" % boundary,
                                   'Content-Disposition: form-data; name="file"; filename="banner.txt"',
                                   "Content-Type: text/plain",
                                   "",
                                   self.login_banner_message])
                data_parts.extend(["--%s--" % boundary, ""])
                data = newline.join(data_parts)

            else:
                newline = six.b("\r\n")
                data_parts.extend([six.b("--%s" % boundary),
                                   six.b('Content-Disposition: form-data; name="file"; filename="banner.txt"'),
                                   six.b("Content-Type: text/plain"),
                                   six.b(""),
                                   six.b(self.login_banner_message)])
                data_parts.extend([six.b("--%s--" % boundary), b""])
                data = newline.join(data_parts)

            headers = {"Content-Type": "multipart/form-data; boundary=%s" % boundary, "Content-Length": str(len(data))}

            try:
                rc, result = self.request("storage-systems/%s/login-banner" % self.ssid,
                                          method="POST",
                                          headers=headers,
                                          data=data)
            except Exception as err:
                self.module.fail_json(msg="Failed to set the storage system login banner message! Array Id [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(err)))
        else:
            try:
                rc, result = self.request("storage-systems/%s/login-banner" % self.ssid, method="DELETE")
            except Exception as err:
                self.module.fail_json(msg="Failed to clear the storage system login banner message! Array Id [%s]. "
                                          "Error [%s]." % (self.ssid, to_native(err)))

    def update_controller_shelf_id(self):
        """Update controller shelf tray identifier."""
        current_configuration = self.get_current_configuration()
        try:
            rc, tray = \
                self.request("storage-systems/%s/symbol/updateTray?verboseErrorResponse=true" % self.ssid,
                             method="POST",
                             data={"ref": current_configuration["controller_shelf_reference"],
                                   "trayID": self.controller_shelf_id})
        except Exception as error:
            self.module.fail_json(msg="Failed to update controller shelf identifier. Array [%s]. "
                                      "Error [%s]." % (self.ssid, to_native(error)))

    def update(self):
        """Ensure the storage array's global setting are correctly set."""
        change_required = False
        if (self.change_autoload_enabled_required() or
                self.change_cache_block_size_required() or
                self.change_cache_flush_threshold_required() or
                self.change_host_type_required() or
                self.change_name_required() or
                self.change_host_connectivity_reporting_enabled_required() or
                self.change_login_banner_message_required() or
                self.change_controller_shelf_id_required()):
            change_required = True

        if change_required and not self.module.check_mode:
            if self.change_autoload_enabled_required():
                self.update_autoload()
            if self.change_host_connectivity_reporting_enabled_required():
                self.update_host_connectivity_reporting_enabled()
            if self.change_cache_block_size_required() or self.change_cache_flush_threshold_required():
                self.update_cache_settings()
            if self.change_host_type_required():
                self.update_host_type()
            if self.change_name_required():
                self.update_name()
            if self.change_login_banner_message_required():
                self.update_login_banner_message()
            if self.change_controller_shelf_id_required():
                self.update_controller_shelf_id()

        current_configuration = self.get_current_configuration(update=True)
        automatic_load_balancing = "enabled" if current_configuration["autoload_enabled"] else "disabled"
        host_connectivity_reporting = "enabled" \
            if current_configuration["host_connectivity_reporting_enabled"] else "disabled"

        self.module.exit_json(changed=change_required,
                              cache_settings=current_configuration["cache_settings"],
                              default_host_type_index=current_configuration["default_host_type_index"],
                              automatic_load_balancing=automatic_load_balancing,
                              host_connectivity_reporting=host_connectivity_reporting,
                              array_name=current_configuration["name"],
                              login_banner_message=current_configuration["login_banner_message"],
                              controller_shelf_id=current_configuration["controller_shelf_id"])


def main():
    global_settings = NetAppESeriesGlobalSettings()
    global_settings.update()


if __name__ == "__main__":
    main()
