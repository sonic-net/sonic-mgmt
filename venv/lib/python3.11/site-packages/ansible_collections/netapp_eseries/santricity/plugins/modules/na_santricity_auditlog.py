#!/usr/bin/python

# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_auditlog
short_description: NetApp E-Series manage audit-log configuration
description:
    - This module allows an e-series storage system owner to set audit-log configuration parameters.
author: Nathan Swartz (@ndswartz)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    max_records:
        description:
            - The maximum number log messages audit-log will retain.
            - Max records must be between and including 100 and 50000.
        type: int
        default: 50000
    log_level:
        description: Filters the log messages according to the specified log level selection.
        choices:
            - all
            - writeOnly
        type: str
        default: writeOnly
    full_policy:
        description: Specifies what audit-log should do once the number of entries approach the record limit.
        choices:
            - overWrite
            - preventSystemAccess
        type: str
        default: overWrite
    threshold:
        description:
            - This is the memory full percent threshold that audit-log will start issuing warning messages.
            - Percent range must be between and including 60 and 90.
        type: int
        default: 90
    force:
        description:
            - Forces the audit-log configuration to delete log history when log messages fullness cause immediate
              warning or full condition.
            - Warning! This will cause any existing audit-log messages to be deleted.
            - This is only applicable for I(full_policy=preventSystemAccess).
        type: bool
        default: no
notes:
    - Check mode is supported.
    - Use I(ssid=="0") or I(ssid=="proxy") to configure SANtricity Web Services Proxy auditlog settings otherwise.
"""

EXAMPLES = """
- name: Define audit-log to prevent system access if records exceed 50000 with warnings occurring at 60% capacity.
  na_santricity_auditlog:
    ssid: "1"
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
    max_records: 50000
    log_level: all
    full_policy: preventSystemAccess
    threshold: 60
"""

RETURN = """
msg:
    description: Success message
    returned: on success
    type: str
    sample: The settings have been updated.
"""
import json

from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native


class NetAppESeriesAuditLog(NetAppESeriesModule):
    """Audit-log module configuration class."""
    MAX_RECORDS = 50000

    def __init__(self):
        ansible_options = dict(max_records=dict(type="int", default=50000),
                               log_level=dict(type="str", default="writeOnly", choices=["all", "writeOnly"]),
                               full_policy=dict(type="str", default="overWrite", choices=["overWrite", "preventSystemAccess"]),
                               threshold=dict(type="int", default=90),
                               force=dict(type="bool", default=False))
        super(NetAppESeriesAuditLog, self).__init__(ansible_options=ansible_options,
                                                    web_services_version="02.00.0000.0000",
                                                    supports_check_mode=True)

        args = self.module.params
        self.log_level = args["log_level"]
        self.force = args["force"]
        self.full_policy = args["full_policy"]
        self.max_records = args["max_records"]
        self.threshold = args["threshold"]

        if self.max_records < 100 or self.max_records > self.MAX_RECORDS:
            self.module.fail_json(msg="Audit-log max_records count must be between 100 and 50000: [%s]" % self.max_records)

        if self.threshold < 60 or self.threshold > 90:
            self.module.fail_json(msg="Audit-log percent threshold must be between 60 and 90: [%s]" % self.threshold)

        # Append web services proxy forward end point.
        self.url_path_prefix = ""
        if not self.is_embedded() and self.ssid != "0" and self.ssid.lower() != "proxy":
            self.url_path_prefix = "storage-systems/%s/forward/devmgr/v2/" % self.ssid

    def get_configuration(self):
        """Retrieve the existing audit-log configurations.

        :returns: dictionary containing current audit-log configuration
        """
        try:
            if self.is_proxy() and (self.ssid == "0" or self.ssid.lower() != "proxy"):
                rc, data = self.request("audit-log/config")
            else:
                rc, data = self.request(self.url_path_prefix + "storage-systems/1/audit-log/config")
            return data
        except Exception as err:
            self.module.fail_json(msg="Failed to retrieve the audit-log configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

    def build_configuration(self):
        """Build audit-log expected configuration.

        :returns: Tuple containing update boolean value and dictionary of audit-log configuration
        """
        config = self.get_configuration()

        current = dict(auditLogMaxRecords=config["auditLogMaxRecords"],
                       auditLogLevel=config["auditLogLevel"],
                       auditLogFullPolicy=config["auditLogFullPolicy"],
                       auditLogWarningThresholdPct=config["auditLogWarningThresholdPct"])

        body = dict(auditLogMaxRecords=self.max_records,
                    auditLogLevel=self.log_level,
                    auditLogFullPolicy=self.full_policy,
                    auditLogWarningThresholdPct=self.threshold)

        update = current != body
        return update, body

    def delete_log_messages(self):
        """Delete all audit-log messages."""
        try:
            if self.is_proxy() and (self.ssid == "0" or self.ssid.lower() != "proxy"):
                rc, result = self.request("audit-log?clearAll=True", method="DELETE")
            else:
                rc, result = self.request(self.url_path_prefix + "storage-systems/1/audit-log?clearAll=True", method="DELETE")
        except Exception as err:
            self.module.fail_json(msg="Failed to delete audit-log messages! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

    def update_configuration(self, update=None, body=None, attempt_recovery=True):
        """Update audit-log configuration."""
        if update is None or body is None:
            update, body = self.build_configuration()

        if update and not self.module.check_mode:
            try:
                if self.is_proxy() and (self.ssid == "0" or self.ssid.lower() != "proxy"):
                    rc, result = self.request("audit-log/config", data=json.dumps(body), method='POST', ignore_errors=True)
                else:
                    rc, result = self.request(self.url_path_prefix + "storage-systems/1/audit-log/config",
                                              data=json.dumps(body), method='POST', ignore_errors=True)

                if rc == 422:
                    if self.force and attempt_recovery:
                        self.delete_log_messages()
                        update = self.update_configuration(update, body, False)
                    else:
                        self.module.fail_json(msg="Failed to update audit-log configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(rc, result)))

            except Exception as error:
                self.module.fail_json(msg="Failed to update audit-log configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(error)))
        return update

    def update(self):
        """Update the audit-log configuration."""
        update = self.update_configuration()
        if update:
            self.module.exit_json(msg="Audit-log update complete", changed=update)
        else:
            self.module.exit_json(msg="No audit-log changes required", changed=update)


def main():
    auditlog = NetAppESeriesAuditLog()
    auditlog.update()


if __name__ == "__main__":
    main()
