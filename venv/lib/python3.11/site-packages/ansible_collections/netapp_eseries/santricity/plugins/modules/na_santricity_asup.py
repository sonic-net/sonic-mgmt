#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_asup
short_description: NetApp E-Series manage auto-support settings
description:
    - Allow the auto-support settings to be configured for an individual E-Series storage-system
author:
    - Michael Price (@lmprice)
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    state:
        description:
            - Enable/disable the E-Series auto-support configuration or maintenance mode.
            - When this option is enabled, configuration, logs, and other support-related information will be relayed
              to NetApp to help better support your system. No personally identifiable information, passwords, etc, will
              be collected.
            - The maintenance state enables the maintenance window which allows maintenance activities to be performed on the storage array without
              generating support cases.
            - Maintenance mode cannot be enabled unless ASUP has previously been enabled.
        type: str
        default: enabled
        choices:
            - enabled
            - disabled
            - maintenance_enabled
            - maintenance_disabled
    active:
        description:
            - Enable active/proactive monitoring for ASUP. When a problem is detected by our monitoring systems, it's
              possible that the bundle did not contain all of the required information at the time of the event.
              Enabling this option allows NetApp support personnel to manually request transmission or re-transmission
              of support data in order ot resolve the problem.
            - Only applicable if I(state=enabled).
        default: true
        type: bool
    start:
        description:
            - A start hour may be specified in a range from 0 to 23 hours.
            - ASUP bundles will be sent daily between the provided start and end time (UTC).
            - I(start) must be less than I(end).
        type: int
        default: 0
    end:
        description:
            - An end hour may be specified in a range from 1 to 24 hours.
            - ASUP bundles will be sent daily between the provided start and end time (UTC).
            - I(start) must be less than I(end).
        type: int
        default: 24
    days:
        description:
            - A list of days of the week that ASUP bundles will be sent. A larger, weekly bundle will be sent on one
              of the provided days.
        type: list
        elements: str
        choices:
            - monday
            - tuesday
            - wednesday
            - thursday
            - friday
            - saturday
            - sunday
        required: false
        aliases:
            - schedule_days
            - days_of_week
    method:
        description:
            - AutoSupport dispatch delivery method.
        choices:
            - https
            - http
            - email
        type: str
        required: false
        default: https
    routing_type:
        description:
            - AutoSupport routing
            - Required when I(method==https or method==http).
        choices:
            - direct
            - proxy
            - script
        type: str
        default: direct
        required: false
    proxy:
        description:
            - Information particular to the proxy delivery method.
            - Required when I((method==https or method==http) and routing_type==proxy).
        type: dict
        required: false
        suboptions:
            host:
                description:
                    - Proxy host IP address or fully qualified domain name.
                    - Required when I(method==http or method==https) and I(routing_type==proxy).
                type: str
                required: false
            port:
                description:
                    - Proxy host port.
                    - Required when I(method==http or method==https) and I(routing_type==proxy).
                type: int
                required: false
            script:
                description:
                    - Path to the AutoSupport routing script file.
                    - Required when I(method==http or method==https) and I(routing_type==script).
                type: str
                required: false
            username:
                description:
                    - Username for the proxy.
                type: str
                required: false
            password:
                description:
                    - Password for the proxy.
                type: str
                required: false
    email:
        description:
            - Information particular to the e-mail delivery method.
            - Uses the SMTP protocol.
            - Required when I(method==email).
        type: dict
        required: false
        suboptions:
            server:
                description:
                    - Mail server's IP address or fully qualified domain name.
                    - Required when I(routing_type==email).
                type: str
                required: false
            sender:
                description:
                    - Sender's email account
                    - Required when I(routing_type==email).
                type: str
                required: false
            test_recipient:
                description:
                    - Test verification email
                    - Required when I(routing_type==email).
                type: str
                required: false
    maintenance_duration:
        description:
            - The duration of time the ASUP maintenance mode will be active.
            - Permittable range is between 1 and 72 hours.
            - Required when I(state==maintenance_enabled).
        type: int
        default: 24
        required: false
    maintenance_emails:
        description:
            - List of email addresses for maintenance notifications.
            - Required when I(state==maintenance_enabled).
        type: list
        elements: str
        required: false
    validate:
        description:
            - Validate ASUP configuration.
        type: bool
        default: false
        required: false
notes:
    - Check mode is supported.
    - Enabling ASUP will allow our support teams to monitor the logs of the storage-system in order to proactively
      respond to issues with the system. It is recommended that all ASUP-related options be enabled, but they may be
      disabled if desired.
    - This API is currently only supported with the Embedded Web Services API v2.0 and higher.
"""

EXAMPLES = """
    - name: Enable ASUP and allow pro-active retrieval of bundles
      na_santricity_asup:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        state: enabled
        active: true
        days: ["saturday", "sunday"]
        start: 17
        end: 20
    - name: Set the ASUP schedule to only send bundles from 12 AM CST to 3 AM CST.
      na_santricity_asup:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        state: disabled
    - name: Set the ASUP schedule to only send bundles from 12 AM CST to 3 AM CST.
      na_santricity_asup:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        state: maintenance_enabled
        maintenance_duration: 24
        maintenance_emails:
          - admin@example.com
    - name: Set the ASUP schedule to only send bundles from 12 AM CST to 3 AM CST.
      na_santricity_asup:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        state: maintenance_disabled
"""

RETURN = """
msg:
    description: Success message
    returned: on success
    type: str
    sample: The settings have been updated.
asup:
    description:
        - True if ASUP is enabled.
    returned: on success
    sample: true
    type: bool
active:
    description:
        - True if the active option has been enabled.
    returned: on success
    sample: true
    type: bool
cfg:
    description:
        - Provide the full ASUP configuration.
    returned: on success
    type: complex
    contains:
        asupEnabled:
            description:
                    - True if ASUP has been enabled.
            type: bool
        onDemandEnabled:
            description:
                    - True if ASUP active monitoring has been enabled.
            type: bool
        daysOfWeek:
            description:
                - The days of the week that ASUP bundles will be sent.
            type: list
"""
import time

from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native


class NetAppESeriesAsup(NetAppESeriesModule):
    DAYS_OPTIONS = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"]

    def __init__(self):

        ansible_options = dict(
            state=dict(type="str", required=False, default="enabled", choices=["enabled", "disabled", "maintenance_enabled", "maintenance_disabled"]),
            active=dict(type="bool", required=False, default=True),
            days=dict(type="list", elements="str", required=False, aliases=["schedule_days", "days_of_week"], choices=self.DAYS_OPTIONS),
            start=dict(type="int", required=False, default=0),
            end=dict(type="int", required=False, default=24),
            method=dict(type="str", required=False, choices=["https", "http", "email"], default="https"),
            routing_type=dict(type="str", required=False, choices=["direct", "proxy", "script"], default="direct"),
            proxy=dict(type="dict", required=False, options=dict(host=dict(type="str", required=False),
                                                                 port=dict(type="int", required=False),
                                                                 script=dict(type="str", required=False),
                                                                 username=dict(type="str", required=False),
                                                                 password=dict(type="str", no_log=True, required=False))),
            email=dict(type="dict", required=False, options=dict(server=dict(type="str", required=False),
                                                                 sender=dict(type="str", required=False),
                                                                 test_recipient=dict(type="str", required=False))),
            maintenance_duration=dict(type="int", required=False, default=24),
            maintenance_emails=dict(type="list", elements="str", required=False),
            validate=dict(type="bool", required=False, default=False))

        # # mutually_exclusive did not work with suboptions. Comment out this for now.
        # mutually_exclusive = [["host", "script"],
        #                       ["port", "script"]]
        mutually_exclusive = None

        required_if = [["method", "https", ["routing_type"]],
                       ["method", "http", ["routing_type"]],
                       ["method", "email", ["email"]],
                       ["state", "maintenance_enabled", ["maintenance_duration", "maintenance_emails"]]]

        super(NetAppESeriesAsup, self).__init__(ansible_options=ansible_options,
                                                web_services_version="02.00.0000.0000",
                                                mutually_exclusive=mutually_exclusive,
                                                required_if=required_if,
                                                supports_check_mode=True)

        args = self.module.params
        self.state = args["state"]
        self.active = args["active"]
        self.days = args["days"]
        self.start = args["start"]
        self.end = args["end"]

        self.method = args["method"]
        self.routing_type = args["routing_type"] if args["routing_type"] else "none"
        self.proxy = args["proxy"]
        self.email = args["email"]
        self.maintenance_duration = args["maintenance_duration"]
        self.maintenance_emails = args["maintenance_emails"]
        self.validate = args["validate"]

        if self.validate and self.email and "test_recipient" not in self.email.keys():
            self.module.fail_json(msg="test_recipient must be provided for validating email delivery method. Array [%s]" % self.ssid)

        self.check_mode = self.module.check_mode

        if self.start >= self.end:
            self.module.fail_json(msg="The value provided for the start time is invalid."
                                      " It must be less than the end time.")
        if self.start < 0 or self.start > 23:
            self.module.fail_json(msg="The value provided for the start time is invalid. It must be between 0 and 23.")
        else:
            self.start = self.start * 60
        if self.end < 1 or self.end > 24:
            self.module.fail_json(msg="The value provided for the end time is invalid. It must be between 1 and 24.")
        else:
            self.end = min(self.end * 60, 1439)

        if self.maintenance_duration < 1 or self.maintenance_duration > 72:
            self.module.fail_json(msg="The maintenance duration must be equal to or between 1 and 72 hours.")

        if not self.days:
            self.days = self.DAYS_OPTIONS

        # Check whether request needs to be forwarded on to the controller web services rest api.
        self.url_path_prefix = ""
        if not self.is_embedded() and self.ssid != "0" and self.ssid.lower() != "proxy":
            self.url_path_prefix = "storage-systems/%s/forward/devmgr/v2/" % self.ssid

    def get_configuration(self):
        try:
            rc, result = self.request(self.url_path_prefix + "device-asup")

            if not (result["asupCapable"] and result["onDemandCapable"]):
                self.module.fail_json(msg="ASUP is not supported on this device. Array Id [%s]." % self.ssid)
            return result

        except Exception as err:
            self.module.fail_json(msg="Failed to retrieve ASUP configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

    def in_maintenance_mode(self):
        """Determine whether storage device is currently in maintenance mode."""
        results = False
        try:
            rc, key_values = self.request(self.url_path_prefix + "key-values")

            for key_value in key_values:
                if key_value["key"] == "ansible_asup_maintenance_email_list":
                    if not self.maintenance_emails:
                        self.maintenance_emails = key_value["value"].split(",")
                elif key_value["key"] == "ansible_asup_maintenance_stop_time":
                    if time.time() < float(key_value["value"]):
                        results = True

        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve maintenance windows information! Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

        return results

    def update_configuration(self):
        config = self.get_configuration()
        update = False
        body = dict()

        # Build request body
        if self.state == "enabled":
            body = dict(asupEnabled=True)
            if not config["asupEnabled"]:
                update = True

            if (config["onDemandEnabled"] and config["remoteDiagsEnabled"]) != self.active:
                update = True
                body.update(dict(onDemandEnabled=self.active,
                                 remoteDiagsEnabled=self.active))
            self.days.sort()
            config["schedule"]["daysOfWeek"].sort()

            body["schedule"] = dict(daysOfWeek=self.days,
                                    dailyMinTime=self.start,
                                    dailyMaxTime=self.end,
                                    weeklyMinTime=self.start,
                                    weeklyMaxTime=self.end)

            if self.days != config["schedule"]["daysOfWeek"]:
                update = True
            if self.start != config["schedule"]["dailyMinTime"] or self.start != config["schedule"]["weeklyMinTime"]:
                update = True
            elif self.end != config["schedule"]["dailyMaxTime"] or self.end != config["schedule"]["weeklyMaxTime"]:
                update = True

            if self.method in ["https", "http"]:
                if self.routing_type == "direct":
                    body["delivery"] = dict(method=self.method,
                                            routingType="direct")
                elif self.routing_type == "proxy":
                    body["delivery"] = dict(method=self.method,
                                            proxyHost=self.proxy["host"],
                                            proxyPort=self.proxy["port"],
                                            routingType="proxyServer")
                    if "username" in self.proxy.keys():
                        body["delivery"].update({"proxyUserName": self.proxy["username"]})
                    if "password" in self.proxy.keys():
                        body["delivery"].update({"proxyPassword": self.proxy["password"]})

                elif self.routing_type == "script":
                    body["delivery"] = dict(method=self.method,
                                            proxyScript=self.proxy["script"],
                                            routingType="proxyScript")

            else:
                body["delivery"] = dict(method="smtp",
                                        mailRelayServer=self.email["server"],
                                        mailSenderAddress=self.email["sender"],
                                        routingType="none")

            # Check whether changes are required.
            if config["delivery"]["method"] != body["delivery"]["method"]:
                update = True
            elif config["delivery"]["method"] in ["https", "http"]:
                if config["delivery"]["routingType"] != body["delivery"]["routingType"]:
                    update = True
                elif config["delivery"]["routingType"] == "proxyServer":
                    if (config["delivery"]["proxyHost"] != body["delivery"]["proxyHost"] or
                            config["delivery"]["proxyPort"] != body["delivery"]["proxyPort"] or
                            config["delivery"]["proxyUserName"] != body["delivery"]["proxyUserName"] or
                            config["delivery"]["proxyPassword"] != body["delivery"]["proxyPassword"]):
                        update = True
                elif config["delivery"]["routingType"] == "proxyScript":
                    if config["delivery"]["proxyScript"] != body["delivery"]["proxyScript"]:
                        update = True
            elif (config["delivery"]["method"] == "smtp" and
                  config["delivery"]["mailRelayServer"] != body["delivery"]["mailRelayServer"] and
                  config["delivery"]["mailSenderAddress"] != body["delivery"]["mailSenderAddress"]):
                update = True

            if self.in_maintenance_mode():
                update = True

        elif self.state == "disabled":
            if config["asupEnabled"]:     # Disable asupEnable is asup is disabled.
                body = dict(asupEnabled=False)
                update = True

        else:
            if not config["asupEnabled"]:
                self.module.fail_json(msg="AutoSupport must be enabled before enabling or disabling maintenance mode. Array [%s]." % self.ssid)

            if self.in_maintenance_mode() or self.state == "maintenance_enabled":
                update = True

        # Apply required changes.
        if update and not self.check_mode:
            if self.state == "maintenance_enabled":
                try:
                    rc, response = self.request(self.url_path_prefix + "device-asup/maintenance-window", method="POST",
                                                data=dict(maintenanceWindowEnabled=True,
                                                          duration=self.maintenance_duration,
                                                          emailAddresses=self.maintenance_emails))
                except Exception as error:
                    self.module.fail_json(msg="Failed to enabled ASUP maintenance window. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

                # Add maintenance information to the key-value store
                try:
                    rc, response = self.request(self.url_path_prefix + "key-values/ansible_asup_maintenance_email_list", method="POST",
                                                data=",".join(self.maintenance_emails))
                    rc, response = self.request(self.url_path_prefix + "key-values/ansible_asup_maintenance_stop_time", method="POST",
                                                data=str(time.time() + 60 * 60 * self.maintenance_duration))
                except Exception as error:
                    self.module.fail_json(msg="Failed to store maintenance information. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

            elif self.state == "maintenance_disabled":
                try:
                    rc, response = self.request(self.url_path_prefix + "device-asup/maintenance-window", method="POST",
                                                data=dict(maintenanceWindowEnabled=False,
                                                          emailAddresses=self.maintenance_emails))
                except Exception as error:
                    self.module.fail_json(msg="Failed to disable ASUP maintenance window. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

                # Remove maintenance information to the key-value store
                try:
                    rc, response = self.request(self.url_path_prefix + "key-values/ansible_asup_maintenance_email_list", method="DELETE")
                    rc, response = self.request(self.url_path_prefix + "key-values/ansible_asup_maintenance_stop_time", method="DELETE")
                except Exception as error:
                    self.module.fail_json(msg="Failed to store maintenance information. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

            else:
                if body["asupEnabled"] and self.validate:
                    validate_body = dict(delivery=body["delivery"])
                    if self.email:
                        validate_body["mailReplyAddress"] = self.email["test_recipient"]

                    try:
                        rc, response = self.request(self.url_path_prefix + "device-asup/verify-config", timeout=600, method="POST", data=validate_body)
                    except Exception as err:
                        self.module.fail_json(msg="Failed to validate ASUP configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

                try:
                    rc, response = self.request(self.url_path_prefix + "device-asup", method="POST", data=body)
                # This is going to catch cases like a connection failure
                except Exception as err:
                    self.module.fail_json(msg="Failed to change ASUP configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

        return update

    def apply(self):
        update = self.update_configuration()
        cfg = self.get_configuration()

        if update:
            self.module.exit_json(msg="The ASUP settings have been updated.", changed=update, asup=cfg["asupEnabled"], active=cfg["onDemandEnabled"], cfg=cfg)
        else:
            self.module.exit_json(msg="No ASUP changes required.", changed=update, asup=cfg["asupEnabled"], active=cfg["onDemandEnabled"], cfg=cfg)


def main():
    asup = NetAppESeriesAsup()
    asup.apply()


if __name__ == "__main__":
    main()
