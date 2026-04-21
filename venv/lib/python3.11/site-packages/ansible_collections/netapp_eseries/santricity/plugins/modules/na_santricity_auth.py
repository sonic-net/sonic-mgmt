#!/usr/bin/python

# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_auth
short_description: NetApp E-Series set or update the password for a storage array device or SANtricity Web Services Proxy.
description:
    - Sets or updates the password for a storage array device or SANtricity Web Services Proxy.
author:
    - Nathan Swartz (@ndswartz)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    current_admin_password:
        description:
            - The current admin password.
            - When making changes to the embedded web services's login passwords, api_password will be used and current_admin_password will be ignored.
            - When making changes to the proxy web services's login passwords, api_password will be used and current_admin_password will be ignored.
            - Only required when the password has been set and will be ignored if not set.
        type: str
        required: false
    password:
        description:
            - The password you would like to set.
            - Cannot be more than 30 characters.
        type: str
        required: false
    user:
        description:
            - The local user account password to update
            - For systems prior to E2800, use admin to change the rw (system password).
            - For systems prior to E2800, all choices except admin will be ignored.
        type: str
        choices: ["admin", "monitor", "support", "security", "storage"]
        default: "admin"
        required: false
    minimum_password_length:
        description:
            - This option defines the minimum password length.
        type: int
        required: false
notes:
    - Set I(ssid=="0") or I(ssid=="proxy") when attempting to change the password for SANtricity Web Services Proxy.
    - SANtricity Web Services Proxy storage password will be updated when changing the password on a managed storage system from the proxy; This is only true
      when the storage system has been previously contacted.
"""

EXAMPLES = """
- name: Set the initial password
  na_santricity_auth:
    ssid: 1
    api_url: https://192.168.1.100:8443/devmgr/v2
    api_username: admin
    api_password: adminpass
    validate_certs: true
    current_admin_password: currentadminpass
    password: newpassword123
    user: admin
"""

RETURN = """
msg:
    description: Success message
    returned: success
    type: str
    sample: "Password Updated Successfully"
"""
from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native


class NetAppESeriesAuth(NetAppESeriesModule):
    def __init__(self):
        version = "02.00.0000.0000"
        ansible_options = dict(current_admin_password=dict(type="str", required=False, no_log=True),
                               password=dict(type="str", required=False, no_log=True),
                               user=dict(type="str", choices=["admin", "monitor", "support", "security", "storage"], default="admin", required=False),
                               minimum_password_length=dict(type="int", required=False, no_log=True))

        super(NetAppESeriesAuth, self).__init__(ansible_options=ansible_options, web_services_version=version, supports_check_mode=True)
        args = self.module.params
        self.current_admin_password = args["current_admin_password"]
        self.password = args["password"]
        self.user = args["user"]
        self.minimum_password_length = args["minimum_password_length"]

        self.DEFAULT_HEADERS.update({"x-netapp-password-validate-method": "none"})

        self.is_admin_password_set = None
        self.current_password_length_requirement = None

    def minimum_password_length_change_required(self):
        """Retrieve the current storage array's global configuration."""
        change_required = False
        try:
            if self.is_proxy():
                if self.ssid == "0" or self.ssid.lower() == "proxy":
                    rc, system_info = self.request("local-users/info", force_basic_auth=False)

                elif self.is_embedded_available():
                    rc, system_info = self.request("storage-systems/%s/forward/devmgr/v2/storage-systems/1/local-users/info" % self.ssid,
                                                   force_basic_auth=False)
                else:
                    return False    # legacy systems without embedded web services.
            else:
                rc, system_info = self.request("storage-systems/%s/local-users/info" % self.ssid, force_basic_auth=False)
        except Exception as error:
            self.module.fail_json(msg="Failed to determine minimum password length. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

        self.is_admin_password_set = system_info["adminPasswordSet"]
        if self.minimum_password_length is not None and self.minimum_password_length != system_info["minimumPasswordLength"]:
            change_required = True

        if (self.password is not None and ((change_required and self.minimum_password_length > len(self.password)) or
                                           (not change_required and system_info["minimumPasswordLength"] > len(self.password)))):
            self.module.fail_json(msg="Password does not meet the length requirement [%s]. Array Id [%s]." % (system_info["minimumPasswordLength"], self.ssid))

        return change_required

    def update_minimum_password_length(self):
        """Update automatic load balancing state."""
        try:
            if self.is_proxy():
                if self.ssid == "0" or self.ssid.lower() == "proxy":
                    try:
                        if not self.is_admin_password_set:
                            self.creds["url_password"] = "admin"
                        rc, minimum_password_length = self.request("local-users/password-length", method="POST",
                                                                   data={"minimumPasswordLength": self.minimum_password_length})
                    except Exception as error:
                        if not self.is_admin_password_set:
                            self.creds["url_password"] = ""
                        rc, minimum_password_length = self.request("local-users/password-length", method="POST",
                                                                   data={"minimumPasswordLength": self.minimum_password_length})
                elif self.is_embedded_available():
                    if not self.is_admin_password_set:
                        self.creds["url_password"] = ""
                    rc, minimum_password_length = self.request("storage-systems/%s/forward/devmgr/v2/storage-systems/1/local-users/password-length" % self.ssid,
                                                               method="POST", data={"minimumPasswordLength": self.minimum_password_length})
            else:
                if not self.is_admin_password_set:
                    self.creds["url_password"] = ""
                rc, minimum_password_length = self.request("storage-systems/%s/local-users/password-length" % self.ssid, method="POST",
                                                           data={"minimumPasswordLength": self.minimum_password_length})
        except Exception as error:
            self.module.fail_json(msg="Failed to set minimum password length. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

    def logout_system(self):
        """Ensure system is logged out. This is required because login test will always succeed if previously logged in."""
        try:
            if self.is_proxy():
                if self.ssid == "0" or self.ssid.lower() == "proxy":
                    rc, system_info = self.request("utils/login", rest_api_path=self.DEFAULT_BASE_PATH, method="DELETE", force_basic_auth=False)
                elif self.is_embedded_available():
                    rc, system_info = self.request("storage-systems/%s/forward/devmgr/utils/login" % self.ssid, method="DELETE", force_basic_auth=False)
                else:
                    # Nothing to do for legacy systems without embedded web services.
                    pass
            else:
                rc, system_info = self.request("utils/login", rest_api_path=self.DEFAULT_BASE_PATH, method="DELETE", force_basic_auth=False)
        except Exception as error:
            self.module.fail_json(msg="Failed to log out of storage system [%s]. Error [%s]." % (self.ssid, to_native(error)))

    def password_change_required(self):
        """Verify whether the current password is expected array password. Works only against embedded systems."""
        if self.password is None:
            return False

        change_required = False
        system_info = None
        try:
            if self.is_proxy():
                if self.ssid == "0" or self.ssid.lower() == "proxy":
                    rc, system_info = self.request("local-users/info", force_basic_auth=False)
                elif self.is_embedded_available():
                    rc, system_info = self.request("storage-systems/%s/forward/devmgr/v2/storage-systems/1/local-users/info" % self.ssid,
                                                   force_basic_auth=False)
                else:
                    rc, response = self.request("storage-systems/%s/passwords" % self.ssid, ignore_errors=True)
                    system_info = {"minimumPasswordLength": 0, "adminPasswordSet": response["adminPasswordSet"]}
            else:
                rc, system_info = self.request("storage-systems/%s/local-users/info" % self.ssid, force_basic_auth=False)
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve information about storage system [%s]. Error [%s]." % (self.ssid, to_native(error)))

        self.is_admin_password_set = system_info.get("adminPasswordSet", False) \
            if isinstance(system_info, dict) else False

        if not self.is_admin_password_set:
            if self.user == "admin" and self.password != "":
                change_required = True

        # Determine whether user's password needs to be changed
        else:
            utils_login_used = False
            self.logout_system()    # This ensures that login test functions correctly. The query onlycheck=true does not work.

            if self.is_proxy():
                if self.ssid == "0" or self.ssid.lower() == "proxy":
                    utils_login_used = True
                    rc, response = self.request("utils/login?uid=%s&pwd=%s&xsrf=false&onlycheck=false" % (self.user, self.password),
                                                rest_api_path=self.DEFAULT_BASE_PATH, log_request=False, ignore_errors=True, force_basic_auth=False)
                # elif self.is_embedded_available():
                #     utils_login_used = True
                #     rc, response = self.request("storage-systems/%s/forward/devmgr/utils/login?uid=%s&pwd=%s&xsrf=false&onlycheck=false"
                #                                 % (self.ssid, self.user, self.password), log_request=False, ignore_errors=True, force_basic_auth=False)
                else:
                    if self.user == "admin":
                        rc, response = self.request("storage-systems/%s/stored-password/validate" % self.ssid, method="POST", log_request=False,
                                                    ignore_errors=True, data={"password": self.password})
                        if rc == 200:
                            change_required = not response.get("isValidPassword", False) \
                                if isinstance(response, dict) else False
                        elif rc == 404:     # endpoint did not exist, old proxy version
                            if self.is_web_services_version_met("04.10.0000.0000"):
                                self.module.fail_json(msg="For platforms before E2800 use SANtricity Web Services Proxy 4.1 or later! Array Id [%s].")
                            self.module.fail_json(msg="Failed to validate stored password! Array Id [%s].")
                        else:
                            self.module.fail_json(msg="Failed to validate stored password! Array Id [%s]." % self.ssid)
                    else:
                        self.module.fail_json(msg="Role based login not available! Only storage system password can be set for storage systems prior to E2800."
                                                  " Array Id [%s]." % self.ssid)
            else:
                utils_login_used = True
                rc, response = self.request("utils/login?uid=%s&pwd=%s&xsrf=false&onlycheck=false" % (self.user, self.password),
                                            rest_api_path=self.DEFAULT_BASE_PATH, log_request=False, ignore_errors=True, force_basic_auth=False)

            # Check return codes to determine whether a change is required
            if utils_login_used:
                if rc == 401:
                    change_required = True
                elif rc == 422:
                    self.module.fail_json(msg="SAML enabled! SAML disables default role based login. Array [%s]" % self.ssid)

        return change_required

    def set_array_admin_password(self):
        """Set the array's admin password."""
        if self.is_proxy():

            # Update proxy's local users
            if self.ssid == "0" or self.ssid.lower() == "proxy":
                self.creds["url_password"] = "admin"
                try:
                    body = {"currentAdminPassword": "", "updates": {"userName": "admin", "newPassword": self.password}}
                    rc, proxy = self.request("local-users", method="POST", data=body)
                except Exception as error:
                    self.creds["url_password"] = ""
                    try:
                        body = {"currentAdminPassword": "", "updates": {"userName": "admin", "newPassword": self.password}}
                        rc, proxy = self.request("local-users", method="POST", data=body)
                    except Exception as error:
                        self.module.fail_json(msg="Failed to set proxy's admin password. Error [%s]." % to_native(error))

                self.creds["url_password"] = self.password

            # Update password using the password endpoints, this will also update the storaged password
            else:
                try:
                    body = {"currentAdminPassword": "", "newPassword": self.password, "adminPassword": True}
                    rc, storage_system = self.request("storage-systems/%s/passwords" % self.ssid, method="POST", data=body)
                except Exception as error:
                    self.module.fail_json(msg="Failed to set storage system's admin password. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

        # Update embedded local users
        else:
            self.creds["url_password"] = ""
            try:
                body = {"currentAdminPassword": "", "updates": {"userName": "admin", "newPassword": self.password}}
                rc, proxy = self.request("storage-systems/%s/local-users" % self.ssid, method="POST", data=body)
            except Exception as error:
                self.module.fail_json(msg="Failed to set embedded storage system's admin password. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))
            self.creds["url_password"] = self.password

    def set_array_password(self):
        """Set the array password."""
        if not self.is_admin_password_set:
            self.module.fail_json(msg="Admin password not set! Set admin password before changing non-admin user passwords. Array [%s]." % self.ssid)

        if self.is_proxy():

            # Update proxy's local users
            if self.ssid == "0" or self.ssid.lower() == "proxy":
                try:
                    body = {"currentAdminPassword": self.creds["url_password"], "updates": {"userName": self.user, "newPassword": self.password}}
                    rc, proxy = self.request("local-users", method="POST", data=body)
                except Exception as error:
                    self.module.fail_json(msg="Failed to set proxy password. Error [%s]." % to_native(error))

            # Update embedded admin password via proxy passwords endpoint to include updating proxy/unified manager
            elif self.user == "admin":
                try:
                    body = {"adminPassword": True, "currentAdminPassword": self.current_admin_password, "newPassword": self.password}
                    rc, proxy = self.request("storage-systems/%s/passwords" % self.ssid, method="POST", data=body)
                except Exception as error:
                    self.module.fail_json(msg="Failed to set embedded user password. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

            # Update embedded non-admin passwords via proxy forward endpoint.
            elif self.is_embedded_available():
                try:
                    body = {"currentAdminPassword": self.current_admin_password, "updates": {"userName": self.user, "newPassword": self.password}}
                    rc, proxy = self.request("storage-systems/%s/forward/devmgr/v2/storage-systems/1/local-users" % self.ssid, method="POST", data=body)
                except Exception as error:
                    self.module.fail_json(msg="Failed to set embedded user password. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

        # Update embedded local users
        else:
            try:
                body = {"currentAdminPassword": self.creds["url_password"], "updates": {"userName": self.user, "newPassword": self.password}}
                rc, proxy = self.request("storage-systems/%s/local-users" % self.ssid, method="POST", data=body)
            except Exception as error:
                self.module.fail_json(msg="Failed to set embedded user password. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

    def apply(self):
        """Apply any required changes."""
        password_change_required = self.password_change_required()
        minimum_password_length_change_required = self.minimum_password_length_change_required()
        change_required = password_change_required or minimum_password_length_change_required

        if change_required and not self.module.check_mode:
            if minimum_password_length_change_required:
                self.update_minimum_password_length()

            if password_change_required:
                if not self.is_admin_password_set:
                    self.set_array_admin_password()
                else:
                    self.set_array_password()

            if password_change_required and minimum_password_length_change_required:
                self.module.exit_json(msg="'%s' password and required password length has been changed. Array [%s]."
                                          % (self.user, self.ssid), changed=change_required)
            elif password_change_required:
                self.module.exit_json(msg="'%s' password has been changed. Array [%s]." % (self.user, self.ssid), changed=change_required)
            elif minimum_password_length_change_required:
                self.module.exit_json(msg="Required password length has been changed. Array [%s]." % self.ssid, changed=change_required)
        self.module.exit_json(msg="No changes have been made. Array [%s]." % self.ssid, changed=change_required)


def main():
    auth = NetAppESeriesAuth()
    auth.apply()


if __name__ == "__main__":
    main()
