#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_proxy_firmware_upload
short_description: NetApp E-Series manage proxy firmware uploads.
description:
    - Ensure specific firmware versions are available on SANtricity Web Services Proxy.
author:
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_proxy_doc
options:
    firmware:
        description:
            - List of paths and/or directories containing firmware/NVSRAM files.
            - All firmware/NVSRAM files that are not specified will be removed from the proxy if they exist.
        type: list
        elements: str
        required: false
"""
EXAMPLES = """
- name: Ensure proxy has the expected firmware versions.
  na_santricity_proxy_firmware_upload:
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
    firmware:
      - "path/to/firmware/dlp_files"
      - "path/to/nvsram.dlp"
      - "path/to/firmware.dlp"
"""
RETURN = """
msg:
    description: Status and version of firmware and NVSRAM.
    type: str
    returned: always
    sample:
"""
import os

from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule, create_multipart_formdata


class NetAppESeriesProxyFirmwareUpload(NetAppESeriesModule):
    def __init__(self):
        ansible_options = dict(firmware=dict(type="list", elements="str", required=False))
        super(NetAppESeriesProxyFirmwareUpload, self).__init__(ansible_options=ansible_options,
                                                               web_services_version="02.00.0000.0000",
                                                               supports_check_mode=True,
                                                               proxy_specific_task=True)

        args = self.module.params
        self.firmware = args["firmware"]
        self.files = None
        self.add_files = []
        self.remove_files = []
        self.upload_failures = []

    def determine_file_paths(self):
        """Determine all the drive firmware file paths."""
        self.files = {}
        if self.firmware:
            for firmware_path in self.firmware:

                if not os.path.exists(firmware_path):
                    self.module.fail_json(msg="Drive firmware file does not exist! File [%s]" % firmware_path)
                elif os.path.isdir(firmware_path):
                    if not firmware_path.endswith("/"):
                        firmware_path = firmware_path + "/"

                    for dir_filename in os.listdir(firmware_path):
                        if ".dlp" in dir_filename:
                            self.files.update({dir_filename: firmware_path + dir_filename})
                elif ".dlp" in firmware_path:
                    name = os.path.basename(firmware_path)
                    self.files.update({name: firmware_path})

    def determine_changes(self):
        """Determine whether files need to be added or removed."""
        try:
            rc, results = self.request("firmware/cfw-files")
            current_files = [result["filename"] for result in results]

            for current_file in current_files:
                if current_file not in self.files.keys():
                    self.remove_files.append(current_file)

            for expected_file in self.files.keys():
                if expected_file not in current_files:
                    self.add_files.append(expected_file)
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve current firmware file listing.")

    def upload_files(self):
        """Upload firmware and nvsram file."""
        for filename in self.add_files:
            fields = [("validate", "true")]
            files = [("firmwareFile", filename, self.files[filename])]
            headers, data = create_multipart_formdata(files=files, fields=fields)
            try:
                rc, response = self.request("firmware/upload/", method="POST", data=data, headers=headers)
            except Exception as error:
                self.upload_failures.append(filename)
                self.module.warn("Failed to upload firmware file. File [%s]" % filename)

    def delete_files(self):
        """Remove firmware and nvsram file."""
        for filename in self.remove_files:
            try:
                rc, response = self.request("firmware/upload/%s" % filename, method="DELETE")
            except Exception as error:
                self.upload_failures.append(filename)
                self.module.warn("Failed to delete firmware file. File [%s]" % filename)

    def apply(self):
        """Upgrade controller firmware."""
        change_required = False
        if not self.is_proxy():
            self.module.fail_json(msg="Module can only be executed against SANtricity Web Services Proxy.")

        self.determine_file_paths()
        self.determine_changes()
        if self.add_files or self.remove_files:
            change_required = True

        if change_required and not self.module.check_mode:
            self.upload_files()
            self.delete_files()

        if self.upload_failures:
            self.module.fail_json(msg="Some file failed to be uploaded! changed=%s, Files_added [%s]. Files_removed [%s]. Upload_failures [%s]"
                                      % (change_required, self.add_files, self.remove_files, self.upload_failures))
        self.module.exit_json(changed=change_required, files_added=self.add_files, files_removed=self.remove_files)


def main():
    proxy_firmware_upload = NetAppESeriesProxyFirmwareUpload()
    proxy_firmware_upload.apply()


if __name__ == "__main__":
    main()
