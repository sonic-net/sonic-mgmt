#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_proxy_drive_firmware_upload
short_description: NetApp E-Series manage proxy drive firmware files
description:
    - Ensure drive firmware files are available on SANtricity Web Service Proxy.
author:
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_proxy_doc
options:
    firmware:
        description:
            - This option can be a list of file paths and/or directories containing drive firmware.
            - Note that only files with the extension .dlp will be attempted to be added to the proxy; all other files will be ignored.
            - NetApp E-Series drives require special firmware which can be downloaded from https://mysupport.netapp.com/NOW/download/tools/diskfw_eseries/
        type: list
        elements: str
        required: false
"""
EXAMPLES = """
- name: Ensure correct firmware versions
  na_santricity_proxy_drive_firmware_upload:
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
    firmware:
        - "path/to/drive_firmware_file1.dlp"
        - "path/to/drive_firmware_file2.dlp"
        - "path/to/drive_firmware_directory"
"""
RETURN = """
msg:
    description: Whether any changes have been made to the collection of drive firmware on SANtricity Web Services Proxy.
    type: str
    returned: always
"""
import os
from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule, create_multipart_formdata


class NetAppESeriesProxyDriveFirmwareUpload(NetAppESeriesModule):
    WAIT_TIMEOUT_SEC = 60 * 15

    def __init__(self):
        ansible_options = dict(firmware=dict(type="list", elements="str", required=False))

        super(NetAppESeriesProxyDriveFirmwareUpload, self).__init__(ansible_options=ansible_options,
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
            for path in self.firmware:

                if not os.path.exists(path):
                    self.module.fail_json(msg="Drive firmware file does not exist! File [%s]" % path)
                elif os.path.isdir(path):
                    if not path.endswith("/"):
                        path = path + "/"
                    for dir_filename in os.listdir(path):
                        if ".dlp" in dir_filename:
                            self.files.update({dir_filename: path + dir_filename})
                elif ".dlp" in path:
                    name = os.path.basename(path)
                    self.files.update({name: path})

        self.module.warn("%s" % self.files)

    def determine_changes(self):
        """Determine whether drive firmware files should be uploaded to the proxy."""
        try:
            rc, results = self.request("files/drive")
            current_files = [result["fileName"] for result in results]

            for current_file in current_files:
                if current_file not in self.files.keys():
                    self.remove_files.append(current_file)

            for expected_file in self.files.keys():
                if expected_file not in current_files:
                    self.add_files.append(expected_file)
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve proxy drive firmware file list. Error [%s]" % error)

    def upload_files(self):
        """Add drive firmware file to the proxy."""
        for filename in self.add_files:
            firmware_name = os.path.basename(filename)
            files = [("file", firmware_name, self.files[filename])]
            headers, data = create_multipart_formdata(files)
            try:
                rc, response = self.request("/files/drive", method="POST", headers=headers, data=data)
            except Exception as error:
                self.upload_failures.append(filename)
                self.module.warn("Failed to upload drive firmware file. File [%s]." % firmware_name)

    def delete_files(self):
        """Remove drive firmware file to the proxy."""
        for filename in self.remove_files:
            try:
                rc, response = self.request("files/drive/%s" % filename, method="DELETE")
            except Exception as error:
                self.upload_failures.append(filename)
                self.module.warn("Failed to delete drive firmware file. File [%s]" % filename)

    def apply(self):
        """Apply state to the web services proxy."""
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

        self.module.exit_json(changed=change_required, files_added=self.add_files, files_removed=self.remove_files)


def main():
    proxy_firmware_upload = NetAppESeriesProxyDriveFirmwareUpload()
    proxy_firmware_upload.apply()


if __name__ == "__main__":
    main()
