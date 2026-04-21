#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_firmware
short_description: NetApp E-Series manage firmware.
description:
    - Ensure specific firmware versions are activated on E-Series storage system.
author:
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    nvsram:
        description:
            - Path to the NVSRAM file.
            - NetApp recommends upgrading the NVSRAM when upgrading firmware.
            - Due to concurrency issues, use M(netapp_eseries.santricity.na_santricity_proxy_firmware_upload) to upload
              firmware and nvsram to SANtricity Web Services Proxy when upgrading multiple systems at the same time on
              the same instance of the proxy.
        type: str
        required: false
    firmware:
        description:
            - Path to the firmware file.
            - Due to concurrency issues, use M(netapp_eseries.santricity.na_santricity_proxy_firmware_upload) to upload
              firmware and nvsram to SANtricity Web Services Proxy when upgrading multiple systems at the same time on
              the same instance of the proxy.
        type: str
        required: True
    wait_for_completion:
        description:
            - This flag will cause module to wait for any upgrade actions to complete.
            - When changes are required to both firmware and nvsram and task is executed against SANtricity Web Services Proxy,
              the firmware will have to complete before nvsram can be installed.
        type: bool
        default: false
    clear_mel_events:
        description:
            - This flag will force firmware to be activated in spite of the storage system mel-event issues.
            - Warning! This will clear all storage system mel-events. Use at your own risk!
        type: bool
        default: false
"""
EXAMPLES = """
- name: Ensure correct firmware versions
  na_santricity_firmware:
    ssid: "1"
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
    nvsram: "path/to/nvsram"
    firmware: "path/to/bundle"
    wait_for_completion: true
    clear_mel_events: true
- name: Ensure correct firmware versions
  na_santricity_firmware:
    ssid: "1"
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
    nvsram: "path/to/nvsram"
    firmware: "path/to/firmware"
"""
RETURN = """
msg:
    description: Status and version of firmware and NVSRAM.
    type: str
    returned: always
    sample:
"""
import os
import threading

from time import sleep
from ansible.module_utils import six
from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule, create_multipart_formdata
from ansible.module_utils._text import to_native


class NetAppESeriesFirmware(NetAppESeriesModule):
    COMPATIBILITY_CHECK_TIMEOUT_SEC = 60
    REBOOT_TIMEOUT_SEC = 30 * 60
    MINIMUM_PROXY_VERSION = "04.10.00.0000"

    def __init__(self):
        ansible_options = dict(
            nvsram=dict(type="str", required=False),
            firmware=dict(type="str", required=True),
            wait_for_completion=dict(type="bool", default=False),
            clear_mel_events=dict(type="bool", default=False))

        super(NetAppESeriesFirmware, self).__init__(ansible_options=ansible_options,
                                                    web_services_version="02.00.0000.0000",
                                                    supports_check_mode=True)

        args = self.module.params
        self.nvsram = args["nvsram"]
        self.firmware = args["firmware"]
        self.wait_for_completion = args["wait_for_completion"]
        self.clear_mel_events = args["clear_mel_events"]

        self.nvsram_name = None
        self.firmware_name = None
        self.is_bundle_cache = None
        self.firmware_version_cache = None
        self.nvsram_version_cache = None
        self.upgrade_required = False
        self.upgrade_in_progress = False
        self.module_info = dict()

        if self.nvsram:
            self.nvsram_name = os.path.basename(self.nvsram)
        if self.firmware:
            self.firmware_name = os.path.basename(self.firmware)

        self.last_known_event = -1
        self.is_firmware_activation_started_mel_event_count = 1
        self.is_nvsram_download_completed_mel_event_count = 1
        self.proxy_wait_for_upgrade_mel_event_count = 1

    def is_upgrade_in_progress(self):
        """Determine whether an upgrade is already in progress."""
        in_progress = False

        if self.is_proxy():
            try:
                rc, status = self.request("storage-systems/%s/cfw-upgrade" % self.ssid)
                in_progress = status["running"]
            except Exception as error:
                if "errorMessage" in to_native(error):
                    self.module.warn("Failed to retrieve upgrade status. Array [%s]. Error [%s]." % (self.ssid, error))
                    in_progress = False
                else:
                    self.module.fail_json(msg="Failed to retrieve upgrade status. Array [%s]. Error [%s]." % (self.ssid, error))
        else:
            in_progress = False

        return in_progress

    def is_firmware_bundled(self):
        """Determine whether supplied firmware is bundle."""
        if self.is_bundle_cache is None:
            with open(self.firmware, "rb") as fh:
                signature = fh.read(16).lower()

                if b"firmware" in signature:
                    self.is_bundle_cache = False
                elif b"combined_content" in signature:
                    self.is_bundle_cache = True
                else:
                    self.module.fail_json(msg="Firmware file is invalid. File [%s]. Array [%s]" % (self.firmware, self.ssid))

        return self.is_bundle_cache

    def firmware_version(self):
        """Retrieve firmware version of the firmware file. Return: bytes string"""
        if self.firmware_version_cache is None:

            # Search firmware file for bundle or firmware version
            with open(self.firmware, "rb") as fh:
                line = fh.readline()
                while line:
                    if self.is_firmware_bundled():
                        if b'displayableAttributeList=' in line:
                            for item in line[25:].split(b','):
                                key, value = item.split(b"|")
                                if key == b'VERSION':
                                    self.firmware_version_cache = value.strip(b"\n")
                            break
                    elif b"Version:" in line:
                        self.firmware_version_cache = line.split()[-1].strip(b"\n")
                        break
                    line = fh.readline()
                else:
                    self.module.fail_json(msg="Failed to determine firmware version. File [%s]. Array [%s]." % (self.firmware, self.ssid))
        return self.firmware_version_cache

    def nvsram_version(self):
        """Retrieve NVSRAM version of the NVSRAM file. Return: byte string"""
        if self.nvsram_version_cache is None:

            with open(self.nvsram, "rb") as fh:
                line = fh.readline()
                while line:
                    if b".NVSRAM Configuration Number" in line:
                        self.nvsram_version_cache = line.split(b'"')[-2]
                        break
                    line = fh.readline()
                else:
                    self.module.fail_json(msg="Failed to determine NVSRAM file version. File [%s]. Array [%s]." % (self.nvsram, self.ssid))
        return self.nvsram_version_cache

    def check_system_health(self):
        """Ensure E-Series storage system is healthy. Works for both embedded and proxy web services."""
        try:
            rc, response = self.request("storage-systems/%s/health-check" % self.ssid, method="POST")
            return response["successful"]
        except Exception as error:
            self.module.fail_json(msg="Health check failed! Array Id [%s]. Error[%s]." % (self.ssid, to_native(error)))

    def embedded_check_compatibility(self):
        """Verify files are compatible with E-Series storage system."""
        if self.nvsram:
            self.embedded_check_nvsram_compatibility()
        if self.firmware:
            self.embedded_check_bundle_compatibility()

    def embedded_check_nvsram_compatibility(self):
        """Verify the provided NVSRAM is compatible with E-Series storage system."""
        files = [("nvsramimage", self.nvsram_name, self.nvsram)]
        headers, data = create_multipart_formdata(files=files)
        compatible = {}
        try:
            rc, compatible = self.request("firmware/embedded-firmware/%s/nvsram-compatibility-check" % self.ssid, method="POST", data=data, headers=headers)
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve NVSRAM compatibility results. Array Id [%s]. Error[%s]." % (self.ssid, to_native(error)))

        if not compatible["signatureTestingPassed"]:
            self.module.fail_json(msg="Invalid NVSRAM file. File [%s]." % self.nvsram)
        if not compatible["fileCompatible"]:
            self.module.fail_json(msg="Incompatible NVSRAM file. File [%s]." % self.nvsram)

        # Determine whether nvsram upgrade is required
        for module in compatible["versionContents"]:
            if module["bundledVersion"] != module["onboardVersion"]:
                self.upgrade_required = True

            # Update bundle info
            self.module_info.update({module["module"]: {"onboard_version": module["onboardVersion"], "bundled_version": module["bundledVersion"]}})

    def embedded_check_bundle_compatibility(self):
        """Verify the provided firmware bundle is compatible with E-Series storage system."""
        files = [("files[]", "blob", self.firmware)]
        headers, data = create_multipart_formdata(files=files, send_8kb=True)
        compatible = {}
        try:
            rc, compatible = self.request("firmware/embedded-firmware/%s/bundle-compatibility-check" % self.ssid, method="POST", data=data, headers=headers)
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve bundle compatibility results. Array Id [%s]. Error[%s]." % (self.ssid, to_native(error)))

        # Determine whether valid and compatible firmware
        if not compatible["signatureTestingPassed"]:
            self.module.fail_json(msg="Invalid firmware bundle file. File [%s]." % self.firmware)
        if not compatible["fileCompatible"]:
            self.module.fail_json(msg="Incompatible firmware bundle file. File [%s]." % self.firmware)

        # Determine whether bundle upgrade is required
        for module in compatible["versionContents"]:
            bundle_module_version = module["bundledVersion"].split(".")
            onboard_module_version = module["onboardVersion"].split(".")
            version_minimum_length = min(len(bundle_module_version), len(onboard_module_version))

            if bundle_module_version[:version_minimum_length] != onboard_module_version[:version_minimum_length]:
                self.upgrade_required = True

            # Build the modules information for logging purposes
            self.module_info.update({module["module"]: {"onboard_version": module["onboardVersion"], "bundled_version": module["bundledVersion"]}})

    def embedded_firmware_activate(self):
        """Activate firmware."""
        rc, response = self.request("firmware/embedded-firmware/activate", method="POST", ignore_errors=True, timeout=10)
        if rc == "422":
            self.module.fail_json(msg="Failed to activate the staged firmware. Array Id [%s]. Error [%s]" % (self.ssid, response))

    def embedded_firmware_download(self):
        """Execute the firmware download."""
        if self.nvsram:
            firmware_url = "firmware/embedded-firmware?nvsram=true&staged=true"
            headers, data = create_multipart_formdata(files=[("nvsramfile", self.nvsram_name, self.nvsram),
                                                             ("dlpfile", self.firmware_name, self.firmware)])
        else:
            firmware_url = "firmware/embedded-firmware?nvsram=false&staged=true"
            headers, data = create_multipart_formdata(files=[("dlpfile", self.firmware_name, self.firmware)])

        # Stage firmware and nvsram
        try:

            rc, response = self.request(firmware_url, method="POST", data=data, headers=headers, timeout=(30 * 60))
        except Exception as error:
            self.module.fail_json(msg="Failed to stage firmware. Array Id [%s]. Error[%s]." % (self.ssid, to_native(error)))

        # Activate firmware
        activate_thread = threading.Thread(target=self.embedded_firmware_activate)
        activate_thread.start()
        self.wait_for_reboot()

    def wait_for_reboot(self):
        """Wait for controller A to fully reboot and web services running"""
        reboot_started = False
        reboot_completed = False
        self.module.log("Controller firmware: Reboot commencing. Array Id [%s]." % self.ssid)
        while self.wait_for_completion and not (reboot_started and reboot_completed):
            try:
                rc, response = self.request("storage-systems/%s/symbol/pingController?controller=a&verboseErrorResponse=true"
                                            % self.ssid, method="POST", timeout=10, log_request=False)

                if reboot_started and response == "ok":
                    self.module.log("Controller firmware: Reboot completed. Array Id [%s]." % self.ssid)
                    reboot_completed = True
                sleep(2)
            except Exception as error:
                if not reboot_started:
                    self.module.log("Controller firmware: Reboot started. Array Id [%s]." % self.ssid)
                    reboot_started = True
                continue

    def firmware_event_logger(self):
        """Determine if firmware activation has started."""
        # Determine the last known event
        try:
            rc, events = self.request("storage-systems/%s/events" % self.ssid)
            for event in events:
                if int(event["eventNumber"]) > int(self.last_known_event):
                    self.last_known_event = event["eventNumber"]
        except Exception as error:
            self.module.fail_json(msg="Failed to determine last known event. Array Id [%s]. Error[%s]." % (self.ssid, to_native(error)))

        while True:
            try:
                rc, events = self.request("storage-systems/%s/events?lastKnown=%s&wait=1" % (self.ssid, self.last_known_event), log_request=False)
                for event in events:
                    if int(event["eventNumber"]) > int(self.last_known_event):
                        self.last_known_event = event["eventNumber"]

                    # Log firmware events
                    if event["eventType"] == "firmwareDownloadEvent":
                        self.module.log("%s" % event["status"])
                        if event["status"] == "informational" and event["statusMessage"]:
                            self.module.log("Controller firmware: %s Array Id [%s]." % (event["statusMessage"], self.ssid))

                        # When activation is successful, finish thread
                        if event["status"] == "activate_success":
                            self.module.log("Controller firmware activated. Array Id [%s]." % self.ssid)
                            return
            except Exception as error:
                pass

    def wait_for_web_services(self):
        """Wait for web services to report firmware and nvsram upgrade."""
        # Wait for system to reflect changes
        for count in range(int(self.REBOOT_TIMEOUT_SEC / 5)):
            try:
                if self.is_firmware_bundled():
                    firmware_rc, firmware_version = self.request("storage-systems/%s/graph/xpath-filter?query=/controller/"
                                                                 "codeVersions[codeModule='bundleDisplay']" % self.ssid, log_request=False)
                    current_firmware_version = six.b(firmware_version[0]["versionString"])
                else:
                    firmware_rc, firmware_version = self.request("storage-systems/%s/graph/xpath-filter?query=/sa/saData/fwVersion"
                                                                 % self.ssid, log_request=False)
                    current_firmware_version = six.b(firmware_version[0])

                nvsram_rc, nvsram_version = self.request("storage-systems/%s/graph/xpath-filter?query=/sa/saData/nvsramVersion" % self.ssid, log_request=False)
                current_nvsram_version = six.b(nvsram_version[0])

                if current_firmware_version == self.firmware_version() and (not self.nvsram or current_nvsram_version == self.nvsram_version()):
                    break
            except Exception as error:
                pass
            sleep(5)
        else:
            self.module.fail_json(msg="Timeout waiting for Santricity Web Services. Array [%s]" % self.ssid)

        # Wait for system to be optimal
        for count in range(int(self.REBOOT_TIMEOUT_SEC / 5)):
            try:
                rc, response = self.request("storage-systems/%s" % self.ssid, log_request=False)

                if response["status"] == "optimal":
                    self.upgrade_in_progress = False
                    break
            except Exception as error:
                pass
            sleep(5)
        else:
            self.module.fail_json(msg="Timeout waiting for storage system to return to optimal status. Array [%s]" % self.ssid)

    def embedded_upgrade(self):
        """Upload and activate both firmware and NVSRAM."""
        download_thread = threading.Thread(target=self.embedded_firmware_download)
        event_thread = threading.Thread(target=self.firmware_event_logger)
        download_thread.start()
        event_thread.start()
        download_thread.join()
        event_thread.join()

    def proxy_check_nvsram_compatibility(self, retries=10):
        """Verify nvsram is compatible with E-Series storage system."""
        self.module.log("Checking nvsram compatibility...")
        data = {"storageDeviceIds": [self.ssid]}
        try:
            rc, check = self.request("firmware/compatibility-check", method="POST", data=data)
        except Exception as error:
            if retries:
                sleep(1)
                self.proxy_check_nvsram_compatibility(retries - 1)
            else:
                self.module.fail_json(msg="Failed to receive NVSRAM compatibility information. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

        for count in range(int(self.COMPATIBILITY_CHECK_TIMEOUT_SEC / 5)):
            try:
                rc, response = self.request("firmware/compatibility-check?requestId=%s" % check["requestId"])
            except Exception as error:
                continue

            if not response["checkRunning"]:
                for result in response["results"][0]["nvsramFiles"]:
                    if result["filename"] == self.nvsram_name:
                        return
                self.module.fail_json(msg="NVSRAM is not compatible. NVSRAM [%s]. Array [%s]." % (self.nvsram_name, self.ssid))
            sleep(5)

        self.module.fail_json(msg="Failed to retrieve NVSRAM status update from proxy. Array [%s]." % self.ssid)

    def proxy_check_firmware_compatibility(self, retries=10):
        """Verify firmware is compatible with E-Series storage system."""
        check = {}
        try:
            rc, check = self.request("firmware/compatibility-check", method="POST", data={"storageDeviceIds": [self.ssid]})
        except Exception as error:
            if retries:
                sleep(1)
                self.proxy_check_firmware_compatibility(retries - 1)
            else:
                self.module.fail_json(msg="Failed to receive firmware compatibility information. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

        for count in range(int(self.COMPATIBILITY_CHECK_TIMEOUT_SEC / 5)):
            try:
                rc, response = self.request("firmware/compatibility-check?requestId=%s" % check["requestId"])
            except Exception as error:
                continue

            if not response["checkRunning"]:
                for result in response["results"][0]["cfwFiles"]:
                    if result["filename"] == self.firmware_name:
                        return
                self.module.fail_json(msg="Firmware bundle is not compatible. firmware [%s]. Array [%s]." % (self.firmware_name, self.ssid))
            sleep(5)

        self.module.fail_json(msg="Failed to retrieve firmware status update from proxy. Array [%s]." % self.ssid)

    def proxy_upload_and_check_compatibility(self):
        """Ensure firmware/nvsram file is uploaded and verify compatibility."""
        uploaded_files = []
        try:
            rc, uploaded_files = self.request("firmware/cfw-files")
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve uploaded firmware and nvsram files. Error [%s]" % to_native(error))

        if self.firmware:
            for uploaded_file in uploaded_files:
                if uploaded_file["filename"] == self.firmware_name:
                    break
            else:
                fields = [("validate", "true")]
                files = [("firmwareFile", self.firmware_name, self.firmware)]
                headers, data = create_multipart_formdata(files=files, fields=fields)
                try:
                    rc, response = self.request("firmware/upload", method="POST", data=data, headers=headers)
                except Exception as error:
                    self.module.fail_json(msg="Failed to upload firmware bundle file. File [%s]. Array [%s]. Error [%s]."
                                              % (self.firmware_name, self.ssid, to_native(error)))
            self.proxy_check_firmware_compatibility()

        if self.nvsram:
            for uploaded_file in uploaded_files:
                if uploaded_file["filename"] == self.nvsram_name:
                    break
            else:
                fields = [("validate", "true")]
                files = [("firmwareFile", self.nvsram_name, self.nvsram)]
                headers, data = create_multipart_formdata(files=files, fields=fields)
                try:
                    rc, response = self.request("firmware/upload", method="POST", data=data, headers=headers)
                except Exception as error:
                    self.module.fail_json(msg="Failed to upload NVSRAM file. File [%s]. Array [%s]. Error [%s]."
                                              % (self.nvsram_name, self.ssid, to_native(error)))
            self.proxy_check_nvsram_compatibility()

    def proxy_check_upgrade_required(self):
        """Determine whether the onboard firmware/nvsram version is the same as the file"""
        # Verify controller consistency and get firmware versions
        if self.firmware:
            current_firmware_version = b""
            try:
                # Retrieve current bundle version
                if self.is_firmware_bundled():
                    rc, response = self.request("storage-systems/%s/graph/xpath-filter?query=/controller/codeVersions[codeModule='bundleDisplay']" % self.ssid)
                    current_firmware_version = six.b(response[0]["versionString"])
                else:
                    rc, response = self.request("storage-systems/%s/graph/xpath-filter?query=/sa/saData/fwVersion" % self.ssid)
                    current_firmware_version = six.b(response[0])
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve controller firmware information. Array [%s]. Error [%s]" % (self.ssid, to_native(error)))

            # Determine whether the current firmware version is the same as the file
            new_firmware_version = self.firmware_version()
            if current_firmware_version != new_firmware_version:
                self.upgrade_required = True

            # Build the modules information for logging purposes
            self.module_info.update({"bundleDisplay": {"onboard_version": current_firmware_version, "bundled_version": new_firmware_version}})

        # Determine current NVSRAM version and whether change is required
        if self.nvsram:
            try:
                rc, response = self.request("storage-systems/%s/graph/xpath-filter?query=/sa/saData/nvsramVersion" % self.ssid)

                if six.b(response[0]) != self.nvsram_version():
                    self.upgrade_required = True
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve storage system's NVSRAM version. Array [%s]. Error [%s]" % (self.ssid, to_native(error)))

    def proxy_wait_for_upgrade(self):
        """Wait for SANtricity Web Services Proxy to report upgrade complete"""
        self.module.log("(Proxy) Waiting for upgrade to complete...")

        status = {}
        while True:
            try:
                rc, status = self.request("storage-systems/%s/cfw-upgrade" % self.ssid, log_request=False, ignore_errors=True)
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve firmware upgrade status! Array [%s]. Error[%s]." % (self.ssid, to_native(error)))

            if "errorMessage" in status:
                self.module.warn("Proxy reported an error. Checking whether upgrade completed. Array [%s]. Error [%s]." % (self.ssid, status["errorMessage"]))
                self.wait_for_web_services()
                break

            if not status["running"]:
                if status["activationCompletionTime"]:
                    self.upgrade_in_progress = False
                    break
                else:
                    self.module.fail_json(msg="Failed to complete upgrade. Array [%s]." % self.ssid)
            sleep(5)

    def delete_mel_events(self):
        """Clear all mel-events."""
        try:
            rc, response = self.request("storage-systems/%s/mel-events?clearCache=true&resetMel=true" % self.ssid, method="DELETE")
        except Exception as error:
            self.module.fail_json(msg="Failed to clear mel-events. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

    def proxy_upgrade(self):
        """Activate previously uploaded firmware related files."""
        self.module.log("(Proxy) Firmware upgrade commencing...")
        body = {"stageFirmware": False, "skipMelCheck": self.clear_mel_events, "cfwFile": self.firmware_name}
        if self.nvsram:
            body.update({"nvsramFile": self.nvsram_name})

        try:
            rc, response = self.request("storage-systems/%s/cfw-upgrade" % self.ssid, method="POST", data=body)
        except Exception as error:
            self.module.fail_json(msg="Failed to initiate firmware upgrade. Array [%s]. Error [%s]." % (self.ssid, to_native(error)))

        self.upgrade_in_progress = True
        if self.wait_for_completion:
            self.proxy_wait_for_upgrade()

    def apply(self):
        """Upgrade controller firmware."""
        if self.is_upgrade_in_progress():
            self.module.fail_json(msg="Upgrade is already is progress. Array [%s]." % self.ssid)

        if self.is_embedded():
            self.embedded_check_compatibility()
        else:
            if not self.is_web_services_version_met(self.MINIMUM_PROXY_VERSION):
                self.module.fail_json(msg="Minimum proxy version %s required!")
            self.proxy_check_upgrade_required()

            # This will upload the firmware files to the web services proxy but not to the controller
            if self.upgrade_required:
                self.proxy_upload_and_check_compatibility()

        # Perform upgrade
        if self.upgrade_required and not self.module.check_mode:

            if self.clear_mel_events:
                self.delete_mel_events()

            if self.is_embedded():
                self.embedded_upgrade()
            else:
                self.proxy_upgrade()

        self.module.exit_json(changed=self.upgrade_required, upgrade_in_process=self.upgrade_in_progress, modules_info=self.module_info)


def main():
    firmware = NetAppESeriesFirmware()
    firmware.apply()


if __name__ == "__main__":
    main()
