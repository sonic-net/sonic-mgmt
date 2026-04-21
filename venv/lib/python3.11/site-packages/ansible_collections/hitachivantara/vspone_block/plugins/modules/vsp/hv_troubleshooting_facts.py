#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_troubleshooting_facts
short_description: Collects the log bundles for Hitachi ansible modules host.
description:
    - This module collects all logs from the different services and all the relevant configuration files
       for further troubleshooting. The log bundle is a zip archive that contains this information.
    - For examples, go to URL
      U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/tools/logbundle_direct_connection.yml)

version_added: '3.0.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
- hitachivantara.vspone_block.common.gateway_note
"""

EXAMPLES = """
- name: Collect log bundle
  hitachivantara.vspone_block.vsp.hv_troubleshooting_facts:
  # no_log: true
"""

RETURN = """
ansible_facts:
    description: The facts collected by the module.
    returned: always
    type: dict
    contains:
        filename:
            description: Path to the log bundle created.
            type: str
            sample: "$HOME/logs/hitachivantara/ansible/vspone_block/log_bundles/ansible_log_bundle_2024_05_23_13_15_36.zip"
        msg:
            description: Success or failure message.
            type: str
            sample: "LogBundle with direct connection logs"
"""

import json
from zipfile import ZipFile
from datetime import datetime
from ansible.module_utils.basic import AnsibleModule
import pathlib

# nosec - This is a trusted command that is used to get the ansible version from the system
import subprocess  # nosec
import shutil
import os
import glob
import platform

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    get_logger_dir,
)

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "supported_by": "certified",
    "status": ["stableinterface"],
}
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common_constants import (
    NAMESPACE,
    PROJECT_NAME,
    TELEMETRY_FILE_NAME,
)

logger = Log()
moduleName = "hv_troubleshooting_facts"
gmanagement_address = ""
gmanagement_username = ""
gmanagement_password = ""
gauth_token = ""


def writeLog(*args):
    logger.writeInfo(*args)


def remove_old_logbundles(zipdir):
    # Define the directory and pattern for the zip files
    pattern = os.path.join(zipdir, "ansible_log_bundle_*.zip")  # nosec
    # Get a list of all zip files matching the pattern
    zip_files = glob.glob(pattern)
    # Sort files by creation time (or last modification time if creation time is unavailable)
    zip_files.sort(key=os.path.getmtime, reverse=True)
    # Keep only the latest 3 files
    files_to_delete = zip_files[3:]
    # Delete the older files
    for file_path in files_to_delete:
        os.remove(file_path)
        logger.writeDebug(f"Deleted: {file_path}")
    logger.writeDebug("Cleanup completed. Kept the latest 3 zip files.")


def get_linux_distro_info():
    try:
        with open("/etc/os-release") as f:
            os_info = f.read()
        # Extract distribution name and version from /etc/os-release
        distro_name = None
        distro_version = None
        for line in os_info.splitlines():
            if line.startswith("NAME="):
                distro_name = line.split("=")[1].strip('"')
            elif line.startswith("VERSION="):
                distro_version = line.split("=")[1].strip('"')
        return distro_name, distro_version
    except Exception as ex:
        logger.writeError("File /etc/os-release is not available.")
        logger.writeError(str(ex))
        raise


def get_os_version(os_edition):
    # Get OS version based on the platform
    if os_edition == "Linux":
        # Get detailed Linux distribution info
        distro_name, distro_version = get_linux_distro_info()
        if distro_name and distro_version:
            os_version = f"{distro_name} {distro_version}"
        else:
            # Fallback to kernel version if the distribution info is unavailable
            os_version = platform.release()
    elif os_edition == "Darwin":
        os_version = platform.mac_ver()[0]  # macOS version
    elif os_edition == "Windows":
        os_version = platform.version()  # Windows version
    else:
        os_version = platform.release()  # Fallback for other systems
    return os_version


def get_os_info():
    # Get OS edition
    os_edition = platform.system()

    # Get OS version
    try:
        os_version = get_os_version(os_edition)
    except Exception as e:
        logger.writeError(f"Error getting OS version: {e}")
        os_version = "Unknown OS version"

    # Get Ansible version (if installed)
    ansible_version = ""
    try:
        # Check if Ansible is installed
        ansible_full_path = shutil.which("ansible")

        # Check if the Ansible executable is valid
        if not ansible_full_path:
            raise FileNotFoundError("Ansible executable not found.")

        # Check if the Ansible executable is valid and accessible
        # nosec - This is a trusted command that is used to get the ansible version from the system
        if not os.path.isfile(ansible_full_path) or not os.access(
            ansible_full_path, os.X_OK
        ):
            raise FileNotFoundError(f"'{ansible_full_path}' is not a valid executable.")

        # Get the Ansible version
        # nosec - This is a trusted command that is used to get the ansible version from the system
        ansible_version = subprocess.check_output(
            [ansible_full_path, "--version"], text=True
        )
    except FileNotFoundError:
        ansible_version = "Ansible not installed"
    except subprocess.SubprocessError as e:
        ansible_version = f"Error retrieving Ansible version: {e}"
    except Exception as e:
        ansible_version = f"Unexpected error: {e}"
    # Get Python version
    python_version = platform.python_version()
    return os_edition, os_version, ansible_version, python_version


def write_os_info_to_file(filename):
    # Get system information
    os_edition, os_version, ansible_version, python_version = get_os_info()

    # Print the results
    writeLog(f"OS Edition: {os_edition}")
    writeLog(f"OS Version: {os_version}")
    writeLog(f"Ansible Version: {ansible_version}")
    writeLog(f"Python Version: {python_version}")

    # Write the system information to file
    with open(filename, "w") as file:
        file.write(f"OS Edition: {os_edition}\n")
        file.write(f"OS Version: {os_version}\n")
        file.write(f"Ansible Version: {ansible_version}\n")
        file.write(f"Python Version: {python_version}\n")

    # Print a success message
    writeLog("System information has been written to os_info.txt")


def main(module=None):
    fields = {}

    if module is None:
        module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    logger.writeEnterModule(moduleName)
    comments = "LogBundle with direct connection logs"
    writeLog("Collecting logbundle for direct connection logs")

    tempdir = datetime.now().strftime("ansible_log_bundle_%Y_%m_%d_%H_%M_%S")
    zipdir = get_logger_dir() + "/log_bundles"
    zipPath = os.path.join(zipdir, "{0}.zip".format(tempdir))  # nosec
    usages_dir = pathlib.Path.home() / f"ansible/{NAMESPACE}/{PROJECT_NAME}/usages"
    temp_usages_dir = os.path.join(tempdir, "usages")  # nosec

    consent_dir = (
        pathlib.Path.home() / f"ansible/{NAMESPACE}/{PROJECT_NAME}/user_consent"
    )
    try:
        os.makedirs(tempdir)

        if not os.path.exists(zipdir):
            os.makedirs(zipdir)
        for subdir in ("gateway_service", "modules", "playbooks"):
            subpath = os.path.join(tempdir, subdir)  # nosec
            if not os.path.exists(subpath):
                os.makedirs(subpath)

        write_os_info_to_file(os.path.join(tempdir, "os_info.txt"))  # nosec

        writeLog("Copying Ansible playbooks")

        # Log.getHomePath() is /opt/hitachivantara/ansible
        playb_src = Log.getHomePath() + "/playbooks"
        playb_dest = os.path.join(tempdir, "playbooks")  # nosec

        for dirpath, dirnames, filenames in os.walk(playb_src):
            # Calculate relative path to preserve the directory structure in the destination
            if "ansible_vault_vars" in dirpath:
                continue
            relative_path = os.path.relpath(dirpath, playb_src)  # nosec
            dest_path = os.path.join(playb_dest, relative_path)  # nosec

            # Make sure each corresponding directory exists in the destination
            if not os.path.exists(dest_path):
                os.makedirs(dest_path)

            # Copy each .yml file to the corresponding directory in the destination
            for filename in filenames:
                if filename.endswith(".yml"):
                    src_file = os.path.join(dirpath, filename)  # nosec
                    dest_file = os.path.join(dest_path, filename)  # nosec
                    shutil.copy(src_file, dest_file)  # nosec
                    logger.writeInfo(f"Copied {src_file} to {dest_file}")

        # copy registration files

        # handle the usage file content
        try:
            if os.path.exists(usages_dir):
                shutil.copytree(usages_dir, temp_usages_dir)

            with open(
                os.path.join(temp_usages_dir, TELEMETRY_FILE_NAME),
                "r+",  # nosec
            ) as file:
                file_data = json.load(file)
                new_data = {
                    "directConnectTasks": file_data.get("directConnectTasks"),
                    "sdsBlockTasks": file_data.get("sdsBlockTasks"),
                    "directConnectStorageSystems": file_data.get(
                        "directConnectStorageSystems"
                    ),
                    "sdsBlockStorageSystems": file_data.get("sdsBlockStorageSystems"),
                }
                file.seek(0)
                json.dump(new_data, file, indent=4)
                file.truncate()
            logger.writeInfo(f"Copied usages files to {temp_usages_dir}")
            # comment out the registration files

            if os.path.exists(consent_dir):
                shutil.copytree(
                    consent_dir, os.path.join(tempdir, "user_consent")  # nosec
                )  # nosec
                logger.writeInfo(f"Copied user_consent files to {tempdir}/user_consent")
        except Exception as e:
            logger.writeInfo(e)

        for file in glob.glob(Log.getHomePath() + "/support/*.yml"):
            shutil.copy(file, playb_dest)
        try:
            shutil.copy(
                os.path.join(Log.getHomePath(), "MANIFEST.json"), tempdir
            )  # nosec
        except Exception as e:
            logger.writeInfo(e)

        writeLog("Copying Ansible log files")
        src = get_logger_dir()
        src_files = os.listdir(src)
        for file_name in src_files:
            full_file_name = os.path.join(src, file_name)  # nosec
            if os.path.isfile(full_file_name):  # nosec
                shutil.copy(full_file_name, os.path.join(tempdir, "modules"))  # nosec

        filePaths = []
        for root, directories, files in os.walk(tempdir):
            for filename in files:
                filePath = os.path.join(root, filename)  # nosec
                filePaths.append(filePath)  # nosec
        with ZipFile(zipPath, "w") as zip_file:  # nosec
            for file in filePaths:
                zip_file.write(file)

        remove_old_logbundles(zipdir)

        logger.writeExitModule(moduleName)
        module.exit_json(
            changed=False, ansible_facts={"filename": zipPath, "msg": comments}
        )
    except EnvironmentError as ex:
        logger.writeError(str(ex))
        module.fail_json(msg=ex.strerror)
    except Exception as ex:
        logger.writeError(str(ex))
        module.fail_json(msg=repr(ex), type=ex.__class__.__name__, log=module._debug)
    finally:
        shutil.rmtree(tempdir, ignore_errors=True)


if __name__ == "__main__":
    main()
