#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = """
---
module: hv_troubleshooting_facts
short_description: Create a log bundle for troubleshooting
description:
  - This module generates log bundle for troublshooting the issues.
version_added: '1.0.0'
author:
  - Hitachi Vantara, LTD. (@hitachi-vantara)
requirements:
  - python >= 3.7
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
options:
  log_bundle_retention_count:
    description: Number of log bundles to retain.
    default: 3
    type: int
    required: false
"""

EXAMPLES = r"""
- name: Collect log bundle
  hitachivantara.vspone_object.oneobject_node.hv_troubleshooting_facts:

- name: Collect log bundle
  hitachivantara.vspone_object.oneobject_node.hv_troubleshooting_facts:
    log_bundle_retention_count: 5
"""

RETURN = r"""
ansible_facts:
    description: >
        Dictionary containing the properties of the log bundle.
    returned: always
    type: dict
    contains:
        missing_files:
            description: List of paths that were not found during the log bundle creation.
            type: list
            elements: str
            sample: ["/path/to/missing/file1.log", "/path/to/missing/file2.log"]
        filename:
            description: The path to the zip file containing the log bundle.
            type: str
            sample: "/path/to/log_bundles/log_bundle_20250416_131840.zip"
"""

from ansible.module_utils.basic import AnsibleModule
from pathlib import Path
import shutil
import os
import platform
from datetime import datetime
import re
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_object.plugins.module_utils.oneobject_node.ansible_argument_spec_oo import (
    OOArgumentSpec,
)

HOME = str(Path.home())
BASE_ANSIBLE_PATH = Path(HOME) / "ansible" / "hitachivantara" / "vspone_object"
ANSIBLE_INSTALLATION_PATH = (
    Path(os.getenv("HOME")) / ".ansible" / "collections"
    / "ansible_collections" / "hitachivantara" / "vspone_object"
)

PATHS = [
    str(BASE_ANSIBLE_PATH / "usages"),
    str(BASE_ANSIBLE_PATH / "user_consent"),
    str(ANSIBLE_INSTALLATION_PATH / "playbooks"),
    str(ANSIBLE_INSTALLATION_PATH / "MANIFEST.json"),
]
LOGS_DIR = Path(HOME) / "logs" / "hitachivantara" / "ansible" / "vspone_object"
LOG_BUNDLE_DIR = Path(HOME) / "logs" / "hitachivantara" / "ansible" / "vspone_object" / "log_bundles"
LOG_BUNDLE_DIR.mkdir(parents=True, exist_ok=True)

DEST_DIR = "/tmp"

logger = Log()


def writeLog(*args):
    logger.writeInfo(*args)


def get_linux_distro_info():
    try:
        with open("/etc/os-release") as f:
            os_info = f.read()
        distro_name = distro_version = None
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
    if os_edition == "Linux":
        distro_name, distro_version = get_linux_distro_info()
        return f"{distro_name} {distro_version}" if distro_name and distro_version else platform.release()
    elif os_edition == "Darwin":
        return platform.mac_ver()[0]
    elif os_edition == "Windows":
        return platform.version()
    else:
        return platform.release()


def get_os_info():
    os_edition = platform.system()
    try:
        os_version = get_os_version(os_edition)
    except Exception as e:
        logger.writeError(f"Error getting OS version: {e}")
        os_version = "Unknown OS version"

    try:
        ansible_path = shutil.which("ansible")
        if not ansible_path or not os.path.isfile(ansible_path) or not os.access(ansible_path, os.X_OK):
            raise FileNotFoundError("Ansible not installed or not executable.")
        ansible_version = os.popen(f"{ansible_path} --version").read().strip()
    except Exception as e:
        ansible_version = f"Error: {e}"

    python_version = platform.python_version()
    return os_edition, os_version, ansible_version, python_version


def write_os_info_to_file(filename):
    os_edition, os_version, ansible_version, python_version = get_os_info()
    writeLog(f"OS Edition: {os_edition}")
    writeLog(f"OS Version: {os_version}")
    writeLog(f"Ansible Version: {ansible_version}")
    writeLog(f"Python Version: {python_version}")

    with open(filename, "w") as file:
        file.write(f"OS Edition: {os_edition}\n")
        file.write(f"OS Version: {os_version}\n")
        file.write(f"Ansible Version: {ansible_version}\n")
        file.write(f"Python Version: {python_version}\n")


def get_log_files():
    log_files = []
    if LOGS_DIR.exists() and LOGS_DIR.is_dir():
        for root, dirs, files in os.walk(LOGS_DIR):
            for file in files:
                if ".log" in file and not file.endswith((".zip", ".gz", ".tar", ".xz")):
                    log_files.append(Path(root) / file)
    return log_files


def delete_folder(folder_path):
    if os.path.exists(folder_path) and os.path.isdir(folder_path):
        try:
            shutil.rmtree(folder_path)
            logger.writeDebug(f"Folder deleted successfully: {folder_path}")
        except Exception as e:
            logger.writeError(f"Error deleting folder: {e}")
    else:
        logger.writeError(f"Folder does not exist: {folder_path}")


def cleanup_old_log_bundles(log_retention_count: int, path: Path):
    """
    Keep only the most recent `log_retention_count` log bundles in the specified path.
    Deletes older log bundle zip files of the form: log_bundle_YYYYMMDD_HHMMSS.zip

    :param log_retention_count: Number of most recent log bundles to retain
    :param path: Directory containing the log bundle zip files
    """
    if not path.exists() or not path.is_dir():
        logger.writeDebug("Invalid path: {}".format(path))
        return

    # Regex to match and extract timestamp for sorting
    pattern = re.compile(r"log_bundle_(\d{8}_\d{6})\.zip")

    # List and filter log bundle files
    log_files = [f for f in path.iterdir() if f.is_file() and pattern.fullmatch(f.name)]

    # Sort files by timestamp in filename, most recent first
    log_files_sorted = sorted(
        log_files,
        key=lambda f: pattern.fullmatch(f.name).group(1),
        reverse=True
    )

    # Files to delete
    files_to_delete = log_files_sorted[log_retention_count:]

    # Delete older files
    for f in files_to_delete:
        try:
            f.unlink()
            logger.writeDebug("Deleted old log bundle: {}".format(f))
        except Exception as e:
            logger.writeDebug("Error deleting file {}: {}".format(f, e))


def create_log_bundle(log_retention_count: int = 3):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"log_bundle_{timestamp}"
    bundle_dir = Path(DEST_DIR) / base_name
    zip_path = Path(DEST_DIR) / f"{base_name}.zip"

    bundle_dir.mkdir(parents=True, exist_ok=True)

    missing_paths = []

    for path in PATHS:
        src_path = Path(path)
        if src_path.exists():
            dest_path = bundle_dir / src_path.name
            try:
                if src_path.is_dir():
                    shutil.copytree(src_path, dest_path)
                else:
                    shutil.copy2(src_path, dest_path)
            except Exception as copy_error:
                logger.writeError(f"Error copying {src_path}: {copy_error}")
                missing_paths.append(str(src_path))
        else:
            logger.writeError(f"Path not found: {src_path}")
            missing_paths.append(str(src_path))

    ansible_vault_path = bundle_dir / "playbooks" / "ansible_vault_vars"
    delete_folder(ansible_vault_path)

    log_files = get_log_files()
    if log_files:
        modules_dir = bundle_dir / "modules"
        modules_dir.mkdir(parents=True, exist_ok=True)

        for log_file in log_files:
            try:
                shutil.copy2(log_file, modules_dir / log_file.name)
            except Exception as copy_error:
                logger.writeError(f"Error copying log file {log_file}: {copy_error}")
                missing_paths.append(str(log_file))

    # Always write OS info
    write_os_info_to_file(bundle_dir / "os_info.txt")

    # Create zip
    shutil.make_archive(str(zip_path).replace('.zip', ''), 'zip',
                        root_dir=DEST_DIR, base_dir=base_name
                        )
    shutil.copy(zip_path, LOG_BUNDLE_DIR)

    # Clean up temp directory
    shutil.rmtree(bundle_dir)
    os.remove(zip_path)

    # Clean up old log bundles
    cleanup_old_log_bundles(log_retention_count, LOG_BUNDLE_DIR)

    return str(LOG_BUNDLE_DIR) + "/" + base_name + ".zip", missing_paths


def main():
    fields = OOArgumentSpec.troubleshooting()
    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    log_retention_count = module.params.get("log_bundle_retention_count", 3)

    try:
        zip_file_path, missing = create_log_bundle(log_retention_count)

        result = {
            "filename": zip_file_path,
            "missing_files": missing,
        }

        # Optionally treat missing files as a non-fatal warning
        if missing:
            result["msg"] = "Some paths were missing and not included in the bundle."

        response = {
            "ansible_facts": result,
            "changed": True,
        }

        module.exit_json(**response)

    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
