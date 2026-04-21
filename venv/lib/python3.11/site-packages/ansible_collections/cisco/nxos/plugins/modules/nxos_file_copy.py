#!/usr/bin/python
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_file_copy
extends_documentation_fragment:
- cisco.nxos.nxos
short_description: Copy a file to a remote NXOS device.
description:
- This module supports two different workflows for copying a file to flash (or bootflash)
  on NXOS devices.  Files can either be (1) pushed from the Ansible controller to
  the device or (2) pulled from a remote SCP file server to the device.  File copies
  are initiated from the NXOS device to the remote SCP server.  This module only supports
  the use of connection C(network_cli) or C(Cli) transport with connection C(local).
version_added: 1.0.0
author:
- Jason Edelman (@jedelman8)
- Gabriele Gerbino (@GGabriele)
- Rewritten as a plugin by (@mikewiebe)
notes:
- Tested against NXOS 7.0(3)I2(5), 7.0(3)I4(6), 7.0(3)I5(3), 7.0(3)I6(1), 7.0(3)I7(3),
  6.0(2)A8(8), 7.0(3)F3(4), 7.3(0)D1(1), 8.3(0), 9.2, 9.3
- Limited Support for Cisco MDS
- When pushing files (file_pull is False) to the NXOS device, feature scp-server must
  be enabled.
- When pulling files (file_pull is True) to the NXOS device, feature scp-server is
  not required.
- When pulling files (file_pull is True) to the NXOS device, no transfer will take
  place if the file is already present.
- Check mode will tell you if the file would be copied.
requirements:
- paramiko or libssh (required when file_pull is False)
- scp (required when file_pull is False)
options:
  local_file:
    description:
    - When (file_pull is False) this is the path to the local file on the Ansible
      controller. The local directory must exist.
    - When (file_pull is True) this is the target file name on the NXOS device.
    type: path
  remote_file:
    description:
    - When (file_pull is False) this is the remote file path on the NXOS device. If
      omitted, the name of the local file will be used. The remote directory must
      exist.
    - When (file_pull is True) this is the full path to the file on the remote SCP
      server to be copied to the NXOS device.
    type: path
  file_system:
    description:
    - The remote file system on the nxos device. If omitted, devices that support
      a I(file_system) parameter will use their default values.
    default: 'bootflash:'
    type: str
  connect_ssh_port:
    description:
    - B(Deprecated)
    - This option has been deprecated and will be removed in a release after 2024-06-01.
    - To maintain backwards compatibility, this option will continue to override the value of I(ansible_port) until removed.
    - HORIZONTALLINE
    - SSH server port used for file transfer.
    - Only used when I(file_pull) is C(True).
    default: 22
    type: int
  file_pull:
    description:
    - When (False) file is copied from the Ansible controller to the NXOS device.
    - When (True) file is copied from a remote SCP server to the NXOS device. In this
      mode, the file copy is initiated from the NXOS device.
    - If the file is already present on the device it will be overwritten and therefore
      the operation is NOT idempotent.
    type: bool
    default: false
  file_pull_protocol:
    description:
    - When file_pull is True, this can be used to define the transfer protocol for
      copying file from remote to the NXOS device.
    - When (file_pull is False), this is not used.
    default: 'scp'
    choices:
    - scp
    - sftp
    - ftp
    - http
    - https
    - tftp
    type: str
  file_pull_compact:
    description:
    - When file_pull is True, this is used to compact nxos image files. This option
      can only be used with nxos image files.
    - When (file_pull is False), this is not used.
    type: bool
    default: false
  file_pull_kstack:
    description:
    - When file_pull is True, this can be used to speed up file copies when the nxos
      running image supports the use-kstack option.
    - When (file_pull is False), this is not used.
    type: bool
    default: false
  local_file_directory:
    description:
    - When (file_pull is True) file is copied from a remote SCP server to the NXOS
      device, and written to this directory on the NXOS device. If the directory does
      not exist, it will be created under the file_system. This is an optional parameter.
    - When (file_pull is False), this is not used.
    type: path
  file_pull_timeout:
    description:
    - B(Deprecated)
    - This option has been deprecated and will be removed in a release after 2024-06-01.
    - To maintain backwards compatibility, this option will continue to override the value of I(ansible_command_timeout) until removed.
    - HORIZONTALLINE
    - Use this parameter to set timeout in seconds, when transferring large files
      or when the network is slow.
    - When (file_pull is False), this is not used.
    default: 300
    type: int
  remote_scp_server:
    description:
    - The remote scp server address when file_pull is True. This is required if file_pull
      is True.
    - When (file_pull is False), this is not used.
    type: str
  remote_scp_server_user:
    description:
    - The remote scp server username when file_pull is True. This is required if file_pull
      is True.
    - When (file_pull is False), this is not used.
    type: str
  remote_scp_server_password:
    description:
    - The remote scp server password when file_pull is True. This is required if file_pull
      is True.
    - When (file_pull is False), this is not used.
    type: str
  vrf:
    description:
    - The VRF used to pull the file. Useful when no vrf management is defined.
    - This option is not applicable for MDS switches.
    default: management
    type: str
"""

EXAMPLES = """
# File copy from ansible controller to nxos device
- name: copy from server to device
  cisco.nxos.nxos_file_copy:
    local_file: ./test_file.txt
    remote_file: test_file.txt

# Initiate file copy from the nxos device to transfer file from an SCP server back to the nxos device
- name: initiate file copy from device
  cisco.nxos.nxos_file_copy:
    file_pull: true
    local_file: xyz
    local_file_directory: dir1/dir2/dir3
    remote_file: /mydir/abc
    remote_scp_server: 192.168.0.1
    remote_scp_server_user: myUser
    remote_scp_server_password: myPassword
    vrf: management

# Initiate file copy from the nxos device to transfer file from a ftp server back to the nxos device.
# remote_scp_server_user and remote_scp_server_password are used to login to the FTP server.
- name: initiate file copy from device
  cisco.nxos.nxos_file_copy:
    file_pull: true
    file_pull_protocol: ftp
    local_file: xyz
    remote_file: /mydir/abc
    remote_scp_server: 192.168.0.1
    remote_scp_server_user: myUser
    remote_scp_server_password: myPassword
    vrf: management
"""

RETURN = """
transfer_status:
    description: Whether a file was transferred to the nxos device.
    returned: success
    type: str
    sample: 'Sent'
local_file:
    description: The path of the local file.
    returned: success
    type: str
    sample: '/path/to/local/file'
remote_file:
    description: The path of the remote file.
    returned: success
    type: str
    sample: '/path/to/remote/file'
remote_scp_server:
    description: The name of the scp server when file_pull is True.
    returned: success
    type: str
    sample: 'fileserver.example.com'
changed:
    description: Indicates whether or not the file was copied.
    returned: success
    type: bool
    sample: true
"""

import hashlib
import os
import re

from ansible.module_utils._text import to_bytes, to_text
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.network import (
    get_resource_connection,
)


class FileCopy:
    def __init__(self, module):
        self._module = module
        self._connection = get_resource_connection(self._module)
        device_info = self._connection.get_device_info()
        self._model = device_info.get("network_os_model", "")
        self._platform = device_info.get("network_os_platform", "")


class FilePush(FileCopy):
    def __init__(self, module):
        super(FilePush, self).__init__(module)
        self.result = {}

    def md5sum_check(self, dst, file_system):
        command = "show file {0}{1} md5sum".format(file_system, dst)
        remote_filehash = self._connection.run_commands(command)[0]
        remote_filehash = to_bytes(remote_filehash, errors="surrogate_or_strict")

        local_file = self._module.params["local_file"]
        try:
            with open(local_file, "rb") as f:
                filecontent = f.read()
        except (OSError, IOError) as exc:
            self._module.fail_json("Error reading the file: {0}".format(to_text(exc)))

        filecontent = to_bytes(filecontent, errors="surrogate_or_strict")
        local_filehash = hashlib.md5(filecontent).hexdigest()

        decoded_rhash = remote_filehash.decode("UTF-8")

        if local_filehash == decoded_rhash:
            return True
        else:
            return False

    def remote_file_exists(self, remote_file, file_system):
        command = "dir {0}/{1}".format(file_system, remote_file)
        body = self._connection.run_commands(command)[0]

        if "No such file" in body:
            return False
        else:
            return self.md5sum_check(remote_file, file_system)

    def get_flash_size(self, file_system):
        command = "dir {0}".format(file_system)
        body = self._connection.run_commands(command)[0]

        match = re.search(r"(\d+) bytes free", body)
        if match:
            bytes_free = match.group(1)
            return int(bytes_free)

        match = re.search(r"No such file or directory", body)
        if match:
            self._module.fail_json("Invalid nxos filesystem {0}".format(file_system))
        else:
            self._module.fail_json("Unable to determine size of filesystem {0}".format(file_system))

    def enough_space(self, file, file_system):
        flash_size = self.get_flash_size(file_system)
        file_size = os.path.getsize(file)
        if file_size > flash_size:
            return False

        return True

    def transfer_file_to_device(self, remote_file):
        local_file = self._module.params["local_file"]
        file_system = self._module.params["file_system"]

        if not self.enough_space(local_file, file_system):
            self._module.fail_json("Could not transfer file. Not enough space on device.")

        # frp = full_remote_path, flp = full_local_path
        frp = remote_file
        if not file_system.startswith("bootflash:"):
            frp = "{0}{1}".format(file_system, remote_file)
        flp = os.path.join(os.path.abspath(local_file))

        try:
            self._connection.copy_file(
                source=flp,
                destination=frp,
                proto="scp",
                timeout=self._connection.get_option("persistent_command_timeout"),
            )
            self.result["transfer_status"] = "Sent: File copied to remote device."
        except Exception as exc:
            self.result["failed"] = True
            self.result["msg"] = "Exception received : %s" % exc

    def run(self):
        local_file = self._module.params["local_file"]
        remote_file = self._module.params["remote_file"] or os.path.basename(local_file)
        file_system = self._module.params["file_system"]

        if not os.path.isfile(local_file):
            self._module.fail_json("Local file {0} not found".format(local_file))

        remote_file = remote_file or os.path.basename(local_file)
        remote_exists = self.remote_file_exists(remote_file, file_system)

        if not remote_exists:
            self.result["changed"] = True
            file_exists = False
        else:
            self.result["transfer_status"] = "No Transfer: File already copied to remote device."
            file_exists = True

        if not self._module.check_mode and not file_exists:
            self.transfer_file_to_device(remote_file)

        self.result["local_file"] = local_file
        if remote_file is None:
            remote_file = os.path.basename(local_file)
        self.result["remote_file"] = remote_file
        self.result["file_system"] = file_system

        return self.result


class FilePull(FileCopy):
    def __init__(self, module):
        super(FilePull, self).__init__(module)
        self.result = {}

    def mkdir(self, directory):
        local_dir_root = "/"
        dir_array = directory.split("/")
        for each in dir_array:
            if each:
                mkdir_cmd = "mkdir " + local_dir_root + each
                self._connection.run_commands(mkdir_cmd)
                local_dir_root += each + "/"
        return local_dir_root

    def copy_file_from_remote(self, local, local_file_directory, file_system):
        # Build copy command components that will be used to initiate copy from the nxos device.
        cmdroot = "copy " + self._module.params["file_pull_protocol"] + "://"
        ruser = self._module.params["remote_scp_server_user"] + "@"
        rserver = self._module.params["remote_scp_server"]
        rserverpassword = self._module.params["remote_scp_server_password"]
        rfile = self._module.params["remote_file"] + " "
        if not rfile.startswith("/"):
            rfile = "/" + rfile

        if not self._platform.startswith("DS-") and "MDS" not in self._model:
            vrf = " vrf " + self._module.params["vrf"]
        else:
            vrf = ""
        if self._module.params["file_pull_compact"]:
            compact = " compact "
        else:
            compact = ""
        if self._module.params["file_pull_kstack"]:
            kstack = " use-kstack "
        else:
            kstack = ""

        # Create local file directory under NX-OS filesystem if
        # local_file_directory playbook parameter is set.
        local_dir_root = "/"
        if local_file_directory:
            local_dir_root = self.mkdir(local_file_directory)

        copy_cmd = (
            cmdroot
            + ruser
            + rserver
            + rfile
            + file_system
            + local_dir_root
            + local
            + compact
            + vrf
            + kstack
        )

        self.result["copy_cmd"] = copy_cmd
        pulled = self._connection.pull_file(command=copy_cmd, remotepassword=rserverpassword)
        if pulled:
            self.result["transfer_status"] = (
                "Received: File copied/pulled to nxos device from remote scp server."
            )
        else:
            self.result["failed"] = True

    def run(self):
        self.result["failed"] = False
        remote_file = self._module.params["remote_file"]
        local_file = self._module.params["local_file"] or remote_file.split("/")[-1]
        file_system = self._module.params["file_system"]
        # Note: This is the local file directory on the remote nxos device.
        local_file_dir = self._module.params["local_file_directory"]

        if not self._module.check_mode:
            self.copy_file_from_remote(local_file, local_file_dir, file_system)

        self.result["remote_file"] = remote_file
        if local_file_dir:
            dir = local_file_dir
        else:
            dir = ""
        self.result["local_file"] = file_system + dir + "/" + local_file
        self.result["remote_scp_server"] = self._module.params["remote_scp_server"]
        self.result["file_system"] = self._module.params["file_system"]

        if not self.result["failed"]:
            self.result["changed"] = True

        return self.result


def main():
    argument_spec = dict(
        vrf=dict(type="str", default="management"),
        connect_ssh_port=dict(type="int", default=22),
        file_system=dict(type="str", default="bootflash:"),
        file_pull=dict(type="bool", default=False),
        file_pull_timeout=dict(type="int", default=300),
        file_pull_protocol=dict(
            type="str",
            default="scp",
            choices=["scp", "sftp", "http", "https", "tftp", "ftp"],
        ),
        file_pull_compact=dict(type="bool", default=False),
        file_pull_kstack=dict(type="bool", default=False),
        local_file=dict(type="path"),
        local_file_directory=dict(type="path"),
        remote_file=dict(type="path"),
        remote_scp_server=dict(type="str"),
        remote_scp_server_user=dict(type="str"),
        remote_scp_server_password=dict(no_log=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[("file_pull", True, ("remote_file", "remote_scp_server"))],
        required_together=[("remote_scp_server", "remote_scp_server_user")],
        supports_check_mode=True,
    )

    file_pull = module.params["file_pull"]

    warnings = list()

    if file_pull:
        result = FilePull(module).run()
    else:
        result = FilePush(module).run()

    result["warnings"] = warnings

    module.exit_json(**result)


if __name__ == "__main__":
    main()
