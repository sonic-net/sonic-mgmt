#
# (c) 2017 Red Hat Inc.
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
author: Ansible Networking Team (@ansible-network)
name: iosxr
short_description: Use iosxr cliconf to run command on Cisco IOS XR platform
description:
- This iosxr plugin provides low level abstraction apis for sending and receiving
  CLI commands from Cisco IOS XR network devices.
version_added: 1.0.0
notes:
- IOSXR commit confirmed command varies with IOSXR version releases,
  commit_comment and commit_label may or may not
  be valid together as per the device version.
options:
  commit_confirmed:
    type: boolean
    default: false
    description:
    - enable or disable commit confirmed mode
    env:
    - name: ANSIBLE_IOSXR_COMMIT_CONFIRMED
    vars:
    - name: ansible_iosxr_commit_confirmed
  commit_confirmed_timeout:
    type: int
    description:
    - Commits the configuration on a trial basis for the time specified in seconds or minutes.
    env:
    - name: ANSIBLE_IOSXR_COMMIT_CONFIRMED_TIMEOUT
    vars:
    - name: ansible_iosxr_commit_confirmed_timeout
  commit_label:
    type: str
    description:
    - Adds label to commit confirmed.
    env:
    - name: ANSIBLE_IOSXR_COMMIT_LABEL
    vars:
    - name: ansible_iosxr_commit_label
  commit_comment:
    type: str
    description:
    - Adds comment to commit confirmed..
    env:
    - name: ANSIBLE_IOSXR_COMMIT_COMMENT
    vars:
    - name: ansible_iosxr_commit_comment
  config_commands:
    description:
    - Specifies a list of commands that can make configuration changes
      to the target device.
    - When `ansible_network_single_user_mode` is enabled, if a command sent
      to the device is present in this list, the existing cache is invalidated.
    version_added: 2.0.0
    type: list
    elements: str
    default: []
    vars:
    - name: ansible_iosxr_config_commands
  config_mode_exclusive:
    type: boolean
    default: false
    description:
    - enable or disable config mode exclusive
    env:
    - name: ANSIBLE_IOSXR_CONFIG_MODE_EXCLUSIVE
    vars:
    - name: ansible_iosxr_config_mode_exclusive
"""

EXAMPLES = """
# Use commit confirmed within a task with timeout, label and comment

- name: Commit confirmed with a task
  vars:
    ansible_iosxr_commit_confirmed: True
    ansible_iosxr_commit_confirmed_timeout: 50
    ansible_iosxr_commit_label: TestLabel
    ansible_iosxr_commit_comment: I am a test comment
  cisco.iosxr.iosxr_logging_global:
    state: merged
    config:
      buffered:
        severity: errors #alerts #informational
      correlator:
        buffer_size: 2024

# Commands (cliconf specific)
# ["commit confirmed 50 label TestLabel comment I am a test comment"]

# Use commit within a task with label

- name: Commit label with a task
  vars:
    ansible_iosxr_commit_label: lblTest
  cisco.iosxr.iosxr_hostname:
    state: merged
    config:
      hostname: R1

# Commands (cliconf specific)
# ["commit label lblt1"]

# Use commit confirm with timeout and confirm the commit

# NOTE - IOSXR waits for a `commit` when the command
# executed is `commit confirmed <timeout>` within the timeout
# period for the config to commit successfully, else a rollback
# happens.

- name: Example commit confirmed
  vars:
    ansible_iosxr_commit_confirmed: True
    ansible_iosxr_commit_confirmed_timeout: 60
  tasks:
    - name: "Commit confirmed with timeout"
      cisco.iosxr.iosxr_hostname:
        state: merged
        config:
          hostname: R1

    - name: "Confirm the Commit"
      cisco.iosxr.iosxr_command:
        commands:
          - commit

# Commands (cliconf specific)
# ["commit confirmed 60"]

# Use exclusive mode with a task

- name: Configure exclusive mode with a task
  vars:
    ansible_iosxr_config_mode_exclusive: True
  cisco.iosxr.iosxr_interfaces:
    state: merged
    config:
      - name: GigabitEthernet0/0/0/2
        description: Configured via Ansible
      - name: GigabitEthernet0/0/0/3
        description: Configured via Ansible

# Commands (cliconf specific)
# ["configure exclusive"]

# Use Replace option with commit confirmed

# NOTE - IOSXR waits for a `commit` when the command
# executed is `commit replace confirmed <timeout>` within the timeout
# period for the config to commit successfully, else a rollback
# happens.
# This option is supported by only iosxr_config module

- name: Example replace config with commit confirmed
  vars:
    ansible_iosxr_commit_confirmed: True
    ansible_iosxr_commit_confirmed_timeout: 60
  tasks:
    - name: "Replace config with Commit confirmed"
      cisco.iosxr.iosxr_config:
        src: 'replace_running_cfg_iosxr.txt'
        replace: config

    - name: "Confirm the Commit"
      cisco.iosxr.iosxr_command:
        commands:
          - commit
"""

import json
import re

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils._text import to_text
from ansible.module_utils.common._collections_compat import Mapping
from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.config import (
    NetworkConfig,
    dumps,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list
from ansible_collections.ansible.netcommon.plugins.plugin_utils.cliconf_base import CliconfBase

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.iosxr import (
    mask_config_blocks_from_diff,
    sanitize_config,
)


class Cliconf(CliconfBase):
    def __init__(self, *args, **kwargs):
        self._device_info = {}
        super(Cliconf, self).__init__(*args, **kwargs)

    def get_command_output(self, command):
        reply = self.get(command)
        data = to_text(reply, errors="surrogate_or_strict").strip()
        return data

    def get_device_info(self):
        if not self._device_info:
            device_info = dict()
            device_info["network_os"] = "iosxr"
            data = self.get_command_output("show version | utility head -n 20")
            match = re.search(r"Version (\S+)$", data, re.M)
            if match:
                device_info["network_os_version"] = match.group(1)
            else:
                match = re.search(r"Version (\S+ \S+)$", data, re.M)
                if match:
                    device_info["network_os_version"] = match.group(1)

            match = re.search(r'image file is "(.+)"', data)
            if match:
                device_info["network_os_image"] = match.group(1)

            model_search_strs = [
                r"^[Cc]isco (.+) \(\) processor",
                r"^[Cc]isco ([A-Z0-9\-]+) processor",
                r"^[Cc]isco (.+) \(revision",
                r"^[Cc]isco (\S+ \S+).+bytes of .*memory",
            ]
            for item in model_search_strs:
                match = re.search(item, data, re.M)
                if match:
                    device_info["network_os_model"] = match.group(1)
                    break

            try:
                data = self.get_command_output("show inventory")
            except AnsibleConnectionFailure:
                data = ""

            if "network_os_model" not in device_info:
                match = re.search(r"DESCR: \"[Cc]isco (\S+ \S+)", data, re.M)
                if match:
                    device_info["network_os_model"] = match.group(1)

            match = re.search(r"SN: (\S+)\n\nNAME:", data, re.M)
            if match:
                device_info["network_os_serialnum"] = match.group(1)

            hostname = self.get_command_output("show running-config hostname")
            match = re.search(r"hostname\s(\S+)$", hostname, re.M)
            if match:
                device_info["network_os_hostname"] = match.group(1)

            self._device_info = device_info

        return self._device_info

    def configure(self, admin=False, exclusive=False):
        prompt = to_text(self._connection.get_prompt(), errors="surrogate_or_strict").strip()
        if not prompt.endswith(")#"):
            if admin and "admin-" not in prompt:
                self.send_command("admin")
            if exclusive or self.get_option("config_mode_exclusive"):
                self.send_command("configure exclusive")
                return
            self.send_command("configure terminal")

    def abort(self, admin=False):
        prompt = to_text(self._connection.get_prompt(), errors="surrogate_or_strict").strip()
        if prompt.endswith(")#"):
            self.send_command("abort")
            if admin and "admin-" in prompt:
                self.send_command("exit")

    def get_config(self, source="running", flags=None, format="text"):
        if source not in ["running"]:
            raise ValueError("fetching configuration from %s is not supported" % source)

        lookup = {"running": "running-config"}

        cmd = "show {0} ".format(lookup[source])
        cmd += " ".join(to_list(flags))
        cmd = cmd.strip()

        return self.send_command(cmd)

    def edit_config(
        self,
        candidate=None,
        commit=True,
        replace=None,
        diff=False,
        comment=None,
        admin=False,
        exclusive=False,
        label=None,
    ):
        operations = self.get_device_operations()
        self.check_edit_config_capability(operations, candidate, commit, replace, comment)

        resp = {}
        results = []
        requests = []

        self.configure(admin=admin, exclusive=exclusive)

        if replace:
            candidate = "load {0}".format(replace)

        for line in to_list(candidate):
            if not isinstance(line, Mapping):
                line = {"command": line}
            cmd = line["command"]
            results.append(self.send_command(**line))
            requests.append(cmd)

        # Before any commit happened, we can get a real configuration
        # diff from the device and make it available by the iosxr_config module.
        # This information can be useful either in check mode or normal mode.
        resp["show_commit_config_diff"] = self.get("show commit changes diff")

        if commit:
            try:
                self.commit(comment=comment, label=label, replace=replace)
            except AnsibleConnectionFailure as exc:
                error_msg = to_text(exc, errors="surrogate_or_strict").strip()
                if "Invalid input detected" in error_msg and "comment" in error_msg:
                    msg = (
                        "value of comment option '%s' is ignored as it in not supported by IOSXR"
                        % comment
                    )
                    self._connection.queue_message("warning", msg)
                    comment = None
                    self.commit(comment=comment, label=label, replace=replace)
                else:
                    raise ConnectionError(error_msg)

        else:
            self.discard_changes()

        if not self.get_option("commit_confirmed"):
            self.abort(admin=admin)

        resp["request"] = requests
        resp["response"] = results
        return resp

    def restore(self, filename=None, path=""):
        if not filename:
            raise ValueError("'file_name' value is required for restore")
        self.configure()
        cmd = f"load {path}{filename}"
        resp = self.send_command(cmd)
        self.commit()
        return resp

    def get_diff(
        self,
        candidate=None,
        running=None,
        diff_match="line",
        diff_ignore_lines=None,
        path=None,
        diff_replace="line",
    ):
        diff = {}
        device_operations = self.get_device_operations()
        option_values = self.get_option_values()

        if candidate is None and device_operations["supports_generate_diff"]:
            raise ValueError("candidate configuration is required to generate diff")

        if diff_match not in option_values["diff_match"]:
            raise ValueError(
                "'match' value %s in invalid, valid values are %s"
                % (diff_match, ", ".join(option_values["diff_match"])),
            )

        if diff_replace not in option_values["diff_replace"]:
            raise ValueError(
                "'replace' value %s in invalid, valid values are %s"
                % (diff_replace, ", ".join(option_values["diff_replace"])),
            )

        # prepare candidate configuration
        sanitized_candidate = sanitize_config(candidate)
        candidate_obj = NetworkConfig(indent=1, comment_tokens=["!"])
        candidate_obj.load(sanitized_candidate)

        if running and diff_match != "none":
            # running configuration
            running = mask_config_blocks_from_diff(running, candidate, "ansible")
            running = sanitize_config(running)

            running_obj = NetworkConfig(
                indent=1,
                contents=running,
                ignore_lines=diff_ignore_lines,
                comment_tokens=["!"],
            )
            configdiffobjs = candidate_obj.difference(
                running_obj,
                path=path,
                match=diff_match,
                replace=diff_replace,
            )

        else:
            configdiffobjs = candidate_obj.items

        diff["config_diff"] = dumps(configdiffobjs, "commands") if configdiffobjs else ""
        return diff

    def get(
        self,
        command=None,
        prompt=None,
        answer=None,
        sendonly=False,
        newline=True,
        output=None,
        check_all=False,
    ):
        if output:
            raise ValueError("'output' value %s is not supported for get" % output)
        return self.send_command(
            command=command,
            prompt=prompt,
            answer=answer,
            sendonly=sendonly,
            newline=newline,
            check_all=check_all,
        )

    def commit(self, comment=None, label=None, replace=None):
        """Implements commit functionality of config module
        and commit confirmed functionality of cliconf module

        Args:
            comment (str, optional): commit comment. Defaults to None.
            label (str, optional): commit label. Defaults to None.
            replace (bool, optional): Flag to replace commit. Defaults to None.
        """

        cmd_obj = {}
        if replace:
            cmd_obj["command"] = "commit replace"
            if self.get_option("commit_confirmed"):
                cmd_obj["command"] = "commit replace confirmed"
                if self.get_option("commit_confirmed_timeout"):
                    cmd_obj["command"] += " {0}".format(
                        self.get_option("commit_confirmed_timeout"),
                    )

            cmd_obj["prompt"] = (
                "This commit will replace or remove the entire running configuration"
            )
            cmd_obj["answer"] = "yes"

        elif self.get_option("commit_confirmed"):
            cmd_obj["command"] = "commit confirmed"
            if self.get_option("commit_confirmed_timeout"):
                cmd_obj["command"] += " {0}".format(
                    self.get_option("commit_confirmed_timeout"),
                )
            if self.get_option("commit_label"):
                cmd_obj["command"] += " label {0}".format(
                    self.get_option("commit_label"),
                )
            if self.get_option("commit_comment"):
                cmd_obj["command"] += " comment {0}".format(
                    self.get_option("commit_comment"),
                )

        else:
            label = label or self.get_option("commit_label")
            comment = comment or self.get_option("commit_comment")

            if comment or label:
                cmd_obj["command"] = "commit"
                if label:
                    cmd_obj["command"] += " label {0}".format(label)
                if comment:
                    cmd_obj["command"] += " comment {0}".format(comment)

            else:
                cmd_obj["command"] = "commit show-error"
            # In some cases even a normal commit, i.e., !replace,
            # throws a prompt and we need to handle it before
            # proceeding further
            cmd_obj["prompt"] = "(C|c)onfirm"
            cmd_obj["answer"] = "y"
        self.send_command(**cmd_obj)

    def run_commands(self, commands=None, check_rc=True):
        if commands is None:
            raise ValueError("'commands' value is required")
        responses = list()
        for cmd in to_list(commands):
            if not isinstance(cmd, Mapping):
                cmd = {"command": cmd}

            output = cmd.pop("output", None)
            if output:
                raise ValueError(
                    "'output' value %s is not supported for run_commands" % output,
                )

            try:
                out = self.send_command(**cmd)
            except AnsibleConnectionFailure as e:
                if check_rc:
                    raise
                out = getattr(e, "err", e)

            if out is not None:
                try:
                    out = to_text(out, errors="surrogate_or_strict").strip()
                except UnicodeError:
                    raise ConnectionError(
                        message="Failed to decode output from %s: %s" % (cmd, to_text(out)),
                    )

                try:
                    out = json.loads(out)
                except ValueError:
                    pass

                responses.append(out)
        return responses

    def discard_changes(self):
        self.send_command("abort")

    def get_device_operations(self):
        return {
            "supports_diff_replace": True,
            "supports_commit": True,
            "supports_rollback": False,
            "supports_defaults": False,
            "supports_onbox_diff": False,
            "supports_commit_comment": True,
            "supports_multiline_delimiter": False,
            "supports_diff_match": True,
            "supports_diff_ignore_lines": True,
            "supports_generate_diff": True,
            "supports_replace": True,
            "supports_admin": True,
            "supports_commit_label": True,
        }

    def get_option_values(self):
        return {
            "format": ["text"],
            "diff_match": ["line", "strict", "exact", "none"],
            "diff_replace": ["line", "block", "config"],
            "output": [],
        }

    def get_capabilities(self):
        result = super(Cliconf, self).get_capabilities()
        result["rpc"] += ["commit", "discard_changes", "get_diff", "configure", "exit"]
        result["device_operations"] = self.get_device_operations()
        result.update(self.get_option_values())
        return json.dumps(result)

    def set_cli_prompt_context(self):
        """
        Make sure we are in the operational cli mode
        :return: None
        """
        if self._connection.connected and not self.get_option("commit_confirmed"):
            self._update_cli_prompt_context(config_context=")#", exit_command="abort")
