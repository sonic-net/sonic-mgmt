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
name: nxos
short_description: Use NX-OS cliconf to run commands on Cisco NX-OS platform
description:
- This nxos plugin provides low level abstraction apis for sending and receiving CLI
  commands from Cisco NX-OS network devices.
version_added: 1.0.0
options:
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
    - name: ansible_nxos_config_commands
"""

import json
import re

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils._text import to_bytes, to_text
from ansible.module_utils.common._collections_compat import Mapping
from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.config import (
    NetworkConfig,
    dumps,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list
from ansible_collections.ansible.netcommon.plugins.plugin_utils.cliconf_base import CliconfBase


class Cliconf(CliconfBase):
    def __init__(self, *args, **kwargs):
        self._module_context = {}
        self._device_info = {}
        super(Cliconf, self).__init__(*args, **kwargs)

    def read_module_context(self, module_key):
        if self._module_context.get(module_key):
            return self._module_context[module_key]

        return None

    def save_module_context(self, module_key, module_context):
        self._module_context[module_key] = module_context

        return None

    def get_device_info(self):
        if not self._device_info:
            device_info = {}

            device_info["network_os"] = "nxos"
            reply = self.get("show version")
            platform_reply = self.get("show inventory")

            match_sys_ver = re.search(r"\s+system:\s+version\s*(\S+)", reply, re.M)
            if match_sys_ver:
                device_info["network_os_version"] = match_sys_ver.group(1)
            else:
                match_kick_ver = re.search(r"\s+kickstart:\s+version\s*(\S+)", reply, re.M)
                if match_kick_ver:
                    device_info["network_os_version"] = match_kick_ver.group(1)

            if "network_os_version" not in device_info:
                match_sys_ver = re.search(r"\s+NXOS:\s+version\s*(\S+)", reply, re.M)
                if match_sys_ver:
                    device_info["network_os_version"] = match_sys_ver.group(1)

            match_chassis_id = re.search(r"Hardware\n\s+cisco(.+)$", reply, re.M)
            if match_chassis_id:
                device_info["network_os_model"] = match_chassis_id.group(1).strip()

            match_host_name = re.search(r"\s+Device name:\s*(\S+)", reply, re.M)
            if match_host_name:
                device_info["network_os_hostname"] = match_host_name.group(1)

            match_isan_file_name = re.search(r"\s+system image file is:\s*(\S+)", reply, re.M)
            if match_isan_file_name:
                device_info["network_os_image"] = match_isan_file_name.group(1)
            else:
                match_kick_file_name = re.search(
                    r"\s+kickstart image file is:\s*(\S+)",
                    reply,
                    re.M,
                )
                if match_kick_file_name:
                    device_info["network_os_image"] = match_kick_file_name.group(1)

            if "network_os_image" not in device_info:
                match_isan_file_name = re.search(r"\s+NXOS image file is:\s*(\S+)", reply, re.M)
                if match_isan_file_name:
                    device_info["network_os_image"] = match_isan_file_name.group(1)

            match_os_platform = re.search(
                r'NAME: "Chassis",\s*DESCR:.*\nPID:\s*(\S+)',
                platform_reply,
                re.M,
            )
            if match_os_platform:
                device_info["network_os_platform"] = match_os_platform.group(1)

            self._device_info = device_info

        return self._device_info

    def restore(self, filename=None, path=""):
        if not filename:
            raise ValueError("'file_name' value is required for restore")
        cmd = f"configure replace {path}{filename} best-effort"
        return self.send_command(cmd)

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
        candidate_obj = NetworkConfig(indent=2)
        candidate_obj.load(candidate)

        if running and diff_match != "none" and diff_replace != "config":
            # running configuration
            running_obj = NetworkConfig(indent=2, contents=running, ignore_lines=diff_ignore_lines)
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

    def get_config(self, source="running", flags=None, format="text"):
        options_values = self.get_option_values()
        if format not in options_values["format"]:
            raise ValueError(
                "'format' value %s is invalid. Valid values are %s"
                % (format, ",".join(options_values["format"])),
            )

        lookup = {"running": "running-config", "startup": "startup-config"}
        if source not in lookup:
            raise ValueError("fetching configuration from %s is not supported" % source)

        cmd = "show {0} ".format(lookup[source])
        if format and format != "text":
            cmd += "| %s " % format

        if flags:
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
        err_responses=None,
    ):
        if diff:
            self._connection.queue_message(
                "warning",
                message="setting `diff=True` in edit_config() no effect for platform cisco.nxos",
            )

        resp = {}
        operations = self.get_device_operations()
        self.check_edit_config_capability(
            operations,
            candidate,
            commit,
            replace,
            comment,
        )
        results = []
        requests = []

        if err_responses:
            # update platform default stderr regexes to include modules specific ones
            err_responses = [re.compile(to_bytes(err_re)) for err_re in err_responses]
            current_stderr_re = self._connection._get_terminal_std_re(
                "terminal_stderr_re",
            )
            current_stderr_re.extend(err_responses)

        if replace:
            # not all NX-OS versions support `config replace`
            # we let the device throw the invalid command error
            candidate = f"config replace {replace}"

        try:
            if commit:
                self.send_command("configure terminal")

                for line in to_list(candidate):
                    if not isinstance(line, Mapping):
                        line = {"command": line}

                    cmd = line["command"]
                    if cmd != "end":
                        results.append(self.send_command(**line))
                        requests.append(cmd)

                self.send_command("end")
            else:
                raise ValueError("check mode is not supported")

            resp["request"] = requests
            resp["response"] = results
            return resp

        finally:
            # always reset terminal regexes to platform default
            if err_responses:
                for x in err_responses:
                    current_stderr_re.remove(x)

    def get(
        self,
        command,
        prompt=None,
        answer=None,
        sendonly=False,
        newline=True,
        output=None,
        check_all=False,
    ):
        if output:
            command = self._get_command_with_output(command, output)
        return self.send_command(
            command=command,
            prompt=prompt,
            answer=answer,
            sendonly=sendonly,
            newline=newline,
            check_all=check_all,
        )

    def run_commands(self, commands=None, check_rc=True):
        if commands is None:
            raise ValueError("'commands' value is required")

        responses = list()
        for cmd in to_list(commands):
            if not isinstance(cmd, Mapping):
                cmd = {"command": cmd}

            output = cmd.pop("output", None)
            if output:
                cmd["command"] = self._get_command_with_output(cmd["command"], output)

            try:
                out = self.send_command(**cmd)
            except AnsibleConnectionFailure as e:
                if check_rc is True:
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

    def get_device_operations(self):
        return {
            "supports_diff_replace": True,
            "supports_commit": False,
            "supports_rollback": False,
            "supports_defaults": True,
            "supports_onbox_diff": False,
            "supports_commit_comment": False,
            "supports_multiline_delimiter": False,
            "supports_diff_match": True,
            "supports_diff_ignore_lines": True,
            "supports_generate_diff": True,
            "supports_replace": True,
        }

    def get_option_values(self):
        return {
            "format": ["text", "json"],
            "diff_match": ["line", "strict", "exact", "none"],
            "diff_replace": ["line", "block", "config"],
            "output": ["text", "json", "json-pretty"],
        }

    def get_capabilities(self):
        result = super(Cliconf, self).get_capabilities()
        result["rpc"] += ["get_diff", "run_commands"]
        result["device_operations"] = self.get_device_operations()
        result.update(self.get_option_values())

        return json.dumps(result)

    def pull_file(self, command, remotepassword=None):
        possible_errors_re = [
            re.compile(rb"timed out"),
            re.compile(rb"(?i)No space.*#"),
            re.compile(rb"(?i)Permission denied.*#"),
            re.compile(rb"(?i)No such file.*#"),
            re.compile(rb"Compaction is not supported on this platform.*#"),
            re.compile(rb"Compact of.*failed.*#"),
            re.compile(rb"(?i)Could not resolve hostname"),
            re.compile(rb"(?i)Too many authentication failures"),
            re.compile(rb"Access Denied"),
            re.compile(rb"(?i)Copying to\/from this server name is not permitted"),
            re.compile(rb"Could not resolve hostname"),
        ]

        # set error regex for copy command
        current_stderr_re = self._connection._get_terminal_std_re("terminal_stderr_re")
        current_stderr_re.extend(possible_errors_re)

        # do not change the ordering of this list
        possible_prompts_re = [
            re.compile(rb"file existing with this name"),
            re.compile(rb"sure you want to continue connecting"),
            re.compile(rb"(?i)Password:.*"),
        ]

        # set stdout regex for copy command to handle optional user prompts
        # based on different match conditions
        current_stdout_re = self._connection._get_terminal_std_re("terminal_stdout_re")
        current_stdout_re.extend(possible_prompts_re)

        retry = 1
        file_pulled = False

        try:
            while not file_pulled and retry <= 6:
                retry += 1
                output = self.send_command(command=command, strip_prompt=False)

                if possible_prompts_re[0].search(to_bytes(output)):
                    output = self.send_command(command="y", strip_prompt=False)

                if possible_prompts_re[1].search(to_bytes(output)):
                    output = self.send_command(command="yes", strip_prompt=False)

                if possible_prompts_re[2].search(to_bytes(output)):
                    output = self.send_command(command=remotepassword, strip_prompt=False)
                if "Copy complete" in output:
                    file_pulled = True
            return file_pulled
        finally:
            # always reset terminal regexes to default
            for x in possible_prompts_re:
                current_stdout_re.remove(x)
            for x in possible_errors_re:
                current_stderr_re.remove(x)

    def set_cli_prompt_context(self):
        """
        Make sure we are in the operational cli context
        :return: None
        """
        if self._connection.connected:
            out = self._connection.get_prompt()
            if out is None:
                raise AnsibleConnectionFailure(
                    message="cli prompt is not identified from the last received"
                    " response window: %s" % self._connection._last_recv_window,
                )
            # Match prompts ending in )# except those with (maint-mode)#
            config_prompt = re.compile(r"^.*\((?!maint-mode).*\)#$")

            while config_prompt.match(to_text(out, errors="surrogate_then_replace").strip()):
                self._connection.queue_message("vvvv", "wrong context, sending exit to device")
                self._connection.send_command("exit")
                out = self._connection.get_prompt()

    def _get_command_with_output(self, command, output):
        output_re = r".+\|\s*json(?:-pretty)?$"
        options_values = self.get_option_values()
        if output not in options_values["output"]:
            raise ValueError(
                "'output' value %s is invalid. Valid values are %s"
                % (output, ",".join(options_values["output"])),
            )

        if output in ["json", "json-pretty"] and not re.search(output_re, command):
            device_info = self.get_device_info()
            model = device_info.get("network_os_model", "")
            platform = device_info.get("network_os_platform", "")
            if platform.startswith("DS-") and "MDS" in model:
                cmd = "%s | json native" % command
            else:
                cmd = "%s | %s" % (command, output)
        elif output == "text" and re.search(output_re, command):
            cmd = command.rsplit("|", 1)[0]
        else:
            cmd = command
        return cmd
