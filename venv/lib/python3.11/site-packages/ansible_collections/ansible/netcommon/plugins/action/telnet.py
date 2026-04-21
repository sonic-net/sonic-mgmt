# (c) 2017, Ansible Project
#
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from time import sleep

from ansible.module_utils.common.text.converters import to_bytes, to_text
from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

from ansible_collections.ansible.netcommon.plugins.plugin_utils.compat import telnetlib


text_type = str
display = Display()


class ActionModule(ActionBase):
    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        if self._task.environment and any(self._task.environment):
            self._display.warning("The telnet task does not support the environment keyword")

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        if self._play_context.check_mode:
            # in --check mode, always skip this module execution
            result["skipped"] = True
            result["msg"] = "The telnet task does not support check mode"
        else:
            result["changed"] = True
            result["failed"] = False

            host = to_text(self._task.args.get("host", self._play_context.remote_addr))
            user = to_text(self._task.args.get("user", self._play_context.remote_user))
            password = to_text(self._task.args.get("password", self._play_context.password))

            # FIXME, default to play_context?
            port = int(self._task.args.get("port", 23))
            timeout = int(self._task.args.get("timeout", 120))
            pause = int(self._task.args.get("pause", 1))

            send_newline = self._task.args.get("send_newline", False)
            crlf = self._task.args.get("crlf", False)

            login_prompt = to_text(self._task.args.get("login_prompt", "login: "))
            password_prompt = to_text(self._task.args.get("password_prompt", "Password: "))
            prompts = self._task.args.get("prompts", ["\\$ "])
            commands = self._task.args.get("command") or self._task.args.get("commands")

            if crlf:
                line_ending = "\r\n"
            else:
                line_ending = "\n"

            if isinstance(commands, text_type):
                commands = commands.split(",")

            if isinstance(commands, list) and commands:
                self.tn = telnetlib.Telnet(host, port, timeout)

                self.output = bytes()
                try:
                    if send_newline:
                        self.tn.write(to_bytes(line_ending))

                    self.await_prompts([login_prompt], timeout)
                    display.vvvvv(">>>user: %s" % user)
                    self.tn.write(to_bytes(user + line_ending))

                    if password:
                        self.await_prompts([password_prompt], timeout)
                        display.vvvvv(">>>password: %s" % password)
                        self.tn.write(to_bytes(password + line_ending))

                    self.await_prompts(prompts, timeout)

                    for cmd in commands:
                        display.vvvvv(">>> %s" % cmd)
                        self.tn.write(to_bytes(cmd + line_ending))
                        self.await_prompts(prompts, timeout)
                        display.vvvvv("<<< %s" % cmd)
                        sleep(pause)

                    self.tn.write(to_bytes("exit" + line_ending))

                except EOFError as e:
                    result["failed"] = True
                    result["msg"] = "Telnet action failed: %s" % to_text(e)
                except TimeoutError as e:
                    result["failed"] = True
                    result["msg"] = "Telnet timed out trying to find prompt(s): '%s'" % to_text(e)
                finally:
                    if self.tn:
                        self.tn.close()
                    result["stdout"] = to_text(self.output)
                    result["stdout_lines"] = self.output.splitlines(True)
            else:
                result["failed"] = True
                result["msg"] = "Telnet requires a command to execute"

        return result

    def await_prompts(self, prompts, timeout):
        index, match, out = self.tn.expect(list(map(to_bytes, prompts)), timeout=timeout)
        self.output += out
        if not match:
            raise TimeoutError(prompts)

        return index
