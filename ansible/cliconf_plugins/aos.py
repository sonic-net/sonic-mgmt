from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils._text import to_text
from ansible.module_utils.common._collections_compat import Mapping
from ansible.module_utils.network.common.utils import to_list
from ansible.module_utils.network.common.config import NetworkConfig, dumps
from ansible.plugins.cliconf import CliconfBase, enable_mode


class Cliconf(CliconfBase):

    def __init__(self, *args, **kwargs):
        super(Cliconf, self).__init__(*args, **kwargs)
        self._session_support = None

    @enable_mode
    def get_config(self, source='running', format='text', flags=None):
        options_values = self.get_option_values()
        if format not in options_values['format']:
            raise ValueError("'format' value %s is invalid. Valid values are %s" %
                             (format, ','.join(options_values['format'])))

        lookup = {'running': 'running-config', 'startup': 'startup-config'}
        if source not in lookup:
            raise ValueError("fetching configuration from %s is not supported" % source)

        cmd = 'show %s ' % lookup[source]
        if format and format != 'text':
            cmd += '| %s ' % format

        cmd += ' '.join(to_list(flags))
        cmd = cmd.strip()

        return self.run_commands(cmd)[0]

    @enable_mode
    def edit_config(self, candidate=None, commit=True, replace=None, comment=None):

        operations = self.get_device_operations()
        self.check_edit_config_capability(operations, candidate, commit, replace, comment)

        if (commit is False) and (not self.supports_sessions()):
            raise ValueError('check mode is not supported without configuration session')

        resp = {}

        self.send_command('configure')

        results = []
        requests = []
        multiline = False
        for line in to_list(candidate):
            if not isinstance(line, Mapping):
                line = {'command': line}

            cmd = line['command']
            if cmd == 'end':
                continue
            elif cmd.startswith('banner') or multiline:
                multiline = True

            if multiline:
                line['sendonly'] = True

            if cmd != 'end' and cmd[0] != '!':
                try:
                    results.append(self.send_command(**line))
                    requests.append(cmd)
                except AnsibleConnectionFailure as e:
                    raise AnsibleConnectionFailure(e.message)

        resp['request'] = requests
        resp['response'] = results
        self.send_command('end')
        return resp

    def get(self, command, prompt=None, answer=None, sendonly=False, output=None, check_all=False):
        if output:
            command = self._get_command_with_output(command, output)
        return self.send_command(command, prompt=prompt, answer=answer, sendonly=sendonly, check_all=check_all)

    def run_commands(self, commands=None, check_rc=True):
        if commands is None:
            raise ValueError("'commands' value is required")
        responses = list()
        for cmd in to_list(commands):
            if not isinstance(cmd, Mapping):
                cmd = {'command': cmd}

            output = cmd.pop('output', None)
            if output:
                cmd['command'] = self._get_command_with_output(cmd['command'], output)

            # pass interactive prompt
            cmd['prompt'] = r'--- \[Space\] Next page, \[Enter\] Next line, \[A\] All, Others to exit ---'
            cmd['answer'] = 'a'

            try:
                out = self.send_command(**cmd)
            except AnsibleConnectionFailure as e:
                if check_rc:
                    raise
                out = getattr(e, 'err', e)
            out = to_text(out, errors='surrogate_or_strict')

            if out is not None:
                try:
                    out = json.loads(out)
                except ValueError:
                    out = out.strip()

                # remove interactive prompt messages
                out = out.replace(r'--- [Space] Next page, [Enter] Next line, [A] All, Others to exit ---', '')
                out = out.replace(r'Building running configuration. Please wait...', '')
                responses.append(out)
        return responses

    def get_diff(self, candidate=None, running=None, diff_match='line',
                 diff_ignore_lines=None, path=None, diff_replace='line'):
        diff = {}
        device_operations = self.get_device_operations()
        option_values = self.get_option_values()

        if candidate is None and device_operations['supports_generate_diff']:
            raise ValueError("candidate configuration is required to generate diff")

        if diff_match not in option_values['diff_match']:
            raise ValueError("'match' value %s in invalid, valid values are %s" %
                             (diff_match, ', '.join(option_values['diff_match'])))

        if diff_replace not in option_values['diff_replace']:
            raise ValueError("'replace' value %s in invalid, valid values are %s" %
                             (diff_replace, ', '.join(option_values['diff_replace'])))

        # prepare candidate configuration
        candidate_obj = NetworkConfig(indent=1)
        candidate_obj.load(candidate)

        if running and diff_match != 'none' and diff_replace != 'config':
            running_obj = NetworkConfig(indent=1, contents=running, ignore_lines=diff_ignore_lines)
            configdiffobjs = candidate_obj.difference(running_obj, path=path, match=diff_match, replace=diff_replace)

        else:
            configdiffobjs = candidate_obj.items

        diff['config_diff'] = dumps(configdiffobjs, 'commands') if configdiffobjs else ''
        return diff

    def supports_sessions(self):
        return False

    def get_device_info(self):
        reply = self.get('show version')

        def extract_val(prop_name):
            import re
            return re.search(r'{}\s+:\s+(.+)'.format(prop_name), reply).group(1)

        device_info = {}
        device_info['network_os'] = 'aos'
        device_info['network_os_version'] = extract_val('Operation Code Version')
        device_info['network_os_model'] = extract_val('Serial Number')
        return device_info

    def get_device_operations(self):
        return {
            'supports_diff_replace': True,
            'supports_commit': bool(self.supports_sessions()),
            'supports_rollback': False,
            'supports_defaults': False,
            'supports_onbox_diff': bool(self.supports_sessions()),
            'supports_commit_comment': False,
            'supports_multiline_delimiter': False,
            'supports_diff_match': True,
            'supports_diff_ignore_lines': True,
            'supports_generate_diff': not bool(self.supports_sessions()),
            'supports_replace': bool(self.supports_sessions()),
        }

    def get_option_values(self):
        return {
            'format': ['text'],
            'diff_match': ['line', 'strict', 'exact', 'none'],
            'diff_replace': ['line', 'block', 'config'],
            'output': ['text']
        }

    def get_capabilities(self):
        result = super(Cliconf, self).get_capabilities()
        result['rpc'] += ['get_diff', 'run_commands', 'supports_sessions']
        result['device_operations'] = self.get_device_operations()
        result.update(self.get_option_values())

        return json.dumps(result)

    def _get_command_with_output(self, command, output):
        options_values = self.get_option_values()
        if output not in options_values['output']:
            raise ValueError("'output' value %s is invalid. Valid values are %s" %
                             (output, ','.join(options_values['output'])))

        return command
