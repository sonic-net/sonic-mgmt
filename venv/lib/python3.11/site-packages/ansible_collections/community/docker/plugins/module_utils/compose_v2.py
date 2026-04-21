# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# Copyright (c) 2023, Léo El Amri (@lel-amri)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import json
import os
import re
import shutil
import tempfile
import traceback
from collections import namedtuple

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native, to_text
from ansible_collections.community.docker.plugins.module_utils._six import shlex_quote, string_types

from ansible_collections.community.docker.plugins.module_utils.util import DockerBaseClass
from ansible_collections.community.docker.plugins.module_utils.version import LooseVersion
from ansible_collections.community.docker.plugins.module_utils._logfmt import (
    InvalidLogFmt as _InvalidLogFmt,
    parse_line as _parse_logfmt_line,
)

try:
    import yaml
    try:
        # use C version if possible for speedup
        from yaml import CSafeDumper as _SafeDumper
    except ImportError:
        from yaml import SafeDumper as _SafeDumper
    HAS_PYYAML = True
    PYYAML_IMPORT_ERROR = None
except ImportError:
    HAS_PYYAML = False
    PYYAML_IMPORT_ERROR = traceback.format_exc()


DOCKER_COMPOSE_FILES = ('compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml')

DOCKER_STATUS_DONE = frozenset((
    'Started',
    'Healthy',
    'Exited',
    'Restarted',
    'Running',
    'Created',
    'Stopped',
    'Killed',
    'Removed',
    # An extra, specific to containers
    'Recreated',
    # Extras for pull events
    'Pulled',
    # Extras for built events
    'Built',
))
DOCKER_STATUS_WORKING = frozenset((
    'Creating',
    'Starting',
    'Restarting',
    'Stopping',
    'Killing',
    'Removing',
    # An extra, specific to containers
    'Recreate',
    # Extras for pull events
    'Pulling',
    # Extras for build start events
    'Building',
))
DOCKER_STATUS_PULL = frozenset((
    'Pulled',
    'Pulling',
))
DOCKER_STATUS_BUILD = frozenset((
    'Built',
    'Building',
))
DOCKER_STATUS_ERROR = frozenset((
    'Error',
))
DOCKER_STATUS_WARNING = frozenset((
    'Warning',
))
DOCKER_STATUS_WAITING = frozenset((
    'Waiting',
))
DOCKER_STATUS = frozenset(DOCKER_STATUS_DONE | DOCKER_STATUS_WORKING | DOCKER_STATUS_PULL | DOCKER_STATUS_ERROR | DOCKER_STATUS_WAITING)
DOCKER_STATUS_AND_WARNING = frozenset(DOCKER_STATUS | DOCKER_STATUS_WARNING)

DOCKER_PULL_PROGRESS_DONE = frozenset((
    'Already exists',
    'Download complete',
    'Pull complete',
))
DOCKER_PULL_PROGRESS_WORKING_OLD = frozenset(
    (
        "Pulling fs layer",
        "Waiting",
        "Downloading",
        "Verifying Checksum",
        "Extracting",
    )
)
DOCKER_PULL_PROGRESS_WORKING = frozenset(DOCKER_PULL_PROGRESS_WORKING_OLD | set(["Working"]))


class ResourceType(object):
    UNKNOWN = "unknown"
    NETWORK = "network"
    IMAGE = "image"
    IMAGE_LAYER = "image-layer"
    VOLUME = "volume"
    CONTAINER = "container"
    SERVICE = "service"

    @classmethod
    def from_docker_compose_event(cls, resource_type):
        # type: (Type[ResourceType], Text) -> Any
        return {
            "Network": cls.NETWORK,
            "Image": cls.IMAGE,
            "Volume": cls.VOLUME,
            "Container": cls.CONTAINER,
            "Service": cls.SERVICE,
        }[resource_type]


Event = namedtuple(
    'Event',
    ['resource_type', 'resource_id', 'status', 'msg']
)


_DRY_RUN_MARKER = 'DRY-RUN MODE -'

_RE_RESOURCE_EVENT = re.compile(
    r'^'
    r'\s*'
    r'(?P<resource_type>Network|Image|Volume|Container)'
    r'\s+'
    r'(?P<resource_id>\S+)'
    r'\s+'
    r'(?P<status>\S(?:|.*\S))'
    r'\s*'
    r'$'
)

_RE_PULL_EVENT = re.compile(
    r'^'
    r'\s*'
    r'(?P<service>\S+)'
    r'\s+'
    r'(?P<status>%s)'
    r'\s*'
    r'$'
    % '|'.join(re.escape(status) for status in DOCKER_STATUS_PULL)
)

_RE_PULL_PROGRESS = re.compile(
    r'^'
    r'\s*'
    r'(?P<layer>\S+)'
    r'\s+'
    r'(?P<status>%s)'
    r'\s*'
    r'(?:|\s\[[^]]+\]\s+\S+\s*|\s+[0-9.kKmMgGbB]+/[0-9.kKmMgGbB]+\s*)'
    r'$'
    % '|'.join(re.escape(status) for status in sorted(DOCKER_PULL_PROGRESS_DONE | DOCKER_PULL_PROGRESS_WORKING_OLD))
)

_RE_ERROR_EVENT = re.compile(
    r'^'
    r'\s*'
    r'(?P<resource_id>\S+)'
    r'\s+'
    r'(?P<status>%s)'
    r'\s*'
    r'(?P<msg>\S.*\S)?'
    r'$'
    % '|'.join(re.escape(status) for status in DOCKER_STATUS_ERROR)
)

_RE_WARNING_EVENT = re.compile(
    r'^'
    r'\s*'
    r'(?P<resource_id>\S+)'
    r'\s+'
    r'(?P<status>%s)'
    r'\s*'
    r'(?P<msg>\S.*\S)?'
    r'$'
    % '|'.join(re.escape(status) for status in DOCKER_STATUS_WARNING)
)

_RE_CONTINUE_EVENT = re.compile(
    r'^'
    r'\s*'
    r'(?P<resource_id>\S+)'
    r'\s+'
    r'-'
    r'\s*'
    r'(?P<msg>\S(?:|.*\S))'
    r'$'
)

_RE_SKIPPED_EVENT = re.compile(
    r'^'
    r'\s*'
    r'(?P<resource_id>\S+)'
    r'\s+'
    r'Skipped(?: -'
    r'\s*'
    r'(?P<msg>\S(?:|.*\S))|\s*)'
    r'$'
)

_RE_BUILD_START_EVENT = re.compile(
    r'^'
    r'\s*'
    r'build service'
    r'\s+'
    r'(?P<resource_id>\S+)'
    r'$'
)

_RE_BUILD_PROGRESS_EVENT = re.compile(
    r'^'
    r'\s*'
    r'==>'
    r'\s+'
    r'(?P<msg>.*)'
    r'$'
)

# The following needs to be kept in sync with the MINIMUM_VERSION compose_v2 docs fragment
MINIMUM_COMPOSE_VERSION = '2.18.0'


def _extract_event(line, warn_function=None):
    match = _RE_RESOURCE_EVENT.match(line)
    if match is not None:
        status = match.group('status')
        msg = None
        if status not in DOCKER_STATUS:
            status, msg = msg, status
        return Event(
            ResourceType.from_docker_compose_event(match.group('resource_type')),
            match.group('resource_id'),
            status,
            msg,
        ), True
    match = _RE_PULL_EVENT.match(line)
    if match:
        return Event(
            ResourceType.SERVICE,
            match.group('service'),
            match.group('status'),
            None,
        ), True
    match = _RE_ERROR_EVENT.match(line)
    if match:
        return Event(
            ResourceType.UNKNOWN,
            match.group('resource_id'),
            match.group('status'),
            match.group('msg') or None,
        ), True
    match = _RE_WARNING_EVENT.match(line)
    if match:
        if warn_function:
            if match.group('msg'):
                msg = '{rid}: {msg}'
            else:
                msg = 'Unspecified warning for {rid}'
            warn_function(msg.format(rid=match.group('resource_id'), msg=match.group('msg')))
        return None, True
    match = _RE_PULL_PROGRESS.match(line)
    if match:
        return Event(
            ResourceType.IMAGE_LAYER,
            match.group('layer'),
            match.group('status'),
            None,
        ), True
    match = _RE_SKIPPED_EVENT.match(line)
    if match:
        return Event(
            ResourceType.UNKNOWN,
            match.group('resource_id'),
            'Skipped',
            match.group('msg'),
        ), True
    match = _RE_BUILD_START_EVENT.match(line)
    if match:
        return Event(
            ResourceType.SERVICE,
            match.group('resource_id'),
            'Building',
            None,
        ), True
    return None, False


def _extract_logfmt_event(line, warn_function=None):
    try:
        result = _parse_logfmt_line(line, logrus_mode=True)
    except _InvalidLogFmt:
        return None, False
    if 'time' not in result or 'level' not in result or 'msg' not in result:
        return None, False
    if result['level'] == 'warning':
        if warn_function:
            warn_function(result['msg'])
        return None, True
    # TODO: no idea what to do with this
    return None, False


def _warn_missing_dry_run_prefix(line, warn_missing_dry_run_prefix, warn_function):
    if warn_missing_dry_run_prefix and warn_function:
        # This could be a bug, a change of docker compose's output format, ...
        # Tell the user to report it to us :-)
        warn_function(
            'Event line is missing dry-run mode marker: {0!r}. Please check with the latest community.docker version,'
            ' and if the problem still happens there, please report this at '
            'https://github.com/ansible-collections/community.docker/issues/new?assignees=&labels=&projects=&template=bug_report.md'
            .format(line)
        )


def _warn_unparsable_line(line, warn_function):
    # This could be a bug, a change of docker compose's output format, ...
    # Tell the user to report it to us :-)
    if warn_function:
        warn_function(
            'Cannot parse event from line: {0!r}. Please check with the latest community.docker version,'
            ' and if the problem still happens there, please report this at '
            'https://github.com/ansible-collections/community.docker/issues/new?assignees=&labels=&projects=&template=bug_report.md'
            .format(line)
        )


def _find_last_event_for(events, resource_id):
    for index, event in enumerate(reversed(events)):
        if event.resource_id == resource_id:
            return len(events) - 1 - index, event
    return None


def _concat_event_msg(event, append_msg):
    return Event(
        event.resource_type,
        event.resource_id,
        event.status,
        '\n'.join(msg for msg in [event.msg, append_msg] if msg is not None),
    )


_JSON_LEVEL_TO_STATUS_MAP = {
    'warning': 'Warning',
    'error': 'Error',
}


def parse_json_events(stderr, warn_function=None):
    events = []
    stderr_lines = stderr.splitlines()
    if stderr_lines and stderr_lines[-1] == b'':
        del stderr_lines[-1]
    for line in stderr_lines:
        line = line.strip()
        if not line.startswith(b'{') or not line.endswith(b'}'):
            if line.startswith(b'Warning: '):
                # This is a bug in Compose that will get fixed by https://github.com/docker/compose/pull/11996
                event = Event(
                    ResourceType.UNKNOWN,
                    None,
                    'Warning',
                    to_native(line[len(b'Warning: '):]),
                )
                events.append(event)
                continue
            if warn_function:
                warn_function(
                    'Cannot parse event from non-JSON line: {0!r}. Please check with the latest community.docker version,'
                    ' and if the problem still happens there, please report this at '
                    'https://github.com/ansible-collections/community.docker/issues/new?assignees=&labels=&projects=&template=bug_report.md'
                    .format(line)
                )
            continue
        try:
            line_data = json.loads(to_text(line))
        except Exception as exc:
            if warn_function:
                warn_function(
                    'Cannot parse event from line: {0!r}: {1}. Please check with the latest community.docker version,'
                    ' and if the problem still happens there, please report this at '
                    'https://github.com/ansible-collections/community.docker/issues/new?assignees=&labels=&projects=&template=bug_report.md'
                    .format(line, exc)
                )
            continue
        if line_data.get('tail'):
            resource_type = ResourceType.UNKNOWN
            msg = line_data.get('text')
            status = 'Error'
            if isinstance(msg, str) and msg.lower().startswith('warning:'):
                # For some reason, Writer.TailMsgf() is always used for errors *except* in one place,
                # where its message is prepended with 'WARNING: ' (in pkg/compose/pull.go).
                status = 'Warning'
                msg = msg[len('warning:'):].lstrip()
            event = Event(
                resource_type,
                None,
                status,
                msg,
            )
        elif line_data.get('error'):
            resource_type = ResourceType.UNKNOWN
            event = Event(
                resource_type,
                line_data.get('id'),
                'Error',
                line_data.get('message'),
            )
        else:
            resource_type = ResourceType.UNKNOWN
            resource_id = to_native(line_data.get('id'), nonstring='passthru')
            parent_id = to_native(line_data.get("parent_id"), nonstring='passthru')
            status = to_native(line_data.get('status'), nonstring='passthru')
            text = to_native(line_data.get('text'), nonstring='passthru')
            level = to_native(line_data.get('level'), nonstring='passthru')
            msg = to_native(line_data.get('msg'), nonstring='passthru')
            if resource_id == " " and text and text.startswith("build service "):
                # Example:
                # {"dry-run":true,"id":" ","text":"build service app"}
                resource_id = "S" + text[len("build s"):]
                text = "Building"
            if isinstance(resource_id, str) and resource_id.endswith("==>") and text and text.startswith("==> writing image "):
                # Example:
                # {"dry-run":true,"id":"==>","text":"==> writing image dryRun-7d1043473d55bfa90e8530d35801d4e381bc69f0"}
                # {"dry-run":true,"id":"ansible-docker-test-dc713f1f-container ==>","text":"==> writing image dryRun-5d9204268db1a73d57bbd24a25afbeacebe2bc02"}
                # (The longer form happens since Docker Compose 2.39.0)
                continue
            if isinstance(resource_id, str) and resource_id.endswith("==> ==>") and text and text.startswith("naming to "):
                # Example:
                # {"dry-run":true,"id":"==> ==>","text":"naming to display-app"}
                # {"dry-run":true,"id":"ansible-docker-test-dc713f1f-container ==> ==>","text":"naming to ansible-docker-test-dc713f1f-image"}
                # (The longer form happens since Docker Compose 2.39.0)
                continue
            if status in ("Working", "Done") and isinstance(parent_id, str) and parent_id.startswith("Image "):
                # Compose 5.0.0+:
                # {"id":"63a26ae4e8a8","parent_id":"Image ghcr.io/ansible-collections/simple-1:tag","status":"Working"}
                # {"id":"63a26ae4e8a8","parent_id":"Image ghcr.io/ansible-collections/simple-1:tag","status":"Done","percent":100}
                resource_type = ResourceType.IMAGE_LAYER
                resource_id = parent_id[len("Image ") :]
            elif isinstance(resource_id, str) and ' ' in resource_id:
                resource_type_str, resource_id = resource_id.split(' ', 1)
                try:
                    resource_type = ResourceType.from_docker_compose_event(resource_type_str)
                except KeyError:
                    if warn_function:
                        warn_function(
                            'Unknown resource type {0!r} in line {1!r}. Please check with the latest community.docker version,'
                            ' and if the problem still happens there, please report this at '
                            'https://github.com/ansible-collections/community.docker/issues/new?assignees=&labels=&projects=&template=bug_report.md'
                            .format(resource_type_str, line)
                        )
                    resource_type = ResourceType.UNKNOWN
            elif text in DOCKER_STATUS_PULL:
                resource_type = ResourceType.IMAGE
                status, text = text, status
            elif text in DOCKER_PULL_PROGRESS_DONE or text in DOCKER_PULL_PROGRESS_WORKING_OLD:
                resource_type = ResourceType.IMAGE_LAYER
                status, text = text, status
            elif status is None and isinstance(text, string_types) and text.startswith('Skipped - '):
                status, text = text.split(' - ', 1)
            elif level in _JSON_LEVEL_TO_STATUS_MAP and 'msg' in line_data:
                status = _JSON_LEVEL_TO_STATUS_MAP[level]
                text = msg
            if status not in DOCKER_STATUS_AND_WARNING and text in DOCKER_STATUS_AND_WARNING:
                status, text = text, status
            event = Event(
                resource_type,
                resource_id,
                status,
                text,
            )

        events.append(event)
    return events


def parse_events(stderr, dry_run=False, warn_function=None, nonzero_rc=False):
    events = []
    error_event = None
    stderr_lines = stderr.splitlines()
    if stderr_lines and stderr_lines[-1] == b'':
        del stderr_lines[-1]
    for index, line in enumerate(stderr_lines):
        line = to_native(line.strip())
        if not line:
            continue
        warn_missing_dry_run_prefix = False
        if dry_run:
            if line.startswith(_DRY_RUN_MARKER):
                line = line[len(_DRY_RUN_MARKER):].lstrip()
            else:
                warn_missing_dry_run_prefix = True
        event, parsed = _extract_event(line, warn_function=warn_function)
        if event is not None:
            events.append(event)
            if event.status in DOCKER_STATUS_ERROR:
                error_event = event
            else:
                error_event = None
            _warn_missing_dry_run_prefix(line, warn_missing_dry_run_prefix, warn_function)
            continue
        elif parsed:
            continue
        match = _RE_BUILD_PROGRESS_EVENT.match(line)
        if match:
            # Ignore this
            continue
        match = _RE_CONTINUE_EVENT.match(line)
        if match:
            # Continuing an existing event
            index_event = _find_last_event_for(events, match.group('resource_id'))
            if index_event is not None:
                index, event = index_event
                events[index] = _concat_event_msg(event, match.group('msg'))
        event, parsed = _extract_logfmt_event(line, warn_function=warn_function)
        if event is not None:
            events.append(event)
        elif parsed:
            continue
        if error_event is not None:
            # Unparsable line that apparently belongs to the previous error event
            events[-1] = _concat_event_msg(error_event, line)
            continue
        if line.startswith('Error '):
            # Error message that is independent of an error event
            error_event = Event(
                ResourceType.UNKNOWN,
                '',
                'Error',
                line,
            )
            events.append(error_event)
            continue
        if len(stderr_lines) == 1 or (nonzero_rc and index == len(stderr_lines) - 1):
            # **Very likely** an error message that is independent of an error event
            error_event = Event(
                ResourceType.UNKNOWN,
                '',
                'Error',
                line,
            )
            events.append(error_event)
            continue
        _warn_missing_dry_run_prefix(line, warn_missing_dry_run_prefix, warn_function)
        _warn_unparsable_line(line, warn_function)
    return events


def has_changes(events, ignore_service_pull_events=False, ignore_build_events=False):
    for event in events:
        if event.status in DOCKER_STATUS_WORKING:
            if ignore_service_pull_events and event.status in DOCKER_STATUS_PULL:
                continue
            if ignore_build_events and event.status in DOCKER_STATUS_BUILD:
                continue
            return True
        if event.resource_type == ResourceType.IMAGE_LAYER and event.status in DOCKER_PULL_PROGRESS_WORKING:
            return True
    return False


def extract_actions(events):
    actions = []
    pull_actions = set()
    for event in events:
        if event.resource_type == ResourceType.IMAGE_LAYER and event.status in DOCKER_PULL_PROGRESS_WORKING:
            pull_id = (event.resource_id, event.status)
            if pull_id not in pull_actions:
                pull_actions.add(pull_id)
                actions.append({
                    'what': event.resource_type,
                    'id': event.resource_id,
                    'status': event.status,
                })
        if event.resource_type != ResourceType.IMAGE_LAYER and event.status in DOCKER_STATUS_WORKING:
            actions.append({
                'what': event.resource_type,
                'id': event.resource_id,
                'status': event.status,
            })
    return actions


def emit_warnings(events, warn_function):
    for event in events:
        # If a message is present, assume it is a warning
        if (event.status is None and event.msg is not None) or event.status in DOCKER_STATUS_WARNING:
            warn_function('Docker compose: {resource_type} {resource_id}: {msg}'.format(
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                msg=event.msg,
            ))


def is_failed(events, rc):
    if rc:
        return True
    return False


def update_failed(result, events, args, stdout, stderr, rc, cli):
    if not rc:
        return False
    errors = []
    for event in events:
        if event.status in DOCKER_STATUS_ERROR:
            if event.resource_id is None:
                if event.resource_type == 'unknown':
                    msg = 'General error: ' if event.resource_type == 'unknown' else 'Error when processing {resource_type}: '
            else:
                msg = 'Error when processing {resource_type} {resource_id}: '
                if event.resource_type == 'unknown':
                    msg = 'Error when processing {resource_id}: '
                    if event.resource_id == '':
                        msg = 'General error: '
            msg += '{status}' if event.msg is None else '{msg}'
            errors.append(msg.format(
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                status=event.status,
                msg=event.msg,
            ))
    if not errors:
        errors.append('Return code {code} is non-zero'.format(code=rc))
    result['failed'] = True
    result['msg'] = '\n'.join(errors)
    result['cmd'] = ' '.join(shlex_quote(arg) for arg in [cli] + args)
    result['stdout'] = to_native(stdout)
    result['stderr'] = to_native(stderr)
    result['rc'] = rc
    return True


def common_compose_argspec():
    return dict(
        project_src=dict(type='path'),
        project_name=dict(type='str'),
        files=dict(type='list', elements='path'),
        definition=dict(type='dict'),
        env_files=dict(type='list', elements='path'),
        profiles=dict(type='list', elements='str'),
        check_files_existing=dict(type='bool', default=True),
    )


def common_compose_argspec_ex():
    return dict(
        argspec=common_compose_argspec(),
        mutually_exclusive=[
            ('definition', 'project_src'),
            ('definition', 'files')
        ],
        required_one_of=[
            ('definition', 'project_src'),
        ],
        required_by={
            'definition': ('project_name', ),
        },
    )


def combine_binary_output(*outputs):
    return b'\n'.join(out for out in outputs if out)


def combine_text_output(*outputs):
    return '\n'.join(out for out in outputs if out)


class BaseComposeManager(DockerBaseClass):
    def __init__(self, client, min_version=MINIMUM_COMPOSE_VERSION):
        super(BaseComposeManager, self).__init__()
        self.client = client
        self.check_mode = self.client.check_mode
        self.cleanup_dirs = set()
        parameters = self.client.module.params

        if parameters['definition'] is not None and not HAS_PYYAML:
            self.fail(
                missing_required_lib('PyYAML'),
                exception=PYYAML_IMPORT_ERROR
            )

        self.project_name = parameters['project_name']
        if parameters['definition'] is not None:
            self.project_src = tempfile.mkdtemp(prefix='ansible')
            self.cleanup_dirs.add(self.project_src)
            compose_file = os.path.join(self.project_src, 'compose.yaml')
            self.client.module.add_cleanup_file(compose_file)
            try:
                with open(compose_file, 'wb') as f:
                    yaml.dump(parameters['definition'], f, encoding="utf-8", Dumper=_SafeDumper)
            except Exception as exc:
                self.fail("Error writing to %s - %s" % (compose_file, to_native(exc)))
        else:
            self.project_src = os.path.abspath(parameters['project_src'])

        self.files = parameters['files']
        self.env_files = parameters['env_files']
        self.profiles = parameters['profiles']

        compose_version = self.get_compose_version()
        self.compose_version = LooseVersion(compose_version)
        if self.compose_version < LooseVersion(min_version):
            self.fail('Docker CLI {cli} has the compose plugin with version {version}; need version {min_version} or later'.format(
                cli=self.client.get_cli(),
                version=compose_version,
                min_version=min_version,
            ))

        if not os.path.isdir(self.project_src):
            self.fail('"{0}" is not a directory'.format(self.project_src))

        self.check_files_existing = parameters['check_files_existing']
        if self.files:
            for file in self.files:
                path = os.path.join(self.project_src, file)
                if not os.path.exists(path):
                    self.fail('Cannot find Compose file "{0}" relative to project directory "{1}"'.format(file, self.project_src))
        elif self.check_files_existing and all(not os.path.exists(os.path.join(self.project_src, f)) for f in DOCKER_COMPOSE_FILES):
            filenames = ', '.join(DOCKER_COMPOSE_FILES[:-1])
            self.fail('"{0}" does not contain {1}, or {2}'.format(self.project_src, filenames, DOCKER_COMPOSE_FILES[-1]))

        # Support for JSON output was added in Compose 2.29.0 (https://github.com/docker/compose/releases/tag/v2.29.0);
        # more precisely in https://github.com/docker/compose/pull/11478
        self.use_json_events = self.compose_version >= LooseVersion('2.29.0')

    def get_compose_version(self):
        return self.get_compose_version_from_cli() or self.get_compose_version_from_api()

    def get_compose_version_from_cli(self):
        rc, version_info, stderr = self.client.call_cli('compose', 'version', '--format', 'json')
        if rc:
            return None
        try:
            version = json.loads(version_info)['version']
            if version == 'dev':
                return None
            return version.lstrip('v')
        except Exception:
            return None

    def get_compose_version_from_api(self):
        compose = self.client.get_client_plugin_info('compose')
        if compose is None:
            self.fail('Docker CLI {0} does not have the compose plugin installed'.format(self.client.get_cli()))
        if compose['Version'] == 'dev':
            self.fail(
                'Docker CLI {0} has a compose plugin installed, but it reports version "dev".'
                ' Please use a version of the plugin that returns a proper version.'
                .format(self.client.get_cli())
            )
        return compose['Version'].lstrip('v')

    def fail(self, msg, **kwargs):
        self.cleanup()
        self.client.fail(msg, **kwargs)

    def get_base_args(self, plain_progress=False):
        args = ['compose', '--ansi', 'never']
        if self.use_json_events and not plain_progress:
            args.extend(['--progress', 'json'])
        elif self.compose_version >= LooseVersion('2.19.0'):
            # https://github.com/docker/compose/pull/10690
            args.extend(['--progress', 'plain'])
        args.extend(['--project-directory', self.project_src])
        if self.project_name:
            args.extend(['--project-name', self.project_name])
        for file in self.files or []:
            args.extend(['--file', file])
        for env_file in self.env_files or []:
            args.extend(['--env-file', env_file])
        for profile in self.profiles or []:
            args.extend(['--profile', profile])
        return args

    def _handle_failed_cli_call(self, args, rc, stdout, stderr):
        events = parse_json_events(stderr, warn_function=self.client.warn)
        result = {}
        self.update_failed(result, events, args, stdout, stderr, rc)
        self.client.module.exit_json(**result)

    def list_containers_raw(self):
        args = self.get_base_args() + ['ps', '--format', 'json', '--all']
        if self.compose_version >= LooseVersion('2.23.0'):
            # https://github.com/docker/compose/pull/11038
            args.append('--no-trunc')
        kwargs = dict(cwd=self.project_src, check_rc=not self.use_json_events)
        if self.compose_version >= LooseVersion('2.21.0'):
            # Breaking change in 2.21.0: https://github.com/docker/compose/pull/10918
            rc, containers, stderr = self.client.call_cli_json_stream(*args, **kwargs)
        else:
            rc, containers, stderr = self.client.call_cli_json(*args, **kwargs)
        if self.use_json_events and rc != 0:
            self._handle_failed_cli_call(args, rc, containers, stderr)
        return containers

    def list_containers(self):
        result = []
        for container in self.list_containers_raw():
            labels = {}
            if container.get('Labels'):
                for part in container['Labels'].split(','):
                    label_value = part.split('=', 1)
                    labels[label_value[0]] = label_value[1] if len(label_value) > 1 else ''
            container['Labels'] = labels
            container['Names'] = container.get('Names', container['Name']).split(',')
            container['Networks'] = container.get('Networks', '').split(',')
            container['Publishers'] = container.get('Publishers') or []
            result.append(container)
        return result

    def list_images(self):
        args = self.get_base_args() + ['images', '--format', 'json']
        kwargs = dict(cwd=self.project_src, check_rc=not self.use_json_events)
        rc, images, stderr = self.client.call_cli_json(*args, **kwargs)
        if self.use_json_events and rc != 0:
            self._handle_failed_cli_call(args, rc, images, stderr)
        if isinstance(images, dict):
            # Handle breaking change in Docker Compose 2.37.0; see
            # https://github.com/ansible-collections/community.docker/issues/1082
            # and https://github.com/docker/compose/issues/12916 for details
            images = list(images.values())
        return images

    def parse_events(self, stderr, dry_run=False, nonzero_rc=False):
        if self.use_json_events:
            return parse_json_events(stderr, warn_function=self.client.warn)
        return parse_events(stderr, dry_run=dry_run, warn_function=self.client.warn, nonzero_rc=nonzero_rc)

    def emit_warnings(self, events):
        emit_warnings(events, warn_function=self.client.warn)

    def update_result(
        self,
        result,
        events,
        stdout,
        stderr,
        ignore_service_pull_events=False,
        ignore_build_events=False,
    ):
        result['changed'] = result.get('changed', False) or has_changes(
            events,
            ignore_service_pull_events=ignore_service_pull_events,
            ignore_build_events=ignore_build_events,
        )
        result['actions'] = result.get('actions', []) + extract_actions(events)
        result['stdout'] = combine_text_output(result.get('stdout'), to_native(stdout))
        result['stderr'] = combine_text_output(result.get('stderr'), to_native(stderr))

    def update_failed(self, result, events, args, stdout, stderr, rc):
        return update_failed(
            result,
            events,
            args=args,
            stdout=stdout,
            stderr=stderr,
            rc=rc,
            cli=self.client.get_cli(),
        )

    def cleanup_result(self, result):
        if not result.get('failed'):
            # Only return stdout and stderr if it is not empty
            for res in ('stdout', 'stderr'):
                if result.get(res) == '':
                    result.pop(res)

    def cleanup(self):
        for dir in self.cleanup_dirs:
            try:
                shutil.rmtree(dir, True)
            except Exception:
                # should not happen, but simply ignore to be on the safe side
                pass
