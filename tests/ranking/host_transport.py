"""Deploy and invoke the file-state agent through the existing Ansible boundary."""
import json
import tempfile
import uuid
from pathlib import Path
from shutil import copyfile

from .environment_ownership import _validate_component, _validate_resource


REQUEST_ROOT = '/var/tmp/ranking-requests'
AGENT_FILES = ('__init__.py', 'remote_agent.py', 'environment_ownership.py',
               'state_store.py', 'snapshot_contract.py')


def operation_root(identity):
    environment = _validate_component(identity['environment_id'])
    operation = _validate_component(identity['operation_id'])
    return '{}/{}/{}'.format(REQUEST_ROOT, environment, operation)


def request_path(request):
    identity = request['handle'] if 'handle' in request else request
    resource = _validate_resource(identity['resource'])
    action = _validate_component(request['action'])
    return '{}/{}-{}-{}.json'.format(operation_root(identity), action,
                                     resource.replace(':', '-'), uuid.uuid4().hex)


class HostTransport:
    def __init__(self, invoke):
        self._invoke = invoke
        self._deployed = set()

    def _call(self, route, module, arguments):
        argv = ['ansible', route['host'], '--inventory', route['inventory'],
                '--become', '-m', 'ansible.builtin.' + module, '-a',
                json.dumps(arguments, sort_keys=True, separators=(',', ':'), allow_nan=False)]
        return self._invoke(argv)

    def invoke_agent(self, route, request):
        identity = request['handle'] if 'handle' in request else request
        root = operation_root(identity)
        key = (route['host'], route['inventory'], root)
        if key not in self._deployed:
            bootstrap = Path(__file__).with_name('host_bootstrap.py').read_text(encoding='utf-8')
            self._call(route, 'command', {'argv': ['python3', '-c', bootstrap, REQUEST_ROOT, root + '/agent/ranking']})
            with tempfile.TemporaryDirectory(prefix='ranking-agent-') as staging:
                package = Path(staging) / 'ranking'
                package.mkdir(mode=0o700)
                for name in AGENT_FILES:
                    copyfile(Path(__file__).parent / name, package / name)
                self._call(route, 'copy', {'src': str(package), 'dest': root + '/agent/',
                                           'mode': '0600', 'directory_mode': '0700'})
            self._deployed.add(key)
        path = request_path(request)
        self._call(route, 'copy', {
            'content': json.dumps(request, sort_keys=True, separators=(',', ':'), allow_nan=False),
            'dest': path, 'mode': '0600'})
        return self._call(route, 'command', {
            'argv': ['python3', root + '/agent/ranking/remote_agent.py', '--request', path],
            'chdir': root})
