"""Unit tests for agentmanager.

Covers the new AAD-token-service flow that replaces the legacy PAT-refresh
mechanism. Uses pyfakefs for the conf/secret files and unittest.mock for
the docker client and HTTP layer.
"""

import stat
import time
import unittest
import uuid
from unittest.mock import MagicMock, patch

from pyfakefs.fake_filesystem_unittest import TestCase

import agentmanager


CONF_PATH = '/etc/agent-manager.conf'
SECRET_PATH = '/etc/agent-manager.secret'

VALID_CONF = """
image:
    name: sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt
    tag: 2026.04.x-pinned
azp:
    url: "https://dev.azure.com/mssonic"
    pool: "nightly"
    token_service:
        url: "https://sonic-nightly-service.azurewebsites.net/token"
        secret_file: "/etc/agent-manager.secret"
proxy:
    http: "http://10.201.148.40:8080"
    https: "http://10.201.148.40:8080"
agent:
    count: 5
    name: azp-agent
"""


class _FakeImage(object):
    def __init__(self, image_id):
        self.id = image_id
        self.tags = []


class _FakeContainer(object):
    """Minimal mock matching the docker.Container surface we touch."""

    def __init__(self, image_id, status='running', busy=False, slot=None,
                 name=None, managed=True):
        self.attrs = {'Image': image_id}
        self.status = status
        self.busy = busy
        self.short_id = uuid.uuid4().hex[:12]
        self.id = 'sha256:' + uuid.uuid4().hex
        self.name = name or 'azp-agent-{:02d}-{}'.format(slot or 0, uuid.uuid4().hex[:8])
        self.labels = {}
        if managed:
            self.labels[agentmanager.AgentManager.LABEL_MANAGED] = 'true'
        if slot is not None:
            self.labels[agentmanager.AgentManager.LABEL_SLOT] = str(slot)
        self.removed = False

    def remove(self, force=False):
        self.removed = True

    def stop(self, timeout=None):
        self.stopped = True
        self.stop_timeout = timeout
        self.status = 'exited'

    def exec_run(self, cmd):
        rv = MagicMock()
        rv.exit_code = 0 if self.busy else 1
        return rv


class _FakeDockerClient(object):
    def __init__(self, image_id='sha256:current', containers=None):
        self.image_id = image_id
        self._containers = containers or []
        self.images = MagicMock()
        self.images.list.return_value = [_FakeImage(image_id)]
        self.images.get.return_value = _FakeImage(image_id)
        self.containers = MagicMock()
        self.containers.list = self._list_containers
        self.containers.run = MagicMock(return_value=MagicMock(
            id='sha256:' + uuid.uuid4().hex, short_id='new1234', name='new-container'))

    def _list_containers(self, all=False, filters=None, ignore_removed=False):
        if filters and 'label' in filters:
            label = filters['label']
            key, _, val = label.partition('=')
            return [c for c in self._containers if c.labels.get(key) == val]
        return list(self._containers)

    def ping(self):
        return True


def _setup_fs(self, secret_value='test-secret-value', secret_mode=0o600):
    """Set up the fake filesystem with a conf and a secret file.

    `self` is the pyfakefs TestCase instance; we use `self.fs.create_file`
    so st_mode is set explicitly (pyfakefs's os.chmod is unreliable on
    Windows hosts where it keeps the default 0o666).
    """
    self.fs.create_file(CONF_PATH, contents=VALID_CONF)
    self.fs.create_file(
        SECRET_PATH,
        contents=secret_value + '\n',
        st_mode=stat.S_IFREG | secret_mode,
    )


class TestTokenProvider(unittest.TestCase):

    def _make_response(self, status=200, payload=None):
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = payload or {
            'access_token': 'tok-abc',
            'expires_on': int(time.time()) + 3600,
        }
        return resp

    def test_first_call_fetches(self):
        http = MagicMock(return_value=self._make_response())
        tp = agentmanager.TokenProvider(
            url='https://x/token', secret_loader=lambda: 'sec', http_get=http)
        self.assertEqual(tp.get_token(), 'tok-abc')
        self.assertEqual(http.call_count, 1)
        # Authorization header sent as Bearer secret
        self.assertEqual(
            http.call_args[1]['headers']['Authorization'], 'Bearer sec')

    def test_second_call_uses_cache(self):
        http = MagicMock(return_value=self._make_response())
        tp = agentmanager.TokenProvider(
            url='https://x/token', secret_loader=lambda: 'sec', http_get=http)
        tp.get_token()
        tp.get_token()
        self.assertEqual(http.call_count, 1)

    def test_refresh_when_near_expiry(self):
        # First fetch: token expires in 100 seconds, well under 300s safety margin.
        near_exp = self._make_response(payload={
            'access_token': 'tok-1', 'expires_on': int(time.time()) + 100,
        })
        far_exp = self._make_response(payload={
            'access_token': 'tok-2', 'expires_on': int(time.time()) + 3600,
        })
        http = MagicMock(side_effect=[near_exp, far_exp])
        tp = agentmanager.TokenProvider(
            url='https://x/token', secret_loader=lambda: 'sec', http_get=http)
        self.assertEqual(tp.get_token(), 'tok-1')
        self.assertEqual(tp.get_token(), 'tok-2')
        self.assertEqual(http.call_count, 2)

    def test_http_error_raises_after_retries(self):
        resp = MagicMock()
        resp.status_code = 401
        http = MagicMock(return_value=resp)
        tp = agentmanager.TokenProvider(
            url='https://x/token', secret_loader=lambda: 'sec', http_get=http)
        # No actual sleeping
        with patch('agentmanager.time.sleep'):
            with self.assertRaises(agentmanager.TokenServiceError):
                tp.get_token()
        self.assertEqual(http.call_count, agentmanager.TokenProvider.MAX_RETRIES)

    def test_empty_secret_raises_immediately(self):
        http = MagicMock()
        tp = agentmanager.TokenProvider(
            url='https://x/token', secret_loader=lambda: '', http_get=http)
        with self.assertRaises(agentmanager.TokenServiceError):
            tp.get_token()
        http.assert_not_called()

    def test_secret_reread_on_each_refresh(self):
        # Simulates dual-secret rotation: secret_loader changes between fetches.
        secrets = iter(['sec1', 'sec2'])
        http = MagicMock(return_value=self._make_response(payload={
            'access_token': 'tok', 'expires_on': int(time.time()) + 100,
        }))
        tp = agentmanager.TokenProvider(
            url='https://x/token',
            secret_loader=lambda: next(secrets),
            http_get=http,
        )
        tp.get_token()
        tp.get_token()
        self.assertEqual(http.call_args_list[0][1]['headers']['Authorization'], 'Bearer sec1')
        self.assertEqual(http.call_args_list[1][1]['headers']['Authorization'], 'Bearer sec2')


class TestConfigLoad(TestCase):

    def setUp(self):
        self.setUpPyfakefs()
        _setup_fs(self)

    def _build_mgr(self):
        with patch('agentmanager.docker.from_env') as df:
            df.return_value = _FakeDockerClient()
            return agentmanager.AgentManager(conf=CONF_PATH)

    def test_valid_conf_loads(self):
        mgr = self._build_mgr()
        self.assertEqual(mgr.config['azp']['pool'], 'nightly')
        self.assertEqual(mgr.config['agent']['count'], 5)
        self.assertEqual(
            mgr.config['azp']['token_service']['url'],
            'https://sonic-nightly-service.azurewebsites.net/token',
        )
        self.assertEqual(
            mgr.config['azp']['token_service']['secret_file'], SECRET_PATH)
        # No legacy 'token' key
        self.assertNotIn('token', mgr.config['azp'])

    def test_missing_token_service_url_fails(self):
        with open(CONF_PATH, 'w') as f:
            f.write(VALID_CONF.replace(
                'url: "https://sonic-nightly-service.azurewebsites.net/token"',
                ''))
        with patch('agentmanager.docker.from_env') as df:
            df.return_value = _FakeDockerClient()
            with self.assertRaises(SystemExit):
                agentmanager.AgentManager(conf=CONF_PATH)

    def test_both_secret_and_secret_file_fails(self):
        bad = VALID_CONF.replace(
            'secret_file: "/etc/agent-manager.secret"',
            'secret_file: "/etc/agent-manager.secret"\n        secret: "inline"',
        )
        with open(CONF_PATH, 'w') as f:
            f.write(bad)
        with patch('agentmanager.docker.from_env') as df:
            df.return_value = _FakeDockerClient()
            with self.assertRaises(SystemExit):
                agentmanager.AgentManager(conf=CONF_PATH)

    def test_neither_secret_nor_secret_file_fails(self):
        bad = VALID_CONF.replace(
            'secret_file: "/etc/agent-manager.secret"', '')
        with open(CONF_PATH, 'w') as f:
            f.write(bad)
        with patch('agentmanager.docker.from_env') as df:
            df.return_value = _FakeDockerClient()
            with self.assertRaises(SystemExit):
                agentmanager.AgentManager(conf=CONF_PATH)

    def test_world_readable_secret_file_rejected(self):
        # Recreate the secret with world-readable mode (0o644). pyfakefs's
        # os.chmod is a no-op on Windows, so use create_file with explicit
        # st_mode after removing the existing one.
        self.fs.remove(SECRET_PATH)
        self.fs.create_file(
            SECRET_PATH, contents='x', st_mode=stat.S_IFREG | 0o644)
        with patch('agentmanager.docker.from_env') as df:
            df.return_value = _FakeDockerClient()
            with self.assertRaises(SystemExit):
                agentmanager.AgentManager(conf=CONF_PATH)

    def test_inline_secret_works(self):
        inline_conf = VALID_CONF.replace(
            'secret_file: "/etc/agent-manager.secret"',
            'secret: "inline-secret-value"',
        )
        with open(CONF_PATH, 'w') as f:
            f.write(inline_conf)
        with patch('agentmanager.docker.from_env') as df:
            df.return_value = _FakeDockerClient()
            mgr = agentmanager.AgentManager(conf=CONF_PATH)
        self.assertEqual(mgr._secret_loader(), 'inline-secret-value')

    def test_secret_file_loader_strips(self):
        mgr = self._build_mgr()
        self.assertEqual(mgr._secret_loader(), 'test-secret-value')


class TestImageClassification(TestCase):

    def setUp(self):
        self.setUpPyfakefs()
        _setup_fs(self)

    def _mgr_with_containers(self, image_id, containers):
        client = _FakeDockerClient(image_id=image_id, containers=containers)
        with patch('agentmanager.docker.from_env', return_value=client):
            mgr = agentmanager.AgentManager(conf=CONF_PATH)
        # AgentManager stashes the image-id on validate(); confirm it.
        return mgr, client

    def test_split_by_image_id(self):
        current_id = 'sha256:NEW'
        mgr, _ = self._mgr_with_containers(current_id, [
            _FakeContainer(image_id='sha256:OLD', slot=1),
            _FakeContainer(image_id=current_id, slot=2),
            _FakeContainer(image_id=current_id, slot=3),
        ])
        old, curr = mgr.get_agent_containers()
        self.assertEqual(len(old), 1)
        self.assertEqual(len(curr), 2)

    def test_name_prefix_treated_as_strong_namespace_claim(self):
        # The agent.name prefix is a strong namespace marker: any container
        # starting with it is treated as ours, labeled or not. This is
        # required so that legacy/orphan containers that survived the
        # initial drain (because they were busy) keep being tracked across
        # subsequent reconcile cycles, not just on the very first one.
        client = _FakeDockerClient(image_id='sha256:NEW', containers=[
            _FakeContainer(image_id='sha256:OLD', slot=1),
            _FakeContainer(image_id='sha256:OLD',
                           name='azp-agent-orphan', managed=False),
        ])
        # A container that doesn't share the prefix must still be ignored.
        client._containers.append(
            _FakeContainer(image_id='sha256:UNRELATED',
                           name='unrelated-svc', managed=False))
        with patch('agentmanager.docker.from_env', return_value=client):
            mgr = agentmanager.AgentManager(conf=CONF_PATH)
        listed = mgr.list_of_agent_containers()
        self.assertEqual(len(listed), 2)
        self.assertNotIn('unrelated-svc', [c.name for c in listed])

    def test_no_labeled_falls_back_to_name_prefix(self):
        # No managed=true containers; the legacy fallback should kick in
        # so we don't lose track during the rollout.
        client = _FakeDockerClient(image_id='sha256:NEW', containers=[
            _FakeContainer(image_id='sha256:OLD', name='azp-agent-legacy',
                           managed=False),
            _FakeContainer(image_id='sha256:OLD', name='unrelated',
                           managed=False),
        ])
        with patch('agentmanager.docker.from_env', return_value=client):
            mgr = agentmanager.AgentManager(conf=CONF_PATH)
        listed = mgr.list_of_agent_containers()
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0].name, 'azp-agent-legacy')


class TestStartContainers(TestCase):

    def setUp(self):
        self.setUpPyfakefs()
        _setup_fs(self)

    def _build(self, containers=None, http_payload=None, http_status=200):
        client = _FakeDockerClient(image_id='sha256:NEW',
                                   containers=containers or [])
        with patch('agentmanager.docker.from_env', return_value=client):
            mgr = agentmanager.AgentManager(conf=CONF_PATH)
        # Replace the token provider with a stub fed by our fake HTTP.
        resp = MagicMock()
        resp.status_code = http_status
        resp.json.return_value = http_payload or {
            'access_token': 'tok-fresh',
            'expires_on': int(time.time()) + 3600,
        }
        http = MagicMock(return_value=resp)
        mgr.token_provider = agentmanager.TokenProvider(
            url='https://x/token',
            secret_loader=lambda: 'sec',
            http_get=http,
        )
        return mgr, client

    def test_starts_with_aad_env_and_labels(self):
        mgr, client = self._build()
        started = mgr.start_containers(num=2)
        self.assertEqual(len(started), 2)
        self.assertEqual(client.containers.run.call_count, 2)

        first_call = client.containers.run.call_args_list[0]
        env = first_call[1]['environment']
        self.assertEqual(env['AZP_TOKEN'], 'tok-fresh')
        self.assertEqual(env['AZP_URL'], 'https://dev.azure.com/mssonic')
        self.assertEqual(env['AZP_POOL'], 'nightly')
        self.assertEqual(env['AZP_WORK'], '_work')
        self.assertIn('AZP_AGENT_NAME', env)
        self.assertIn('http_proxy', env)
        self.assertEqual(first_call[1]['command'], ['/azp/start.sh'])
        self.assertEqual(first_call[1]['working_dir'], '/azp')

        labels = first_call[1]['labels']
        self.assertEqual(labels[mgr.LABEL_MANAGED], 'true')
        self.assertEqual(labels[mgr.LABEL_POOL], 'nightly')
        self.assertIn(mgr.LABEL_SLOT, labels)

    def test_skips_when_token_fetch_fails(self):
        mgr, client = self._build(http_status=503)
        with patch('agentmanager.time.sleep'):  # don't sleep on retry
            started = mgr.start_containers(num=3)
        self.assertEqual(started, [])
        client.containers.run.assert_not_called()

    def test_allocates_free_slots(self):
        # Slots 1 and 3 are taken; only 2, 4, 5 are free.
        existing = [
            _FakeContainer(image_id='sha256:NEW', slot=1),
            _FakeContainer(image_id='sha256:NEW', slot=3),
        ]
        mgr, client = self._build(containers=existing)
        mgr.start_containers(num=2)
        slots_started = [
            int(call[1]['labels'][mgr.LABEL_SLOT])
            for call in client.containers.run.call_args_list
        ]
        self.assertEqual(sorted(slots_started), [2, 4])

    def test_request_more_than_free_slots(self):
        # 4 of 5 slots taken; asking for 3 starts only 1.
        existing = [
            _FakeContainer(image_id='sha256:NEW', slot=s) for s in (1, 2, 3, 4)
        ]
        mgr, client = self._build(containers=existing)
        mgr.start_containers(num=3)
        self.assertEqual(client.containers.run.call_count, 1)
        self.assertEqual(
            client.containers.run.call_args_list[0][1]['labels'][mgr.LABEL_SLOT],
            '5',
        )


class TestGracefulStop(TestCase):

    def setUp(self):
        self.setUpPyfakefs()
        _setup_fs(self)

    def test_running_container_is_stopped_then_removed(self):
        # Idle running old container -> SIGTERM via stop() (so the
        # in-container trap can deregister the agent), then remove().
        c = _FakeContainer(image_id='sha256:OLD', slot=1)
        client = _FakeDockerClient(image_id='sha256:NEW', containers=[c])
        with patch('agentmanager.docker.from_env', return_value=client):
            mgr = agentmanager.AgentManager(conf=CONF_PATH)
        mgr.remove_healthy_containers([c])
        self.assertTrue(getattr(c, 'stopped', False),
                        'running container must be stopped() before removal')
        self.assertTrue(c.removed)

    def test_force_remove_used_when_graceful_stop_fails(self):
        # If stop() raises an APIError, fall back to remove(force=True)
        # so we never leak a container.
        c = _FakeContainer(image_id='sha256:OLD', slot=1)
        force_calls = []
        original_remove = c.remove

        def remove(force=False):
            force_calls.append(force)
            original_remove(force=force)
        c.remove = remove
        c.stop = MagicMock(
            side_effect=agentmanager.docker.errors.APIError('stop failed'))
        client = _FakeDockerClient(image_id='sha256:NEW', containers=[c])
        with patch('agentmanager.docker.from_env', return_value=client):
            mgr = agentmanager.AgentManager(conf=CONF_PATH)
        mgr.remove_healthy_containers([c])
        self.assertTrue(c.removed)
        self.assertIn(True, force_calls,
                      'fallback path must call remove(force=True)')

    def test_exited_container_skips_stop(self):
        # Already-exited containers (status != 'running') should be
        # removed but not stopped first.
        c = _FakeContainer(image_id='sha256:OLD', slot=1, status='exited')
        client = _FakeDockerClient(image_id='sha256:NEW', containers=[c])
        with patch('agentmanager.docker.from_env', return_value=client):
            mgr = agentmanager.AgentManager(conf=CONF_PATH)
        mgr.remove_unhealthy_containers([c])
        self.assertFalse(getattr(c, 'stopped', False),
                         'already-exited containers must not be re-stopped')
        self.assertTrue(c.removed)


class TestSighup(TestCase):

    def setUp(self):
        self.setUpPyfakefs()
        _setup_fs(self)

    def test_sighup_only_sets_pending_flag(self):
        with patch('agentmanager.docker.from_env', return_value=_FakeDockerClient()):
            mgr = agentmanager.AgentManager(conf=CONF_PATH)
        self.assertFalse(mgr._pending_reload)
        original_pool = mgr.config['azp']['pool']
        mgr.sighup_handler(1, None)
        # Config must NOT have been touched yet
        self.assertEqual(mgr.config['azp']['pool'], original_pool)
        self.assertTrue(mgr._pending_reload)


if __name__ == '__main__':
    unittest.main()
