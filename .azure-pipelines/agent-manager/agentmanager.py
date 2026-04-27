"""Azure Pipelines agent manager.

Runs as a systemd service on each lab host and supervises a fixed-size
pool of docker-sonic-mgmt containers, each of which registers itself
as an Azure Pipelines self-hosted agent against an AzDevOps pool.

Authentication: AAD access-tokens minted on demand by the
sonic-nightly-service App Service (system-assigned managed identity).
The legacy 7-day PAT-on-disk model has been dropped.
"""

from __future__ import print_function, division

import argparse
import copy
import json
import logging
import os
import signal
import socket
import stat
import sys
import threading
import time
import uuid

from logging.handlers import RotatingFileHandler

import docker
import requests
import yaml


logging.basicConfig(level=logging.INFO)

logger = logging.getLogger('agent-manager')

try:
    rfh = RotatingFileHandler(
        '/tmp/agent-manager.log',
        maxBytes=10 * 1024 * 1024,
        backupCount=15,
    )
    rfh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s #%(lineno)d: %(message)s'))
    rfh.setLevel(logging.INFO)
    logger.addHandler(rfh)
except OSError:
    # Logging dir not available (e.g. running unit tests on Windows). Fall
    # back to console-only logging configured via basicConfig above.
    pass


class TokenServiceError(Exception):
    """Raised when the token service is unreachable or returns an error."""


class TokenProvider(object):
    """In-memory cache for the AAD access-token used to register agents.

    The cache refreshes whenever the cached token would expire within
    SAFETY_MARGIN_SECONDS. The shared secret is read from the loader on
    every refresh so rotation works without restarting agent-manager.
    The token is never written to disk by this class; never logged.
    """

    SAFETY_MARGIN_SECONDS = 300
    DEFAULT_TIMEOUT_SECONDS = 10
    MAX_RETRIES = 3
    BACKOFF_BASE_SECONDS = 2

    def __init__(self, url, secret_loader, http_get=None, proxies=None):
        self._url = url
        self._secret_loader = secret_loader
        self._http_get = http_get if http_get is not None else requests.get
        self._proxies = proxies
        self._token = None
        self._expires_on = 0
        self._lock = threading.Lock()

    def get_token(self):
        with self._lock:
            now = int(time.time())
            if self._token and (self._expires_on - now) > self.SAFETY_MARGIN_SECONDS:
                return self._token
            self._refresh_locked()
            return self._token

    def _refresh_locked(self):
        secret = self._secret_loader()
        if not secret:
            raise TokenServiceError('Empty shared secret')

        last_exc = None
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = self._http_get(
                    self._url,
                    headers={'Authorization': 'Bearer ' + secret},
                    timeout=self.DEFAULT_TIMEOUT_SECONDS,
                    proxies=self._proxies,
                )
                if resp.status_code != 200:
                    raise TokenServiceError(
                        'Token service returned HTTP {}'.format(resp.status_code))
                data = resp.json()
                self._token = data['access_token']
                self._expires_on = int(data['expires_on'])
                logger.info(
                    'Refreshed access-token; valid for %d seconds',
                    self._expires_on - int(time.time()),
                )
                return
            except (requests.RequestException, ValueError, KeyError, TokenServiceError) as e:
                last_exc = e
                if attempt + 1 < self.MAX_RETRIES:
                    sleep_s = self.BACKOFF_BASE_SECONDS ** attempt
                    logger.warning(
                        'Token fetch attempt %d/%d failed (%s); retrying in %ds',
                        attempt + 1, self.MAX_RETRIES, type(e).__name__, sleep_s,
                    )
                    time.sleep(sleep_s)

        raise TokenServiceError(
            'Token fetch failed after {} attempts: {}'.format(self.MAX_RETRIES, repr(last_exc)))


class AgentManager(object):

    CHECK_INTERVAL = 60

    LABEL_MANAGED = 'com.sonic.agent-manager.managed'
    LABEL_POOL = 'com.sonic.agent-manager.pool'
    LABEL_SLOT = 'com.sonic.agent-manager.slot'

    def __init__(self, conf):
        self.client = docker.from_env()
        self.config_path = conf
        self._pending_reload = False
        self.token_provider = None
        self.load_config(conf=conf)
        self.validate()
        self._build_token_provider()

    # ------------------------------------------------------------------
    # config
    # ------------------------------------------------------------------

    def sighup_handler(self, sig, frame):
        # Atomic: only set a flag. The main loop applies the reload
        # at a safe boundary so respawn() never sees a half-updated config.
        logger.info('Received signal %s; reload pending', sig)
        self._pending_reload = True

    def reload_config(self, conf):
        logger.info('Reloading configuration %s', conf)
        config_backup = copy.deepcopy(self.config)
        token_provider_backup = self.token_provider
        if self._load_config(conf) is False or self._validate() is False:
            logger.error('Error reloading config; reverting')
            self.config = config_backup
            self.token_provider = token_provider_backup
            return False
        self._build_token_provider()
        return True

    def load_config(self, conf):
        if self._load_config(conf) is False:
            sys.exit(20)

    def _load_config(self, conf):
        # Defaults.
        self.config = {
            'image': {
                'name': 'sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt',
                'tag': 'latest',
            },
            'azp': {
                'url': None,
                'pool': None,
                'token_service': {
                    'url': None,
                    'secret': None,
                    'secret_file': None,
                },
            },
            'proxy': {
                'http': None,
                'https': None,
            },
            'agent': {
                'count': 10,
                'name': 'azp-agent',
            },
        }

        try:
            with open(conf) as f:
                raw_config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.error('Unable to find configuration file %s', conf)
            return False

        if 'image' in raw_config:
            if 'name' in raw_config['image']:
                self.config['image']['name'] = raw_config['image']['name']
            if 'tag' in raw_config['image']:
                self.config['image']['tag'] = raw_config['image']['tag']

        if 'azp' not in raw_config:
            logger.error('Missing mandatory "azp" configuration in conf file')
            return False
        for key in ('url', 'pool'):
            if key not in raw_config['azp'] or not raw_config['azp'][key]:
                logger.error('Missing mandatory "azp.%s" configuration in conf file', key)
                return False
            self.config['azp'][key] = raw_config['azp'][key]

        ts_raw = raw_config['azp'].get('token_service')
        if not ts_raw or not ts_raw.get('url'):
            logger.error('Missing mandatory "azp.token_service.url" configuration')
            return False
        self.config['azp']['token_service']['url'] = ts_raw['url']

        secret = ts_raw.get('secret')
        secret_file = ts_raw.get('secret_file')
        if bool(secret) == bool(secret_file):
            logger.error(
                'azp.token_service must specify exactly one of "secret" or "secret_file"')
            return False
        self.config['azp']['token_service']['secret'] = secret
        self.config['azp']['token_service']['secret_file'] = secret_file

        if secret_file:
            try:
                st = os.stat(secret_file)
            except OSError as e:
                logger.error('Cannot stat secret_file %s: %s', secret_file, e)
                return False
            # Refuse world-readable secret files. Owner-readable (0400) and
            # owner-rw (0600) are fine.
            if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                logger.error(
                    'secret_file %s mode 0%o is too permissive (must be 0600 or stricter)',
                    secret_file, st.st_mode & 0o777,
                )
                return False

        if 'proxy' in raw_config:
            for key in ('http', 'https'):
                if key in raw_config['proxy']:
                    self.config['proxy'][key] = raw_config['proxy'][key]

        if 'agent' in raw_config:
            if 'count' in raw_config['agent']:
                try:
                    self.config['agent']['count'] = int(raw_config['agent']['count'])
                except (ValueError, TypeError) as e:
                    logger.error(
                        'Config agent.count "%s" cannot be converted to integer: %s',
                        raw_config['agent']['count'], repr(e),
                    )
                    return False
            if 'name' in raw_config['agent']:
                self.config['agent']['name'] = raw_config['agent']['name']

        return True

    def validate(self):
        if self._validate() is False:
            sys.exit(30)

    def _validate(self):
        try:
            reference = self.config['image']['name'] + ':' + self.config['image']['tag']
            images = self.client.images.list(filters={'reference': reference})
            if len(images) != 1:
                logger.error('Unable to find image %s', reference)
                return False
            self.config['image']['id'] = images[0].id
        except docker.errors.APIError as e:
            logger.error('Possibly docker service down: %s', repr(e))
            return False
        return True

    def _secret_loader(self):
        ts = self.config['azp']['token_service']
        if ts['secret']:
            return ts['secret']
        with open(ts['secret_file'], 'r') as f:
            return f.read().strip()

    def _build_token_provider(self):
        url = self.config['azp']['token_service']['url']
        proxies = None
        p = self.config.get('proxy', {}) or {}
        if p.get('http') or p.get('https'):
            proxies = {}
            if p.get('http'):
                proxies['http'] = p['http']
            if p.get('https'):
                proxies['https'] = p['https']
        self.token_provider = TokenProvider(
            url, self._secret_loader, proxies=proxies)

    # ------------------------------------------------------------------
    # container ownership and classification
    # ------------------------------------------------------------------

    def list_of_agent_containers(self):
        """All containers managed by us.

        Returns the union of:
        * containers with the docker label `com.sonic.agent-manager.managed=true`
          (the canonical ownership marker);
        * any extra containers whose name starts with `agent.name` and that do
          not yet carry the label.

        The second set covers two scenarios:
        * first-time cutover from the legacy agent-manager (existing containers
          were not labeled);
        * busy legacy containers that were skipped on the initial drain — we
          must keep seeing them across subsequent reconcile cycles so we can
          drain them as soon as they go idle.
        """
        labeled = self.client.containers.list(
            all=True,
            ignore_removed=True,
            filters={'label': '{}=true'.format(self.LABEL_MANAGED)},
        )
        labeled_ids = {c.id for c in labeled}
        prefix = self.config['agent']['name']
        legacy = [
            c for c in self.client.containers.list(all=True, ignore_removed=True)
            if c.id not in labeled_ids and c.name.startswith(prefix)
        ]
        return labeled + legacy

    def get_agent_containers(self):
        """Split managed containers into (old, current) by image-id."""
        desired_id = self.config['image']['id']
        old_agents, current_agents = [], []
        for c in self.list_of_agent_containers():
            cid = c.attrs.get('Image') if hasattr(c, 'attrs') else None
            if cid == desired_id:
                current_agents.append(c)
            else:
                old_agents.append(c)
        return old_agents, current_agents

    def _used_slots(self, containers):
        slots = set()
        for c in containers:
            try:
                labels = c.labels or {}
            except AttributeError:
                labels = {}
            try:
                s = int(labels.get(self.LABEL_SLOT, 0))
                if 1 <= s <= self.config['agent']['count']:
                    slots.add(s)
            except (ValueError, TypeError):
                continue
        return slots

    # ------------------------------------------------------------------
    # container start
    # ------------------------------------------------------------------

    def start_containers(self, num=0):
        if num <= 0:
            return []

        logger.info('Need to start %d new container(s)', num)

        # Fetch token first; without it there's no point starting anything.
        try:
            token = self.token_provider.get_token()
        except TokenServiceError as e:
            logger.error('Skipping container start: token fetch failed: %s', repr(e))
            return []

        # Allocate stable slot numbers so AzDevOps agent rows are bounded by
        # `agent.count` and `--replace` collapses stale entries on restart.
        used = self._used_slots(self.list_of_agent_containers())
        free = [s for s in range(1, self.config['agent']['count'] + 1) if s not in used]
        slots_to_use = free[:num]
        if len(slots_to_use) < num:
            logger.warning(
                'Only %d free slot(s) available for %d requested starts',
                len(slots_to_use), num,
            )

        env = {
            'AZP_URL': self.config['azp']['url'],
            'AZP_POOL': self.config['azp']['pool'],
            'AZP_TOKEN': token,
            'AZP_WORK': '_work',
            # docker-sonic-mgmt /azp/start.sh queries the AzDevOps agent
            # package URL with `?platform=$TARGETARCH`. TARGETARCH is a
            # docker-buildkit build-time variable and is unset at runtime,
            # so without this AzDevOps returns the first package which is
            # the macOS one (Mach-O), giving "Exec format error".
            'TARGETARCH': 'linux-x64',
        }
        if self.config['proxy']['http']:
            env['http_proxy'] = self.config['proxy']['http']
        if self.config['proxy']['https']:
            env['https_proxy'] = self.config['proxy']['https']

        full_image = self.config['image']['name'] + ':' + self.config['image']['tag']
        host = socket.gethostname()
        started = []
        for slot in slots_to_use:
            agent_name = '{}-{}-{:02d}'.format(
                self.config['agent']['name'], host, slot)
            container_name = '{}-{:02d}-{}'.format(
                self.config['agent']['name'], slot, uuid.uuid4().hex[:8])
            slot_env = dict(env)
            slot_env['AZP_AGENT_NAME'] = agent_name
            labels = {
                self.LABEL_MANAGED: 'true',
                self.LABEL_POOL: self.config['azp']['pool'],
                self.LABEL_SLOT: str(slot),
            }
            try:
                c = self.client.containers.run(
                    full_image,
                    detach=True,
                    environment=slot_env,
                    name=container_name,
                    command=['/azp/start.sh'],
                    working_dir='/azp',
                    labels=labels,
                    tty=True,
                )
            except docker.errors.APIError as e:
                logger.error(
                    'Failed to start container for slot %d: %s', slot, repr(e))
                continue
            logger.info(
                'Started slot %d, container=%s, name=%s, agent=%s',
                slot, c.short_id, c.name, agent_name,
            )
            started.append(c.id)

        logger.info('Started %d new container(s): %s', len(started), json.dumps(started))
        return started

    # ------------------------------------------------------------------
    # container removal
    # ------------------------------------------------------------------

    def check_is_busy(self, container):
        return container.exec_run('pgrep -af "Agent.Worker"').exit_code == 0

    def _stop_then_remove(self, c, timeout=30):
        """Stop a running container so its in-container SIGTERM trap can
        deregister the agent from the AzDevOps pool, then remove it.
        Falls back to force-remove on error so we never leak a container."""
        try:
            if c.status == 'running':
                c.stop(timeout=timeout)
            c.remove()
        except docker.errors.APIError as e:
            logger.warning('Graceful stop of %s failed (%s); forcing', c.short_id, e)
            c.remove(force=True)

    def remove_n_containers(self, containers, n, is_running, force=False):
        removed = []
        c = None
        try:
            for c in containers:
                if len(removed) >= n:
                    break
                if is_running:
                    if c.status != 'running':
                        continue
                    is_busy = self.check_is_busy(c)
                    if is_busy and not force:
                        continue
                    self._stop_then_remove(c)
                    logger.info('Removed container %s with status %s', c.short_id, c.status)
                    removed.append(c.id)
                else:
                    if c.status != 'running':
                        self._stop_then_remove(c)
                        logger.info('Removed container %s with status %s', c.short_id, c.status)
                        removed.append(c.id)
        except docker.errors.APIError as e:
            cid = c.short_id if c is not None else '?'
            logger.error('Error removing container %s: %s', cid, repr(e))
        if removed:
            logger.info('Removed containers: %s', json.dumps(removed))
        return removed

    def remove_healthy_containers(self, containers):
        return self.remove_n_containers(containers, n=len(containers), is_running=True)

    def remove_unhealthy_containers(self, containers):
        return self.remove_n_containers(containers, n=len(containers), is_running=False)

    def prune_containers(self, n, containers):
        return self.remove_n_containers(containers, n, is_running=True)

    # ------------------------------------------------------------------
    # main reconcile
    # ------------------------------------------------------------------

    def respawn(self):
        n_started = 0
        n_pruned = 0
        n_updated = 0

        old_agents, current_agents = self.get_agent_containers()
        all_agents = old_agents + current_agents
        logger.info('Running a total of %d agents', len(all_agents))
        unhealthy_agents = [c for c in all_agents if c.status != 'running']
        logger.info('Found %d unhealthy agents', len(unhealthy_agents))
        removed_count = 0

        if unhealthy_agents:
            removed = self.remove_unhealthy_containers(unhealthy_agents)
            removed_count += len(removed)
            unhealthy_agents = [c for c in unhealthy_agents if c.id not in removed]
            old_agents = [c for c in old_agents if c.id not in {x.id for x in unhealthy_agents}
                          and c.id not in removed]
            current_agents = [c for c in current_agents if c.id not in {x.id for x in unhealthy_agents}
                              and c.id not in removed]

        # discard the unhealthy ones we couldn't remove; they will be retried next cycle
        old_agents = [c for c in old_agents if c.status == 'running']
        current_agents = [c for c in current_agents if c.status == 'running']
        logger.info(
            'Post cleanup: %d healthy agents (old=%d, current=%d)',
            len(old_agents) + len(current_agents), len(old_agents), len(current_agents),
        )

        busy_agents = []
        if old_agents:
            removed = self.remove_healthy_containers(old_agents)
            removed_count += len(removed)
            n_updated += len(removed)
            old_agents = [c for c in old_agents if c.id not in removed]
            busy_agents += old_agents

        # Current-image agents are always counted as filled capacity. We no
        # longer recycle them on token refresh — the agent maintains its own
        # auth with AzDevOps after registration.
        busy_agents += current_agents

        target = self.config['agent']['count']
        if len(busy_agents) == target:
            logger.info('Running expected %d healthy agents. OK', target)
        elif len(busy_agents) > target:
            n_more = len(busy_agents) - target
            if old_agents:
                # Don't prune anything while we still have busy old-image
                # agents waiting to finish their jobs — those drains will
                # bring us back under target on their own. Pruning here
                # would kill fresh current-image agents that we will only
                # need to recreate on the next cycle.
                logger.info(
                    'Healthy agents (%d) > target (%d) but %d busy old '
                    'agent(s) still draining; deferring prune',
                    len(busy_agents), target, len(old_agents),
                )
            else:
                logger.info('Healthy agents (%d) > target (%d); pruning %d',
                            len(busy_agents), target, n_more)
                pruned = self.prune_containers(n_more, busy_agents)
                n_pruned = len(pruned)
        else:
            n = target - len(busy_agents)
            started = self.start_containers(n)
            n_started = len(started)

        return n_started, n_updated, removed_count, n_pruned

    def run(self):
        signal.signal(signal.SIGHUP, self.sighup_handler)
        while True:
            try:
                if self._pending_reload:
                    self._pending_reload = False
                    self.reload_config(self.config_path)
                self.client.ping()
                self.respawn()
            except Exception as e:
                logger.exception('Unexpected exception in run loop: %s', repr(e))
            logger.info('Sleeping %d seconds to check again', self.CHECK_INTERVAL)
            time.sleep(self.CHECK_INTERVAL)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Azure Pipeline Agent Manager')
    parser.add_argument(
        '-f', '--conf',
        type=str,
        dest='conf',
        required=False,
        default='/etc/agent-manager.conf',
        help='Configuration file.')

    args = parser.parse_args()
    mgr = AgentManager(conf=args.conf)
    mgr.run()
