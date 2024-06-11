from __future__ import print_function, division

import argparse
import copy
import json
import logging
import pathlib
import signal
import sys
import time
import uuid
import yaml

from logging.handlers import RotatingFileHandler

import docker


rfh = RotatingFileHandler(
    '/tmp/agent-manager.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=15
)
rfh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s #%(lineno)d: %(message)s'))
rfh.setLevel(logging.INFO)

logging.basicConfig(
    level=logging.INFO,
)

logger = logging.getLogger('agent-manager')
logger.addHandler(rfh)

# str_presenter renders one line string with quotes
# and multi-line strings with yaml style |. This is
# used for saving yaml config
def str_presenter(dumper, data):
    if len(data.splitlines()) > 1:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='"')


class AgentManager(object):

    CHECK_INTERVAL = 60
    PAT_FILE_PATH = "/tmp/.__az_pat.tok"

    def __init__(self, conf):
        self.client = docker.from_env()
        self.config_path = conf
        self.load_config(conf=conf)
        self.validate()

    # signal handler for SIGHUP to reload the configuration file
    def sighup_handler(self, sig, frame):
        logger.info("Received signal {}; Reloading configuration".format(sig))
        self.reload_config(self.config_path)

    def reload_config(self, conf):
        logger.info('Reloading configuration {}'.format(conf))
        config_backup = copy.deepcopy(self.config)
        if self._load_config(conf) is False or self._validate() is False:
            logger.error('Error reloading config. Ensure configuration file has no errors')
            self.config = config_backup
            return False
        return True

    def load_config(self, conf):
        if self._load_config(conf) is False:
            sys.exit(20)

    def _load_config(self, conf):
        # Init default config
        self.config = {
            'image': {
                'name': 'dockeragent',
                'tag': 'latest'
            },
            'azp': {
                'url': None,
                'pool': None,
                'token': None
            },
            'proxy': {
                'http': None,
                'https': None
            },
            'agent': {
                'count': 10,
                'name': 'azp-agent'
            }
        }

        # Load configuration file
        try:
            with open(conf) as f:
                raw_config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.error('Unable to find configuration file {}'.format(conf))
            return False

        # Update default config with content from configuration file
        if 'image' in raw_config:
            if 'name' in raw_config['image']:
                self.config['image']['name'] = raw_config['image']['name']
            if 'tag' in raw_config['image']:
                self.config['image']['tag'] = raw_config['image']['tag']

        if 'azp' not in raw_config:
            logger.error('Missing mandatory "azp" configuration in conf file')
            return False

        if 'url' not in raw_config['azp']:
            logger.error('Missing mandatory "azp.url" configuration in conf file')
            return False

        if 'pool' not in raw_config['azp']:
            logger.error('Missing mandatory "azp.pool" configuration in conf file')
            return False

        if 'token' not in raw_config['azp']:
            logger.error('Missing mandatory "azp.token" configuration in conf file')
            return False

        self.config['azp']['url'] = raw_config['azp']['url']
        self.config['azp']['pool'] = raw_config['azp']['pool']
        self.config['azp']['token'] = raw_config['azp']['token']

        if 'proxy' in raw_config:
            if 'http' in raw_config['proxy']:
                self.config['proxy']['http'] = raw_config['proxy']['http']
            if 'https' in raw_config['proxy']:
                self.config['proxy']['https'] = raw_config['proxy']['https']

        if 'agent' in raw_config:
            if 'count' in raw_config['agent']:
                try:
                    count = raw_config['agent']['count']
                    self.config['agent']['count'] = int(count)
                except ValueError as e:
                    logger.error('Config agent.count "{}" cannot be converted to integer: {}'.format(count, repr(e)))
                    return False
            if 'name' in raw_config['agent']:
                self.config['agent']['name'] = raw_config['agent']['name']
        return True

    def save_config(self):
        yaml.add_representer(str, str_presenter) # type: ignore
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f, indent=4)

    def validate(self):
        if self._validate() is False:
            sys.exit(30)

    def _validate(self):
        try:
            reference = self.config['image']['name'] + ':' + self.config['image']['tag']
            images = self.client.images.list(filters={'reference': reference})
            if len(images) != 1:
                logger.error('Unable to find image {}'.format(reference))
                return False
            else:
                self.config['image']['id'] = images[0].id
        except docker.errors.APIError as e:
            logger.error('Possibly docker service down: {}'.format(repr(e)))
            return False
        return True

    def list_of_agent_containers(self):
        agent_containers = [c for c in self.client.containers.list(all=True)
                            if c.name.startswith(self.config['agent']['name'])]
        return agent_containers

    def get_agent_containers(self):
        old_agents, current_agents = [], []
        agent_containers = self.list_of_agent_containers()
        for c in agent_containers:
            image_match = False
            full_match = False

            for tag in c.image.tags:
                unpacked = tag.split(':', 1)
                if len(unpacked) > 1:
                    image = unpacked[0]
                    tag = unpacked[1]
                else:
                    image = unpacked[0]
                    tag = ''

                if image == self.config['image']['name']:
                    image_match = True
                    if tag == self.config['image']['tag']:
                        full_match = True

                if full_match:
                    break

            if image_match and not full_match:
                old_agents.append(c)
            elif image_match and full_match:
                current_agents.append(c)

        return old_agents, current_agents

    def start_containers(self, num=0):
        logger.info('Agents number lower than expected, trying to start {} new containers'.format(num))
        started = []
        try:
            env = {
                    'AZP_URL': self.config['azp']['url'],
                    'AZP_POOL': self.config['azp']['pool'],
                    'AZP_TOKEN': self.config['azp']['token'],
                }
            if self.config['proxy']['http']:
                env['http_proxy'] = self.config['proxy']['http']
            if self.config['proxy']['https']:
                env['https_proxy'] = self.config['proxy']['https']
            full_image = self.config['image']['name'] + ':' + self.config['image']['tag']

            for i in range(num):
                c = self.client.containers.run(
                    full_image,
                    detach=True,
                    environment=env,
                    name=self.config['agent']['name'] + '-' + str(uuid.uuid4()),
                    tty=True,
                )
                logger.info('Started container #{}, id={}, name={}'.format(i, c.short_id, c.name))
                started.append(c.short_id)
        except docker.errors.APIError as e:
            logger.error('Start container failed with exception: {}'.format(repr(e)))

        logger.info('Started {} new containers: {}'.format(len(started), json.dumps(started)))
        return started

    # returns True if Agent.Worker is running in the container
    # False otherwise
    def check_is_busy(self, container):
        return container.exec_run('pgrep -af "Agent.Worker"').exit_code == 0

    # remove_n_containers removes 'n' containers based on
    # - n indicates how many containers need to be removed. To act on
    #   all running containers n would usually have len(containers)
    # - is_running - True removes running containers; False removes 
    #   only unhealthy or non running containers
    # - force - forces a container to be removed even if it is busy
    #   running a nightly job
    # returns the list of container short ids that were removed
    def remove_n_containers(self, containers, n, is_running, force=False):
        removed = []
        try:
            for c in containers:
                if len(removed) >= n:
                    break
                if is_running:
                    is_busy = self.check_is_busy(c)
                    if c.status == 'running':
                        # remove a running container if 
                        # 1. It is busy running a job and is forced
                        # 2. If it is not busy (irrespective of the force setting)
                        if (is_busy is True and force is True) or (is_busy is False):
                            c.remove(force=True)
                            logger.info('Removed container {} with status {}'.format(c.short_id, c.status))
                            removed.append(c.short_id)
                else:
                    if c.status != 'running':
                        c.remove(force=True)
                        logger.info('Removed container {} with status {}'.format(c.short_id, c.status))
                        removed.append(c.short_id)
        except docker.errors.APIError as e:
            logger.error('Error removing {} container {}'.format(c.status, c.short_id, repr(e)))
        logger.info('Removed containers {} with status {}'.format(json.dumps(removed), c.status))
        return removed

    def remove_healthy_containers(self, containers):
        # remove all healthy containers that are not busy
        return self.remove_n_containers(containers, n=len(containers), is_running=True)
    
    def remove_unhealthy_containers(self, containers):
        # anything other than 'running' to indicate container is not running
        return self.remove_n_containers(containers, n=len(containers), is_running=False)

    def prune_containers(self, n, containers):
        return self.remove_n_containers(containers, n, is_running=True)

    # check_pat_file_exists checks if the PAT token file path exists.
    # returns True if the path is a file and it exists
    # returns False if path is not a file or does not exist
    def check_pat_file_exists(self):
        pat_file = pathlib.Path(self.PAT_FILE_PATH)
        if pat_file.is_file():
            return True
        if pat_file.is_dir():
            logger.error('%s is a directory! Interferes with PAT refresh process', self.PAT_FILE_PATH)
        return False

    # config_token_same compares the pat_token to the value in the config
    # returns False if they are both empty or None
    # returns True if they are the same
    # returns False otherwise
    def config_token_same(self, pat_token):
        if self.config['azp']['token'] is None or self.config['azp']['token'] == "":
            return False
        if self.config['azp']['token'] == pat_token:
            return True
        return False

    # read_pat_token returns token if the PAT_FILE_PATH exists and valid
    # returns None otherwise
    def read_pat_token(self):
        if self.check_pat_file_exists():
            pat_file = pathlib.Path(self.PAT_FILE_PATH)
            token = pat_file.read_text()
            return token
        return None

    def unlink_pat_file(self):
        if self.check_pat_file_exists():
            pat_file = pathlib.Path(self.PAT_FILE_PATH)
            pat_file.unlink()

    # refresh token updates self.current_token to the value
    # obtained from the token file; In the absence of the file
    # the function returns; self.current_token holds the last
    # read token
    def refresh_token(self):
        new_token = self.read_pat_token()
        if new_token is None or new_token == "":
            return False
        if self.config_token_same(new_token) is False:
            self.current_token = new_token
            self.config['azp']['token'] = self.current_token
            self.save_config()
            self.unlink_pat_file()
            return True
        return False

    # respawn managers agent containers. 
    # - gather all agents (all_agents)
    # - determine unhealthy agents (unhealthy_agents)
    # - tries to clean unhealthy agents
    # - re-consolidates old_agents and current_agents after cleanup
    # - if pat_refresh is true (i.e. new PAT is available)
    #   - refresh all old_agents that are not busy
    #   - refresh all current agents that are not busy
    # - keep track of busy agents;
    #   - if number of busy agents
    #   - > configured threshold then prune
    #   - < configured threshold start new containers
    #   - = configured threshold just return
    # returns number of containers started, updated, removed, pruned
    def respawn(self, pat_refresh = False):

        n_started = 0
        n_pruned = 0
        n_updated = 0

        old_agents, current_agents = self.get_agent_containers()
        all_agents = old_agents + current_agents
        logger.info('Running a total of {} agents'.format(len(all_agents)))
        unhealthy_agents = [c for c in all_agents if c.status != 'running']
        logger.info('Running {} unhealthy agents'.format(len(unhealthy_agents)))
        removed_count = 0
        removed = []
        logger.info('Cleaning unhealthy containers')
        if len(unhealthy_agents) > 0:
           removed = self.remove_unhealthy_containers(unhealthy_agents)
           removed_count += len(removed)
           # update unhealthy_agents; delete the removed ones; keep the ones that couldn't be removed
           unhealthy_agents = [c for c in unhealthy_agents if c.short_id not in removed]

        # update old and current agents to have only ones that couldn't be cleaned up / removed
        old_agents = [c for c in old_agents if not any(c.short_id == short_id for short_id in removed) ]
        current_agents = [c for c in current_agents if not any(c.short_id == short_id for short_id in removed) ]
        # discard/untrack the unhealthy ones we couldn't remove; they will get removed on the next refresh hopefully
        n_old = len(old_agents)
        n_curr = len(current_agents)
        old_agents = [c for c in old_agents if c.status == 'running']
        current_agents = [c for c in current_agents if c.status == 'running']
        logger.info('{} unhealthy old and {} unhealthy new agents could not be cleaned up'.format(n_old - len(old_agents), n_curr - len(current_agents)))

        logger.info('Post cleanup step a total of {} healthy agents are running'.format(len(old_agents) + len(current_agents)))
        # pending busy agents
        busy_agents = []
        if len(old_agents) > 0:
           # remove old idle ones for update
           removed = self.remove_healthy_containers(old_agents)
           removed_count += len(removed)
           n_updated += len(removed)
           # update old_agents; delete the removed ones
           old_agents = [c for c in old_agents if c.short_id not in removed]
           busy_agents += old_agents

        # Only refresh up-to-date agents if there was a PAT refresh in this cycle
        if pat_refresh is True:
            if len(current_agents) > 0:
                removed = self.remove_healthy_containers(current_agents)   
                removed_count += len(removed)
                n_updated += len(removed)
                current_agents = [c for c in current_agents if c.short_id not in removed]
                busy_agents += current_agents
        else:
            # if it is not a PAT refresh we'll just need to make sure that we have enough
            # workers running. Add current_agents to the busy_agents list to maintain
            # the count so that more containers than agent.count is not started
            busy_agents += current_agents

        if len(busy_agents) == self.config['agent']['count']:
            logger.info('Running expected {} healthy agents. OK'.format(self.config['agent']['count']))
        elif len(busy_agents) > self.config['agent']['count']:
            # try to reduce them
            n_more = len(busy_agents) - self.config['agent']['count']
            logger.info('Healthy agents count higher than expected {}, need to reduce {} agents'.format(
                            self.config['agent']['count'],
                            n_more
                        ))
            pruned = self.prune_containers(n_more, busy_agents)
            n_pruned = len(pruned)
        else:
            # number of running containers are less than required configured number
            n = self.config['agent']['count'] - len(busy_agents)
            started = self.start_containers(n)
            n_started = len(started)

        # return the current state of the system
        return n_started, n_updated, removed_count, n_pruned

    def run(self):
        signal.signal(signal.SIGHUP, self.sighup_handler)
        while True:
            try:
                pat_refresh = self.refresh_token()
                self.client.ping()
                self.respawn(pat_refresh)
            except Exception as e:
                logger.error('Unexpected exception: {}'.format(repr(e)))
            logger.info('Sleeping {} seconds to check again.'.format(self.CHECK_INTERVAL))
            time.sleep(self.CHECK_INTERVAL)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Azure Pipeline Agent Manager")

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