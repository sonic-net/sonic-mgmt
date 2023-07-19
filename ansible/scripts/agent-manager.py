from __future__ import print_function, division

import argparse
import json
import logging
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


class AgentManager(object):

    CHECK_INTERVAL = 60

    def __init__(self, conf):
        self.client = docker.from_env()
        self.load_config(conf=conf)
        self.validate()

    def load_config(self, conf):
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
            sys.exit(10)

        # Update default config with content from configuration file
        if 'image' in raw_config:
            if 'name' in raw_config['image']:
                self.config['image']['name'] = raw_config['image']['name']
            if 'tag' in raw_config['image']:
                self.config['image']['tag'] = raw_config['image']['tag']

        if 'azp' not in raw_config:
            logger.error('Missing mandatory "azp" configuration in conf file')
            sys.exit(20)

        if 'url' not in raw_config['azp']:
            logger.error('Missing mandatory "azp.url" configuration in conf file')
            sys.exit(20)

        if 'pool' not in raw_config['azp']:
            logger.error('Missing mandatory "azp.pool" configuration in conf file')
            sys.exit(20)

        if 'token' not in raw_config['azp']:
            logger.error('Missing mandatory "azp.token" configuration in conf file')
            sys.exit(20)

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
                    sys.exit(20)
            if 'name' in raw_config['agent']:
                self.config['agent']['name'] = raw_config['agent']['name']

    def validate(self):
        try:
            reference = self.config['image']['name'] + ':' + self.config['image']['tag']
            images = self.client.images.list(filters={'reference': reference})
            if len(images) != 1:
                logger.error('Unable to find image {}'.format(reference))
                sys.exit(30)
            else:
                self.config['image']['id'] = images[0].id
        except docker.errors.APIError as e:
            logger.error('Possibly docker service down: {}'.format(repr(e)))

    def get_agent_containers(self):
        agent_containers = [c for c in self.client.containers.list(all=True)
                            if c.name.startswith(self.config['agent']['name'])]
        old_agents, current_agents = [], []
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

    def remove_unhealthy_containers(self, containers):
        removed = []
        try:
            for c in containers:
                c.remove(force=True)
                logger.info('Removed unhealthy container {}'.format(c.short_id))
                removed.append(c.short_id)
        except docker.errors.APIError as e:
            logger.error('Remove unhealthy container {} failed with exception: {}'.format(c.short_id, repr(e)))
        logger.info('Removed {} unhealthy containers: {}'.format(len(removed), json.dumps(removed)))
        return removed

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

    def reduce_healthy_containers(self, containers, num=0):
        logger.info('Trying to reduce {} instances from healthy containers: {}'.format(
            num,
            json.dumps([c.short_id for c in containers]))
        )
        reduced = []
        try:
            for c in containers:
                if len(reduced) >= num:
                    break
                if c.exec_run('pgrep -af "Agent.Worker"').exit_code != 0:
                    # Only reduce container without job running
                    c.remove(force=True)
                    reduced.append(c.short_id)
        except docker.errors.APIError as e:
            logger.error('Reduce unhealthy container failed with exception: {}'.format(repr(e)))
        logger.info('Reduced {} healthy containers: {}'.format(len(reduced), json.dumps(reduced)))
        return reduced

    def remove_old_agents(self, containers):
        removed = []
        try:
            for c in containers:
                if c.exec_run('pgrep -af "Agent.Worker"').exit_code != 0:
                    # Only remove container without job running
                    c.remove(force=True)
                    removed.append(c.short_id)
        except docker.errors.APIError as e:
            logger.error('Remove old agents failed with exception: {}'.format(repr(e)))
        logger.info('Removed {} old agents: {}'.format(len(removed), json.dumps(removed)))
        return removed

    def run(self):
        while True:
            try:
                self.client.ping()
                old_agents, current_agents = self.get_agent_containers()
                all_agents = old_agents + current_agents
                logger.info('Found {} old agents, {} current agents, total {} agents'
                            .format(len(old_agents), len(current_agents), len(all_agents)))

                unhealthy_old_agents = [c for c in old_agents if c.status != 'running']
                unhealthy_current_agents = [c for c in current_agents if c.status != 'running']
                healthy_current_agents = [c for c in current_agents if c.status == 'running']

                num_old_healthy = len(old_agents)
                num_current_healthy = len(current_agents)

                # Remove unhealthy agent containers
                if unhealthy_old_agents:
                    unhealthy_old_removed = self.remove_unhealthy_containers(unhealthy_old_agents)
                    num_old_healthy -= len(unhealthy_old_removed)
                    logger.info('Removed {} unhealthy old agents'.format(len(unhealthy_old_removed)))
                if unhealthy_current_agents:
                    unhealthy_current_removed = self.remove_unhealthy_containers(unhealthy_current_agents)
                    num_current_healthy -= len(unhealthy_current_agents)
                    logger.info('Removed {} unhealthy current agents'.format(len(unhealthy_current_removed)))

                # Remove old agents that do not have a job running
                if old_agents:
                    old_removed = self.remove_old_agents(old_agents)
                    num_old_healthy -= len(old_removed)
                    logger.info('Removed {} old agents without job running.'
                                .format(len(old_removed)))

                logger.info('Remaining {} old healthy agents and {} current healthy agents, total: {}, expected: {}'
                            .format(
                                num_old_healthy,
                                num_current_healthy,
                                num_old_healthy + num_current_healthy,
                                self.config['agent']['count']
                            ))

                if num_old_healthy > 0:
                    logger.info('Pending removing {} old agents that still have job running'.format(num_old_healthy))

                if num_old_healthy + num_current_healthy == self.config['agent']['count']:
                    logger.info('Running expected {} healthy agents. OK'.format(self.config['agent']['count']))
                elif num_old_healthy + num_current_healthy > self.config['agent']['count']:
                    if num_current_healthy > self.config['agent']['count']:
                        num = num_current_healthy - self.config['agent']['count']
                        logger.info('Healthy agents count higher than expected {}, need to reduce {} agents'.format(
                            self.config['agent']['count'],
                            num
                        ))
                        self.reduce_healthy_containers(healthy_current_agents, num)
                elif num_old_healthy + num_current_healthy < self.config['agent']['count']:
                    num = self.config['agent']['count'] - num_old_healthy - num_current_healthy
                    logger.info('Healthy agents count lower than expected {}, need to start {} new'.format(
                        self.config['agent']['count'],
                        num
                    ))
                    self.start_containers(num)

            except docker.errors.APIError as e:
                logger.error('Possibly docker service down: {}'.format(repr(e)))
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
