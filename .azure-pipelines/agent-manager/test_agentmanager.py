import agentmanager
import json
from json import dumps as _dumps
import pathlib
import os
import random
import uuid
import unittest
from unittest.mock import patch
from pyfakefs.fake_filesystem_unittest import TestCase, patchfs
import yaml

agent_manager_conf = """
image:
    name: dockeragent
    tag: v1.1.9
azp:
    url: "https://dev.azure.com/mssonic"
    pool: "nightly"
    token: "this is a test token"
proxy:
    http: "http://10.201.148.40:8080"
    https: "http://10.201.148.40:8080"
agent:
    count: 28 
    name: azp-agent
"""

class MockDockerImage:
    VERSIONS = ['v1.1.8', 'v1.1.9', 'v2.0.0']
    # version_selector 
    # <0 - old
    # =0 - current,
    # >0 - new
    def __init__(self, version_selector):
        self.name = 'dockeragent'
        idx = 0
        if version_selector < 0:
            idx = 0
        if version_selector == 0:
            idx = 1
        if version_selector > 0:
            idx = 2
        self.tags = [self.name + ':' + self.VERSIONS[idx]]

class MockContainerProcess:
    def __init__(self, busy):
        if busy:
            self.exit_code = 0
        else:
            self.exit_code = 1

class MockContainer:
    MAX_ID = 2**32
    # version_selector for docker image
    # <0 - old
    # =0 - current,
    # >0 - new
    def __init__(self, version_selector, status, busy=False):
        self.image = MockDockerImage(version_selector)
        self.id = random.randint(0, self.MAX_ID)
        self.name = "azp-agent-" + str(uuid.uuid4())
        self.short_id = random.randint(0, self.MAX_ID)
        # valid status include
        # created, restarting, running, removing, paused, exited, dead
        self.status = status
        self.busy = busy

    def remove(*args, **kwargs):
        return

    def exec_run(self, cmd):
        return MockContainerProcess(self.busy)


def dumps_wrapper(*args, **kwargs):
    return _dumps(*args, **(kwargs | {"default": lambda obj: "mock"}))


class TestAgentManager(TestCase):

    AGENT_CONF_PATH = '/etc/agent-manager.conf'

    @classmethod
    def setUpClass(cls):
        cls.setUpClassPyfakefs()
        # setup the fake filesystem using standard functions
        path = pathlib.Path("/etc")
        path.mkdir()
        (path / cls.AGENT_CONF_PATH).touch()
        with open(cls.AGENT_CONF_PATH, 'w') as f:
            f.write(agent_manager_conf)
 
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_agent_manager_init(self, mock_docker, fake_fs, mock_validate):
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)

    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'read_pat_token')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_refresh_token_no_token_file(self, mock_docker, fake_fs, mock_read_pat_token, mock_validate):
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        mock_read_pat_token.return_value = None
        assert agt_mgr.refresh_token() is False

    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'read_pat_token')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_refresh_token_new_token_file(self, mock_docker, fake_fs, mock_read_pat_token, mock_validate):
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        new_token = "this is a new token"
        mock_read_pat_token.return_value = new_token
        assert agt_mgr.config_token_same(new_token) is False
        assert agt_mgr.config['azp']['token'] != new_token
        old_config = None
        with open(self.AGENT_CONF_PATH, 'r') as f:
            old_config = yaml.safe_load(f)
        assert agt_mgr.refresh_token() is True
        new_config = None
        with open(self.AGENT_CONF_PATH, 'r') as f:
            new_config = yaml.safe_load(f)
        res = all(old_config.get(k) == v for k, v in new_config.items())
        assert res is False

    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'list_of_agent_containers')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_get_agent_containers_empty(self, mock_docker, fake_fs, mock_list_of_agent_containers, mock_validate):
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        mock_list_of_agent_containers.return_value = []
        old, curr = agt_mgr.get_agent_containers()
        assert len(old) == 0
        assert len(curr) == 0

    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'list_of_agent_containers')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_get_agent_containers_old_only(self, mock_docker, fake_fs, mock_list_of_agent_containers, mock_validate):
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        mock_list_of_agent_containers.return_value = [
            MockContainer(-1, 'running'),
            MockContainer(-1, 'dead'),
            MockContainer(-1, 'running')
        ]
        old, curr = agt_mgr.get_agent_containers()
        assert len(old) == 3
        assert len(curr) == 0

    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'list_of_agent_containers')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_get_agent_containers_old_and_curr(self, mock_docker, fake_fs, mock_list_of_agent_containers, mock_validate):
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        mock_list_of_agent_containers.return_value = [
            MockContainer(-1, 'running'),
            MockContainer(0, 'running'),
            MockContainer(0, 'running')
        ]
        old, curr = agt_mgr.get_agent_containers()
        assert len(old) == 1
        assert len(curr) == 2

    # test_remove_healthy_containers_none tests the fact that 'No' container running
    # an active Agent.Worker process should be removed.
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_remove_healthy_containers_none(self, mock_docker, fake_fs, mock_validate):
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = [
            MockContainer(0, 'running', True),
            MockContainer(0, 'running', True),
            MockContainer(0, 'running', True)
        ]
        removed = agt_mgr.remove_healthy_containers(containers)
        assert len(removed) == 0

    # test_remove_healthy_containers_one removes one container that was idle
    # it does not matter if it is old or current.
    # old agents are removed anyway
    # new agents are removed only for a pat refresh
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_remove_healthy_containers_none(self, mock_docker, fake_fs, mock_validate):
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = [
            MockContainer(0, 'running', True),   # current version; running pipeline job.
            MockContainer(0, 'running', False),  # current version; running but no pipeline job.
            MockContainer(-1, 'running', False)  # old version; running but no pipeline job.
        ]
        removed = agt_mgr.remove_healthy_containers(containers)
        assert len(removed) == 2
        assert removed[0] == containers[1].short_id
        assert removed[1] == containers[2].short_id

    # test should remove only one dead container
    # via remove_unhealthy_containers
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_remove_unhealthy_containers(self, mock_docker, fake_fs, mock_validate):
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = [
            MockContainer(0, 'dead'),   # current version; dead
            MockContainer(0, 'running', True),  # current version; running pipeline job
            MockContainer(-1, 'running', True)  # old version; running pipeline job.
        ]
        removed = agt_mgr.remove_unhealthy_containers(containers)
        assert len(removed) == 1
        assert removed[0] == containers[0].short_id

    # test prune containers to remove any containers that are running and not busy
    # but are too many (greater than threshold)
    # configuration has max of 28
    # test should prune the last two containers that are not busy
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_remove_unhealthy_containers(self, mock_docker, fake_fs, mock_validate):
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = []
        for i in range(28):
            containers.append(MockContainer(0, 'running', True))
        containers.append(MockContainer(0, 'running', False))
        containers.append(MockContainer(0, 'running', False))
        removed = agt_mgr.prune_containers(2, containers)
        assert len(removed) == 2
        assert removed[0] == containers[28].short_id
        assert removed[1] == containers[29].short_id

    # test start containers 
    # just starts n containers;
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_start_containers(self, mock_docker, fake_fs, mock_validate):
        # make MagicMock serializable to JSON by mocking dumps
        # without this the test fails due to logging errors
        json.dumps = unittest.mock.MagicMock(wraps=dumps_wrapper)
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = []
        n_running = 10
        for i in range(n_running):
            containers.append(MockContainer(0, 'running', True))
        to_start = agt_mgr.config['agent']['count'] - n_running
        started = agt_mgr.start_containers(to_start)
        assert len(started) == to_start

    #
    # respawn tests
    # - should only remove and respawn unhealthy containers
    # - should keep number of containers running to the configured
    #   threshold
    # 

    # No PAT refresh; 10 healthy containers running; Number is below configured threshold
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'list_of_agent_containers')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_respawn_number_below_threshold(self, mock_docker, fake_fs, mock_list_of_agent_containers, mock_validate):
        # make MagicMock serializable to JSON by mocking dumps
        # without this the test fails due to logging errors
        json.dumps = unittest.mock.MagicMock(wraps=dumps_wrapper)
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = []
        n_running = 10
        for i in range(n_running):
            containers.append(MockContainer(0, 'running', True))
        mock_list_of_agent_containers.return_value = containers
        # have 10 healthy current containers
        # respawn should start 18 more
        n_started, n_updated, n_removed, n_pruned = agt_mgr.respawn()
        assert n_started == agt_mgr.config['agent']['count'] - n_running
        assert n_updated == 0
        assert n_removed == 0
        assert n_pruned == 0

    # No PAT refresh; 5 dead containers
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'list_of_agent_containers')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_respawn_remove_unhealthy_containers(self, mock_docker, fake_fs, mock_list_of_agent_containers, mock_validate):
        # make MagicMock serializable to JSON by mocking dumps
        # without this the test fails due to logging errors
        json.dumps = unittest.mock.MagicMock(wraps=dumps_wrapper)
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = []
        n_running = 10
        for i in range(n_running):
            containers.append(MockContainer(0, 'running', True))
        n_dead = 5
        for i in range(n_dead):
            containers.append(MockContainer(0, 'dead'))
        mock_list_of_agent_containers.return_value = containers
        n_started, n_updated, n_removed, n_pruned = agt_mgr.respawn()
        assert n_started == agt_mgr.config['agent']['count'] - n_running
        assert n_updated == 0
        assert n_removed == n_dead
        assert n_pruned == 0

    # PAT refresh; 5 busy agents; 5 idle agents; 
    # So should refresh the 5 idle agents
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'list_of_agent_containers')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_respawn_pat_refresh_with_few_idle_agents(self, mock_docker, fake_fs, mock_list_of_agent_containers, mock_validate):
        # make MagicMock serializable to JSON by mocking dumps
        # without this the test fails due to logging errors
        json.dumps = unittest.mock.MagicMock(wraps=dumps_wrapper)
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = []
        n_running = 5
        # running and busy
        for i in range(n_running):
            containers.append(MockContainer(0, 'running', True))
        # running and idle (i.e. no Agent.Worker)
        n_idle = 5
        for i in range(n_idle):
            containers.append(MockContainer(0, 'running', False))

        mock_list_of_agent_containers.return_value = containers
        n_started, n_updated, n_removed, n_pruned = agt_mgr.respawn(pat_refresh=True)
        assert n_started == agt_mgr.config['agent']['count'] - n_running
        assert n_updated == n_idle
        assert n_removed == n_idle
        assert n_pruned == 0

    # PAT refresh;
    # All healthy case
    # 5 busy agents; --> Should not touch
    # 5 idle agents with current version; --> Should be updated
    # 5 busy agents with older version; --> Should not touch
    # 5 idle agents with older version; --> Should be updated
    # Must start containers to keep number of workers to configured threshold
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'list_of_agent_containers')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_respawn_pat_refresh_with_mixed_case(self, mock_docker, fake_fs, mock_list_of_agent_containers, mock_validate):
        # make MagicMock serializable to JSON by mocking dumps
        # without this the test fails due to logging errors
        json.dumps = unittest.mock.MagicMock(wraps=dumps_wrapper)
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = []

        # 5 busy agents; --> Should not touch
        n_running = 5
        for i in range(n_running):
            containers.append(MockContainer(0, 'running', True))

        # 5 idle agents with current version; --> Should be updated
        n_idle = 5
        for i in range(n_idle):
            containers.append(MockContainer(0, 'running', False))

        # 5 busy agents with older version; --> Should not touch
        n_old_and_busy = 5
        for i in range(n_old_and_busy):
            containers.append(MockContainer(-1, 'running', True))
        
        # 5 idle agents with older version; --> Should be updated
        n_old_and_idle = 5
        for i in range(n_old_and_idle):
            containers.append(MockContainer(-1, 'running', False))

        mock_list_of_agent_containers.return_value = containers
        n_started, n_updated, n_removed, n_pruned = agt_mgr.respawn(pat_refresh=True)
        assert n_started == agt_mgr.config['agent']['count'] - (n_running + n_old_and_busy)
        assert n_updated == n_idle + n_old_and_idle
        assert n_removed == n_idle + n_old_and_idle
        assert n_pruned == 0

    # PAT refresh;
    # Few unhealthy case
    # 5 busy agents; --> Should not touch
    # 5 idle agents with current version; --> Should be updated
    # 5 busy agents with older version; --> Should not touch
    # 5 idle agents with older version; --> Should be updated
    # 1 unhealthy agent current version; --> Should be removed
    # 1 unhealthy agent old version; --> Should be removed
    # Must start containers to keep number of workers to configured threshold
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'list_of_agent_containers')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_respawn_pat_refresh_with_mixed_case(self, mock_docker, fake_fs, mock_list_of_agent_containers, mock_validate):
        # make MagicMock serializable to JSON by mocking dumps
        # without this the test fails due to logging errors
        json.dumps = unittest.mock.MagicMock(wraps=dumps_wrapper)
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = []

        # 5 busy agents; --> Should not touch
        n_running = 5
        for i in range(n_running):
            containers.append(MockContainer(0, 'running', True))

        # 5 idle agents with current version; --> Should be updated
        n_idle = 5
        for i in range(n_idle):
            containers.append(MockContainer(0, 'running', False))

        # 5 busy agents with older version; --> Should not touch
        n_old_and_busy = 5
        for i in range(n_old_and_busy):
            containers.append(MockContainer(-1, 'running', True))
        
        # 5 idle agents with older version; --> Should be updated
        n_old_and_idle = 5
        for i in range(n_old_and_idle):
            containers.append(MockContainer(-1, 'running', False))

        # 1 unhealthy agent current version; --> Should be removed
        n_unhealthy = 2
        containers.append(MockContainer(0, 'dead'))
        # 1 unhealthy agent old version; --> Should be removed
        containers.append(MockContainer(-1, 'dead'))
        
        mock_list_of_agent_containers.return_value = containers
        n_started, n_updated, n_removed, n_pruned = agt_mgr.respawn(pat_refresh=True)
        assert n_started == agt_mgr.config['agent']['count'] - (n_running + n_old_and_busy)
        assert n_updated == n_idle + n_old_and_idle
        assert n_removed == n_idle + n_old_and_idle + n_unhealthy
        assert n_pruned == 0

    # PAT refresh;
    # Few unhealthy case and pruning needed
    # 5 busy agents; --> Should not touch
    # 5 idle agents with current version; --> Should be updated
    # 5 busy agents with older version; --> Should not touch
    # 5 idle agents with older version; --> Should be updated
    # 1 unhealthy agent current version; --> Should be removed
    # 1 unhealthy agent old version; --> Should be removed
    # Must start containers to keep number of workers to configured threshold
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'list_of_agent_containers')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_respawn_pat_refresh_with_mixed_case_prune_needed(self, mock_docker, fake_fs, mock_list_of_agent_containers, mock_validate):
        # make MagicMock serializable to JSON by mocking dumps
        # without this the test fails due to logging errors
        json.dumps = unittest.mock.MagicMock(wraps=dumps_wrapper)
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = []

        # 5 busy agents; --> Should not touch
        n_running = 5
        for i in range(n_running):
            containers.append(MockContainer(0, 'running', True))

        # 5 idle agents with current version; --> Should be updated
        n_idle = 5
        for i in range(n_idle):
            containers.append(MockContainer(0, 'running', False))

        # 5 busy agents with older version; --> Should not touch
        n_old_and_busy = 5
        for i in range(n_old_and_busy):
            containers.append(MockContainer(-1, 'running', True))
        
        # 5 idle agents with older version; --> Should be updated
        n_old_and_idle = 5
        for i in range(n_old_and_idle):
            containers.append(MockContainer(-1, 'running', False))

        # 1 unhealthy agent current version; --> Should be removed
        n_unhealthy = 2
        containers.append(MockContainer(0, 'dead'))
        # 1 unhealthy agent old version; --> Should be removed
        containers.append(MockContainer(-1, 'dead'))

        # starting another 10 healthy containers; number goes to 32
        # so should prune 4 down
        # NOTE they are not busy; else they won't be pruned
        n_extra = 10
        for i in range(n_extra):
            containers.append(MockContainer(0, 'running'))
        
        mock_list_of_agent_containers.return_value = containers
        n_started, n_updated, n_removed, n_pruned = agt_mgr.respawn(pat_refresh=True)
        assert n_started == agt_mgr.config['agent']['count'] - (n_running + n_old_and_busy)
        assert n_updated == n_idle + n_old_and_idle + n_extra
        assert n_removed == n_idle + n_old_and_idle + n_unhealthy + n_extra # extra because they are not busy
        # the extra ones got pruned during the removal process
        assert n_pruned == 0 

    # Full loop check; Finds the PAT file
    # 5 busy agents; --> Should not touch
    # 5 idle agents with current version; --> Should be updated
    # 5 busy agents with older version; --> Should not touch
    # 5 idle agents with older version; --> Should be updated
    # 1 unhealthy agent current version; --> Should be removed
    # 1 unhealthy agent old version; --> Should be removed
    # Must start containers to keep number of workers to configured threshold
    @patch('agentmanager.docker')
    @patchfs
    @patch.object(agentmanager.AgentManager, 'list_of_agent_containers')
    @patch.object(agentmanager.AgentManager, 'validate')
    def test_respawn_pat_refresh_with_mixed_case_full_loop(self, mock_docker, fake_fs, mock_list_of_agent_containers, mock_validate):
        # make MagicMock serializable to JSON by mocking dumps
        # without this the test fails due to logging errors
        json.dumps = unittest.mock.MagicMock(wraps=dumps_wrapper)
        agt_mgr = agentmanager.AgentManager(conf=self.AGENT_CONF_PATH)
        containers = []

        # 5 busy agents; --> Should not touch
        n_running = 5
        for i in range(n_running):
            containers.append(MockContainer(0, 'running', True))

        # 5 idle agents with current version; --> Should be updated
        n_idle = 5
        for i in range(n_idle):
            containers.append(MockContainer(0, 'running', False))

        # 5 busy agents with older version; --> Should not touch
        n_old_and_busy = 5
        for i in range(n_old_and_busy):
            containers.append(MockContainer(-1, 'running', True))
        
        # 5 idle agents with older version; --> Should be updated
        n_old_and_idle = 5
        for i in range(n_old_and_idle):
            containers.append(MockContainer(-1, 'running', False))

        # 1 unhealthy agent current version; --> Should be removed
        n_unhealthy = 2
        containers.append(MockContainer(0, 'dead'))
        # 1 unhealthy agent old version; --> Should be removed
        containers.append(MockContainer(-1, 'dead'))

        # simulate landing of a PAT file
        with open(agt_mgr.PAT_FILE_PATH, 'w') as f:
            f.write("this is a fresh token")

        mock_list_of_agent_containers.return_value = containers

        pat_refresh = agt_mgr.refresh_token()
        assert pat_refresh is True
        assert pathlib.Path(agt_mgr.PAT_FILE_PATH).exists() is False

        n_started, n_updated, n_removed, n_pruned = agt_mgr.respawn(pat_refresh)
        assert n_started == agt_mgr.config['agent']['count'] - (n_running + n_old_and_busy)
        assert n_updated == n_idle + n_old_and_idle
        assert n_removed == n_idle + n_old_and_idle + n_unhealthy
        # the extra ones got pruned during the removal process
        assert n_pruned == 0 

if __name__ == '__main__':
    unittest.main()