# Agent Manager

The agent manager is a tool for managing Azure Pipeline agents for SONiC nightly tests.

Currently we built a special sonic-mgmt docker image which has the Azure Pipeline agent package installed and configured. Containers started from this image can talk to the Azure Pipeline platform and work as agent of agent pools. The agent pools are used for our nightly test.

There are couple of reasons I built this tool:
1. In starlab, the agents are running on server_15 and server_19. The docker containers are managed by Kubernetes Master running on trusty9 (a classic Azure VM). Server 15&19 are kubernetes worker nodes. The k8s service is kind of too heavy and hard to use for such a simple purpose. Meanwhile, trusty9 is a classic Azure VM that need to be deprecated according to Azure security requirements. We need a better way to manage the starlab agents.
2. In SVC and BJW lab, the agents are manually managed. We need a better way to manager the agents in SVC and BJW lab too.

## How it works

The agent manager has 2 pieces:
* `agent-manager.py` script
* `agent-manager.conf` configuration file.

By default `agent-manager.py` expects configuration located at `/etc/agent-manager.conf`. The configuration file also can be specified using command line argument `-f` or `--conf`.

This tool tries to ensure that expected number of agents are started using specified docker image + tag. It also tries to remove agents running with older tag. Before remove an agent, it always ensure that there is no job is running in the agent. With this check, this tool supports rolling upgrade.

### Configuration
The configuration file must be `yaml` format. Sample configuration file looks like below:
```
image:
    name: dockeragent
    tag: v1.1.0
azp:
    url: "https://dev.azure.com/<your-organization>"
    pool: "your-pool-name"
    token: "fake-token"
proxy:
    http: "http://100.127.20.21:8080"
    https: "http://100.127.20.21:8080"
agent:
    count: 10
    name: azp-agent
```

* `image`
  * Purpose: For specifying the docker image
  * Required: no
  * Keys:
    * `name`
      * Purpose: Specifying docker image name
      * Required: no
      * Default value: `dockeragent`
      * Example: `dockeragent`
    * `tag`:
      * Purpose: Specifying docker image tag
      * Required: no
      * Default value: `latest`
      * Example: `v1.1.0`
* `azp`
  * Purpose: Configure parameters for talking with Azure Pipeline platform
  * Required: yes
  * Keys:
    * `url`
      * Purpose: Azure DevOps organization URL
      * Required: yes
      * Example: `https://dev.azure.com/mssonic`
    * `pool`
      * Purpose: Azure Pipeline agent pool name
      * Required: yes
      * Example: `nightly`
    * `token`
      * Purpose: Token for talking with Azure Pipeline platform
      * Required: yes
* `proxy`
  * Purpose: For configuring http proxy if required
  * Required: no
  * Keys:
    * `http`
      * Purpose: For configuring `http_proxy`
      * Required: no
    * `https`
      * Purpose: For configuring `https_proxy`
      * Required: no
* `agent`
  * Purpose: For configuring agent name pattern and expected number of agents
  * Required: no
  * Keys:
    * `count`
      * Purpose: For configuring expected number of agents to start
      * Required: no
      * Default: 10
    * `name`
      * Purpose: For configuring agent name. All agents will have the configured name plus `-<uuid>`.
      * Required: no
      * Default: azp-agent

### Execution logic

Init:
* Upon start, read and parse configuration file.
* Verify that the specified docker iamge + tag exists.
* Load all required configuration into dict `self.config`.

Main loop:
* Find out all the docker containers matching these conditions:
  * Running specified docker image, but not the tag -> old agents
  * Running specified docker image and the tag -> current agents
  * Name starts with `azp.name`.
* Loop the containers, find out containers not in `running` state. Remove them one by one.
* Remove all old agents that have no `Agent.Worker` process running.
* Count the remaining containers. Compare with `agent.count`.
  * If container count == `agent.count`, do nothing.
  * If container count < `agent.count`, start new containers until container count == `agent.count`.
  * If container count > `agents.count` and current container count > `agents.count` remove extra current containers until current container count == `agent.count`. Before remove, check if `Agent.Worker` process is running. If yes, skip removing the current container and go to next one.
* Sleep 60 seconds and start over main loop.

### Logging
This tool logs to `/tmp/agent-manager.log`. Log rotation is enabled.

## Deploy

1. Create a service file to `/lib/systemd/system/agent-manager.service` with content like below:
```
[Unit]
Description=Agent Manager
After=network.target

[Service]
ExecStart=/usr/bin/python /usr/bin/agent-manager.py

[Install]
WantedBy=multi-user.target
```

2. Prepare the configuration file `/etc/agent-manager.conf` with content like below:
```
image:
    name: dockeragent
    tag: v1.1.0
azp:
    url: "https://dev.azure.com/<your-organization>"
    pool: "your-pool-name"
    token: "fake-token"
proxy:
    http: "http://100.127.20.21:8080"
    https: "http://100.127.20.21:8080"
agent:
    count: 10
    name: azp-agent
```

3. Download file `agent-manager.py` and put it at `/usr/bin/agent-manager.py`.

4. Ensure that required python packages are installed:
```
sudo pip install docker
sudo pip install PyYAML
```

5. Start the service:
```
sudo systemctl start agent-manager
```

6. Enable the service to ensure that it starts after system reboot.
```
sudo systemctl enable agent-manager
```

## Rolling upgrade
When the docker image for nightly test is updated and we need to upgrade the agents, we can do rolling upgrade.

1. Build new docker image.
2. Load the docker image to host server running agents. Give the new image a new tag.
3. Update `image.tag` in `/etc/agent-manager.conf`.
4. Restart agent-manager: `sudo systemctl restart agent-manager`. The agent-manager will start new agents and remove old agents not running any job. If one round is not enough to update all agents, it will retry with 60 seconds interval.
