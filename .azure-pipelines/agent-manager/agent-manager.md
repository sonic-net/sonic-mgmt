# Agent Manager

The Agent Manager serves as a solution for overseeing Azure Pipeline agents utilized in SONiC's nightly tests. It operates through a specialized sonic-mgmt Docker image, which comes pre-installed and pre-configured with the Azure Pipeline agent package. This enables containers derived from this image to communicate with the Azure Pipeline platform and function as agents within agent pools, which are integral to our nightly testing process.

The creation of this tool was motivated by several factors:

* In the StarLab environment, agents operate on servers 15 and 19, with the Docker containers being orchestrated by a Kubernetes Master hosted on trusty9, an older Azure VM. Given that Kubernetes services are somewhat cumbersome for such straightforward tasks and trusty9's impending deprecation due to Azure's security policies, a more streamlined approach to managing StarLab agents was necessary. 
* In both the SVC and BJW labs, agent management has been a manual process. To enhance efficiency and oversight in these labs, a more sophisticated management solution was required.

The table below shows the self managed hosts for the various labs:

| Nightly Pool Name | Lab Name | Server List           |
| ----------------- | -------- | --------------------- |
| nightly           | str      | str-acs-serv-15       |
| nightly           | str3     | str-acs-serv-65       |
| nightly-svc       | svc      | svcstr-server-2       |
| nightly-bjw       | bjw      | bjw-ca-serv-5         |
| nightly-tk5       | tk5      | strtk5-serv-02        |

## How it works

The Agent Manager is a Python script that operates as a systemd service on self-managed hosts. At the heart of the Agent Manager are several key components:

* The agent-manager.py script, which functions as a service located at .azure-pipelines/agent-manager/agent-manager.py.
* The agent-manager.conf configuration file, found at .azure-pipelines/agent-manager/agent-manager.conf.

By default, the agent-manager.py script anticipates the configuration to be present at /etc/agent-manager.conf. However, an alternative configuration file location can be specified using the -f or --conf command-line arguments.

The Agent Manager's process involves routine checks on the status and health of all Azure agents within the Docker containers. Should any agents be deemed unhealthy, require updates due to an outdated Personal Access Token, or if the number of agents deviates from the configured threshold, the Agent Manager takes action. It will either remove or initiate the necessary number of containers housing the Azure agents. For an in-depth understanding of the operational logic, please refer to the Execution Logic section below.

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

The execution starts by agent manager loading the configuration file. The execution logic of the Agent Manager operates on a continuous loop, executing every minute with the following sequence:

1. It verifies the existence of a Personal Access Token (PAT) file.
2. Should a new token be detected, the Agent Manager updates the configuration file with this fresh token.
3. Post token update, the token file is eliminated.
4. The system proceeds to restart all agents—specifically, the Docker containers with Azure agents—that are not engaged in running a nightly job.
5. It identifies and removes any unhealthy containers, replacing them with new agents.
6. Finally, it adjusts the number of active Azure agents to align with the count specified in the configuration file under agent.count, either by pruning excess containers or initiating new ones as needed.

This structured logic ensures the Agent Manager maintains optimal performance and agent health, adhering to the specified configurations.

### How the Personal Access Token (PAT) refresh works

The Personal Access Token (PAT) refresh mechanism is an enhancement to the Agent Manager, designed to ensure continuous operation of agents. The PAT is programmed to expire every 7 days, necessitating a refresh at this interval to maintain agent functionality. The updated PAT is conveyed to the Agent Manager service through a temporary file, following these steps:

* A pipeline job is configured to execute nightly, as defined in `.azure-pipelines/testbed/update-pat-on-agent.yml`
* This pipeline has access to a confidential PAT.
* The PAT is transferred from the agent to the Agent Manager via an Ansible playbook titled `ansible/pat_refresh.yml`.
* The Ansible job ensures the PAT is accessible to the Agent Manager on the host system.
* The `pat_refresh.yml` playbook is tasked with running the job on specified inventories within the group `self_hosted_azure_agents`. The PAT is exclusively copied to the hosts listed. Should there be any changes to the agents—be it additions, removals, or decommissions—the inventory files and playbook must be updated to reflect these changes.

This systematic approach ensures that the Agent Manager remains up-to-date with valid PATs, thereby facilitating uninterrupted agent operations.

### Logging
This tool logs to `/tmp/agent-manager.log`. Log rotation is enabled.

## Unit Testing

The `test_agentmanager.py` script employs pyfakefs to simulate a virtual filesystem and utilizes unittest.mock to mimic interactions with the Docker layer. This setup is used to validate various aspects of the Agent Manager's functionality. 

This approach ensures that the Agent Manager is thoroughly tested in a controlled environment, verifying its performance and reliability. To run the unit tests run `make test` in the `agent-manager` directory.

## Deploy

1. Create a service file to `/lib/systemd/system/agent-manager.service` with content like below:
```
[Unit]
Description=Agent Manager
After=docker.service

[Service]
ExecStart=/usr/bin/python /usr/bin/agent-manager.py
ExecReload=kill -HUP $MAINPID

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
4. Reload the agent-manager: `sudo systemctl reload agent-manager`. The agent-manager will reload the new configuration. The agent-manager will then update the agents when they are not busy.