## System Testing Agent Manager

The files within this directory are designed to facilitate the testing of the Agent Manager as a systemd service within your development environment. These files enable the creation of a `dockeragent` image that emulates the processes of Azure agent jobs.

For a comprehensive guide on setting up systemd files in your user environment, a valuable resource is available https://github.com/torfsen/python-systemd-tutorial

To conduct the test, follow these steps:

1. Construct a mock `dockeragent` image, selecting any version number as it is not critical. For instance:
   `docker build -t dockeragent:v1.5.0`
2. The provided `Dockerfile` is solely for testing purposes and is based on Ubuntu 22.04. It includes a startup script that executes the "Agent.Worker" script, simulating Azure agent activities at random intervals.
3. Transfer the `agent-manager.py` to the `$HOME/bin` directory.
4. Move the `agent-manager.conf` to the `$HOME/bin` directory as well.
5. Place the `agent-manager.service` file into the `$HOME/.config/systemd/user/agent-manager.service` path.
6. Manage the service with the following commands:
   `systemctl --user start agent-manager.service`
   `systemctl --user stop agent-manager.service`
   `systemctl --user reload agent-manager.service`
7. In case of any modifications to the `agent-manager.service` file, execute `systemctl --user daemon-reload` to apply the changes.

### Sample Configuration Files

The Agent Manager necessitates the installation of Docker and the PyYaml package. If Docker and PyYaml are already installed in your global environment, then you can utilize the [agent-manager.service](../agent-manager.service) file as is. However, if your Python setup relies on pyenv virtual environments, you'll need to adjust the following configuration settings accordingly. 

#### agent-manager.env

Copy this file to $HOME/bin

```
PYENV_SHELL=bash
PYENV_ACTIVATE_SHELL=1
PYENV_VERSION=dev
PYENV_VIRTUALENV_INIT=1
PYENV_ROOT=$HOME/.pyenv
PYENV_VIRTUAL_ENV=$PYENV_ROOT/versions/3.10.0/envs/dev
PATH=$HOME/bin:$PYENV_ROOT/plugins/pyenv-virtualenv/shims:$PYENV_ROOT/shims:$PYENV_ROOT/bin:$HOME/bin:$PYENV_ROOT/plugins/pyenv-virtualenv/shims:$PYENV_ROOT/bin:$HOME/.nvm/versions/node/v21.7.1/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

#### agent-manager.service

Replace YOUR_HOME_DIR_HERE with path to your home directory.

```
[Unit]
Description=Agent Manager
After=docker.service

[Service]
EnvironmentFile=YOUR_HOME_DIR_HERE/bin/agent-manager.env
ExecStart=YOUR_HOME_DIR_HERE/.pyenv/shims/python YOUR_HOME_DIR_HERE/bin/agent-manager.py -f YOUR_HOME_DIR_HERE/bin/agent-manager.conf
ExecReload=kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```