# Ansible role - Mimir

[![License](https://img.shields.io/github/license/grafana/grafana-ansible-collection)](LICENSE)

This role installs and configures a [Mimir](https://grafana.com/docs/mimir/latest/)
standalone application.

## Testing with Molecule

To be able to test this collection locally, we use Molecule. Molecule is an Ansible test tool that enable us to run our roles inside containers. In our case, we are using Podman as a container runtime. To be able to run the Molecule test, you need to have the following installed on your machine:

- Podman
- Ansible
- Python3

### First Time Setup

To install all the dependencies, use the following commands:

```sh
# Create a virtual environment
python -m venv .venv

# On MacOS, WSL, Linux
source .venv/bin/activate

# On Windows
.\.venv\Scripts\activate

# Install dependencies
pip3 install ansible-core==2.16 'molecule-plugins[docker]' pytest-testinfra jmespath selinux passlib

# Create molecule network
docker network create molecule
```

### Run Minio for local S3

To be able to run Mimir using an object store backend, run the following command

```sh
docker run -d \
      -p 9000:9000 \
      -p 9001:9001 \
      --name minio-mimir \
      --network molecule \
      -e "MINIO_ROOT_USER=testtest" \
      -e "MINIO_ROOT_PASSWORD=testtest" \
      -e "MINIO_DEFAULT_BUCKETS=mimir" \
      bitnami/minio:latest
```

### Testing the changes

To test the changes in a role run:

```sh
molecule converge
## example: molecule converge
```

When Ansible has succesfully ran, you can run assertions against your infrastructure using.

```sh
molecule verify
## example: `molecule verify`
```

You can also run commands like `molecule destroy`, `molecule prepare`, and `molecule test`. See Molecule documentation for more information

## Role Variables

---

| Name                                    | Type | Default                                | Description                                                                                                                                                          |
| --------------------------------------- | ---- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| mimir_working_path                      | str  | /usr/share/mimir                       | Used to specify the directory path where Mimir, a component of the Grafana Agent, stores its working files and temporary data.                                       |
| mimir_uninstall                         | bool | false                                  | If set to `true` will perfom uninstall instead of deployment.                                                                                                        |
| mimir_ruler_alert_path                  | str  | /data/ruler                            | Used to specify the directory path where the Mimir ruler component of the Grafana Agent stores its alert files.                                                      |
| mimir_http_listen_port                  | str  | 8080                                   | Used to specify the port number on which the Mimir component of the Grafana Agent listens for incoming HTTP requests.                                                |
| mimir_http_listen_address               | str  | 0.0.0.0                                | Used to specify the network address on which the Mimir component of the Grafana Agent listens for incoming HTTP requests.                                            |
| mimir_ruler.rule_path                   | str  | /data/ruler                            | Used to specify the directory path where the Mimir ruler component of the Grafana Agent looks for rule files.                                                        |
| mimir_ruler.alertmanager_url            | str  | http://127.0.0.1:8080/alertmanager     | Used to specify the URL or address of the Alertmanager API that the Mimir ruler component of the Grafana Agent should communicate with.                              |
| mimir_ruler.ring.heartbeat_period       | str  | 2s                                     | Used to specify the interval at which the Mimir ruler component of the Grafana Agent sends heartbeat signals to the ring.                                            |
| mimir_ruler.heartbeat_timeout           | str  | 10s                                    | Used to specify the maximum duration of time that the Mimir ruler component of the Grafana Agent will wait for a heartbeat signal from other components in the ring. |
| mimir_alertmanager.data_dir             | str  | /data/alertmanager                     | sed to specify the directory path where the Mimir Alertmanager component of the Grafana Agent stores its data files.                                                 |
| mimir_alertmanager.fallback_config_file | str  | /etc/alertmanager-fallback-config.yaml | Used to specify the path to a fallback configuration file for the Mimir Alertmanager component of the Grafana Agent.                                                 |
| mimir_alertmanager.external_url         | str  | http://localhost:9009/alertmanager     | Used to specify the external URL or address at which the Mimir Alertmanager component of the Grafana Agent can be accessed.                                          |
| mimir_memberlist.join_members           | []   | List of members for the Mimir cluster  |

## **Additional Config Variables for `/etc/mimir/config.yml`**

Below variables allow you to extend Mimir configuration to fit your needs.
Always refer to official [Mimir configuration](https://grafana.com/docs/mimir/latest/configure/about-configurations/)
to obtain possible configuration parameters.

> [!NOTE]
> These variables are not set by default.

| Name                         | Description                                                                                                                                                         |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mimir_blocks_storage`       | Configures the `blocks_storage` component. 📚 [documentation](https://grafana.com/docs/mimir/latest/configure/configuration-parameters/#blocks_storage)             |
| `mimir_ruler_storage`        | Configures the `ruler_storage` component. 📚 [documentation](https://grafana.com/docs/mimir/latest/configure/configuration-parameters/#ruler_storage)               |
| `mimir_alertmanager_storage` | Configures the `alertmanager_storage` component. 📚 [documentation](https://grafana.com/docs/mimir/latest/configure/configuration-parameters/#alertmanager_storage) |
| `mimir_distributor`          | Configures the `distributor` component. 📚 [documentation](https://grafana.com/docs/mimir/latest/configure/configuration-parameters/#distributor)                   |
| `mimir_ingester`             | Configures the `ingester` component. 📚 [documentation](https://grafana.com/docs/mimir/latest/configure/configuration-parameters/#ingester)                         |
| `mimir_querier`              | Configures the `querier` component. 📚 [documentation](https://grafana.com/docs/mimir/latest/configure/configuration-parameters/#querier)                           |

For extra configuration samples refer to [`examples` directory](../../examples).
