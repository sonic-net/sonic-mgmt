# Background

In order to run qos sai test, it's essential to build syncd RPC container, upload relevant artifacts to docker registry, and config test code to access docker registry.


# Build your own syncd RPC container image

## understand the build system.

Familiarize yourself with the SONiC build system by reviewing [doc](https://github.com/sonic-net/sonic-buildimage/blob/master/README.md)

## building the syncd RPC Container Image

Follow the build steps in above documentation. Before proceeding to the "build sonic image" step, build the syncd RPC container image for your platforms using below command:

```
# Build syncd rpc conitainer iamge
make ENABLE_SYNCD_RPC=y target/docker-syncd-${platform_rpc}-rpc.gz
```

Replace ${platform_rpc} with the appropriate value for your platform:

- Barefoot: bfn
- Broadcom: brcm
- Centec: centec
- Mellanox: mlnx
- Nephos: nephos

# Setup your docker registry

For detailed instructions on establishing and managing your Docker registry, refer to [Docker Registry Documentation](https://docs.docker.com/registry/)

# Access docker registry in QoS SAI test script

Modify [docker_registry.yml](ansible/vars/docker_registry.yml) to fill docker registry link, username and password. e.g:

```
docker_registry_host: "soniccr1.azurecr.io"

docker_registry_username: "read-only-user"
docker_registry_password: "password-of-user"
```

# Utilize SONiC’s public service for daily syncd RPC container image

If you do not require a private image, recommend to use the SONiC public service to get SONiC images and container image, avoid to build image and setuping docker registry yourself.

The artifacts download link is structured as follows:

```
https://sonic-build.azurewebsites.net/ui/sonic/pipelines/1/builds/{buildid}/artifacts?branchName={branchname}
```

For instance, to download Broadcom SONiC image for master branch build in pipeline:
"https://dev.azure.com/mssonic/build/_build/results?buildId=547766&view=results" to replace {buildid} with 547766 and {branchname} with master:

```
https://sonic-build.azurewebsites.net/ui/sonic/pipelines/1/builds/547766/artifacts?branchName=master
```

As this is a public service, there is no need to modify [docker_registry.yml](ansible/vars/docker_registry.yml). The QoS SAI test script will automatically pull the syncd rpc container image based on the configuration in [public_docker_registry.yml](ansible/group_vars/all/public_docker_registry.yml):

```
public_docker_registry_host: sonicdev-microsoft.azurecr.io
```
