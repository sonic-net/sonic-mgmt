# Background

To run the QoS SAI test, an additional syncd RPC container image and relevant configuration are required. You have two options for building, uploading, and accessing this image:

- [Build your own syncd RPC container image](#1. Build your own syncd RPC container image)
- [Utilize SONiC public image](#2. Utilize image build by SONiC public service)


# 1. Build your own syncd RPC container image

## 1.1 How to build the syncd RPC Container Image

Familiarize yourself with the SONiC build system by reviewing [doc](https://github.com/sonic-net/sonic-buildimage/blob/master/README.md)  
Follow the build steps in above documentation. Before proceeding to the last step "build sonic image", build the syncd RPC container image for your platforms using below command:

```
# Build syncd RPC container iamge
make ENABLE_SYNCD_RPC=y target/docker-syncd-${platform_rpc}-rpc.gz
```

Replace ${platform_rpc} with the appropriate value for your platform:

- Barefoot: bfn
- Broadcom: brcm
- Centec: centec
- Mellanox: mlnx
- Nephos: nephos

## 1.2 How to setup and manage your docker registry

For detailed instructions on establishing and managing your Docker registry, refer to [Docker Registry Documentation](https://docs.docker.com/registry/)

## 1.3 How to access docker registry in QoS SAI test code

For detailed guidance, refer to the "docker_registry section" within the [Sonic-Mgmt Testbed Setup](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.new.testbed.Configuration.md).  
To configure access to the Docker registry, navigate to the `ansible/vars/docker_registry.yml` file. and then enter the appropriate Docker registry URL, your username, and password in the specified format:

```
docker_registry_host: "soniccr1.azurecr.io"

docker_registry_username: "read-only-user"
docker_registry_password: "password-of-user"
```

# 2. Utilize image build by SONiC public service

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

As this is a public service, there is no need to modify `ansible/vars/docker_registry.yml`. The QoS SAI test script will automatically pull the syncd rpc container image based on the configuration in `ansible/group_vars/all/public_docker_registry.yml`:

```
public_docker_registry_host: sonicdev-microsoft.azurecr.io
```
