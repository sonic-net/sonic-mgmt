# SONiC Container Upgrade Test

- [Introduction](#introduction)
- [Scope](#scope)
- [Test](#test)
  - [Pytest](#pytest)
  - [Upgrading OS Versions](#upgrading-os-versions)
  - [Preparing Containers for Test](#preparing-test-container)
  - [Sample parameters.json](#sample-parameters.json)
  - [Running Testcases](#running-test-cases)
  - [Sample testcases.json](#sample-testcases.json)
  - [Planned Minikube Enhancement](#minikube)


## Introduction

With the introduction of KubeSONiC container upgrade, a feature that will support frequent rollouts of new versions of containers, there is a missing test gap between the expected behavior of running different versions of containers and the version running on the host. Up till now, container versions have always matched the version running on the host. With this new nightly test, we expect to bridge the test gap between different running versions of containers and the host to determine if it is safe to roll out such pairings. We will be able to test different OS version and container pairings on the same testbed.

For each test, we will define the testbed, a list of OS Versions to be tested, where the first OS Version in the list is the base OS Version, and the bundle of containers that will be installed on each OS version.

For example, a testplan entry will look like (vms-kvm-t0, "202405-01|20240-02|20240-03|202405-04|202405-05", "docker-snmp:202405-04|docker-sonic-gnmi:202405-07"). This means that the following pairings will be executed on a single testbed in a single run of that testplan.

1. (vms-kvm-t0, 202405-01, docker-snmp:202405-04|docker-sonic-gnmi:202404-07)
2. (vms-kvm-t0, 202405-02, docker-snmp:202405-04|docker-sonic-gnmi:202404-07)
3. (vms-kvm-t0, 202405-03, docker-snmp:202405-04|docker-sonic-gnmi:202404-07)
4. (vms-kvm-t0, 202405-04, docker-snmp:202405-04|docker-sonic-gnmi:202404-07)
5. (vms-kvm-t0, 202405-05, docker-snmp:202405-04|docker-sonic-gnmi:202404-07)


## Scope

Establish a pytest that will be able to test different versions of containers running on different OS versions and run appropriate container testcases to verify that container and service is working as expected.

## Test

container_upgrade/test_container_upgrade_test.py will require specific params such as os_versions, containers, image_url, template file, and testcase file.

### Pytest

This pytest will be responsible for performing the following actions for each possible OS Version.

- **Pulling correct containers from a specified docker registry**
- **Starting new container with pulled images with proper docker run parameters; expectation is that start-up script in containers will stop old and remove old containers**
- **Reading testcase file and executing testcases listed**
- **Archive logs, collect result files, and store test results**
- **Upgrade to next image in iteration**


### Upgrading OS Versions

We will check if the current OS version is the expected OS version and if is not, we will upgrade. After each test, we will increment to the next OS version to be upgraded to. If we are unable to download the image or upgrade, we will publish failure entry in Kusto and then move on to the next image version.


### Preparing Containers for Test

We will docker pull the specified container images by specifying the container name, container version, and for some devices, the platform. After fetching the docker images, we will need to fetch the docker run parameters so that we run the container with the correct parameters. We will fetch these parameters from the parameters JSON file. The expectation is that these container images in their startup script, will stop and remove existing containers.

1. Pull specified containers

```
docker login {CONTAINER_REGISTRY}
```

In the container string, we will split by '|', and for each pull the image.

```
docker pull {CONTAINER_REGISTRY}/docker-sonic-gnmi:202405-07
```

2. Retrieve docker run parameters for container from parameters file


3. Run new containers

```
docker run -d -privileged --pid=host --net=host -v /etc/localtime:/etc/localtime:ro -v /etc/sonic:/etc/sonic:ro --name docker-sonic-gnmi:container_test {CONTAINER_REGISTRY}/docker-sonic-gnmi:202405-07
```

### Sample parameters.json

```json
{
  "docker-sonic-gnmi": {
    "parameters": "-privileged --pid=host --net=host -v /etc/localtime:/etc/localtime:ro -v /etc/sonic:/etc/sonic:ro"
  }
}
```

### Running Testcases

After upgrading to the next OS Version and pulling all containers, we will run all testcases in testcases.json.

We will call run_tests on each testcase in the file.

After run_tests has concluded for all tests, we will archive test result logs to build artifacts, and then store results. We will store the testbed, OS version, container bundle, test results for all testcases.


### Sample testcases.json

We will have a source testcase file container_upgrade/testcases.json that will have a list of testcases to be executed. These testcases are not guaranteed to be in any order of execution regardless of order listed in the JSON.

```json
[
    telemetry/test_telemetry.py
    telemetry/test_telemetry_cert_rotation.py
    snmp/test_snmp_cpu.py
    snmp/test_snmp/default_route.py
    snmp/test_snmp_fdb.py
    snmp/test_snmp_interfaces.py
    snmp/test_snmp_link_local.py
    snmp/test_snmp_lldp.py
    snmp/test_snmp_loopback.py
    gnmi/test_gnmi.py
    gnmi/test_gnmi_appIdb.py
    gnmi/test_gnmi_countersdb.py
    gnmi/test_gnoi_killprocess.py
    gnmi/vrf_aware_tests/test_gnmi_configdb.py
]
```

### Planned Minikube Enhancement

As part of an effort to achieve better test coverage of integration test with KubeSONiC feature, we can utilize Minikube.

With this enhancement we can:

1. Simplify the pulling and running of docker containers by using kubectl command and template file directly.
2. Ensure that Minikube can pull the correct docker images and run them with correct parameters as listed in the template file.

Needed changes in pipeline and test script:

1. We will no longer take in or use a PARAMETERS_FILE, but instead will take in and use a TEMPLATE_FILE which will be the template YAML file that defines the daemonset manifest.
2. This template file will be passed directly to miniKube after providing the needed values.
3. Download, install, and start Minikube on calling test management server if needed.
4. Ensure kubelet config is correct.
5. Create correct daemonset from template file passed to test script and deploy it.
6. Fetch certs for DUT to be able to join Minikube.
7. Ensure Minikube config is correct.
8. Create docker registry secret for miniKube to use when pulling from container registry.
9. Use Minikube to pull docker image from container registry and run docker container.
