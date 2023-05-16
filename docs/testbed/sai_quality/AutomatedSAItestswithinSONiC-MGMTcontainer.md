# Automated SAI tests within SONiC-MGMT container

- [Prepare testbed](#prepare-testbed)
- [Setup sonic-mgmt docker](#setup-sonic-mgmt-docker)
- [Setup testing environments](#setup-testing-environments)
- [Run SAI test](#run-sai-test)
  - [1. Clean up the environments](#1-clean-up-the-environments)
  - [2. Setup environment variables](#2-setup-environment-variables)
  - [3. Execute the corresponding type of testing command](#3-execute-the-corresponding-type-of-testing-command)


This document describes the process of testing SAI test cases under **sonic-mgmt docker**, for **PTF-SAI docker**, please see [this page.](https://github.com/opencomputeproject/SAI/blob/master/ptf/docs/SAI-PTFv2Overview.md#sai-ptfv2-overview)

In addition, the framework of testing SAI test case is same as sonic-mgmt, and the ways of running test cases are similar, except for some different parameters. The details of running `pytest` can be found [here](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/tests/pytest.org.md). The details of running cases can be found [here](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/tests/pytest.run.md).

The whole process of setting up SAI test environment, in this document, can be described as following.
First, a testbed with complete configuration is required. Second, since the test is conducted in docker, we need to prepare sonic-mgmt docker. In the last place, we can run the SAI test cases.


## Prepare testbed
At the beginning, you are recommended to read the [overview of SONiC testbed.](https://github.com/sonic-net/sonic-mgmt/tree/master/docs/testbed) Then, build and setup steps are:
1. [Build testbed](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.Overview.md)
2. [Setup testbed](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.new.testbed.Configuration.md)
3. [Setup saiserverv2](https://github.com/opencomputeproject/SAI/blob/master/ptf/docs/SAI-PTFv2Overview.md#setup-dut-device-under-testing)
4. The SAI test cases are stored in SAI repo, so we need to clone the SAI repo in the PTF. The physical connection of the testbed can be found [here.](https://github.com/opencomputeproject/SAI/blob/master/ptf/docs/ExamplePhysicalConnection.md)
   ```bash
   git clone https://github.com/opencomputeproject/SAI.git
   ```

Now we've got the testbed with complete configuration.

## Setup sonic-mgmt docker
1. Clone the sonic-mgmt repo
   ```bash
   git clone https://github.com/sonic-net/sonic-mgmt
   ```
2. [Setup sonic-mgmt docker.](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.VsSetup.md#setup-sonic-mgmt-docker) After doing so, we are in the sonic-mgmt docker environment. Please go to the sonic-mgmt repo in your docker, i.e., `cd /data/sonic-mgmt`.

The following steps are conducted in the sonic-mgmt docker.

## Setup testing environments
Install the required packages using pip.
```bash
pip3 install -r test_reporting/requirements.txt
pip install -r test_reporting/requirements.txt
```

## Run SAI test
### 1. Clean up the environments
   ```bash
   rm -rf tests/_cache
   rm -rf reports
   mkdir -p reports

   cd tests
   ```
### 2. Setup environment variables
1. Setup testbed information. How to obtain the testbed information, please see [this page](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/sai_quality/DeploySAITestTopologyWithSONiC-MGMT.md), and modify them as appropriate.
   ```bash
   export TESTBED_NAME=vms-sn2700-t1
   export PY_SAITHRIFT_URL=http://10.201.148.43/pipelines/Networking-acs-buildimage-Official/broadcom/202012-saithriftv2/python-saithriftv2_0.9.4_amd64.deb
   ```
   The `PY_SAITHRIFT_URL` is the link to the SAI python header, all packages are listed [here](https://sonic-build.azurewebsites.net/ui/sonic/pipelines). For example, if you are testing on _broadcom, 202205_, click `Build History` of _broadcom, 202205_. Then, find a `succussed` result, and click `Artifacts`. Finally, search the package you want.
**Please make sure you choose the right url.** For more information please go to [this document.](https://github.com/opencomputeproject/SAI/blob/master/ptf/docs/SAI-PTF_resources_download.md)

2. Setup test type as you need.
   ```bash
   export CONFIG_PARAMS="--sai_test_container=saiserver --disable_loganalyzer"
   ```
   - PTF type
      ```bash
      export CONFIG_PARAMS=${CONFIG_PARAMS}" --sai_test_dir=SAI/ptf --enable_ptf_sai_test"
      ```
   - T0 type
      ```bash
      export CONFIG_PARAMS==${CONFIG_PARAMS}" --sai_test_dir=SAI/test/sai_test --enable_sai_test"
      ```
   - Warm reboot PTF type
      ```bash
      export CONFIG_PARAMS==${CONFIG_PARAMS}" --sai_test_dir=SAI/ptf --enable_ptf_warmboot_test --sai_test_enable_deployment --skip_stop_sai_test_container"
      ```
   - Warm reboot T0 type
      ```bash
      export CONFIG_PARAMS==${CONFIG_PARAMS}" --sai_test_dir=SAI/test/sai_test --enable_t0_warmboot_test --sai_test_enable_deployment --skip_stop_sai_test_container"
      ```

3. Setup configurations.
   ```bash
   export LOG_LEVEL=info

   export INVT=ansible/str,ansible/veos
   export MPATH=ansible
   export TESTBED_FILE=ansible/testbed.yaml

   export ANSIBLE_CONFIG=ansible
   export ANSIBLE_LIBRARY=ansible/library/
   export ANSIBLE_CONNECTION_PLUGINS=ansible/plugins/connection/
   export ANSIBLE_KEEP_REMOTE_FILES=1
   export PYTEST_ADDOPTS="-vvvvv --allow_recover --skip_sanity --sai_test_report_dir=reports --py_saithrift_url=${PY_SAITHRIFT_URL} ${CONFIG_PARAMS}"
   ```

   Parameter description:
   - `INVT` and `TESTBED_FILE`: please read [this page.](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/tests/pytest.run.md#run-tests-by-pytest)
   - `ANSIBLE`: please read [this page.](https://github.com/sonic-net/sonic-mgmt/tree/master/docs/ansible)

### 3. Execute the corresponding type of testing command
Choose one of the following commands base on your test type.
   - PTF type
   ```bash
   pytest tests/sai_qualify/test_sai_ptf.py::test_sai --inventory $INVT --host-pattern all --module-path $MPATH --testbed $TESTBED_NAME --testbed_file $TESTBED_FILE --junit-xml=tr.xml --log-cli-level ${LOG_LEVEL} --collect_techsupport=False --topology='ptf'
   ```
  - T0 type
   ```bash
   pytest tests/sai_qualify/test_brcm_t0.py::test_sai --inventory $INVT --host-pattern all --module-path $MPATH --testbed $TESTBED_NAME --testbed_file $TESTBED_FILE --junit-xml=tr.xml --log-cli-level ${LOG_LEVEL} --collect_techsupport=False --topology='ptf'
   ```
  - Warm reboot PTF type
   ```bash
   pytest tests/sai_qualify/test_sai_ptf_warm_reboot.py::test_sai --inventory $INVT --host-pattern all --module-path $MPATH --testbed $TESTBED_NAME --testbed_file $TESTBED_FILE --junit-xml=tr.xml --log-cli-level ${LOG_LEVEL} --collect_techsupport=False --topology='ptf'
   ```
  - Warm reboot T0 type
   ```bash
   pytest tests/sai_qualify/test_sai_t0_warm_reboot.py::test_sai --inventory $INVT --host-pattern all --module-path $MPATH --testbed $TESTBED_NAME --testbed_file $TESTBED_FILE --junit-xml=tr.xml --log-cli-level ${LOG_LEVEL} --collect_techsupport=False --topology='ptf'
   ```

Examples of running SAI test cases can go to [this section](https://github.com/opencomputeproject/SAI/blob/master/ptf/docs/SAI-PTFv2Overview.md#run-test).
