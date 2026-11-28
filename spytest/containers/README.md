# Setting up sonic-mgmt docker container

Two container solutions are provided side by side per your TGEN selection:

| Solution | TGEN | Container dir | Ubuntu base |
|----------|------|---------------|-------------|
| **A. Keysight / Ixia** | IxNetwork | `keysight-ubuntu18/` | 22.04 (jammy) |
| **B. VIAVI TestCenter (STC)** | VIAVI TestCenter (STC) | `viavi-ubuntu/` | 24.04 (noble) |

---

## Common host setup

Follow the steps in [Prepare Testbed Server](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.Setup.md)
and read the [SPyTest documentation](../Doc/README.md).

Clone the sonic-mgmt repo:

```
git clone https://github.com/sonic-net/sonic-mgmt
```

---

## Solution A - Keysight / Ixia (IxNetwork)

download `https://downloads.ixiacom.com/support/downloads_and_updates/public/ixnetwork/9.30/IxNetworkAPI9.30.2212.7Linux64.bin.tgz` in the current directory
```
tar zxvf ./IxNetworkAPI9.30.2212.7Linux64.bin.tgz
cp ./IxNetworkAPI9.30.2212.7Linux64.bin ./sonic-mgmt/spytest/containers/keysight-ubuntu18/
```

### Build container

```
docker build --no-cache --tag spytest/keysight-u18:latest ./sonic-mgmt/spytest/containers/keysight-ubuntu18
docker tag spytest/keysight-u18:latest spytest/keysight-u18:9.30.2212.7
```

---

## Solution B - VIAVI TestCenter (STC)

Contact VIAVI support to obtain the STC Linux installer
(`install_Spirent_TestCenter_Auto_Linux64_5.62.sh` for the default version).
The `docker build` step copies and runs the installer to bake STC into the
image, so the file must be present in the build context (`viavi-ubuntu/`)
before building:

```
cp ./install_Spirent_TestCenter_Auto_Linux64_5.62.sh ./sonic-mgmt/spytest/containers/viavi-ubuntu/
```

To use a different STC version, substitute the version in the filename and
pass `--build-arg stc_version=<version>` to `docker build`.

### Build container

```
docker build --no-cache --tag spytest/viavi-u24:latest ./sonic-mgmt/spytest/containers/viavi-ubuntu
docker tag spytest/viavi-u24:latest spytest/viavi-u24:5.62
```

---

## Running tests

Follow the steps in [SPyTest intro - Testbed section](https://github.com/sonic-net/sonic-mgmt/blob/master/spytest/Doc/intro.md),
then copy and edit a testbed file into `./testbeds/` with the correct TGEN entry
(`type: ixia` or `type: stc`).


### Solution A - Keysight / Ixia (IxNetwork)

```
docker run --network host -v $PWD:/data --mount src=/etc/localtime,target=/etc/localtime,type=bind,readonly -it spytest/keysight-u18 bash
cd /data/sonic-mgmt/spytest
./bin/spytest --testbed-file ./testbeds/testbed_file.yaml --logs-path ./logs --log-level debug --test-suite community-legacy
```

### Solution B - VIAVI TestCenter (STC)

```
docker run --network host -v $PWD:/data --mount src=/etc/localtime,target=/etc/localtime,type=bind,readonly -it spytest/viavi-u24 bash
```

The only difference from an Ixia run is the `TGEN` device entry in the testbed
file - the CLI and the test scripts are identical. The `community-legacy` suite,
however, was curated and verified against Ixia, and has **not yet been fully
verified** against VIAVI TestCenter (STC). Please contact VIAVI support for
the list of test cases currently known to be supported on VIAVI TestCenter (STC).
