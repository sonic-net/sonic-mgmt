# Some Useful Links

<https://wiki.cisco.com/pages/viewpage.action?pageId=789404612> -- Sonic Test Pytest/Spytest/Sim based wiki

<https://wiki.cisco.com/display/HEROBU/Sonic-Mgmt+Pytest+Automation> - Helpful automation tips

## TB Reservation Link

[TB Reservation Link](https://cisco.sharepoint.com/:x:/r/sites/SONIC_on_SF/_layouts/15/doc2.aspx?sourcedoc=%7B535cf1e9-0fb7-4a26-b2aa-44a4d7d80c38%7D&action=edit&activeCell=%27Reservations%27!A5&wdinitialsession=4305bfce-d2c1-40c0-9d03-b1d9a5e908fc&wdrldsc=16&wdrldc=1&wdrldr=AccessTokenExpiredWarning%2CRefreshingExpiredAccessT)

## How to bring up a T0-64/T1-64-lag/T2 Sim based Sonic-mgmt setup

1. Pull sonic-test repo: [sonic-test repo](https://wwwin-github.cisco.com/gplatforms/sonic-test)
2. Navigate to the infra directory:

    ```bash
    cd sonic-test/infra
    ```

3. Build the testbed:

    ```bash
    ./create_sonic_topo.py -f <topo file> -c -u cisco -p cisco123 -t <topo_type>
    ```

    - `-c`: clean any pre-existing sim
    - `-u`: dut username
    - `-p`: dut password
    - `-f`: pyvxr yaml file describing the topology
    - `-t`: topology type, For now we support t0 and t1
    - `-d`: device type, options are sherman, mth32 (default)
    - `-b`: specify the location of your sonic-test tar ball. the tar ball will be pulled in and uploaded to the sonic-mgmt vm.

    Note that you should edit the yaml file to specify the SONiC image to load. If you are using DE workspace build, please see Troubleshooting #1 below.

4. For T1-64-lag:

    ```bash
    ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t1_64_lag_topo.yaml -c -u cisco -p cisco123 -t t1-64-lag
    ```

    - T1 YAML location: [mth64_sonic_t1_64_lag_topo.yaml](https://wwwin-github.cisco.com/gplatforms/sonic-test/blob/master/pyvxr_yaml_files/mth64_sonic_t1_64_lag_topo.yaml)

5. For T0-64:

    ```bash
    ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth32_sonic_t0_topo.yaml -c -u cisco -p cisco123 t t0 64
    ```

    - T0 YAML location: mth64_sonic_t0-64_topo.yaml

6. For T2 reduced topology:

    ```bash
    ./create_sonic_topo.py -f ../pyvxr_yaml_files/sonic_t2_2lc_min_ports-masic.yaml -u cisco -p cisco123 -t t2-min -d sfd -c -b http://172.29.93.10/sonic-images/golden-code/golden_code_202205.tar.gz
    ```

7. For running on 202205 Image:

    ```bash
    ./create_sonic_topo.py -f ../pyvxr_yaml_files/mth64_sonic_t1_64_lag_topo.yaml -c -u cisco -p cisco123 -t t1-64-lag -b http://172.29.93.10/sonic-images/golden-code/golden_code_202205.tar.gz
    ```

8. For T2:

    ```bash
    ./create_sonic_topo.py -f ../pyvxr_yaml_files/sonic_t2_2lc_min_ports-masic.yaml -u cisco -p cisco123 -t t2-min -d sfd -c -b http://172.29.93.10/sonic-images/golden-code/golden_code_202205.tar.gz -r -s sanity-scripts/sanity_scripts.txt
    ```

    Note: Only Gauntlet LC is supported. Work is in progress to support Vanguard.

    If you want to run sanity script while bringing up the testbed, use these additional options:
    - `-s sanity_script.txt`
    - `-r run sanity`

    Example:

    ```bash
    ./create_sonic_topo.py -f <topo file> -c -u cisco -p cisco123 -t <topo_type> -r -s sanity_script.txt
    ```

    At the end of the script, it will print the device details.

9. Log into the sonic-mgmt vm using VXR machine address as `cisco` user and `cisco123` password.

    ```bash
    ssh cisco@<vxr_machine_address>
    ```

10. Enter docker container:

    ```bash
    docker exec -it docker-sonic-mgmt /bin/bash
    ```

11. Testbed name: `docker-ptf`
12. DUT name: `sherman-01/mathilda-01`
