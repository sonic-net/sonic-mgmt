# SONiC testbed management infrastructure
* The SONiC testbed consists of multiple interrelated configuration files that are difficult and error-prone edit manually.
* They are not frequently modified and only handful of persons like owners/admin has authority to modify them. But creating the initial setup or retrieving a broken setup is more challenging task for them.
* User scripts runs inside the docker container loads and access these files, and if the container is corrupted or crashed these files will be lost and will be difficult to get back easily. This will be challenging time for the user who doesn’t have the knowledge of interrelationship of the files.
# So how do we onboard engineer to write tests?
* Keep the testbed files in the separate repository outside the SONiC docker image.
* Provision the engineers to keep the code in their local machine and mount them while loading the docker container. So, code will be in the local directory and won’t get lost if the container is wrecked.
* Give the engineer a script to build the testbed from the stored files in the repository.

# Workflows
Please look into the [basic docker commands to create the sonic-mgmt environment](DockerCommands.md).
Please make sure that you have loaded the sonic docker image to be executed using docker load command.
```sudo docker load -i docker-sonic-mgmt```
### Setting up sonic-mgmt docker container.
* Fork the sonic-mgmt repo (https://github.com/sonic-net/sonic-mgmt).
    - Ex: git clone https://github.com/sonic-net/sonic-mgmt
* load the docker image such that it mounts sonic-mgmt inside the container (recommended).
    * <i> Make sure the path is matching the criteria</i>
    * sudo docker run -it --name sonic --privileged -v /home/ubuntu/sonic-mgmt/:/var/AzDevOps/sonic-mgmt  --user AzDevOps:gAzDevOps docker-sonic-mgmt
    * if no mount is required then run the command "sudo docker run -it --name sonic docker-sonic-mgmt" (optional)
* Install Snappi packages
    * python -m pip install --upgrade "snappi==0.9.1"
    * python -m pip install --upgrade "snappi[convergence]==0.4.1"
    * python -m pip install --upgrade "snappi[ixnetwork]==0.9.1"
* Mention the topology details in the following files
    - ansible/files/graph_groups.yml
    - ansible/files/sonic_snappi-sonic_devices.csv
    - ansible/files/sonic_snappi-sonic_links.csv
    - ansible/group_vars/snappi-sonic/secrets.yml
    - ansible/group_vars/snappi-sonic/snappi-sonic.yml
    - ansible/snappi-sonic
    - ansible/testbed.yaml
* Running the tests
  * cd ~/sonic-mgmt/tests/
  * Add environment variables
    * export ANSIBLE_CONFIG=../ansible
    * export ANSIBLE_LIBRARY=../ansible
  * Run Single-Dut case
    * py.test --inventory ../ansible/snappi-sonic --host-pattern sonic-s6100-dut1 --testbed vms-snappi-sonic --testbed_file ../ansible/testbed.yaml --show-capture=stdout --log-cli-level info --showlocals -ra --allow_recover --skip_sanity --disable_loganalyzer test_pretest.py
  * Run Multi-Dut case
    * py.test --inventory ../ansible/snappi-sonic --host-pattern all --testbed vms-snappi-sonic-multidut --testbed_file ../ansible/testbed.yaml --show-capture=stdout --log-cli-level info --showlocals -ra --allow_recover --skip_sanity --disable_loganalyzer test_pretest.py
 * Test script or code will remain intact even if docker image is destroyed unintentionally by keeping the code in the (mounted) local directory.


# Steps for Running snappi-tests Using sonic-mgmt Framework

## Step 1: Configure Device Inventory
**File:** `~/sonic-mgmt/ansible/files/sonic_snappi-sonic_devices.csv`

- Define all testbed components:
  - `snappi-sonic` → Ixia chassis
  - `sonic-s6100-dut1` & `sonic-s6100-dut2` → DUTs
  - `snappi-sonic-api-serv` → Ixia API server

---

## Step 2: Configure Link Mapping
**File:** `~/sonic-mgmt/ansible/files/sonic_snappi-sonic_links.csv`

- For each link:
  - `StartPort` → DUT interface
  - `EndPort` → Ixia card and port
  - Specify correct `speed` and `mode`
  - Define links for both DUTs if running multidut cases

---

## Step 3: Update snappi-sonic Testbed Configuration
**File:** `~/sonic-mgmt/ansible/snappi-sonic`

- Provide:
  - DUT IPs under `sonic-s6100-dut1` and `sonic-s6100-dut2`
  - Ixia chassis IP under `snappi-sonic`
  - Ixia API server IP under `snappi-sonic-ptf`

---

## Step 4: Verify DUT HWSKU Support
**File:** `~/sonic-mgmt/ansible/module_utils/port_utils.py`

- Ensure your DUT’s `hwsku` is defined
- Add the `hwsku` if it’s missing

---

## Step 5: Export Environment Variables
**Run inside** `~/sonic-mgmt/tests`:

- export ANSIBLE_CONFIG=../ansible
- export ANSIBLE_LIBRARY=../ansible

---

## Step 6: Run Pretest Script
**File:** `test_pretest.py`  
**Location:** `~/sonic-mgmt/tests`

Run the following command to execute the pretest:
- py.test --inventory ../ansible/snappi-sonic --host-pattern sonic-s6100-dut1 --testbed vms-snappi-sonic --testbed_file ../ansible/testbed.yaml --show-capture=stdout --log-cli-level info --showlocals -ra --allow_recover --skip_sanity --disable_loganalyzer test_pretest.py

## Step 7: Verify Pretest Output
**File:** `~/sonic-mgmt/tests/metadata/vms-snappi-sonic.json`

After running the pretest (`test_pretest.py`), verify the generated output:

- Ensure the interfaces (part for the test) listed in `vms-snappi-sonic.json` have:
  - `admin_state: up`
  - `oper_state: up`

- All other interfaces (not part of the test) should be:
  - `admin_state: down`
  - `oper_state: down`

✅ This step confirms that the test interfaces are correctly brought up and ready for the traffic tests.

## Step 8: Check Priority Mapping Files
**Directory:** `~/sonic-mgmt/tests/priority`

Verify the following three JSON files are correctly populated with traffic priorities:

- **`vms-snappi-sonic-all.json`**
  - Should include all priorities used for data traffic:
    ```text
    0, 1, 2, 3, 4, 5, 6
    ```
  - ❗ Priority `7` is excluded as it is reserved for control/management plane.

- **`vms-snappi-sonic-lossless.json`**
  - Should contain priorities:
    ```text
    3, 4
    ```

- **`vms-snappi-sonic-lossy.json`**
  - Should contain priorities:
    ```text
    0, 1, 2, 5, 6
    ```

 ⚠️ **Note:** These files control which priorities are treated as lossless vs lossy. Ensure they align with your QoS and traffic testing requirements. Also, make sure that you have enough permissions for creating those files. If not, it will not be able to create those files. 


## Step 9: Configure Minigraph on DUT
**File:** `/etc/sonic/minigraph.xml`

Make sure the DUT is properly configured using the `minigraph.xml` file:

- Include all interfaces that will be used in the test
- Use **interface alias names** for each interface
- Assign appropriate **IP addresses** to each interface
- Ensure the configuration matches your test setup:
  - If testing over **VLANs (Layer 2)**, ensure VLAN interfaces and members are correctly defined
  - If testing over **L3 interfaces**, confirm IP addressing and routing are in place

✅ This ensures the DUT interfaces are correctly initialized before running tests.

## Step 10: Apply Fanout Speed Mode Changes (Optional)
To enable **fanout speed mode**, apply the changes introduced in **PR#111111**.

- ⚙️ These changes are required to handle fanout port speed configurations correctly
- 🔄 Update the port naming convention as per the new format:
  - **Old Format:** `CardX/PortY`
  - **New Format:** `PortX.Y`

📌 Ensure your testbed and configuration files reflect this naming convention if you're using the fanout mode.

## Step 11: Custom Ixia API Server Credentials

By default, the Ixia API server uses `admin/admin`.

To use custom credentials:
- Edit `~/sonic-mgmt/tests/common/snappi_fixtures.py`
- Uncomment and update these lines:

api._username = "your_username"
api._password = "your_password"

## ⚠️ Additional Requirement: Configure PFC, ECN, and PFCWD on DUT

Before running **RDMA-related tests** (e.g., PFC, ECN, PFCWD), ensure the following configurations are already applied on the DUT:

- ✅ **PFC (Priority Flow Control)** configuration is preconfigured
- ✅ **ECN (Explicit Congestion Notification)** is enabled
- ✅ **PFCWD (PFC Watchdog)** is enabled by default

🛠️ The PFCWD configuration should be present in the DUT’s `config_db.json` file to ensure it is active on boot.

In case you're testing with **Aresone** hardware, set the PFC queue size to `4` by updating the `variable.py` file in the following location:

**File:** `~/sonic-mgmt/tests/common/snappi_tests/variable.py`

- Locate the line where the PFC queue size is defined and set it to `4`:
- pfcQueueGroupSize = 4

## Configuring DUT and Ixia Ports for BGP Tests

When running **BGP test cases**, the following fields will be used to configure the **DUT** and **Ixia ports**:

- **`dut_ip_start`**: Specifies the starting IP address for the DUT interface.
- **`snappi_ip_start`**: Specifies the starting IP address for the Ixia interface.

These fields will allow proper mapping and configuration of DUT and Ixia ports during BGP testing to ensure seamless traffic flow.
