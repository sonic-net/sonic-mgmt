# SONiC Testbed Server OS Upgrade

## Introduction

This guide covers the safe, standard procedure to upgrade the Ubuntu LTS
version of a **testbed server** (the host machine that runs the SONiC testbed
VMs and topology). It includes prerequisites, step-by-step upgrade
instructions, and the post-upgrade configuration checks that are required to
keep the testbed fully functional (NIC port naming, netplan, and MTU).

> **Note:** This procedure applies to the testbed *server/host*, not to the
> SONiC DUT. Drain or pause any running tests and back up critical
> configuration before you start.

## Supported Upgrade Paths

Ubuntu supports direct upgrades between adjacent LTS (Long-Term Support)
versions:

| From      | To        | Supported? |
| --------- | --------- | ---------- |
| 18.04 LTS | 20.04 LTS | Yes        |
| 20.04 LTS | 22.04 LTS | Yes        |

## Pre-Upgrade Checklist

System requirements:

1. The server is connected to the internet.
2. Enough free disk space (at least 2-4 GB free).
3. `sudo`/root privileges.

## Upgrade Steps

### 1. Fully update the current system

```bash
sudo apt update
sudo apt upgrade -y
sudo apt dist-upgrade -y
sudo apt autoremove -y
```

If you are upgrading from 18.04 to 20.04, make sure `lxd` is uninstalled first:

```bash
sudo apt remove --purge lxd lxd-client
```

### 2. Check the upgrade tool

Ensure the upgrade manager is installed:

```bash
sudo apt install update-manager-core
```

Check the LTS prompt setting:

```bash
sudo cat /etc/update-manager/release-upgrades
```

Ensure it contains:

```
Prompt=lts
```

### 3. Pre-upgrade checks

**Record the 100G port renaming rules.** Capture the existing udev rules before
the upgrade so you can restore them afterwards if they are lost:

```bash
sudo ls /etc/udev/rules.d
```

### 4. Start the upgrade

```bash
sudo do-release-upgrade
```

- For any prompt to update a package or restart a service, choose **yes**.
- For any prompt asking whether to keep the current config file or use the
  maintainer's version, choose the **maintainer's version**.

### 5. Reboot and verify the version

The upgrade usually requests a reboot at the end. If it does not, reboot
manually:

```bash
sudo reboot
```

After reboot, verify the version:

```bash
lsb_release -a
```

## Post-Upgrade Configuration Checks

A release upgrade can reset NIC naming, netplan, and MTU settings. The
following checks restore testbed connectivity.

### a) Ensure passwordless sudo (NOPASSWD)

The testbed automation requires members of the `sudo` group to run commands
without a password prompt. Make sure the following line is present in the
sudoers configuration:

```
%sudo ALL=(ALL:ALL) NOPASSWD:ALL
```

**Recommended method** - edit safely with syntax checking using `visudo`:

```bash
sudo visudo
```

Look for:

```
%sudo ALL=(ALL:ALL) ALL
```

Either replace it, or comment it out and add the NOPASSWD line:

```
#%sudo ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) NOPASSWD:ALL
```

Save and exit (in `nano`: `Ctrl+O`, `Enter`, then `Ctrl+X`).

Verify (this should **not** prompt for a password):

```bash
sudo -k sudo ls
```

### b) Confirm 100G port renaming

Check whether the 100G port renaming rule is still present after the upgrade:

```bash
sudo ls /etc/udev/rules.d
```

If the rule is missing, re-add it. For a Mellanox 100G NIC:

1. Get the PCI IDs:

   ```bash
   lspci -D | grep -i ethernet | grep -i Mellanox
   ```

   Example output:

   ```
   0000:17:00.0 Ethernet controller: Mellanox Technologies MT2892 Family [ConnectX-6 Dx]
   0000:17:00.1 Ethernet controller: Mellanox Technologies MT2892 Family [ConnectX-6 Dx]
   ```

2. Add the following lines to `/etc/udev/rules.d/70-persistent-net.rules`
   (adjust the PCI IDs to match your server):

   ```
   ACTION=="add", SUBSYSTEM=="net", KERNELS=="0000:17:00.0", NAME:="ens4f0"
   ACTION=="add", SUBSYSTEM=="net", KERNELS=="0000:17:00.1", NAME:="ens4f1"
   ```

3. Reboot the server.

4. Verify the rename succeeded:

   ```bash
   lspci -D | grep -i ethernet | grep -i Mellanox
   ls -la /sys/class/net/ | grep -i 0000:17:00.
   ```

   Example output:

   ```
   ens4f0 -> ../../devices/pci0000:16/0000:16:02.0/0000:17:00.0/net/ens4f0
   ens4f1 -> ../../devices/pci0000:16/0000:16:02.0/0000:17:00.1/net/ens4f1
   ```

### c) Confirm netplan configuration for `ens4f0` and `ens4f1`

**1) Check whether `ens4f0` / `ens4f1` exist:**

```bash
ip a | egrep "ens4f0|ens4f1"
# or
ip link show ens4f0
ip link show ens4f1
```

If both interfaces are listed, you can stop here. If not, continue.

**2) Find the physical NIC names and MAC addresses:**

```bash
ip link show
# or, for a concise list:
for i in /sys/class/net/*; do printf "%-20s %s\n" "$(basename $i)" "$(cat $i/address)"; done
```

**3) Identify which netplan YAML file to edit:**

```bash
ls -l /etc/netplan/
cat /etc/netplan/<active-file>.yaml
```

> The active file may be `00-installer-config.yaml`, `01-netcfg.yaml`,
> `50-cloud-init.yaml`, etc. Use whichever exists on the host.

**4) Edit the active netplan YAML:**

```bash
sudo nano /etc/netplan/<active-file>.yaml
```

Add the interfaces under `ethernets:` (2-space indentation), for example:

```yaml
network:
  version: 2
  ethernets:
    ens4f0:
      dhcp4: no
    ens4f1:
      dhcp4: no
```

Save (`Ctrl+O`) and exit (`Ctrl+X`).

**5) Apply safely:**

```bash
sudo netplan try   # if the network stays stable, press ENTER to confirm before timeout
sudo netplan apply
```

**6) Verify interfaces and link state:**

```bash
ip a | egrep "ens4f0|ens4f1"
ip link show ens4f0
ip link show ens4f1
```

### d) Verify interface MTU

On some servers, after the upgrade the DUT stops receiving BGP updates from the
EOS container because the OVS rules on the server no longer forward BGP updates
correctly. The root cause is the upgraded server port MTU - it should be
**9216**.

Check and fix the MTU:

```bash
# Check the current MTU (shows "mtu 1500" if it is wrong)
ifconfig ens4f1

# Set the correct MTU
ip link set dev ens4f1 mtu 9216

# Verify (should now show "mtu 9216")
ifconfig ens4f1
```

Example before/after (truncated):

```
ens4f1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
...
ens4f1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9216
```

> To make the MTU persistent across reboots, set it in the netplan
> configuration for the interface (for example, add `mtu: 9216` under
> `ens4f1:`).
