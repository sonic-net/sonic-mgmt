# Kubernetes Cluster Setup and SONiC DUT Join Operational Manuscript

This manuscript provides step-by-step instructions to set up a Kubernetes cluster using minikube and join a SONiC device (DUT/Virtual Switch) to the cluster. Each step includes verification commands to ensure successful execution.

## Command Location Guide

Throughout this document, commands are marked with these indicators:
- **[🖥️ LOCAL]** - Run on your local host/workstation
- **[🔧 DUT]** - Run on the DUT/Virtual Switch (e.g., vlab-01)

## Prerequisites

- **Local Host Requirements:**
  - Ubuntu/Debian Linux system with Docker installed
  - sudo privileges
  - Internet connection for downloading minikube
  - Network connectivity to the DUT

- **DUT/Virtual Switch Requirements:**
  - SONiC device with Kubernetes support
  - **CRITICAL:** SONiC version 202311 or later internal build (kubesonic functionality is NOT available in public SONiC images)
  - SSH access with admin credentials
  - ctrmgrd service running

## Step 1: Verify DUT/Virtual Switch Prerequisites

### 1.1 Verify Internal Build with kubeadm

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
which kubeadm
```

**Expected Output:**
```
/usr/bin/kubeadm
```

**If kubeadm is not found:** Your SONiC build does not include Kubernetes components. You need an internal build from 202311 or later.

### 1.2 Check SONiC Version

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
show version | head -1
```

**Expected Output:** SONiC version 202311 or later
```
SONiC Software Version: SONiC.20231101.xx or later
```

**IMPORTANT:** kubesonic functionality is only available in internal builds from 202311 onwards, not in public SONiC releases.

### 1.3 Check Kubernetes Version on DUT

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
kubeadm version -o short
```

**Expected Output:** (version may vary depending on SONiC build)
```
v1.22.2
```

### 1.4 Verify Kubernetes Configuration Command Availability

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
sudo config kube --help
```

**Expected Output:**
```
Usage: config kube [OPTIONS] COMMAND [ARGS]...

  kubernetes command line

Options:
  -?, -h, --help  Show this message and exit.

Commands:
  label   label configuration
  server  Server configuration
```

**If this command fails or is not found:** Your SONiC build does not include kubesonic functionality. You need a 202311+ internal build.

### 1.5 Verify ctrmgrd Service Status

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
systemctl status ctrmgrd | head -5
```

**Expected Output:**
```
● ctrmgrd.service - Container Manager watcher daemon
     Loaded: loaded (/lib/systemd/system/ctrmgrd.service; enabled; preset: enabled)
     Active: active (running) since [timestamp]
   Main PID: [pid] (ctrmgrd.py)
      Tasks: 1
```

## Step 2: Install Minikube on Local Host

⚠️ **CRITICAL:** The following steps (2.1-2.2) must be run on your **LOCAL HOST/WORKSTATION**, NOT on the DUT/Virtual Switch!

### 2.1 Download Minikube Binary

**[🖥️ LOCAL] Command:**
```bash
curl -L https://github.com/kubernetes/minikube/releases/download/v1.34.0/minikube-linux-amd64 \
  -o /tmp/minikube-linux-amd64 --max-time 360
```

**Expected:** Download completes successfully (file is ~99MB)

### 2.2 Install Minikube

**[🖥️ LOCAL] Command:**
```bash
sudo install /tmp/minikube-linux-amd64 /usr/local/bin/minikube
rm -f /tmp/minikube-linux-amd64
```

**[🖥️ LOCAL] Verification:**
```bash
minikube version
```

**Expected Output:**
```
minikube version: v1.34.0
```

## Step 3: Setup Kubernetes Master with Minikube

### 3.1 Clean Up Any Existing Minikube Setup

**[🖥️ LOCAL] Command:**
```bash
minikube delete --all --purge
```

**Expected Output:**
```
* Successfully deleted all profiles
* Successfully purged minikube directory located at - [/home/[username]/.minikube]
```

### 3.2 Get Local Host IP Address

**[🖥️ LOCAL] Command:**
```bash
hostname -I | awk '{print $1}'
```

**Expected Output:** Your local IP address (e.g., `<YOUR_HOST_IP>`)

**Note:** Save this IP address as `VMHOST_IP` - you'll need it in subsequent steps.

### 3.3 Start Minikube with Custom Configuration

**[🖥️ LOCAL] Command:**
```bash
VMHOST_IP=<YOUR_HOST_IP>  # Replace with your actual IP from step 3.2

minikube start \
  --listen-address=0.0.0.0 \
  --apiserver-port=6443 \
  --ports=6443:6443 \
  --extra-config=kubeadm.skip-phases=addon/kube-proxy,addon/coredns \
  --install-addons=false \
  --kubernetes-version=v1.22.2 \
  --apiserver-ips=${VMHOST_IP} \
  --force
```

**Expected Output:**
```
* minikube v1.34.0 on Ubuntu [version]
* Automatically selected the docker driver
* Starting "minikube" primary control-plane node in "minikube" cluster
* Creating docker container (CPUs=2, Memory=[size]MB)
* Preparing Kubernetes v1.22.2 on Docker
* Verifying Kubernetes components...
* Done! kubectl is now configured to use "minikube" cluster
```

### 3.4 Verify Minikube is Ready

**[🖥️ LOCAL] Command:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- get node minikube --no-headers
```

**Expected Output:**
```
minikube   Ready   control-plane,master   [age]   v1.22.2
```

## Step 4: Configure System and Kubelet

### 4.1 Update Kernel Parameter

**[🖥️ LOCAL] Command:**
```bash
sudo sysctl fs.protected_regular=0
```

**Expected Output:**
```
fs.protected_regular = 0
```

### 4.2 Update Kubelet Configuration for DUT Compatibility

**[🖥️ LOCAL] Commands:**
```bash
# Get current kubelet config
NO_PROXY=192.168.49.2 minikube kubectl -- get cm kubelet-config-1.22 \
  -n kube-system -o yaml > /tmp/kubelet-config.yaml

# Update CA certificate path
sed 's|/var/lib/minikube/certs/ca.crt|/etc/kubernetes/pki/ca.crt|' \
  -i /tmp/kubelet-config.yaml

# Apply updated config
NO_PROXY=192.168.49.2 minikube kubectl -- apply -f /tmp/kubelet-config.yaml
```

**Expected Output:**
```
configmap/kubelet-config-1.22 configured
```

## Step 5: Deploy Test DaemonSet

### 5.1 Create DaemonSet YAML

**[🖥️ LOCAL] Command:**
```bash
cat > /tmp/daemonset.yaml << 'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: test-daemonset
spec:
  selector:
    matchLabels:
      group: test-ds-pod
  template:
    metadata:
      labels:
        group: test-ds-pod
    spec:
      nodeSelector:
        deployDaemonset: "true"
      hostNetwork: true
      containers:
      - image: k8s.gcr.io/pause:3.5
        name: mock-ds-container
EOF
```

### 5.2 Deploy the DaemonSet

**[🖥️ LOCAL] Command:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- apply -f /tmp/daemonset.yaml
```

**Expected Output:**
```
daemonset.apps/test-daemonset created
```

### 5.3 Verify DaemonSet Creation

**[🖥️ LOCAL] Command:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- get daemonset test-daemonset
```

**Expected Output:**
```
NAME             DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR           AGE
test-daemonset   0         0         0       0            0           deployDaemonset=true   [age]
```

## Step 6: Prepare DUT for Joining

### 6.1 Check K8s State Database

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
sonic-db-cli STATE_DB hget 'KUBERNETES_MASTER|SERVER' update_time
```

**Expected Output:** A timestamp (e.g., `2025-09-22 22:05:41`)

**[🔧 DUT] If empty, initialize it on the DUT:**
```bash
sonic-db-cli STATE_DB hset 'KUBERNETES_MASTER|SERVER' \
  update_time '2024-12-24 01:01:01'
sudo systemctl restart ctrmgrd
```

### 6.2 Extract Certificates from Minikube

**[🖥️ LOCAL] Commands:**
```bash
# Extract certificates
docker exec minikube cat /var/lib/minikube/certs/apiserver.crt > /tmp/apiserver.crt
docker exec minikube cat /var/lib/minikube/certs/apiserver.key > /tmp/apiserver.key

# Verify certificates were extracted
ls -la /tmp/apiserver.* | wc -l
```

**Expected Output:**
```
2
```

### 6.3 Transfer Certificates to DUT

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
# Backup existing credentials
sudo bash -c 'if [ -d /etc/sonic/credentials ]; then \
  mv /etc/sonic/credentials /etc/sonic/credentials.bak; fi'

# Create credentials directory
sudo mkdir -p /etc/sonic/credentials
```

**[🖥️ LOCAL] On the Local Host, copy certificates to DUT:**
```bash
scp /tmp/apiserver.crt admin@<DUT_IP>:/tmp/apiserver.crt
scp /tmp/apiserver.key admin@<DUT_IP>:/tmp/apiserver.key
```

**[🔧 DUT] Back on the DUT/Virtual Switch, move certificates to proper location:**
```bash
sudo mv /tmp/apiserver.crt /etc/sonic/credentials/restapiserver.crt
sudo mv /tmp/apiserver.key /etc/sonic/credentials/restapiserver.key
```

**[🔧 DUT] Verification on the DUT:**
```bash
sudo ls -la /etc/sonic/credentials/
```

**Expected Output:**
```
total [size]
drwxr-xr-x 2 root root [size] [date] .
drwxr-xr-x [n] root root [size] [date] ..
-rw-r--r-- 1 root root [size] [date] restapiserver.crt
-rw-r--r-- 1 root root [size] [date] restapiserver.key
```

### 6.4 Configure DNS for Minikube VIP

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
VMHOST_IP=<YOUR_HOST_IP>  # Use your IP from step 3.2

grep "${VMHOST_IP} control-plane.minikube.internal" /etc/hosts || \
  echo "${VMHOST_IP} control-plane.minikube.internal" | sudo tee -a /etc/hosts
```

**Expected Output:**
```
<YOUR_HOST_IP> control-plane.minikube.internal
```

**[🔧 DUT] Verification on the DUT:**
```bash
grep minikube /etc/hosts
```

## Step 7: Join DUT to Kubernetes Cluster

### 7.1 Configure K8s Server IP

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
VMHOST_IP=<YOUR_HOST_IP>  # Use your IP from step 3.2

sudo config kube server ip ${VMHOST_IP}
```

### 7.2 Enable Kubernetes on DUT

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
sudo config kube server disable off
```

### 7.3 Wait and Verify Join Status

**[🖥️ LOCAL] On the Local Host, run:**
```bash
# Wait for join process
sleep 10

# Check if DUT joined the cluster (replace <DUT_HOSTNAME> with actual hostname)
NO_PROXY=192.168.49.2 minikube kubectl -- get nodes <DUT_HOSTNAME>
```

**Expected Output:**
```
NAME            STATUS   ROLES    AGE   VERSION
<DUT_HOSTNAME>  Ready    <none>   [age]   v1.22.2
```

**Note:** The status should show "Ready". If it shows "NotReady", wait another 10 seconds and check again.

## Step 8: Verify DaemonSet Deployment

### 8.1 Label DUT Node

**[🖥️ LOCAL] On the Local Host, run:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- label node <DUT_HOSTNAME> deployDaemonset=true
```

**Expected Output:**
```
node/<DUT_HOSTNAME> labeled
```

### 8.2 Wait for Pod Deployment and Verify

**[🖥️ LOCAL] On the Local Host, run:**
```bash
# Wait for pod scheduling
sleep 15

# Check pod status
NO_PROXY=192.168.49.2 minikube kubectl -- get pods -l group=test-ds-pod \
  --field-selector spec.nodeName=<DUT_HOSTNAME>
```

**Expected Output:**
```
NAME                   READY   STATUS    RESTARTS   AGE
test-daemonset-[hash]  1/1     Running   0          [age]
```

### 8.3 Verify Container on DUT

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
docker ps | grep mock-ds-container
```

**Expected Output:**
```
[container-id]   [image-id]   "/pause"   [time] ago   Up [time]   k8s_mock-ds-container_test-daemonset-[hash]_default_[uuid]_0
```

## Step 9: Test DaemonSet Removal

### 9.1 Remove Label from DUT

**[🖥️ LOCAL] On the Local Host, run:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- label node <DUT_HOSTNAME> deployDaemonset-
```

**Expected Output:**
```
node/<DUT_HOSTNAME> unlabeled
```

### 9.2 Verify Pod Removal

**[🖥️ LOCAL] On the Local Host, run:**
```bash
# Wait for pod termination
sleep 15

# Check that pod is removed
NO_PROXY=192.168.49.2 minikube kubectl -- get pods -l group=test-ds-pod \
  --field-selector spec.nodeName=<DUT_HOSTNAME>
```

**Expected Output:**
```
No resources found in default namespace.
```

### 9.3 Verify Container Removed from DUT

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
docker ps | grep mock-ds-container || echo 'Container not found'
```

**Expected Output:**
```
Container not found
```

## Step 10: Disjoin DUT from Cluster

### 10.1 Disable Kubernetes on DUT

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
sudo config kube server disable on
```

### 10.2 Verify Node Removal

**[🖥️ LOCAL] On the Local Host, run:**
```bash
# Wait for node removal
sleep 20

# Check node is removed
NO_PROXY=192.168.49.2 minikube kubectl -- get nodes <DUT_HOSTNAME> 2>&1
```

**Expected Output:**
```
Error from server (NotFound): nodes "<DUT_HOSTNAME>" not found
```

## Cleanup (Optional)

### Clean Up DUT

**[🔧 DUT] On the DUT/Virtual Switch, run:**
```bash
# Remove DNS entry
sudo sed -i '/control-plane.minikube.internal/d' /etc/hosts

# Restore original certificates
sudo bash -c 'if [ -d /etc/sonic/credentials.bak ]; then \
  rm -rf /etc/sonic/credentials && mv /etc/sonic/credentials.bak /etc/sonic/credentials; fi'

# Clean K8s config
sudo sonic-db-cli CONFIG_DB DEL 'KUBERNETES_MASTER|SERVER'
```

### Clean Up Local Host

**[🖥️ LOCAL] Commands:**
```bash
# Stop and delete minikube
minikube delete --all --purge

# Remove minikube binary
sudo rm -f /usr/local/bin/minikube

# Restore kernel parameter
sudo sysctl fs.protected_regular=2

# Clean up temp files
rm -f /tmp/apiserver.* /tmp/kubelet-config.yaml /tmp/daemonset.yaml
```

## Troubleshooting

### Issue: DUT Shows NotReady Status

**[🔧 DUT] On the DUT/Virtual Switch, check kubelet logs:**
```bash
sudo journalctl -u kubelet -n 50
```

### Issue: DaemonSet Pod Not Starting

**[🖥️ LOCAL] Check pod events:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- describe pods -l group=test-ds-pod
```

### Issue: Certificate Errors

**[🔧 DUT] On the DUT/Virtual Switch, verify certificate content:**
```bash
sudo openssl x509 -in /etc/sonic/credentials/restapiserver.crt -text -noout | grep Subject
```

### Issue: Network Connectivity

**[🔧 DUT] On the DUT/Virtual Switch, test connectivity to master:**
```bash
VMHOST_IP=<YOUR_HOST_IP>  # Replace with your actual host IP
curl -k https://${VMHOST_IP}:6443/healthz
```

**Expected Output:**
```
ok
```

## Summary

This manuscript provides a complete operational procedure for:
1. Setting up a Kubernetes master using minikube
2. Configuring the environment for SONiC device compatibility
3. Joining DUT to the Kubernetes cluster
4. Deploying and managing workloads on DUT
5. Safely removing DUT from the cluster

Each step includes verification commands to ensure successful execution before proceeding to the next step. The procedure has been tested and validated on actual hardware following the test_k8s_join_disjoin.py implementation.