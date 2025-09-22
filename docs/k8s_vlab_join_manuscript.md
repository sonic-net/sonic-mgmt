# Kubernetes Cluster Setup and vlab-01 Join Operational Manuscript

This manuscript provides step-by-step instructions to set up a Kubernetes cluster using minikube and join a SONiC device (vlab-01) to the cluster. Each step includes verification commands to ensure successful execution.

## Prerequisites

- **Local Host Requirements:**
  - Ubuntu/Debian Linux system with Docker installed
  - sudo privileges
  - Internet connection for downloading minikube
  - Network connectivity to vlab-01

- **vlab-01 Requirements:**
  - SONiC device with Kubernetes support (K8s version v1.22.2)
  - SSH access with admin credentials
  - ctrmgrd service running

## Step 1: Verify vlab-01 Prerequisites

### 1.1 Check Kubernetes Version on vlab-01

**Command:**
```bash
ssh admin@vlab-01 "kubeadm version -o short"
```

**Expected Output:**
```
v1.22.2
```

### 1.2 Verify ctrmgrd Service Status

**Command:**
```bash
ssh admin@vlab-01 "systemctl status ctrmgrd | head -5"
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

### 2.1 Download Minikube Binary

**Command:**
```bash
curl -L https://github.com/kubernetes/minikube/releases/download/v1.34.0/minikube-linux-amd64 \
  -o /tmp/minikube-linux-amd64 --max-time 360
```

**Expected Output:**
```
100 99.0M  100 99.0M    0     0   [speed]      0 --:--:-- --:--:-- --:--:-- [speed]
```

### 2.2 Install Minikube

**Command:**
```bash
sudo install /tmp/minikube-linux-amd64 /usr/local/bin/minikube
rm -f /tmp/minikube-linux-amd64
```

**Verification:**
```bash
minikube version
```

**Expected Output:**
```
minikube version: v1.34.0
```

## Step 3: Setup Kubernetes Master with Minikube

### 3.1 Clean Up Any Existing Minikube Setup

**Command:**
```bash
minikube delete --all --purge
```

**Expected Output:**
```
* Successfully deleted all profiles
* Successfully purged minikube directory located at - [/home/[username]/.minikube]
```

### 3.2 Get Local Host IP Address

**Command:**
```bash
hostname -I | awk '{print $1}'
```

**Expected Output:** Your local IP address (e.g., `10.52.0.72`)

**Note:** Save this IP address as `VMHOST_IP` - you'll need it in subsequent steps.

### 3.3 Start Minikube with Custom Configuration

**Command:**
```bash
VMHOST_IP=10.52.0.72  # Replace with your actual IP from step 3.2

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

**Command:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- get node minikube --no-headers
```

**Expected Output:**
```
minikube   Ready   control-plane,master   [age]   v1.22.2
```

## Step 4: Configure System and Kubelet

### 4.1 Update Kernel Parameter

**Command:**
```bash
sudo sysctl fs.protected_regular=0
```

**Expected Output:**
```
fs.protected_regular = 0
```

### 4.2 Update Kubelet Configuration for DUT Compatibility

**Commands:**
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

**Command:**
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

**Command:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- apply -f /tmp/daemonset.yaml
```

**Expected Output:**
```
daemonset.apps/test-daemonset created
```

### 5.3 Verify DaemonSet Creation

**Command:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- get daemonset test-daemonset
```

**Expected Output:**
```
NAME             DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR           AGE
test-daemonset   0         0         0       0            0           deployDaemonset=true   [age]
```

## Step 6: Prepare vlab-01 for Joining

### 6.1 Check K8s State Database

**Command:**
```bash
ssh admin@vlab-01 "sonic-db-cli STATE_DB hget 'KUBERNETES_MASTER|SERVER' update_time"
```

**Expected Output:** A timestamp (e.g., `2025-09-22 22:05:41`)

If empty, initialize it:
```bash
ssh admin@vlab-01 "sonic-db-cli STATE_DB hset 'KUBERNETES_MASTER|SERVER' \
  update_time '2024-12-24 01:01:01'"
ssh admin@vlab-01 "sudo systemctl restart ctrmgrd"
```

### 6.2 Extract Certificates from Minikube

**Commands:**
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

### 6.3 Transfer Certificates to vlab-01

**Commands:**
```bash
# Backup existing credentials on vlab-01
ssh admin@vlab-01 "sudo bash -c 'if [ -d /etc/sonic/credentials ]; then \
  mv /etc/sonic/credentials /etc/sonic/credentials.bak; fi'"

# Create credentials directory
ssh admin@vlab-01 "sudo mkdir -p /etc/sonic/credentials"

# Copy certificates
scp /tmp/apiserver.crt admin@vlab-01:/tmp/apiserver.crt
scp /tmp/apiserver.key admin@vlab-01:/tmp/apiserver.key

# Move to proper location with correct names
ssh admin@vlab-01 "sudo mv /tmp/apiserver.crt /etc/sonic/credentials/restapiserver.crt"
ssh admin@vlab-01 "sudo mv /tmp/apiserver.key /etc/sonic/credentials/restapiserver.key"
```

**Verification:**
```bash
ssh admin@vlab-01 "sudo ls -la /etc/sonic/credentials/"
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

**Command:**
```bash
VMHOST_IP=10.52.0.72  # Use your IP from step 3.2

ssh admin@vlab-01 "grep '${VMHOST_IP} control-plane.minikube.internal' /etc/hosts || \
  echo '${VMHOST_IP} control-plane.minikube.internal' | sudo tee -a /etc/hosts"
```

**Expected Output:**
```
10.52.0.72 control-plane.minikube.internal
```

**Verification:**
```bash
ssh admin@vlab-01 "grep minikube /etc/hosts"
```

## Step 7: Join vlab-01 to Kubernetes Cluster

### 7.1 Configure K8s Server IP

**Command:**
```bash
VMHOST_IP=10.52.0.72  # Use your IP from step 3.2

ssh admin@vlab-01 "sudo config kube server ip ${VMHOST_IP}"
```

### 7.2 Enable Kubernetes on vlab-01

**Command:**
```bash
ssh admin@vlab-01 "sudo config kube server disable off"
```

### 7.3 Wait and Verify Join Status

**Commands:**
```bash
# Wait for join process
sleep 10

# Check if vlab-01 joined the cluster
NO_PROXY=192.168.49.2 minikube kubectl -- get nodes vlab-01
```

**Expected Output:**
```
NAME      STATUS   ROLES    AGE   VERSION
vlab-01   Ready    <none>   [age]   v1.22.2
```

**Note:** The status should show "Ready". If it shows "NotReady", wait another 10 seconds and check again.

## Step 8: Verify DaemonSet Deployment

### 8.1 Label vlab-01 Node

**Command:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- label node vlab-01 deployDaemonset=true
```

**Expected Output:**
```
node/vlab-01 labeled
```

### 8.2 Wait for Pod Deployment and Verify

**Commands:**
```bash
# Wait for pod scheduling
sleep 15

# Check pod status
NO_PROXY=192.168.49.2 minikube kubectl -- get pods -l group=test-ds-pod \
  --field-selector spec.nodeName=vlab-01
```

**Expected Output:**
```
NAME                   READY   STATUS    RESTARTS   AGE
test-daemonset-[hash]  1/1     Running   0          [age]
```

### 8.3 Verify Container on vlab-01

**Command:**
```bash
ssh admin@vlab-01 "docker ps | grep mock-ds-container"
```

**Expected Output:**
```
[container-id]   [image-id]   "/pause"   [time] ago   Up [time]   k8s_mock-ds-container_test-daemonset-[hash]_default_[uuid]_0
```

## Step 9: Test DaemonSet Removal

### 9.1 Remove Label from vlab-01

**Command:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- label node vlab-01 deployDaemonset-
```

**Expected Output:**
```
node/vlab-01 unlabeled
```

### 9.2 Verify Pod Removal

**Commands:**
```bash
# Wait for pod termination
sleep 15

# Check that pod is removed
NO_PROXY=192.168.49.2 minikube kubectl -- get pods -l group=test-ds-pod \
  --field-selector spec.nodeName=vlab-01
```

**Expected Output:**
```
No resources found in default namespace.
```

### 9.3 Verify Container Removed from vlab-01

**Command:**
```bash
ssh admin@vlab-01 "docker ps | grep mock-ds-container || echo 'Container not found'"
```

**Expected Output:**
```
Container not found
```

## Step 10: Disjoin vlab-01 from Cluster

### 10.1 Disable Kubernetes on vlab-01

**Command:**
```bash
ssh admin@vlab-01 "sudo config kube server disable on"
```

### 10.2 Verify Node Removal

**Commands:**
```bash
# Wait for node removal
sleep 20

# Check node is removed
NO_PROXY=192.168.49.2 minikube kubectl -- get nodes vlab-01 2>&1
```

**Expected Output:**
```
Error from server (NotFound): nodes "vlab-01" not found
```

## Cleanup (Optional)

### Clean Up vlab-01

```bash
# Remove DNS entry
ssh admin@vlab-01 "sudo sed -i '/control-plane.minikube.internal/d' /etc/hosts"

# Restore original certificates
ssh admin@vlab-01 "sudo bash -c 'if [ -d /etc/sonic/credentials.bak ]; then \
  rm -rf /etc/sonic/credentials && mv /etc/sonic/credentials.bak /etc/sonic/credentials; fi'"

# Clean K8s config
ssh admin@vlab-01 "sudo sonic-db-cli CONFIG_DB DEL 'KUBERNETES_MASTER|SERVER'"
```

### Clean Up Local Host

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

### Issue: vlab-01 Shows NotReady Status

**Check kubelet logs:**
```bash
ssh admin@vlab-01 "sudo journalctl -u kubelet -n 50"
```

### Issue: DaemonSet Pod Not Starting

**Check pod events:**
```bash
NO_PROXY=192.168.49.2 minikube kubectl -- describe pods -l group=test-ds-pod
```

### Issue: Certificate Errors

**Verify certificate content:**
```bash
ssh admin@vlab-01 "sudo openssl x509 -in /etc/sonic/credentials/restapiserver.crt -text -noout | grep Subject"
```

### Issue: Network Connectivity

**Test connectivity from vlab-01 to master:**
```bash
ssh admin@vlab-01 "curl -k https://${VMHOST_IP}:6443/healthz"
```

**Expected Output:**
```
ok
```

## Summary

This manuscript provides a complete operational procedure for:
1. Setting up a Kubernetes master using minikube
2. Configuring the environment for SONiC device compatibility
3. Joining vlab-01 to the Kubernetes cluster
4. Deploying and managing workloads on vlab-01
5. Safely removing vlab-01 from the cluster

Each step includes verification commands to ensure successful execution before proceeding to the next step. The procedure has been tested and validated on actual hardware following the test_k8s_join_disjoin.py implementation.