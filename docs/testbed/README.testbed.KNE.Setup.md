# One-Time Host Setup for KNE

This is a one-time setup for building a [KNE (Kubernetes Network Emulation)](https://github.com/openconfig/kne) environment on a bare metal server. It installs the required tools and deploys a single-node kind cluster with KNE's networking components and controllers.

## Prerequisites

- An Ubuntu or Debian server (x86_64)
- A user account with `sudo` access
- Outbound internet access for downloading packages, Go modules, and container images

## Tested Versions

| Component | Version |
|-----------|---------|
| Go        | 1.27.1 (1.23 or newer required) |
| kind      | v0.32.0 |
| KNE       | v0.3.2 |
| Docker    | 29.8.2 |
| kubectl   | v1.36.1 |

These versions were validated end-to-end on a fresh Ubuntu 24.04 install.

The KNE, kind, and kubectl versions are linked. KNE checks that kind is at least the version its deployment manifest requires, and kubectl must be within one minor version of the Kubernetes version KNE deploys (v1.36.1 for KNE v0.3.2). If you change the KNE version, update kind and kubectl to match.

---

## 1. Setup

### 1.1 Install Make and Build Tools

1. Update the package index and install the build dependencies:

   ```bash
   sudo apt-get update
   sudo apt-get install -y build-essential libpcap-dev
   ```

   `build-essential` provides `make`, `gcc`, and related tools. `libpcap-dev` provides the packet-capture headers needed to build KNE.

2. Verify:

   ```bash
   make --version
   gcc --version
   ```

### 1.2 Install Go (1.23 or newer)

1. Check whether Go is installed and which version:

   ```bash
   go version
   ```

2. If Go is missing or older than 1.23, download the official release:

   ```bash
   curl -LO https://go.dev/dl/go1.27.1.linux-amd64.tar.gz
   ```

   > **Note:** Don't use `sudo apt install golang-go`, even if your shell suggests it. On Ubuntu 24.04 it installs Go 1.21, which is too old for KNE.

3. Verify the download against its published checksum:

   ```bash
   echo "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445  go1.27.1.linux-amd64.tar.gz" | sha256sum --check
   ```

   This should print `go1.27.1.linux-amd64.tar.gz: OK`. On ARM servers, download `go1.27.1.linux-arm64.tar.gz` instead and use its checksum from [go.dev/dl](https://go.dev/dl/).

4. Remove any previous Go install, extract the new one, and clean up:

   ```bash
   sudo rm -rf /usr/local/go
   sudo tar -C /usr/local -xzf go1.27.1.linux-amd64.tar.gz
   rm go1.27.1.linux-amd64.tar.gz
   ```

   Removing `/usr/local/go` first matters on machines with an older Go, because extracting over an existing install can leave a broken mix of versions.

   `go` will still show "command not found" at this point. That's expected until you complete the next step.

5. Add Go and Go-installed binaries to your `PATH`:

   ```bash
   echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
   echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
   source ~/.bashrc
   ```

6. Verify:

   ```bash
   go version        # should report go1.27.1
   go env GOPATH     # typically $HOME/go
   ```

### 1.3 Install Docker

1. Add Docker's official GPG key:

   ```bash
   sudo apt-get install -y ca-certificates curl
   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc
   ```

2. Add the Docker repository:

   ```bash
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   ```

3. Install Docker Engine:

   ```bash
   sudo apt-get update
   sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```

   These commands are for Ubuntu. On Debian, follow the [Debian instructions](https://docs.docker.com/engine/install/debian/) instead. Don't install the `docker.io` package from Ubuntu's own repositories; use Docker's repository as shown above.

4. Let your user run Docker without `sudo`:

   ```bash
   sudo groupadd docker 2>/dev/null || true   # skip if the group already exists
   sudo usermod -aG docker $USER
   newgrp docker                              # applies to this shell only
   ```

   Log out and back in (or reboot) so the change applies to all sessions.

5. Verify:

   ```bash
   docker version
   docker run --rm hello-world
   ```

### 1.4 Install kubectl

1. Download kubectl v1.36.1, which matches the Kubernetes version KNE v0.3.2 deploys:

   ```bash
   curl -LO "https://dl.k8s.io/release/v1.36.1/bin/linux/amd64/kubectl"
   ```

   On ARM servers, replace `amd64` with `arm64`.

2. (Optional) Verify the download against its checksum:

   ```bash
   curl -LO "https://dl.k8s.io/release/v1.36.1/bin/linux/amd64/kubectl.sha256"
   echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check   # should print "kubectl: OK"
   ```

3. Install and clean up:

   ```bash
   sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
   rm -f kubectl kubectl.sha256
   ```

4. Verify:

   ```bash
   kubectl version --client     # should report v1.36.1
   ```

kubectl is supported within one minor version of the cluster's Kubernetes version. If you change the KNE version, check the `image:` line in `deploy/kne/kind-bridge.yaml` and pin kubectl to the matching version.

### 1.5 Install kind

1. Install kind using Go:

   ```bash
   go install sigs.k8s.io/kind@v0.32.0
   ```

   This places the binary in `$(go env GOPATH)/bin`, which you added to your `PATH` in step 1.2.

2. Verify:

   ```bash
   kind version     # should report kind v0.32.0
   ```

If you get `kind: command not found`, run `source ~/.bashrc` or open a new terminal. kind needs Docker running, so complete step 1.3 first.

### 1.6 Install KNE

1. Clone the upstream KNE repo into your home directory:

   ```bash
   git clone https://github.com/openconfig/kne.git ~/kne
   cd ~/kne
   ```

   KNE's defaults look for examples and manifests under `~/kne`, so keep this location.

2. Check out the tested release:

   ```bash
   git checkout v0.3.2
   ```

3. Build and install the CLI:

   ```bash
   make install
   ```

   This builds the `kne` binary and moves it to `/usr/local/bin` using `sudo`, so you'll be prompted for your password.

4. Verify:

   ```bash
   which kne     # should print /usr/local/bin/kne
   kne help
   ```

> **Note:** This guide uses upstream meshnet. Very large topologies may require additional meshnet tuning.

### 1.7 Deploy the KNE Cluster

1. Deploy the cluster with the standard manifest:

   ```bash
   cd ~/kne
   kne deploy deploy/kne/kind-bridge.yaml
   ```

   The deploy takes a few minutes. A successful run ends with `Deployment complete, ready for topology`.

   This brings up:
   - A single-node kind cluster named `kne`, using the bridge CNI plugin some network OSes need
   - The MetalLB load balancer with 100 IPs
   - meshnet-cni in gRPC mode
   - Controllers for IxiaTG, SR Linux, CEOSLab, and Lemming

2. Verify the cluster is running:

   ```bash
   kind get clusters      # should list "kne"
   kubectl get nodes      # kne-control-plane should be Ready, VERSION v1.36.1
   kubectl get pods -A    # all pods Running or Completed
   ```

   Pods can take a few minutes to settle after the deploy finishes.

   A successful installation looks like this:

   ```
   $ kubectl get pods -A
   NAMESPACE                        NAME                                                          READY   STATUS    RESTARTS   AGE
   arista-ceoslab-operator-system   arista-ceoslab-operator-controller-manager-6dfc7bcf78-nx79k   1/1     Running   0          5m35s
   ixiatg-op-system                 ixiatg-op-controller-manager-856899b996-d2f7g                 1/1     Running   0          5m35s
   kube-system                      coredns-589f44dc88-dmjvg                                      1/1     Running   0          5m35s
   kube-system                      coredns-589f44dc88-n8ffk                                      1/1     Running   0          5m35s
   kube-system                      etcd-kne-control-plane                                        1/1     Running   0          5m41s
   kube-system                      kindnet-g8nsb                                                 1/1     Running   0          5m35s
   kube-system                      kube-apiserver-kne-control-plane                              1/1     Running   0          5m40s
   kube-system                      kube-controller-manager-kne-control-plane                     1/1     Running   0          5m40s
   kube-system                      kube-proxy-p2smv                                              1/1     Running   0          5m35s
   kube-system                      kube-scheduler-kne-control-plane                              1/1     Running   0          5m40s
   lemming-operator                 lemming-controller-manager-5b9f6469c-rb8ld                    2/2     Running   0          5m35s
   local-path-storage               local-path-provisioner-855c7b7774-cpght                       1/1     Running   0          5m35s
   meshnet                          meshnet-tknx6                                                 1/1     Running   0          5m35s
   metallb-system                   controller-7d69cc69fd-qtvvr                                   1/1     Running   0          5m35s
   metallb-system                   speaker-rmgph                                                 1/1     Running   0          5m19s
   srlinux-controller               srlinux-controller-controller-manager-b6f69c477-mwkc4         1/1     Running   0          5m35s
   ```

   The random suffixes on pod names and the `AGE` values will differ on your machine. What matters is that you see all 16 pods across these namespaces, each fully ready (`1/1` or `2/2`) and `Running`. A pod stuck in `Pending`, `ImagePullBackOff`, or `CrashLoopBackOff`, or a steadily rising `RESTARTS` count, points to a problem. Check it with `kubectl describe pod -n <namespace> <pod-name>`.

---

## Troubleshooting

**`error: context "kind-kne" does not exist` at the start of the deploy**
This warning is expected on a fresh machine. KNE first tries to reuse an existing `kne` cluster, finds none, and creates a new one. No action needed.

**`unknown field "status.assignedIPv4"` warnings during the MetalLB step**
These are harmless. The deploy continues and reports ingress healthy.

**`IMAGE:gcr.io/kubebuilder/kube-rbac-proxy:... not found`**
KNE releases before v0.3.2 reference controller images from `gcr.io/kubebuilder`, which have been removed. Use KNE v0.3.2 as listed under Tested Versions, along with the matching kind and kubectl versions. Delete the failed cluster with `kind delete cluster --name kne` before redeploying. Existing clusters may keep working because the images are cached on the node, but they will fail the same way if rebuilt.

**`kind version check failed`**
Your kind version is older than the KNE manifest requires. Install the version named in the error message, or check that you checked out the KNE release listed under Tested Versions.

**`kind: command not found` or `kne: command not found`**
Your `PATH` isn't set up in the current shell. Run `source ~/.bashrc` or open a new terminal.

**`permission denied` when running Docker**
The docker group change hasn't applied to your session yet. Log out and back in, or run `newgrp docker`.

**`make install` appears to hang**
It's waiting for your `sudo` password.

**Existing `kne` cluster**
The manifest reuses an existing cluster named `kne` instead of creating a new one. To start fresh, run `kind delete cluster --name kne` first. This deletes all topologies running on that cluster.
