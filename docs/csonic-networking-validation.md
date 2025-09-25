# cSONiC Networking Validation Guide

This guide provides step-by-step instructions to validate cSONiC networking capabilities through 5 isolated tests. These tests prove that cSONiC networking and BGP functionality work perfectly when properly configured.

## Prerequisites

1. **Docker installed and running**
2. **Root/sudo access**
3. **cSONiC docker image available**

### Load cSONiC Docker Image

```bash
# Load the docker-sonic-vs image (adjust path as needed)
docker load -i /path/to/docker-sonic-vs.gz

# Verify image is loaded
docker images | grep sonic-vs
```

---

## Task 1: Basic cSONiC Container Networking

**Goal**: Verify that a cSONiC container can start and perform basic networking operations.

### Step 1.1: Create Basic cSONiC Container

```bash
# Create a cSONiC container with network capabilities
docker run -d --name test_csonic_basic \
  --cap-add NET_ADMIN --privileged \
  docker-sonic-vs:latest
```

### Step 1.2: Verify Container is Running

```bash
# Check container status
docker ps | grep test_csonic_basic
```

### Step 1.3: Test Basic Network Configuration

```bash
# Configure IP address on eth0
docker exec test_csonic_basic ip addr add 192.168.1.1/24 dev eth0

# Bring up the interface
docker exec test_csonic_basic ip link set eth0 up

# Test connectivity (ping to self)
docker exec test_csonic_basic ping -c 3 192.168.1.1
```

**Expected Result**: 3 packets transmitted, 3 received, 0% packet loss

### Step 1.4: Clean Up Task 1

```bash
docker rm -f test_csonic_basic
```

---

## Task 2: cSONiC → eth1 Interface Connectivity

**Goal**: Verify cSONiC can use eth1 interface created via veth pair.

### Step 2.1: Create Network Namespace Container

```bash
# Create container to provide network namespace
docker run -d --name test_net_container \
  --cap-add NET_ADMIN debian:bookworm sleep infinity
```

### Step 2.2: Get Container PID and Create Veth Pair

```bash
# Get container PID
PID=$(docker inspect test_net_container --format '{{.State.Pid}}')
echo "Container PID: $PID"

# Create veth pair
sudo ip link add test-host type veth peer name test-container

# Move container end to network namespace and rename to eth1
sudo ip link set test-container netns $PID
sudo nsenter -t $PID -n ip link set test-container name eth1
```

### Step 2.3: Create cSONiC Container Using the Network

```bash
# Create cSONiC container sharing the network namespace
docker run -d --name test_csonic_eth1 \
  --network container:test_net_container \
  --cap-add NET_ADMIN --privileged \
  docker-sonic-vs:latest
```

### Step 2.4: Test eth1 Interface

```bash
# Wait for container to start
sleep 5

# Verify eth1 exists in cSONiC container
docker exec test_csonic_eth1 ip link show eth1

# Configure IP on eth1
docker exec test_csonic_eth1 ip addr add 192.168.2.1/24 dev eth1
docker exec test_csonic_eth1 ip link set eth1 up

# Bring up host side and configure IP
sudo ip link set test-host up
sudo ip addr add 192.168.2.2/24 dev test-host

# Test connectivity across veth pair
docker exec test_csonic_eth1 ping -c 3 192.168.2.2
```

**Expected Result**: 3 packets transmitted, 3 received, 0% packet loss

### Step 2.5: Clean Up Task 2

```bash
docker rm -f test_csonic_eth1 test_net_container
sudo ip link delete test-host 2>/dev/null || true
```

---

## Task 3: cSONiC → Host Veth Peer Connectivity (Packet Capture Proof)

**Goal**: Use packet capture to prove packets flow from cSONiC container to host interface.

### Step 3.1: Recreate Setup from Task 2

```bash
# Create network namespace container
docker run -d --name test_net_container \
  --cap-add NET_ADMIN debian:bookworm sleep infinity

# Get PID and create veth pair
PID=$(docker inspect test_net_container --format '{{.State.Pid}}')
sudo ip link add test-host type veth peer name test-container
sudo ip link set test-container netns $PID
sudo nsenter -t $PID -n ip link set test-container name eth1

# Create cSONiC container
docker run -d --name test_csonic_eth1 \
  --network container:test_net_container \
  --cap-add NET_ADMIN --privileged \
  docker-sonic-vs:latest

# Wait and configure interfaces
sleep 5
docker exec test_csonic_eth1 ip addr add 192.168.2.1/24 dev eth1
docker exec test_csonic_eth1 ip link set eth1 up
sudo ip link set test-host up
sudo ip addr add 192.168.2.2/24 dev test-host
```

### Step 3.2: Start Packet Capture and Test

```bash
# Start packet capture on host interface (in background)
sudo tcpdump -i test-host -n icmp &
TCPDUMP_PID=$!

# Wait a moment, then send pings from cSONiC
sleep 2
docker exec test_csonic_eth1 ping -c 3 192.168.2.2

# Wait and stop capture
sleep 2
sudo kill $TCPDUMP_PID
```

**Expected Result**: You should see ICMP packets in both directions:
```
IP 192.168.2.1 > 192.168.2.2: ICMP echo request
IP 192.168.2.2 > 192.168.2.1: ICMP echo reply
```

### Step 3.3: Clean Up Task 3

```bash
docker rm -f test_csonic_eth1 test_net_container
sudo ip link delete test-host 2>/dev/null || true
```

---

## Task 4: cSONiC-to-cSONiC Direct Layer 3 Connectivity

**Goal**: Establish direct ping connectivity between two cSONiC containers.

### Step 4.1: Create Network Namespaces for Both Containers

```bash
# Create network namespace containers
docker run -d --name net_csonic1 --cap-add NET_ADMIN debian:bookworm sleep infinity
docker run -d --name net_csonic2 --cap-add NET_ADMIN debian:bookworm sleep infinity
```

### Step 4.2: Create Veth Pair Connecting the Containers

```bash
# Create veth pair
sudo ip link add csonic1-eth1 type veth peer name csonic2-eth1

# Get container PIDs
PID1=$(docker inspect net_csonic1 --format '{{.State.Pid}}')
PID2=$(docker inspect net_csonic2 --format '{{.State.Pid}}')

# Move veth ends to respective containers and rename to eth1
sudo ip link set csonic1-eth1 netns $PID1
sudo ip link set csonic2-eth1 netns $PID2
sudo nsenter -t $PID1 -n ip link set csonic1-eth1 name eth1
sudo nsenter -t $PID2 -n ip link set csonic2-eth1 name eth1
```

### Step 4.3: Create cSONiC Containers

```bash
# Create both cSONiC containers
docker run -d --name csonic1 \
  --network container:net_csonic1 \
  --cap-add NET_ADMIN --privileged \
  docker-sonic-vs:latest

docker run -d --name csonic2 \
  --network container:net_csonic2 \
  --cap-add NET_ADMIN --privileged \
  docker-sonic-vs:latest

# Wait for containers to start
sleep 10
```

### Step 4.4: Configure IP Addresses and Test Connectivity

```bash
# Configure IP addresses on both containers
docker exec csonic1 ip addr add 10.1.1.1/24 dev eth1
docker exec csonic1 ip link set eth1 up

docker exec csonic2 ip addr add 10.1.1.2/24 dev eth1
docker exec csonic2 ip link set eth1 up

# Test bidirectional connectivity
echo "Testing csonic1 → csonic2:"
docker exec csonic1 ping -c 5 10.1.1.2

echo "Testing csonic2 → csonic1:"
docker exec csonic2 ping -c 3 10.1.1.1
```

**Expected Result**: Both pings should show 0% packet loss

---

## Task 5: cSONiC-to-cSONiC BGP Protocol

**Goal**: Establish BGP session between the two cSONiC containers from Task 4.

### Step 5.1: Start BGP Daemons

```bash
# Start BGP daemon on both containers
docker exec csonic1 /usr/lib/frr/bgpd -d -A 127.0.0.1
docker exec csonic2 /usr/lib/frr/bgpd -d -A 127.0.0.1

# Wait for daemons to start
sleep 5
```

### Step 5.2: Configure BGP

```bash
# Configure BGP on csonic1 (AS 65001)
docker exec csonic1 vtysh -c "configure terminal" \
  -c "router bgp 65001" \
  -c "bgp router-id 10.1.1.1" \
  -c "neighbor 10.1.1.2 remote-as 65002" \
  -c "exit" -c "exit"

# Configure BGP on csonic2 (AS 65002)
docker exec csonic2 vtysh -c "configure terminal" \
  -c "router bgp 65002" \
  -c "bgp router-id 10.1.1.2" \
  -c "neighbor 10.1.1.1 remote-as 65001" \
  -c "exit" -c "exit"
```

### Step 5.3: Verify BGP Session

```bash
# Wait for BGP session to establish
sleep 15

# Check BGP summary on both sides
echo "BGP Summary on csonic1:"
docker exec csonic1 vtysh -c "show bgp summary"

echo "BGP Summary on csonic2:"
docker exec csonic2 vtysh -c "show bgp summary"

# Check detailed neighbor status
echo "Detailed BGP neighbor status on csonic1:"
docker exec csonic1 vtysh -c "show bgp neighbor 10.1.1.2"
```

**Expected Results**:
- BGP Summary should show neighbor with exchanged messages (MsgRcvd/MsgSent > 0)
- Detailed status should show: `BGP state = Established`
- Session should be up for some duration (e.g., "up for 00:00:XX")

### Step 5.4: Clean Up All Tasks

```bash
# Remove all test containers
docker rm -f csonic1 csonic2 net_csonic1 net_csonic2

# Remove any remaining veth interfaces
sudo ip link delete csonic1-eth1 2>/dev/null || true
sudo ip link delete csonic2-eth1 2>/dev/null || true
```

---

## Summary

If all 5 tasks complete successfully, you have proven:

1. ✅ **Basic cSONiC networking** - Container starts and network stack works
2. ✅ **cSONiC → eth1 connectivity** - cSONiC can use topology-created interfaces
3. ✅ **Packet flow verification** - Traffic flows correctly across veth pairs
4. ✅ **cSONiC-to-cSONiC Layer 3** - Direct IP connectivity between containers
5. ✅ **cSONiC BGP protocol** - Full BGP session establishment and maintenance

This demonstrates that **cSONiC networking and BGP functionality are completely functional** when containers are properly initialized. Any issues in topology deployment are in the orchestration/automation layer, not in cSONiC's core networking capabilities.

## Troubleshooting

### Common Issues:

1. **"Permission denied" errors**: Make sure to use `sudo` for ip commands and ensure containers have `--cap-add NET_ADMIN --privileged`

2. **"Container not found" errors**: Verify containers are running with `docker ps`

3. **"Network unreachable" errors**: Check that both interfaces are UP and have correct IP addresses

4. **BGP session doesn't establish**: Verify both containers can ping each other first, and ensure BGP daemons started successfully

5. **tcpdump permission issues**: Run tcpdump commands with `sudo`

### Verification Commands:

```bash
# Check container status
docker ps

# Check interface status in container
docker exec <container> ip link show
docker exec <container> ip addr show

# Check BGP daemon status
docker exec <container> ps aux | grep bgp

# Check if interfaces can reach each other
docker exec <container> ping -c 1 <target_ip>
```