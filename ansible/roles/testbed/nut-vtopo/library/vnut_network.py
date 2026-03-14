#!/usr/bin/env python3
"""
Ansible module to manage virtual network links (veth pairs) for NUT virtual testbed.

Usage in Ansible:
  - name: Create cross-device link
    vnut_network:
      action: create_link
      link_id: "link_0"
      start_device: "switch-t0-1"
      start_port: "Ethernet0"
      end_device: "tg-1"
      end_port: "Port1.1"
      testbed_name: "nut-ci-1"
      container_prefix: "net"

  - name: Create self-link (loopback cable for L2 snake)
    vnut_network:
      action: create_link
      link_id: "link_1"
      start_device: "switch-t0-1"
      start_port: "Ethernet0"
      end_device: "switch-t0-1"
      end_port: "Ethernet4"
      testbed_name: "nut-ci-1"
      container_prefix: "net"

  - name: Delete all links for a testbed
    vnut_network:
      action: cleanup
      testbed_name: "nut-ci-1"
      container_prefix: "net"

  - name: Connect container to management bridge
    vnut_network:
      action: connect_mgmt
      device: "switch-t0-1"
      mgmt_ip: "10.0.0.100/24"
      mgmt_gateway: "10.0.0.1"
      mgmt_bridge: "br-mgmt"
      testbed_name: "nut-ci-1"
      container_prefix: "net"

  - name: Create management bridge
    vnut_network:
      action: create_bridge
      bridge_name: "br-mgmt"
      bridge_ip: "10.0.0.1/24"
"""

import subprocess

from ansible.module_utils.basic import AnsibleModule


def run_cmd(cmd, check=True):
    """Run a shell command and return (rc, stdout, stderr)."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            "Command failed: {}\nstdout: {}\nstderr: {}".format(
                cmd, result.stdout.strip(), result.stderr.strip()
            )
        )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def link_exists_on_host(link_name):
    """Check if a network link exists on the host."""
    rc, _, _ = run_cmd("ip link show {}".format(link_name), check=False)
    return rc == 0


def bridge_exists(bridge_name):
    """Check if a bridge exists on the host."""
    rc, _, _ = run_cmd("ip link show type bridge dev {}".format(bridge_name), check=False)
    return rc == 0


def get_container_pid(container_name):
    """Get the PID of a running Docker container."""
    rc, stdout, stderr = run_cmd(
        "docker inspect -f '{{{{.State.Pid}}}}' {}".format(container_name), check=False
    )
    if rc != 0:
        raise RuntimeError("Container '{}' not found or not running: {}".format(container_name, stderr))
    pid = stdout.strip()
    if pid == "0":
        raise RuntimeError("Container '{}' is not running (PID=0)".format(container_name))
    return pid


def container_name(prefix, testbed, device):
    """Build the Docker container name from components."""
    return "{}_{}_{}".format(prefix, testbed, device)


def interface_exists_in_ns(pid, iface_name):
    """Check if an interface exists inside a container network namespace."""
    rc, _, _ = run_cmd(
        "nsenter -t {} -n ip link show {}".format(pid, iface_name), check=False
    )
    return rc == 0


def action_create_link(module):
    """Create a veth pair and move ends into container namespace(s)."""
    p = module.params
    link_id = p["link_id"]
    start_device = p["start_device"]
    start_port = p["start_port"]
    end_device = p["end_device"]
    end_port = p["end_port"]
    testbed_name = p["testbed_name"]
    prefix = p["container_prefix"]

    veth_a = "{}-a".format(link_id)
    veth_b = "{}-b".format(link_id)

    start_container = container_name(prefix, testbed_name, start_device)
    end_container = container_name(prefix, testbed_name, end_device)

    # Get container PIDs
    start_pid = get_container_pid(start_container)
    if start_device == end_device:
        end_pid = start_pid
    else:
        end_pid = get_container_pid(end_container)

    # Check idempotency: if both target interfaces already exist, nothing to do
    if interface_exists_in_ns(start_pid, start_port) and interface_exists_in_ns(end_pid, end_port):
        module.exit_json(changed=False, msg="Link {} already exists".format(link_id))

    # Create veth pair on host
    if link_exists_on_host(veth_a):
        # Clean up stale host-side veth (deleting one end removes both)
        run_cmd("ip link delete {}".format(veth_a))

    run_cmd("ip link add {} type veth peer name {}".format(veth_a, veth_b))

    # Move start end into start container
    run_cmd("ip link set {} netns {}".format(veth_a, start_pid))
    run_cmd("nsenter -t {} -n ip link set {} name {}".format(start_pid, veth_a, start_port))
    run_cmd("nsenter -t {} -n ip link set {} up".format(start_pid, start_port))

    # Move end into end container (may be same container for self-links)
    run_cmd("ip link set {} netns {}".format(veth_b, end_pid))
    run_cmd("nsenter -t {} -n ip link set {} name {}".format(end_pid, veth_b, end_port))
    run_cmd("nsenter -t {} -n ip link set {} up".format(end_pid, end_port))

    module.exit_json(
        changed=True,
        msg="Created link {}: {}:{} <-> {}:{}".format(
            link_id, start_device, start_port, end_device, end_port
        ),
    )


def action_connect_mgmt(module):
    """Connect a container to a management bridge."""
    p = module.params
    device = p["device"]
    mgmt_ip = p["mgmt_ip"]
    mgmt_gw = p["mgmt_gateway"]
    bridge = p["mgmt_bridge"]
    testbed_name = p["testbed_name"]
    prefix = p["container_prefix"]

    cname = container_name(prefix, testbed_name, device)
    pid = get_container_pid(cname)

    # Idempotency: if eth0 already exists inside container, skip
    if interface_exists_in_ns(pid, "eth0"):
        module.exit_json(changed=False, msg="Management interface eth0 already exists in {}".format(cname))

    veth_a = "{}-mgmt-a".format(cname)
    veth_b = "{}-mgmt-b".format(cname)

    # Truncate veth names to 15 chars (kernel limit)
    veth_a = veth_a[:15]
    veth_b = veth_b[:15]

    # Clean up if host-side veth exists
    if link_exists_on_host(veth_a):
        run_cmd("ip link delete {}".format(veth_a))

    # Create veth pair
    run_cmd("ip link add {} type veth peer name {}".format(veth_a, veth_b))

    # Move one end into container as eth0
    run_cmd("ip link set {} netns {}".format(veth_a, pid))
    run_cmd("nsenter -t {} -n ip link set {} name eth0".format(pid, veth_a))
    run_cmd("nsenter -t {} -n ip addr add {} dev eth0".format(pid, mgmt_ip))
    run_cmd("nsenter -t {} -n ip link set eth0 up".format(pid))
    run_cmd("nsenter -t {} -n ip route add default via {}".format(pid, mgmt_gw))

    # Attach host end to bridge
    run_cmd("ip link set {} master {}".format(veth_b, bridge))
    run_cmd("ip link set {} up".format(veth_b))

    module.exit_json(
        changed=True,
        msg="Connected {} to bridge {} with IP {}".format(cname, bridge, mgmt_ip),
    )


def action_create_bridge(module):
    """Create a Linux bridge with an IP address."""
    p = module.params
    bridge_name = p["bridge_name"]
    bridge_ip = p["bridge_ip"]

    if bridge_exists(bridge_name):
        module.exit_json(changed=False, msg="Bridge {} already exists".format(bridge_name))

    run_cmd("ip link add {} type bridge".format(bridge_name))
    run_cmd("ip addr add {} dev {}".format(bridge_ip, bridge_name))
    run_cmd("ip link set {} up".format(bridge_name))

    module.exit_json(
        changed=True,
        msg="Created bridge {} with IP {}".format(bridge_name, bridge_ip),
    )


def action_cleanup(module):
    """Clean up orphaned veth pairs for a testbed."""
    p = module.params
    testbed_name = p["testbed_name"]
    prefix = p["container_prefix"]

    # List all host interfaces and find any matching our naming pattern
    pattern = "{}_{}_".format(prefix, testbed_name)
    rc, stdout, _ = run_cmd("ip -o link show", check=False)
    if rc != 0:
        module.exit_json(changed=False, msg="Could not list interfaces; nothing to clean")

    cleaned = []
    for line in stdout.splitlines():
        # Lines look like: "2: eth0@if3: <BROADCAST..."
        parts = line.split(":")
        if len(parts) < 2:
            continue
        iface = parts[1].strip().split("@")[0]
        if iface.startswith(pattern) or iface.startswith("link_"):
            # Only delete if it's a veth on the host (not inside a namespace)
            run_cmd("ip link delete {} 2>/dev/null || true".format(iface), check=False)
            cleaned.append(iface)

    if cleaned:
        module.exit_json(changed=True, msg="Cleaned up interfaces: {}".format(", ".join(cleaned)))
    else:
        module.exit_json(changed=False, msg="No orphaned interfaces found")


def main():
    module = AnsibleModule(
        argument_spec=dict(
            action=dict(
                type="str",
                required=True,
                choices=["create_link", "connect_mgmt", "create_bridge", "cleanup"],
            ),
            # create_link params
            link_id=dict(type="str"),
            start_device=dict(type="str"),
            start_port=dict(type="str"),
            end_device=dict(type="str"),
            end_port=dict(type="str"),
            # connect_mgmt params
            device=dict(type="str"),
            mgmt_ip=dict(type="str"),
            mgmt_gateway=dict(type="str"),
            mgmt_bridge=dict(type="str", default="br-mgmt"),
            # create_bridge params
            bridge_name=dict(type="str"),
            bridge_ip=dict(type="str"),
            # common params
            testbed_name=dict(type="str"),
            container_prefix=dict(type="str", default="net"),
        ),
        required_if=[
            ("action", "create_link", ["link_id", "start_device", "start_port", "end_device", "end_port", "testbed_name"]),
            ("action", "connect_mgmt", ["device", "mgmt_ip", "mgmt_gateway", "testbed_name"]),
            ("action", "create_bridge", ["bridge_name", "bridge_ip"]),
            ("action", "cleanup", ["testbed_name"]),
        ],
        supports_check_mode=False,
    )

    action = module.params["action"]

    try:
        if action == "create_link":
            action_create_link(module)
        elif action == "connect_mgmt":
            action_connect_mgmt(module)
        elif action == "create_bridge":
            action_create_bridge(module)
        elif action == "cleanup":
            action_cleanup(module)
    except RuntimeError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg="Unexpected error: {}".format(e))


if __name__ == "__main__":
    main()
