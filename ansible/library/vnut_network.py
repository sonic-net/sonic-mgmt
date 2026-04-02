#!/usr/bin/python3
"""
Ansible module to manage virtual network links (veth pairs) for NUT virtual testbed.

Usage in Ansible:
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

import hashlib
import subprocess

from ansible.module_utils.basic import AnsibleModule


def run_cmd(cmd_args, check=True):
    """Run a command and return (rc, stdout, stderr).

    Args:
        cmd_args: List of command arguments (e.g. ["ip", "link", "show", "eth0"]).
        check: If True, raise RuntimeError on non-zero exit code.
    """
    result = subprocess.run(cmd_args, capture_output=True, text=True, timeout=60)
    if check and result.returncode != 0:
        raise RuntimeError(
            "Command failed: {}\nstdout: {}\nstderr: {}".format(
                " ".join(cmd_args), result.stdout.strip(), result.stderr.strip()
            )
        )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def link_exists_on_host(link_name):
    """Check if a network link exists on the host."""
    rc, _, _ = run_cmd(["ip", "link", "show", link_name], check=False)
    return rc == 0


def bridge_exists(bridge_name):
    """Check if a bridge exists on the host."""
    rc, _, _ = run_cmd(
        ["ip", "link", "show", "type", "bridge", "dev", bridge_name], check=False
    )
    return rc == 0


def get_container_pid(container_name):
    """Get the PID of a running Docker container."""
    rc, stdout, stderr = run_cmd(
        ["docker", "inspect", "-f", "{{.State.Pid}}", container_name], check=False
    )
    if rc != 0:
        raise RuntimeError(
            "Container '{}' not found or not running: {}".format(container_name, stderr)
        )
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
        ["nsenter", "-t", pid, "-n", "ip", "link", "show", iface_name], check=False
    )
    return rc == 0


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
        module.exit_json(
            changed=False,
            msg="Management interface eth0 already exists in {}".format(cname),
        )

    short_id = hashlib.md5(cname.encode()).hexdigest()[:8]
    veth_a = "vm{}a".format(short_id)  # 12 chars, well under 15
    veth_b = "vm{}b".format(short_id)  # 12 chars, well under 15

    # Clean up if host-side veth exists
    if link_exists_on_host(veth_a):
        run_cmd(["ip", "link", "delete", veth_a])

    # Create veth pair and move into container; clean up on failure
    run_cmd(["ip", "link", "add", veth_a, "type", "veth", "peer", "name", veth_b])
    try:
        # Move one end into container as eth0
        run_cmd(["ip", "link", "set", veth_a, "netns", pid])
        run_cmd(["nsenter", "-t", pid, "-n", "ip", "link", "set", veth_a, "name", "eth0"])
        run_cmd(["nsenter", "-t", pid, "-n", "ip", "addr", "add", mgmt_ip, "dev", "eth0"])
        run_cmd(["nsenter", "-t", pid, "-n", "ip", "link", "set", "eth0", "up"])
        run_cmd(["nsenter", "-t", pid, "-n", "ip", "route", "add", "default", "via", mgmt_gw])

        # Attach host end to bridge
        run_cmd(["ip", "link", "set", veth_b, "master", bridge])
        run_cmd(["ip", "link", "set", veth_b, "up"])
    except Exception:
        # Clean up the veth pair to avoid dangling interfaces
        for iface in (veth_a, veth_b):
            try:
                run_cmd(["ip", "link", "delete", iface])
            except Exception:
                pass  # Best-effort cleanup; re-raise original exception below
        raise

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

    run_cmd(["ip", "link", "add", bridge_name, "type", "bridge"])
    run_cmd(["ip", "addr", "add", bridge_ip, "dev", bridge_name])
    run_cmd(["ip", "link", "set", bridge_name, "up"])

    module.exit_json(
        changed=True,
        msg="Created bridge {} with IP {}".format(bridge_name, bridge_ip),
    )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            action=dict(
                type="str",
                required=True,
                choices=["connect_mgmt", "create_bridge"],
            ),
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
            ("action", "connect_mgmt", ["device", "mgmt_ip", "mgmt_gateway", "testbed_name"]),
            ("action", "create_bridge", ["bridge_name", "bridge_ip"]),
        ],
        supports_check_mode=False,
    )

    action = module.params["action"]

    try:
        if action == "connect_mgmt":
            action_connect_mgmt(module)
        elif action == "create_bridge":
            action_create_bridge(module)
    except RuntimeError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg="Unexpected error: {}".format(e))


if __name__ == "__main__":
    main()
