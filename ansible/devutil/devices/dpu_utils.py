import logging
import re
import time

logger = logging.getLogger(__name__)


def is_nat_enabled_for_dpu(npu_host):
    """Check if NAT DNAT rules for DPU SSH access exist on *npu_host*."""
    try:
        nat_output = npu_host.shell(
            "sudo iptables -t nat -L", module_ignore_errors=True
        ).get("stdout", "")
        pattern = r'.*DNAT.*tcp.*anywhere.*anywhere.*tcp dpt:.* to:169\.254\.200.*22.*'
        if re.search(pattern, nat_output):
            logger.info("NAT is already enabled on %s", npu_host.hostname)
            return True
    except Exception as e:
        logger.warning("Failed to check NAT status on %s: %s", npu_host.hostname, repr(e))
    return False


def get_dpu_name_ssh_port_dict(npu_host, inventories, dpu_hostnames):
    """Build a {dpuN: ssh_port} dict for DPUs that belong to *npu_host*."""
    from .factory import init_host  # local import to avoid circular dependency

    npu_hostname = npu_host.hostname
    dpu_name_ssh_port_dict = {}
    for dpu_hostname in dpu_hostnames:
        if npu_hostname not in dpu_hostname:
            continue
        try:
            dpu_host_obj = init_host(inventories, dpu_hostname)
            if dpu_host_obj:
                ssh_port = dpu_host_obj.get_host_visible_var(dpu_hostname, "ansible_ssh_port")
                if ssh_port:
                    match = re.search(r"dpu[.-]?(\d+)", dpu_hostname, re.IGNORECASE)
                    if match:
                        dpu_name = "dpu{}".format(match.group(1))
                        dpu_name_ssh_port_dict[dpu_name] = str(ssh_port)
                        logger.info("Found DPU %s with SSH port %s for NPU %s",
                                    dpu_name, ssh_port, npu_hostname)
        except Exception as e:
            logger.warning("Failed to get SSH port for %s: %s", dpu_hostname, repr(e))
    return dpu_name_ssh_port_dict


def is_pmon_running(npu_host, timeout=300, interval=30):
    """Wait for pmon container to come up on *npu_host*.

    Args:
        npu_host: AnsibleHost object for the NPU.
        timeout: Maximum time in seconds to wait (default 300).
        interval: Polling interval in seconds (default 30).

    Returns:
        True if pmon is running within the timeout, False otherwise.
    """
    max_attempts = timeout // interval
    for attempt in range(max_attempts):
        try:
            output = npu_host.shell("docker ps | grep pmon", module_ignore_errors=True)
            if "up" in output.get("stdout", "").lower():
                logger.info("pmon container is UP on %s", npu_host.hostname)
                return True
        except Exception:
            pass  # Shell may fail if device is still initializing; retry on next attempt
        logger.info("Waiting for pmon container on %s (attempt %d/%d)", npu_host.hostname, attempt + 1, max_attempts)
        time.sleep(interval)
    logger.warning("pmon container not up on %s after %ds", npu_host.hostname, timeout)
    return False


def enable_nat_for_dpuhosts(npu_sonichosts, inventories, dpu_hostnames):
    """Enable NAT on NPU hosts so DPU SSH proxy ports become reachable.

    This is the canonical implementation used by both ``upgrade_image.py``
    and ``testbed_health_check.py``.

    Args:
        npu_sonichosts: Iterable of AnsibleHost objects for NPU hosts
            (SonicHosts instance or plain list).
        inventories: Ansible inventory path(s).
        dpu_hostnames: List of DPU hostname strings.
    """
    if not dpu_hostnames:
        return

    logger.info("Enabling NAT for DPU hosts: %s", dpu_hostnames)

    for npu_host in npu_sonichosts:
        npu_hostname = npu_host.hostname

        if is_nat_enabled_for_dpu(npu_host):
            continue

        dpu_name_ssh_port_dict = get_dpu_name_ssh_port_dict(npu_host, inventories, dpu_hostnames)
        if not dpu_name_ssh_port_dict:
            logger.info("No DPUs found for NPU %s. Skipping NAT.", npu_hostname)
            continue

        # Wait for pmon container to come up before configuring NAT
        if not is_pmon_running(npu_host):
            logger.warning("Skipping NAT on %s — pmon not available.", npu_hostname)
            continue

        logger.info("Enabling NAT on %s for DPUs: %s", npu_hostname, dpu_name_ssh_port_dict)
        try:
            # Determine sysctl file based on OS version
            os_release = npu_host.shell(
                "cat /etc/os-release", module_ignore_errors=True
            ).get("stdout", "")
            is_bookworm = "bookworm" in os_release
            sysctl_file = "/etc/sysctl.conf" if is_bookworm else "/usr/lib/sysctl.d/90-sonic.conf"

            # Enable IP forwarding
            npu_host.shell("echo net.ipv4.ip_forward=1 >> {}".format(sysctl_file),
                           module_attrs={"become": True})
            npu_host.shell("echo net.ipv4.conf.eth0.forwarding=1 >> {}".format(sysctl_file),
                           module_attrs={"become": True})
            npu_host.shell("sysctl -p {}".format(sysctl_file),
                           module_attrs={"become": True})

            # Set up DNAT rules via sonic-dpu-mgmt-traffic.sh
            dpus_arg = ",".join(dpu_name_ssh_port_dict.keys())
            ports_arg = ",".join(dpu_name_ssh_port_dict.values())
            nat_cmd = "sonic-dpu-mgmt-traffic.sh inbound -e --dpus {} --ports {}".format(dpus_arg, ports_arg)
            npu_host.shell(nat_cmd, module_attrs={"become": True})

            # Persist iptables rules
            npu_host.shell("iptables-save > /etc/iptables/rules.v4",
                           module_attrs={"become": True})

            if is_nat_enabled_for_dpu(npu_host):
                logger.info("Successfully enabled NAT on %s", npu_hostname)
            else:
                logger.warning("NAT enablement verification failed on %s", npu_hostname)
        except Exception as e:
            logger.error("Failed to enable NAT on %s: %s", npu_hostname, repr(e))
