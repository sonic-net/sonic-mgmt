"""Test-scoped administrator policy for SetPackage remote downloads."""

import base64
import ipaddress
import json
import socket
from contextlib import contextmanager
from urllib.parse import urlparse


POLICY_PATH = "/etc/sonic/gnoi-download.json"


def image_origin_policy(image_url):
    """Pin only the operator-selected image origin for this test."""
    parsed = urlparse(image_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.fragment:
        raise ValueError("An HTTP(S) image URL without userinfo or fragment is required")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = [str(ipaddress.ip_address(parsed.hostname))]
    except ValueError:
        addresses = sorted({
            str(ipaddress.ip_address(result[4][0]))
            for result in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        })
    if not addresses or any("%" in address for address in addresses):
        raise ValueError("Image origin requires unscoped IP addresses")
    return {"origins": [{
        "scheme": parsed.scheme, "host": parsed.hostname,
        "port": port, "addresses": addresses,
    }]}


@contextmanager
def temporary_image_policy(host, image_url):
    """Restore prior bytes, ownership, permissions and absence even on failure."""
    policy = json.dumps(image_origin_policy(image_url))
    previous = host.stat(path=POLICY_PATH, follow=False)["stat"]
    if previous.get("exists") and not previous.get("isreg"):
        raise ValueError("Refusing to replace non-regular download policy")
    content = None
    if previous.get("exists"):
        # AnsibleHostBase serializes bytes as UTF-8. Reject an unrestorable
        # file before replacing it, rather than failing during teardown.
        content = base64.b64decode(host.slurp(src=POLICY_PATH)["content"]).decode("utf-8")
    try:
        host.copy(content=policy, dest=POLICY_PATH, owner="root", group="root", mode="0644")
        yield
    finally:
        if content is None:
            host.file(path=POLICY_PATH, state="absent")
        else:
            host.copy(
                content=content, dest=POLICY_PATH, owner=str(previous["uid"]),
                group=str(previous["gid"]), mode=previous["mode"],
            )


def snapshot_download_hosts(dpus):
    """Capture unique midplane identities before upgrade workers can reboot."""
    hosts = {}
    for dpu in dpus:
        address = (dpu.show_ip_interface()["ansible_facts"]["ip_interfaces"]
                   .get("eth0-midplane", {}).get("ipv4"))
        if not address or address in hosts:
            raise ValueError("Cannot uniquely map SetPackage target to an inventory DPU")
        hosts[address] = dpu
    return hosts
