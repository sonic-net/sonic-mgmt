import hashlib
import ipaddress
import json
import tarfile


def _image_fingerprint(architecture, os_name, variant, config, layers):
    # Docker's classic and containerd stores expose different kinds of image IDs.
    # Empty optional config fields also differ between save and inspect output.
    content = {
        "architecture": architecture, "os": os_name, "variant": variant,
        "config": {key: value for key, value in config.items() if value not in (None, "", [], {}, False)},
        "layers": layers,
    }
    return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def docker_image_fingerprint(image):
    """Identify runtime configuration and ordered rootfs layers independently of the image store."""
    return _image_fingerprint(
        image["Architecture"], image["Os"], image.get("Variant", ""), image["Config"], image["RootFS"]["Layers"])


def docker_archive_image_info(path, image_name=None):
    """Read a single-image docker-save archive without loading or retagging it."""
    with tarfile.open(path, "r:*") as archive:
        manifest = json.load(archive.extractfile("manifest.json"))
        if len(manifest) != 1:
            raise ValueError("A service upgrade requires an archive containing exactly one image")
        if image_name is not None and not any(
                tag.rsplit(":", 1)[0] == image_name for tag in manifest[0].get("RepoTags", []) or []):
            raise ValueError("Archive does not contain the expected service image {}".format(image_name))
        raw_config = archive.extractfile(manifest[0]["Config"]).read()
        config = json.loads(raw_config)
        return {
            "config_digest": "sha256:" + hashlib.sha256(raw_config).hexdigest(),
            "fingerprint": _image_fingerprint(
                config["architecture"], config["os"], config.get("variant", ""),
                config["config"], config["rootfs"]["diff_ids"]),
        }


def bgp_traffic_endpoints(minigraph, routes, routed=False):
    """Select installed BGP destinations and their actual physical/LAG egress ports."""
    indices = minigraph["minigraph_ptf_indices"]
    portchannels = minigraph["minigraph_portchannels"]
    connected = [
        ipaddress.ip_network("{}/{}".format(interface["addr"], interface["prefixlen"]), strict=False)
        for key in ("minigraph_interfaces", "minigraph_portchannel_interfaces", "minigraph_vlan_interfaces")
        for interface in minigraph.get(key, [])
        if ipaddress.ip_address(interface["addr"]).version == 4
    ]
    networks = {prefix: ipaddress.ip_network(prefix) for prefix in routes}
    prefixes = set(networks.values())
    candidates = {}
    for prefix, entries in routes.items():
        network = networks[prefix]
        if network.version != 4 or network.prefixlen == 0:
            continue
        address = network.network_address + (1 if network.num_addresses > 1 else 0)
        if any(address in subnet for subnet in connected):
            continue
        if any(ipaddress.ip_network((address, length), strict=False) in prefixes
               for length in range(network.prefixlen + 1, 33)):
            continue
        ports = set()
        for entry in entries:
            if not entry.get("selected") or entry.get("protocol") != "bgp":
                continue
            for nexthop in entry.get("nexthops", []):
                if not nexthop.get("fib"):
                    continue
                interface = nexthop.get("interfaceName")
                if not interface or interface in ('lo', 'Null0') or interface.startswith('Loopback'):
                    continue
                members = portchannels.get(interface, {}).get("members", [interface])
                if any(member not in indices for member in members):
                    raise ValueError("BGP route {} has an unmapped egress {}".format(prefix, interface))
                ports.update(indices[member] for member in members)
        if ports:
            key = tuple(sorted(ports))
            candidates.setdefault(key, {"prefix": prefix, "ip": str(address), "ports": list(key)})

    endpoints = sorted(candidates.values(), key=lambda endpoint: (-len(endpoint["ports"]), endpoint["prefix"]))
    if not endpoints:
        raise ValueError("No installed IPv4 BGP destination has mapped PTF egress ports")
    if not routed:
        return endpoints[:1]
    for first in endpoints:
        for second in endpoints:
            if not set(first["ports"]).intersection(second["ports"]):
                return [first, second]
    raise ValueError("Routed BGP traffic requires two destinations with disjoint egress ports")
