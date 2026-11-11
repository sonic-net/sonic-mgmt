#!/usr/bin/python
"""Collect private, read-only Generic HWSKU facts using the installed SONiC parser."""

import base64
import hashlib
import itertools
import json
import os
from pathlib import Path
import socket
import stat
import subprocess


class FactsError(ValueError):
    """The device cannot supply a required, unambiguous source fact."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical_expansions(platform, parser):
    """Keep the installed parser responsible for grammar, lanes, aliases and subports."""
    interfaces = platform.get("interfaces")
    if not isinstance(interfaces, dict) or not interfaces:
        raise FactsError("Installed platform.json has no interface capabilities")
    result = {}
    for cage, properties in sorted(interfaces.items()):
        modes = properties.get("breakout_modes")
        if not isinstance(modes, dict) or not modes:
            raise FactsError("Missing canonical breakout modes for " + cage)
        choices = []
        for mode in sorted(modes):
            handler = parser.BreakoutCfg(cage, mode, properties)
            entries = getattr(handler, "_breakout_mode_entry", None)
            if not entries or any(not hasattr(entry, "supported_speed") for entry in entries):
                raise FactsError("The installed canonical parser lacks its supported-speed contract")
            for speeds in itertools.product(*(sorted(entry.supported_speed) for entry in entries)):
                variant = parser.BreakoutCfg(cage, mode, properties)
                for entry, speed in zip(variant._breakout_mode_entry, speeds):
                    entry.default_speed = speed
                ports = variant.get_config()
                if not isinstance(ports, dict) or not ports:
                    raise FactsError("The canonical parser returned no PORT entries")
                for name, row in ports.items():
                    if not isinstance(name, str) or not isinstance(row, dict):
                        raise FactsError("Malformed canonical PORT entry")
                    for field in ("alias", "lanes", "speed", "index"):
                        if field not in row:
                            raise FactsError("Canonical PORT entry lacks " + field)
                identity = json.dumps([mode, speeds, ports], sort_keys=True, separators=(",", ":")).encode()
                choices.append({"id": sha256(identity)[:24], "name": mode,
                                "operating_speeds": list(speeds), "ports": ports})
        result[cage] = choices
    return result


def canonical_baseline(parser, platform, hwsku, port_config_file, hwsku_config_file=None):
    """Parse the installed base HWSKU explicitly, not the current CONFIG_DB breakout."""
    paths = {"baseline_ports": Path(port_config_file).resolve(strict=True)}
    options = {"platform": platform, "hwsku": hwsku, "port_config_file": str(paths["baseline_ports"])}
    if hwsku_config_file is not None:
        paths["baseline_hwsku"] = Path(hwsku_config_file).resolve(strict=True)
        options["hwsku_config_file"] = str(paths["baseline_hwsku"])
    original = {key: path.read_bytes() for key, path in paths.items()}
    reader = getattr(parser, "get_port_config", None)
    if not callable(reader):
        raise FactsError("The installed parser lacks its explicit base-HWSKU port API")
    parsed = reader(**options)
    if not isinstance(parsed, tuple) or len(parsed) != 3 or not isinstance(parsed[0], dict) or not parsed[0]:
        raise FactsError("The installed parser returned no base-HWSKU ports")
    for name, row in parsed[0].items():
        if (not isinstance(name, str) or not isinstance(row, dict)
                or not isinstance(row.get("lanes"), str) or not row["lanes"]):
            raise FactsError("The installed base-HWSKU port mapping lacks explicit lanes")
    if any(path.read_bytes() != original[key] for key, path in paths.items()):
        raise FactsError("The installed base-HWSKU mapping changed during parsing")
    return parsed[0], {key: {"path": str(path), "sha256": sha256(original[key])} for key, path in paths.items()}


def _read_json_command(arguments, component):
    try:
        return json.loads(subprocess.check_output(arguments, stderr=subprocess.PIPE))
    except subprocess.CalledProcessError as error:
        raise FactsError("{} collection failed with rc {}; private command output is withheld".format(
            component, error.returncode)) from error
    except json.JSONDecodeError as error:
        raise FactsError(component + " did not return JSON") from error


def _asset_path(value):
    if not isinstance(value, str) or not value or Path(value).name != value or value in (".", ".."):
        raise FactsError("Invalid platform/HWSKU metadata path component")
    return value


def applied_buffers(database=None):
    if database is None:
        from ansible.module_utils.multi_asic_utils import load_db_config
        from sonic_py_common import multi_asic
        from swsscommon.swsscommon import SonicV2Connector

        load_db_config()
        database = SonicV2Connector(namespace=multi_asic.get_namespace_list()[0])
        database.connect("APPL_DB")
    result = {}
    for table, prefix in (("pools", "BUFFER_POOL_TABLE:"), ("profiles", "BUFFER_PROFILE_TABLE:"),
                          ("pg", "BUFFER_PG_TABLE:")):
        result[table] = {}
        for key in sorted(database.keys("APPL_DB", prefix + "*") or []):
            value = database.get_all("APPL_DB", key)
            if not isinstance(value, dict) or not value:
                raise FactsError("Applied buffer state changed during collection: " + key)
            result[table][key[len(prefix):]] = value
    database.connect("STATE_DB")
    capacity = database.get_all("STATE_DB", "BUFFER_MAX_PARAM_TABLE|global") or {}
    result["mmu_size"] = capacity.get("mmu_size")
    return result


def transceiver_facts(ports, database=None):
    if database is None:
        from sonic_py_common import multi_asic
        from swsscommon.swsscommon import SonicV2Connector

        database = SonicV2Connector(namespace=multi_asic.get_namespace_list()[0])
    database.connect("STATE_DB")
    result = {}
    for port in sorted(ports):
        row = database.get_all("STATE_DB", "TRANSCEIVER_INFO|" + port) or {}
        if not isinstance(row, dict):
            raise FactsError("Transceiver capability state is malformed on " + port)
        if row:
            result[port] = {field: row[field] for field in (
                "type", "nominal_bit_rate", "specification_compliance") if field in row}
    return result


def collect(device_root="/usr/share/sonic/device", startup="/etc/sonic/config_db.json",
            version="/etc/sonic/sonic_version.yml"):
    """Return private raw facts, not an assertion that the device is deployment-ready."""
    import portconfig
    from sonic_py_common import device_info, multi_asic

    running = _read_json_command(["sonic-cfggen", "-d", "--print-data"], "running CONFIG_DB")
    metadata = running.get("DEVICE_METADATA", {}).get("localhost", {})
    platform_name, hwsku = (_asset_path(metadata.get(field)) for field in ("platform", "hwsku"))
    platform_dir = Path(device_root) / platform_name
    sku_dir = platform_dir / hwsku
    platform_candidates = [path for path in (platform_dir / "platform.json", sku_dir / "platform.json")
                           if path.is_file()]
    if not platform_candidates:
        raise FactsError("No installed platform.json")
    if len({sha256(path.read_bytes()) for path in platform_candidates}) != 1:
        raise FactsError("Conflicting installed platform.json sources require an explicit effective-source decision")
    platform_path = platform_candidates[0].resolve(strict=True)
    platform_bytes = platform_path.read_bytes()
    platform = json.loads(platform_bytes)
    baseline_path = device_info.get_path_to_port_config_file(hwsku)
    if not baseline_path:
        raise FactsError("No effective installed base-HWSKU port mapping")
    hwsku_path = portconfig.get_hwsku_file_name(hwsku, platform_name) if baseline_path.endswith(".json") else None
    if baseline_path.endswith(".json") and not hwsku_path:
        raise FactsError("The installed JSON port mapping lacks its base-HWSKU defaults")
    for path in [baseline_path] + ([hwsku_path] if hwsku_path else []):
        try:
            Path(path).resolve(strict=True).relative_to(platform_dir.resolve(strict=True))
        except ValueError as error:
            raise FactsError("The installed base-HWSKU mapping leaves the verified platform directory") from error
    baseline_ports, baseline_sources = canonical_baseline(
        portconfig, platform_name, hwsku, baseline_path, hwsku_path)
    lookup = []
    seen = set()
    for path in (platform_dir / "pg_profile_lookup.ini", sku_dir / "pg_profile_lookup.ini"):
        if path.is_file():
            resolved = path.resolve(strict=True)
            if str(resolved) in seen:
                continue
            seen.add(str(resolved))
            content = resolved.read_bytes()
            lookup.append({"path": str(resolved), "sha256": sha256(content), "content": content.decode("utf-8")})
    parser_path = Path(portconfig.__file__).resolve(strict=True)
    startup_path = Path(startup)
    startup_bytes = startup_path.read_bytes()
    startup_stat = startup_path.stat()
    version_bytes = Path(version).read_bytes()
    assets, template_paths = {}, {}
    for directory in (platform_dir, sku_dir, Path("/usr/share/sonic/templates")):
        for path in sorted(directory.glob("*.j2")):
            resolved = path.resolve(strict=True)
            assets[str(resolved)] = sha256(resolved.read_bytes())
            template_paths[str(directory.resolve(strict=True) / path.name)] = str(resolved)
    return {
        "hostname": socket.gethostname(),
        "metadata": dict({field: metadata.get(field) for field in ("platform", "hwsku", "buffer_model")},
                         num_asic=multi_asic.get_num_asics()),
        "image": version_bytes.decode("utf-8"),
        "platform_directory": str(platform_dir.resolve(strict=True)),
        "hwsku_directory": str(sku_dir.resolve(strict=True)),
        "platform": platform,
        "expansions": canonical_expansions(platform, portconfig),
        "baseline_ports": baseline_ports,
        "transceivers": transceiver_facts(platform["interfaces"]),
        "running": running,
        "applied_buffers": applied_buffers(),
        "startup": {"bytes_base64": base64.b64encode(startup_bytes).decode("ascii"),
                    "sha256": sha256(startup_bytes), "mode": stat.S_IMODE(startup_stat.st_mode),
                    "uid": startup_stat.st_uid, "gid": startup_stat.st_gid},
        "lookup_candidates": lookup,
        "template_sha256": assets,
        "template_paths": template_paths,
        "sources": {"platform": {"path": str(platform_path), "sha256": sha256(platform_bytes)},
                    "parser": {"path": str(parser_path), "sha256": sha256(parser_path.read_bytes())},
                    "image": {"path": version, "sha256": sha256(version_bytes)}, **baseline_sources},
    }


def write_private(path, data):
    destination = Path(path)
    if destination.parent.is_symlink() or destination.exists() or destination.is_symlink():
        raise FactsError("Refusing to overwrite an existing collection artifact")
    descriptor = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(data, handle, sort_keys=True)
        handle.write("\n")


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(argument_spec={"destination": {"type": "path", "required": True}},
                           supports_check_mode=True)
    try:
        data = collect()
        if module.check_mode:
            module.exit_json(changed=False, platform=data["metadata"]["platform"], artifact_written=False)
        write_private(module.params["destination"], data)
        module.exit_json(changed=False, platform=data["metadata"]["platform"], artifact_written=True,
                         message="Read-only facts captured privately; readiness is not yet established")
    except (OSError, ValueError, KeyError, TypeError, ImportError, RuntimeError) as error:
        module.fail_json(msg="Generic HWSKU read-only collection failed: {}".format(error))


if __name__ == "__main__":
    main()
