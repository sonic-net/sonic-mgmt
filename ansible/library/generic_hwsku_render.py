#!/usr/bin/python
"""Render candidate-port QoS/buffer tables with exact installed SONiC templates."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


PORT_TABLES = {
    "PORT_QOS_MAP", "QUEUE", "BUFFER_PG", "BUFFER_QUEUE", "BUFFER_PORT_INGRESS_PROFILE_LIST",
    "BUFFER_PORT_EGRESS_PROFILE_LIST", "CABLE_LENGTH",
}
GLOBAL_TABLES = {
    "BUFFER_POOL", "BUFFER_PROFILE", "TC_TO_QUEUE_MAP", "TC_TO_PRIORITY_GROUP_MAP",
    "PFC_PRIORITY_TO_PRIORITY_GROUP_MAP", "MAP_PFC_PRIORITY_TO_QUEUE", "DSCP_TO_TC_MAP",
    "DOT1P_TO_TC_MAP", "TC_TO_DSCP_MAP", "WRED_PROFILE", "SCHEDULER",
}


def traditional_profile_cache(context, tables, lookup_text, fully_lossy=False):
    pool = context.get("BUFFER_POOL", {}).get(
        "ingress_lossless_pool", tables.get("BUFFER_POOL", {}).get("ingress_lossless_pool", {}))
    mode = pool.get("mode")
    if mode not in ("dynamic", "static"):
        raise ValueError("Traditional profile-cache closure requires the installed ingress pool mode")
    shared = str(pool.get("xoff", "0"))
    if not shared.isdigit():
        raise ValueError("Traditional cache closure requires a resolved shared-headroom pool size")
    lookup = {}
    for line in lookup_text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split()
        if (len(fields) not in (6, 7) or not fields[0].isdigit()
                or re.fullmatch(r"[0-9]+m", fields[1]) is None
                or any(not value.isdigit() for value in fields[2:5])
                or re.fullmatch(r"-?[0-9]+", fields[5]) is None
                or len(fields) == 7 and not fields[6].isdigit()):
            raise ValueError("Unsupported installed traditional profile lookup row")
        pair = tuple(fields[:2])
        if pair in lookup:
            raise ValueError("Duplicate installed traditional profile lookup pair")
        row = {"pool": "ingress_lossless_pool", "size": fields[2], "xon": fields[3], "xoff": fields[4],
               mode + "_th": fields[5]}
        if len(fields) == 7:
            row["xon_offset"] = fields[6]
        lookup[pair] = row
    if not lookup:
        raise ValueError("The installed traditional profile lookup is empty")
    existing = context.get("BUFFER_PROFILE", {})
    profiles = tables.setdefault("BUFFER_PROFILE", {})
    for lengths in context.get("CABLE_LENGTH", {}).values():
        for port, cable in lengths.items():
            if port not in context["PORT"] or cable == "0m":
                continue
            speed = str(context["PORT"][port]["speed"])
            pair = (speed, cable)
            name = "pg_lossless_{}_{}_profile".format(speed, cable)
            if pair in lookup and name not in existing and name not in profiles:
                profile = dict(lookup[pair])
                if int(shared) == 0 and int(profile["xoff"]) > int(profile["size"]):
                    if fully_lossy is not True:
                        raise ValueError("Nonshared cache normalization requires a source-verified fully lossy policy")
                    # Shared-headroom lookups reserve XON alone; a nonshared object also reserves XOFF.
                    profile["size"] = str(max(int(profile["size"]), int(profile["xon"]) + int(profile["xoff"])))
                profiles[name] = profile


def render(context, templates, expected_sources, directory, lookup_source=None, fully_lossy=False):
    if not isinstance(templates, list) or not templates:
        raise ValueError("An explicit installed-template selection is required")
    for filename, expected in expected_sources.items():
        path = Path(filename)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Installed template assets changed after collection")
    source = directory / "candidate-context.json"
    descriptor = os.open(str(source), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(context, handle, sort_keys=True)
    result = {}
    for index, filename in enumerate(templates):
        path = Path(filename).resolve(strict=True)
        if str(path) not in expected_sources:
            raise ValueError("A selected template lacks recorded installed-source evidence")
        wrapper = directory / ("template-{}.j2".format(index))
        wrapper.write_text(
            "{% macro cable_length(port_name) -%}"
            "{%- for group, lengths in CABLE_LENGTH.items() -%}"
            "{%- if port_name in lengths -%}{{ lengths[port_name] }}{%- endif -%}"
            "{%- endfor -%}{%- endmacro %}\n"
            "{% include " + json.dumps(path.name) + " %}\n", encoding="utf-8")
        command = ["sonic-cfggen", "-j", str(source), "-t", str(wrapper), "-T", str(path.parent)]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode:
            log = directory / ("template-{}-stderr.log".format(index))
            descriptor = os.open(str(log), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(completed.stderr)
            raise ValueError("Installed SONiC template rendering failed (rc {}); private evidence: {}".format(
                completed.returncode, log))
        tables = json.loads(completed.stdout)
        if not isinstance(tables, dict):
            raise ValueError("Installed template output must be a ConfigDB table dictionary")
        unsupported = set(tables) - PORT_TABLES - GLOBAL_TABLES
        if unsupported:
            raise ValueError("An installed template attempted to change tables outside its QoS/buffer contract: "
                             + ", ".join(sorted(unsupported)))
        for table, rows in tables.items():
            if not isinstance(rows, dict):
                raise ValueError("Generated ConfigDB tables must be dictionaries")
            if table in result and result[table] != rows:
                raise ValueError("Installed templates disagree on the same generated table")
            result[table] = rows
    if context.get("DEVICE_METADATA", {}).get("localhost", {}).get("buffer_model") == "traditional":
        if not isinstance(lookup_source, dict) or set(lookup_source) != {"path", "sha256"}:
            raise ValueError("Traditional profile-cache closure requires the recorded installed lookup source")
        lookup = Path(lookup_source["path"])
        data = lookup.read_bytes()
        if hashlib.sha256(data).hexdigest() != lookup_source["sha256"]:
            raise ValueError("Installed profile lookup changed after collection")
        traditional_profile_cache(context, result, data.decode("utf-8"), fully_lossy)
        if hashlib.sha256(lookup.read_bytes()).hexdigest() != lookup_source["sha256"]:
            raise ValueError("Installed profile lookup changed during cache rendering")
    return result


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(argument_spec={
        "request": {"type": "dict", "required": True, "no_log": True},
        "destination": {"type": "path", "required": True},
    })
    try:
        request = module.params["request"]
        destination = Path(module.params["destination"])
        if destination.exists() or destination.is_symlink() or destination.parent.is_symlink():
            raise ValueError("Refusing to overwrite an existing render artifact")
        directory = Path(tempfile.mkdtemp(prefix="sonic-generic-render-", dir=str(destination.parent)))
        # Private directories require owner traversal, not group/world access.
        os.chmod(str(directory), 0o700)  # nosemgrep: insecure-file-permissions
        tables = render(request["context"], request["templates"], request["template_sha256"], directory,
                        request.get("lookup_source"), request.get("fully_lossy", False))
        descriptor = os.open(str(destination), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(tables, handle, sort_keys=True)
        module.exit_json(changed=False, generated_tables=sorted(tables), private_directory=str(directory))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        module.fail_json(msg="Installed Generic QoS/buffer rendering failed: {}".format(error))


if __name__ == "__main__":
    main()
