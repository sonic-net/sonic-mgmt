#!/usr/bin/env python3
"""Read installed SONiC metadata and requested assets without configuring the device."""

import argparse
import json
from pathlib import Path
import subprocess


def collect_device(include_platform, include_lookup, device_root="/usr/share/sonic/device"):
    metadata = json.loads(subprocess.check_output(
        ["sonic-cfggen", "-d", "--var-json", "DEVICE_METADATA"], text=True))["localhost"]
    if not isinstance(metadata, dict):
        raise ValueError("DEVICE_METADATA.localhost must be an object")
    for field in ("platform", "hwsku"):
        value = metadata.get(field)
        if not isinstance(value, str) or not value or value in (".", "..") or Path(value).name != value:
            raise ValueError("DEVICE_METADATA.localhost.{} is missing or invalid".format(field))
    platform_dir = Path(device_root) / metadata["platform"]
    hwsku_dir = platform_dir / metadata["hwsku"]
    paths = {}
    if include_platform:
        platform_path = platform_dir / "platform.json"
        if not platform_path.is_file():
            platform_path = hwsku_dir / "platform.json"
        paths["platform.json"] = platform_path
    if include_lookup:
        lookup = platform_dir / "pg_profile_lookup.ini"
        paths["pg_profile_lookup.ini"] = lookup if lookup.exists() or lookup.is_symlink() else hwsku_dir / lookup.name
    files = {}
    for name, path in paths.items():
        content = path.read_text(encoding="utf-8")
        if name == "platform.json" and not isinstance(json.loads(content), dict):
            raise ValueError("{} must contain a JSON object".format(path))
        files[name] = {"remote_path": str(path.resolve(strict=True)), "content": content}
    return {"platform": metadata["platform"], "hwsku": metadata["hwsku"], "files": files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", action="store_true")
    parser.add_argument("--lookup", action="store_true")
    args = parser.parse_args()
    if not args.platform and not args.lookup:
        parser.error("At least one asset must be requested")
    try:
        print(json.dumps(collect_device(args.platform, args.lookup)))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, "Read-only SONiC collection failed: {}\n".format(error))


if __name__ == "__main__":
    main()
