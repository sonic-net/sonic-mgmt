#!/usr/bin/env python3

"""
Fetch and bundles the hcloud package inside the collection.

Fetch the desired version `HCLOUD_VERSION` from https://github.com/hetznercloud/hcloud-python
`HCLOUD_SOURCE_URL` using git, apply some code modifications to comply with ansible,
move the modified files at the vendor location `HCLOUD_VENDOR_PATH`.
"""

from __future__ import annotations

import logging
import re
from argparse import ArgumentParser
from pathlib import Path
from shutil import move, rmtree
from subprocess import check_call
from tempfile import TemporaryDirectory
from textwrap import dedent

logger = logging.getLogger("vendor")

HCLOUD_SOURCE_URL = "https://github.com/hetznercloud/hcloud-python"
HCLOUD_VERSION = "v2.8.0"
HCLOUD_VENDOR_PATH = "plugins/module_utils/vendor/hcloud"


def apply_code_modifications(source_path: Path):
    for file in source_path.rglob("*.py"):
        content = file.read_text()
        content_orig = content

        # Wrap requests imports
        content = re.sub(
            r"import requests",
            dedent(
                r"""
                try:
                    import requests
                except ImportError:
                    requests = None
                """
            ).strip(),
            content,
        )

        # Wrap dateutil imports
        content = re.sub(
            r"from dateutil.parser import isoparse",
            dedent(
                r"""
                try:
                    from dateutil.parser import isoparse
                except ImportError:
                    isoparse = None
                """
            ).strip(),
            content,
        )

        # Remove requests.Response typings
        content = re.sub(
            r": requests\.Response",
            r"",
            content,
        )

        if content != content_orig:
            logger.info("Applied code modifications on %s", file)

        file.write_text(content)


def main(check: bool = False) -> int:
    with TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        logger.info("Created temporary directory %s", tmp_dir_path)

        check_call(["git", "clone", "--depth=1", "--branch", HCLOUD_VERSION, HCLOUD_SOURCE_URL, tmp_dir_path])
        logger.info("Cloned the source files in %s", tmp_dir_path)

        apply_code_modifications(tmp_dir_path / "hcloud")
        logger.info("Applied code modifications on the source files")

        rmtree(HCLOUD_VENDOR_PATH)
        move(tmp_dir_path / "hcloud", HCLOUD_VENDOR_PATH)
        logger.info("Bundled the modified sources files in the collection")

    if check:
        check_call(["git", "diff", "--exit-code", "--", HCLOUD_VENDOR_PATH])

    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s: %(message)s")

    parser = ArgumentParser()
    parser.add_argument("--check", action="store_true", default=False)
    args = parser.parse_args()

    raise SystemExit(main(check=args.check))
