import re
import os
import sys
import logging

from natsort import natsorted

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Subfolders under tests/ whose scripts are exempt from the topology marker requirement.
EXCLUDED_SUBFOLDERS = {"transceiver", "saitests"}


def _is_excluded(script_path, location):
    """Check whether *script_path* falls under one of the excluded subfolders."""
    rel = os.path.relpath(script_path, location)
    parts = rel.replace("\\", "/").split("/")
    return any(part in EXCLUDED_SUBFOLDERS for part in parts)


def collect_scripts_without_topology_markers():
    """
    Collect all ``test_*.py`` scripts under *location* and verify that each
    one contains a ``pytest.mark.topology`` marker.

    Returns:
        tuple: (scripts_without_marker, total_checked, skipped_scripts)
    """
    location = sys.argv[1]

    # Recursively find all scripts starting with "test_" and ending with ".py"
    scripts = []
    for root, dirs, filenames in os.walk(location):
        for f in filenames:
            if f.startswith("test_") and f.endswith(".py"):
                scripts.append(os.path.join(root, f))
    scripts = natsorted(scripts)

    logger.info("Found %d test scripts under '%s'", len(scripts), location)

    pattern = re.compile(r"[^@]pytest\.mark\.topology\(([^\)]*)\)")

    scripts_without_marker = []
    skipped_scripts = []

    for s in scripts:
        script_name = s[len(location) + 1:]

        if _is_excluded(s, location):
            skipped_scripts.append(script_name)
            continue

        try:
            with open(s, 'r') as fh:
                content = fh.read()
                if pattern.search(content):
                    continue
                scripts_without_marker.append(script_name)
        except Exception as e:
            raise Exception('Exception occurred while trying to get marker in {}, error {}'.format(s, e))

    return scripts_without_marker, len(scripts), skipped_scripts


def main():
    try:
        scripts_without_marker, total, skipped = collect_scripts_without_topology_markers()

        checked = total - len(skipped)

        # --- Summary -----------------------------------------------------------
        logger.info("----------- Markers Check Summary -----------")
        logger.info("Total scripts found  : %d", total)
        logger.info("Scripts checked      : %d", checked)
        logger.info("Scripts skipped      : %d", len(skipped))
        logger.info("Scripts with marker  : %d", checked - len(scripts_without_marker))
        logger.info("Scripts WITHOUT marker: %d", len(scripts_without_marker))

        if skipped:
            logger.info("Skipped subfolders   : %s", ", ".join(sorted(EXCLUDED_SUBFOLDERS)))

        if scripts_without_marker:
            logger.info("---------------------------------------------")
            for script in scripts_without_marker:
                logger.error("Please add `pytest.mark.topology` in script %s", script)
            logger.info("---------------------------------------------")
            sys.exit(1)

        logger.info("All checked scripts have topology markers. PASSED.")
        sys.exit(0)

    except Exception as e:
        logging.error(e)
        sys.exit(2)


if __name__ == '__main__':
    main()
