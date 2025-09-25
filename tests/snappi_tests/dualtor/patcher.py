import os
import importlib

patch_file = "resourcegroup.patch"
target_file = "resourcegroup.py"

import logging
logger = logging.getLogger(__name__)


def patch_snappi_ixnetwork():
    import snappi_ixnetwork
    si_dir = os.path.dirname(snappi_ixnetwork.__file__)
    exit_code = os.system("sudo cp {} {}".format("snappi_tests/dualtor/" + patch_file, si_dir))
    assert exit_code == 0, "Failed to copy patch file"
    logger.info("Checking whether patch {} is reversible (already applied) at directory {}".format(patch_file, si_dir))
    exit_code = os.system("cd {}; sudo patch -i {} -R --dry-run --force".format(si_dir, patch_file))
    if exit_code == 0:
        logger.info("Already patched {} at directory {}".format(patch_file, si_dir))
    else:
        logger.info("Attempting to apply patch {} at directory {}".format(patch_file, si_dir))
        exit_code = os.system("cd {}; sudo patch -i {}".format(si_dir, patch_file))
        if exit_code == 0:
            logger.info("Success patching {} at directory {}".format(patch_file, si_dir))
        assert exit_code == 0, "Patch {} failed at directory {}".format(patch_file, si_dir)
        importlib.reload(snappi_ixnetwork)


if __name__ == "__main__":
    patch_snappi_ixnetwork()
