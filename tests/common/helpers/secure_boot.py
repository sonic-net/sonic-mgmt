import shlex

import pytest


def require_secure_boot(duthost):
    """Skip the test unless UEFI Secure Boot is enabled."""
    secure_boot_state = duthost.command("mokutil --sb-state", module_ignore_errors=True)
    if secure_boot_state["rc"] != 0 or "SecureBoot enabled" not in secure_boot_state["stdout"]:
        pytest.skip("Secure Boot is not enabled")


def get_installed_images(duthost):
    """Return all SONiC images reported in the installer's Available section."""
    output = duthost.command("sonic-installer list")["stdout"]
    installed_images = []
    reading_available = False

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line == "Available:":
            reading_available = True
        elif reading_available and line:
            installed_images.append(line)

    return installed_images


def get_inactive_image(installed_images, current_image):
    """Return an installed image other than the running image."""
    inactive_images = [image for image in installed_images if image != current_image]
    if not inactive_images:
        pytest.skip("--secure_boot_second_image_url or an installed inactive image is required")
    return inactive_images[0]


def get_current_image(duthost):
    """Return the currently running SONiC image."""
    return duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]


def restore_image_selection(duthost, image):
    """Set an image as both the default and next boot selection."""
    quoted_image = shlex.quote(image)
    duthost.command(
        "sudo sonic-installer set-default {}".format(quoted_image),
        module_ignore_errors=True,
    )
    duthost.command(
        "sudo sonic-installer set-next-boot {}".format(quoted_image),
        module_ignore_errors=True,
    )
