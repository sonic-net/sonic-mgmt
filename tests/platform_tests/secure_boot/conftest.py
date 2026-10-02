def pytest_addoption(parser):
    parser.addoption(
        "--secure_boot_second_image_url",
        action="store",
        default=None,
        help=(
            "URL of the signed second image used by Secure Boot kernel "
            "rejection and DB enrollment tests."
        ),
    )
    parser.addoption(
        "--secure_boot_sbat_upgrade_image_url",
        action="store",
        default=None,
        help=(
            "URL of a signed image whose shim has a newer automatic SBAT "
            "level and uses the running image's DB.auth."
        ),
    )
    parser.addoption(
        "--secure_boot_sbat_downgrade_image_url",
        action="store",
        default=None,
        help=(
            "URL of a signed image whose shim has an older automatic SBAT "
            "level and uses the running image's DB.auth."
        ),
    )
