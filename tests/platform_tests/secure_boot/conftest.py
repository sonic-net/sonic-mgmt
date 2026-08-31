def pytest_addoption(parser):
    parser.addoption(
        "--secure_boot_second_image_url",
        action="store",
        default=None,
        help=(
            "URL of the signed second image used by Secure Boot kernel "
            "rejection tests."
        ),
    )
