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
        "--secure_boot_unauthorized_image_url",
        action="store",
        default=None,
        help=(
            "URL of a signed image whose DB.auth is authorized by a KEK that "
            "is not enrolled on the DUT."
        ),
    )
