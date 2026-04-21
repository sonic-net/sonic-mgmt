# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Felix Fontein <felix@fontein.de>

# /// script
# dependencies = ["nox>=2025.02.09", "antsibull-nox"]
# ///

import sys

import nox


try:
    import antsibull_nox
except ImportError:
    print("You need to install antsibull-nox in the same Python environment as nox.")
    sys.exit(1)


antsibull_nox.load_antsibull_nox_toml()


@nox.session(name="create-certificates", default=False)
def create_certificates(session: nox.Session) -> None:
    """
    Regenerate some vendored certificates.
    """
    session.install("cryptography<39.0.0")  # we want support for SHA1 signatures
    session.run("python", "tests/create-certificates.py")
    session.warn(
        "Note that you need to modify some values in tests/integration/targets/x509_certificate_info/tasks/impl.yml"
        " and tests/integration/targets/filter_x509_certificate_info/tasks/impl.yml!"
    )


# Allow to run the noxfile with `python noxfile.py`, `pipx run noxfile.py`, or similar.
# Requires nox >= 2025.02.09
if __name__ == "__main__":
    nox.main()
