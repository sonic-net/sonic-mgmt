# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Felix Fontein <felix@fontein.de>

# /// script
# dependencies = ["nox>=2025.02.09", "antsibull-nox"]
# ///

import os
import sys
import urllib.request
from pathlib import Path

import nox


try:
    import antsibull_nox
    import antsibull_nox.sessions
except ImportError:
    print("You need to install antsibull-nox in the same Python environment as nox.")
    sys.exit(1)


IN_CI = os.environ.get("CI") == "true"


antsibull_nox.load_antsibull_nox_toml()


@nox.session(name="update-docs-fragments", default=True)
def update_docs_fragments(session: nox.Session) -> None:
    """
    Update/check auto-generated parts of docs fragments.
    """
    session.install("ansible-core")
    prepare = antsibull_nox.sessions.prepare_collections(
        session, install_in_site_packages=True
    )
    if not prepare:
        return
    data = ["python", "tests/update-docs-fragments.py"]
    if IN_CI:
        data.append("--lint")
    session.run(*data)


@nox.session(name="update-psl", default=False, python=False)
def update_psl(session: nox.Session) -> None:
    # Sometimes the version on publicsuffix.org differs depending on from where you request it over many hours,
    # so for now let's directly fetch it from GitHub.
    # url = 'https://publicsuffix.org/list/public_suffix_list.dat'
    url = "https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat"
    filename = "plugins/public_suffix_list.dat"

    # Download file
    urllib.request.urlretrieve(url, filename)

    output = session.run("git", "status", "--porcelain=v1", filename, silent=True)
    if output is None:
        # The run was skipped
        return
    if output == "":
        print("PSL is up-to-date!")
        return

    if IN_CI:
        session.error("PSL is not up-to-date! Run 'nox -e update-psl'!")
        return

    fragment = Path("changelogs", "fragments", "update-psl.yml")
    if not fragment.exists():
        fragment.write_text(
            r"""bugfixes:
  - "Update Public Suffix List."
"""
        )

    session.run("git", "status", filename, fragment)


# Allow to run the noxfile with `python noxfile.py`, `pipx run noxfile.py`, or similar.
# Requires nox >= 2025.02.09
if __name__ == "__main__":
    nox.main()
