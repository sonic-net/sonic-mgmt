"""Utilities for resolving the SONiC release identifier.

Kept dependency-free (only the stdlib ``re``) so it is importable both inside an
Ansible module running on the DUT and directly from unit tests on the host.
"""
import re

# A SONiC release token is a 6-digit YYYYMM value at the start of the version
# string, e.g. '202605' in '202605.1166406-18a25e93d'. The same leading-6-digits
# rule also resolves old date-stamped official images, e.g. '20181130.31' ->
# '201811'.
_RELEASE_TOKEN_RE = re.compile(r'(20\d{4})')


def guess_release_from_build_version(release, build_version):
    """Resolve the SONiC release, guessing from ``build_version`` when needed.

    Images that ship ``/etc/sonic/sonic_release`` already carry a populated
    ``release`` field (e.g. '202405'), which is returned unchanged. Self-built
    and virtual-switch (VS/KVM) images do not stamp that file, so ``release``
    arrives empty or ``'none'`` and must be guessed from ``build_version``:

    * a leading 6-digit ``YYYYMM`` token -> that release (e.g. '202605'), which
      also covers old date-stamped images ('20181130.31' -> '201811');
    * a ``build_version`` containing 'master' -> 'master';
    * anything else -> 'unknown'.

    Note: prior to this helper the fallback only recognized '201811', '201911'
    and 'master', so every other release (202012 ... 202605) on an unstamped VS
    image collapsed to 'unknown', silently defeating any ``release``-based
    conditional_mark skip on VS.

    Args:
        release (str): The release value already gathered (may be None/''/'none').
        build_version (str): The image build version string.

    Returns:
        str: The resolved release identifier.
    """
    if release and release != 'none':
        return release

    build_version = build_version or ''
    if 'master' in build_version:
        return 'master'

    match = _RELEASE_TOKEN_RE.match(build_version)
    if match:
        return match.group(1)

    return 'unknown'
