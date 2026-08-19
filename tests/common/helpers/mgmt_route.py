import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@contextmanager
def apply_mgmt_route_workaround_if_needed(duthost, tbinfo):
    """
    Context manager that temporarily pins a host route to the download server via the management
    gateway when the currently-running image needs it to reach the (out-of-subnet) server.

    This is only needed on bjw testbeds running internal-202305/202311: there the download host is
    also the lab syslog server, which newer images (202405+, buildimage PR #20340) force-route over
    the management interface but these older images do not. Without the workaround, a raw curl
    follows the BGP data-plane default route and times out. On any other image/testbed this is a
    no-op.

    A host (/32) route is used rather than replacing the default route so that the DUT's
    BGP-learned default -- which may be multipath and is owned by zebra -- is left untouched.
    """
    # bjw lab image/deb download server, which is also the lab syslog server.
    bjw_download_server = "10.150.22.222"

    route_applied = False
    if tbinfo is not None and "bjw" in duthost.hostname:
        # Derive the running release from the live current image (same logic as
        # SonicHost.sonic_release). The cached duthost.sonic_release is stale after the DUT has
        # been rebooted into the base image, so fetch it live like the upgrade_path tests do.
        current_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
        logger.info("mgmt-route workaround check: hostname={} version={}".format(
            duthost.hostname, current_version))
        if "202305" in current_version or "202311" in current_version:
            gwaddr = duthost.get_extended_minigraph_facts(tbinfo).get(
                "minigraph_mgmt_interface", {}).get("gwaddr")
            if not gwaddr:
                logger.warning("mgmt-route workaround needed but management gateway is not available; skipping")
            else:
                logger.info("Applying mgmt-route workaround: {}/32 via {}".format(bjw_download_server, gwaddr))
                duthost.shell("ip -4 route replace {}/32 via {}".format(bjw_download_server, gwaddr))
                route_applied = True
    try:
        yield
    finally:
        if route_applied:
            logger.info("Removing mgmt-route workaround: {}/32".format(bjw_download_server))
            duthost.shell("ip -4 route del {}/32".format(bjw_download_server), module_ignore_errors=True)
