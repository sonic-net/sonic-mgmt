import logging


logger = logging.getLogger(__name__)

DUTHOSTS_FIXTURE_FAILED_CACHE_KEY = "duthosts_fixture_failed"
TESTBED_UNREACHABLE_STOP_REASON = (
    "DUT/testbed is unreachable; stop the current pytest session"
)


def _iter_exception_chain(exc):
    pending = [exc]
    seen = set()

    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current

        cause = getattr(current, "__cause__", None)
        context = getattr(current, "__context__", None)
        nested = getattr(current, "exceptions", ())
        if cause is not None:
            pending.append(cause)
        if context is not None:
            pending.append(context)
        pending.extend(nested)


def is_testbed_unreachable_exception(exc, connection_failure_type=None):
    """Return whether an exception means the assigned testbed is unusable."""
    for current in _iter_exception_chain(exc):
        if connection_failure_type is not None and isinstance(
                current, connection_failure_type):
            return True

        message = str(current).lower()
        if ("host unreachable" in message or
                "unreachable in the inventory" in message or
                "ansibleconnectionfailure" in message):
            return True

        reboot_failure = (
            "dut not start" in message or
            "did not startup" in message
        )
        reboot_after_failure = "did not startup after reboot" in message
        sanity_recovery_failure = (
            "recovery of sanity check failed" in message
        )
        connectivity_failure = any(marker in message for marker in (
            "unable to connect to port 22",
            "timeout when waiting for",
            "no route to host",
        ))
        if reboot_after_failure or connectivity_failure and (
                reboot_failure or sanity_recovery_failure):
            return True

    return False


def _get_unreachable_hosts(exc):
    for current in _iter_exception_chain(exc):
        dark = getattr(current, "dark", None)
        if isinstance(dark, dict):
            return list(dark.keys())
    return []


def stop_on_testbed_unreachable(node, call, connection_failure_type=None):
    """Flag and stop a pytest session after a testbed connectivity failure."""
    if call.excinfo is None:
        return False

    exc = call.excinfo.value
    if not is_testbed_unreachable_exception(
            exc, connection_failure_type):
        return False

    unreachable_hosts = _get_unreachable_hosts(exc)
    if unreachable_hosts:
        reason = "{}: {}".format(
            TESTBED_UNREACHABLE_STOP_REASON,
            ", ".join(unreachable_hosts),
        )
    else:
        reason = TESTBED_UNREACHABLE_STOP_REASON

    already_flagged = node.config.cache.get(
        DUTHOSTS_FIXTURE_FAILED_CACHE_KEY, None)
    if not already_flagged:
        logger.error(
            "Testbed connectivity failure detected in %s phase of %s: %r",
            call.when,
            getattr(node, "name", "unknown"),
            exc,
        )
        node.config.cache.set(
            DUTHOSTS_FIXTURE_FAILED_CACHE_KEY, True)

    if not node.session.shouldstop:
        node.session.shouldstop = reason

    return True
