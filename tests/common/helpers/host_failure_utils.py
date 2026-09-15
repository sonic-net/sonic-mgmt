import logging


logger = logging.getLogger(__name__)

DUTHOSTS_FIXTURE_FAILED_CACHE_KEY = "duthosts_fixture_failed"
TESTBED_UNREACHABLE_STOP_REASON = (
    "DUT/testbed is unreachable; stop the current pytest session"
)
TESTBED_UNREACHABLE_HANDLED_ATTR = "sonic_testbed_unreachable_handled"

# An exception message may embed a whole ansible module result, the failure
# signatures we look for are always in the leading part of the message.
MAX_INSPECTED_MESSAGE_LENGTH = 8192

# The two messages pytest-ansible raises for an unreachable host, see
# ModuleDispatcherV213._raise_on_unreachable. They are method local literals
# upstream, not an importable constant, so they have to be repeated here:
# https://github.com/ansible/pytest-ansible/blob/9374c591579fffedc85e6bc1509be40c7b505d36/src/pytest_ansible/module_dispatcher/v213.py#L292-L313
# They stay recognizable after the exception is wrapped by pytest_assert or a
# parallel task runner, which is the only case these markers are needed for: a
# directly raised AnsibleConnectionFailure is already matched by its "dark"
# hosts, which is a documented attribute of the exception class.
#
# "in the inventory" is the token that carries the signal, so the leading
# "Host" is deliberately not part of the marker: it adds no precision, and
# omitting it keeps the match working if upstream ever says "Hosts".
# A bare "host unreachable" must never be used: ICMP output embeds
# "Destination Host Unreachable" and tests do put raw ping output into their
# failure messages (tests/common/helpers/tacacs/tacacs_helper.py), which would
# retire a healthy DUT when only the pinged peer is down.
UNREACHABLE_MARKERS = (
    "unreachable in the inventory",
    "unreachable in the extra inventory",
)
# Reboot and sanity recovery detect a dead DUT by running wait_for from
# localhost against the DUT ssh port, so the ansible connection itself succeeds
# and the failure surfaces as a plain Exception that only carries text, see
# wait_for_startup in tests/common/reboot.py. There is no
# AnsibleConnectionFailure and no "dark" hosts to inspect for these, which is
# why matching the message is the only signal available.
# On their own these markers only mean a single connection attempt failed, so
# they need an unhealthy DUT context to tell an unusable testbed from a
# functional failure.
CONNECTIVITY_FAILURE_MARKERS = (
    "unable to connect to port 22",
    "timeout when waiting for",
    "no route to host",
)


def _iter_exception_chain(exc):
    """Yield an exception and every exception it is chained to."""
    pending = [exc]
    seen = set()

    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        yield current

        pending.append(getattr(current, "__cause__", None))
        # __context__ is attached to any exception raised while another one was
        # being handled, so honor an explicit "raise ... from None".
        if not getattr(current, "__suppress_context__", False):
            pending.append(getattr(current, "__context__", None))
        # Exceptions collected by an ExceptionGroup, used by parallel runs.
        nested = getattr(current, "exceptions", None)
        if isinstance(nested, (list, tuple)):
            pending.extend(nested)


def _get_dark_hosts(exc):
    """Return the hosts an ansible connection failure could not reach.

    "dark" is the exception attribute pytest-ansible populates directly from
    its result callback: AnsibleConnectionFailure(msg, dark=callback.unreachable).
    The callback itself is a local of ModuleDispatcherV213._run and AdHocResult
    only carries the contacted hosts, so this attribute is the only supported
    way to read callback.unreachable, and it is exact rather than text matched.
    """
    dark = getattr(exc, "dark", None)
    if isinstance(dark, dict):
        return sorted(dark.keys())
    return []


def _get_message(exc):
    try:
        message = str(exc)
    except Exception:
        return ""
    return message[:MAX_INSPECTED_MESSAGE_LENGTH].lower()


def _is_unreachable_failure(exc, connection_failure_types):
    # A connection failure is only conclusive when it names the hosts that were
    # unreachable. ansible-core raises the same exception type for connection
    # errors that do not mean the testbed became unusable.
    if (connection_failure_types and
            isinstance(exc, connection_failure_types) and
            _get_dark_hosts(exc)):
        return True

    message = _get_message(exc)
    if any(marker in message for marker in UNREACHABLE_MARKERS):
        return True

    # A DUT that never came back from a reboot always leaves the testbed unusable.
    if "did not startup after reboot" in message:
        return True

    if not any(marker in message
               for marker in CONNECTIVITY_FAILURE_MARKERS):
        return False

    # A bare "did not startup" is also used by functional assertions, it only
    # means an unusable testbed when the DUT is unreachable as well.
    reboot_failure = (
        "dut not start" in message or
        "did not startup" in message
    )
    sanity_recovery_failure = "recovery of sanity check failed" in message
    return reboot_failure or sanity_recovery_failure


def is_testbed_unreachable_exception(exc, connection_failure_types=None):
    """Return whether an exception means the assigned testbed is unusable."""
    return any(
        _is_unreachable_failure(current, connection_failure_types)
        for current in _iter_exception_chain(exc)
    )


def _get_unreachable_hosts(exc):
    for current in _iter_exception_chain(exc):
        hosts = _get_dark_hosts(current)
        if hosts:
            return hosts
    return []


def stop_on_testbed_unreachable(node, call, connection_failure_types=None):
    """Flag and stop a pytest session after a testbed connectivity failure."""
    if call.excinfo is None:
        return False

    exc = call.excinfo.value
    if not is_testbed_unreachable_exception(exc, connection_failure_types):
        return False

    session = node.session
    if not getattr(session, TESTBED_UNREACHABLE_HANDLED_ATTR, False):
        setattr(session, TESTBED_UNREACHABLE_HANDLED_ATTR, True)
        logger.error(
            "Testbed connectivity failure detected in %s phase of %s: %r",
            call.when,
            getattr(node, "name", "unknown"),
            exc,
        )

    node.config.cache.set(DUTHOSTS_FIXTURE_FAILED_CACHE_KEY, True)

    unreachable_hosts = _get_unreachable_hosts(exc)
    if unreachable_hosts:
        reason = "{}: {}".format(
            TESTBED_UNREACHABLE_STOP_REASON,
            ", ".join(unreachable_hosts),
        )
    else:
        reason = TESTBED_UNREACHABLE_STOP_REASON

    if not session.shouldstop:
        session.shouldstop = reason

    return True
