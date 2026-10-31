"""Opt-in, serial AAA role-case reuse; audit and lifecycle cases stay fresh."""

from contextlib import contextmanager
import json
import logging
import shlex
import time

import pytest

from tests.common.fixtures.grpc_fixtures import _get_target_duthost, _gnmi_tls_flow
from tests.common.helpers.sonic_db import CONFIG_DB, redis_del, redis_hdel, redis_hset

logger = logging.getLogger(__name__)
PRINCIPAL = "test.client.gnmi.sonic"
ROLE_KEY = "GNMI_CLIENT_CERT|{}".format(PRINCIPAL)
METADATA_KEY = "DEVICE_METADATA|localhost"


def _running_config(duthost):
    # Do not use miss-tolerant HGET helpers: failure must not look like absence,
    # and empty values must remain distinct from absent fields.
    result = duthost.shell("sonic-cfggen -d --print-data", module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise RuntimeError("Cannot snapshot AAA configuration: {}".format(result))
    config = json.loads(result["stdout"])
    if not isinstance(config, dict):
        raise ValueError("AAA configuration snapshot is not an object")
    return config


def _principal_mapping(duthost):
    # cfggen decodes Redis "role@" into a "role" list and drops NULL sentinels.
    # Read the raw hash separately; JSON encoding inside Redis preserves empty
    # strings, delimiters and quotes without relying on CLI HGETALL formatting.
    script = "return cjson.encode(redis.call('HGETALL', KEYS[1]))"
    result = duthost.shell(
        "sonic-db-cli CONFIG_DB EVAL {} 1 {}".format(shlex.quote(script), shlex.quote(ROLE_KEY)),
        module_ignore_errors=True,
    )
    if result.get("rc", 1) != 0:
        raise RuntimeError("Cannot snapshot AAA principal: {}".format(result))
    fields = json.loads(result["stdout"])
    # Redis cjson encodes an empty Lua table as {}, not []. Both mean no hash.
    if fields == {}:
        return {}
    if (not isinstance(fields, list) or len(fields) % 2
            or not all(isinstance(value, str) for value in fields)
            or len(set(fields[::2])) != len(fields) // 2):
        raise ValueError("Invalid raw AAA principal snapshot")
    return dict(zip(fields[::2], fields[1::2]))


def _checked(result):
    if result.get("rc", 1) != 0:
        raise RuntimeError("AAA state restoration failed: {}".format(result))


def _restore_case(duthost, before, mapping):
    """Restore only the two owned mutations, leaving unrelated leaks visible."""
    errors = []
    metadata = before["DEVICE_METADATA"]["localhost"]
    try:
        _checked(redis_del(duthost, CONFIG_DB, ROLE_KEY)[0])
        if mapping:
            _checked(redis_hset(duthost, CONFIG_DB, ROLE_KEY, **mapping))
    except Exception as error:
        errors.append(str(error))
    try:
        if "cloudtype" in metadata:
            _checked(redis_hset(duthost, CONFIG_DB, METADATA_KEY, cloudtype=metadata["cloudtype"]))
        else:
            _checked(redis_hdel(duthost, CONFIG_DB, METADATA_KEY, "cloudtype"))
    except Exception as error:
        errors.append(str(error))
    if errors:
        raise RuntimeError("AAA case cleanup failed: {}".format("; ".join(errors)))


class _RoleTlsOwner:
    """One lazy TLS lifecycle per contiguous sequence of compatible cases.

    Suspend before *any* other case in this module. This avoids overlapping
    checkpoints/certificate files even with an explicit interleaved node list.
    A setup/cleanup error invalidates reuse rather than trusting dirty state.
    Test-body failures still run restoration and verification. If those pass,
    pytest may continue sharing; setup or cleanup failures poison the owner.
    """

    def __init__(self):
        self.flow = None
        self.fixture = None
        self.expected = None
        self.mapping = None
        self.broken = False

    def close(self):
        flow, self.flow = self.flow, None
        self.fixture = self.expected = self.mapping = None
        if flow is not None:
            try:
                next(flow)
            except StopIteration:
                return
            except BaseException:
                self.broken = True
                raise
            self.broken = True
            raise RuntimeError("TLS lifecycle yielded more than once")

    def acquire(self, duthosts, ptfhost, request):
        if self.broken:
            raise RuntimeError("AAA TLS cleanup failed; refusing further reuse")
        if self.flow is None:
            duthost = _get_target_duthost(duthosts, request)
            self.flow = _gnmi_tls_flow(duthost, ptfhost, strict_cleanup=True)
            try:
                self.fixture = next(self.flow)
                self.expected = _running_config(duthost)
                self.mapping = _principal_mapping(duthost)
                if not self.mapping.get("role@"):
                    raise AssertionError("Shared TLS client certificate role is not configured")
                # Validate the restoration target before allowing a mutation.
                if not isinstance(self.expected["DEVICE_METADATA"]["localhost"], dict):
                    raise ValueError("Invalid DEVICE_METADATA restoration target")
            except BaseException:
                # A failed generator may already be exhausted after failed
                # cleanup; conservatively forbid another setup in this module.
                self.broken = True
                self.close()
                raise
        if self.fixture.duthost is not _get_target_duthost(duthosts, request):
            self.close()
            raise RuntimeError("Cannot reuse AAA TLS across different DUTs")
        return self.fixture

    @contextmanager
    def case(self, duthosts, ptfhost, request):
        fixture = self.acquire(duthosts, ptfhost, request)
        duthost = fixture.duthost
        try:
            try:
                fixture.pygnmi_client.close()
                if (_running_config(duthost) != self.expected
                        or _principal_mapping(duthost) != self.mapping):
                    raise AssertionError("Unexpected configuration before shared AAA case")
            except BaseException:
                self.broken = True
                raise
            try:
                yield fixture
            finally:
                # Nested finally guarantees restoration if client close fails.
                try:
                    fixture.pygnmi_client.close()
                except BaseException:
                    self.broken = True
                    raise
                finally:
                    try:
                        _restore_case(duthost, self.expected, self.mapping)
                        if (_running_config(duthost) != self.expected
                                or _principal_mapping(duthost) != self.mapping):
                            raise AssertionError("Unrelated configuration leak in shared AAA case")
                    except BaseException:
                        # Do not let a later case hide failed restoration or an
                        # unrelated leak even if the outer rollback succeeds.
                        self.broken = True
                        raise
        except BaseException:
            # Report the mismatch before the full TLS rollback can hide it.
            self.close()
            raise


@pytest.fixture(scope="module")
def gnmi_aaa_tls_owner(core_dump_and_config_check):
    # Explicit ordering: restore TLS before generic config checking/recovery.
    owner = _RoleTlsOwner()
    try:
        yield owner
    finally:
        owner.close()


def gnmi_aaa_case_boundary(request, gnmi_aaa_tls_owner):
    # This fixture is autouse only in the opting-in AAA module. Check fixture
    # membership, not node names, so renames cannot accidentally enable reuse.
    if gnmi_aaa_tls_owner.broken:
        raise RuntimeError("AAA TLS cleanup failed; refusing further cases")
    if "gnmi_aaa_role_tls" not in request.fixturenames:
        gnmi_aaa_tls_owner.close()


@pytest.fixture
def gnmi_aaa_role_tls(request, duthosts, ptfhost, gnmi_aaa_tls_owner, gnmi_aaa_case_boundary):
    started = time.monotonic()
    try:
        with gnmi_aaa_tls_owner.case(duthosts, ptfhost, request) as fixture:
            logger.info("AAA TLS case setup: %.3fs", time.monotonic() - started)
            yield fixture
    finally:
        logger.info("AAA TLS case lifecycle: %.3fs", time.monotonic() - started)
