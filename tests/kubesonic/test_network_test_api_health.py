import json
import logging
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import pytest


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

API_SERVER_ENDPOINTS = (
    ("DOH01P", "2603:1090:1301::8"),
    ("CDM01P", "2603:10b0:11f::1c"),
    ("BN4Q", "2603:10b0:518::17"),
    ("STG03S", "2603:10b0:802::c"),
    ("BL6P", "2603:10b0:31c:2::59"),
)
MGMT_INTERFACE = "eth0"
API_SERVER_PORT = 6443
PROBE_TIMEOUT_SECONDS = 10
RESULT_LOG_PREFIX = "NETWORK_TEST_API_HEALTH_RESULT"
CONNECT_PROXY_ENV = "NETWORK_TEST_API_CONNECT_PROXY"


def _new_result(duthost, endpoint_name, endpoint_address):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dut": duthost.hostname,
        "endpoint": endpoint_name,
        "address": endpoint_address,
        "url": "https://[{}]:{}/healthz".format(endpoint_address, API_SERVER_PORT),
        "http_status": None,
        "healthy": False,
        "failure_category": None,
        "method": None,
        "attempts": [],
    }


def _get_mgmt_ipv6_path(duthost):
    mgmt_interfaces = duthost.get_running_config_facts().get("MGMT_INTERFACE", {})
    source_address = None
    for address_with_prefix, attributes in mgmt_interfaces.get(MGMT_INTERFACE, {}).items():
        address = address_with_prefix.split("/", 1)[0]
        if ":" not in address or address.lower().startswith("fe80:"):
            continue

        source_address = address
        gateway = (attributes or {}).get("gwaddr")
        if gateway and ":" in gateway:
            return address, gateway

    return source_address, None


def _is_mgmt_vrf_enabled(duthost):
    from tests.common.helpers.syslog_helpers import is_mgmt_vrf_enabled

    try:
        return is_mgmt_vrf_enabled(duthost)
    except Exception as error:
        logger.debug("Unable to detect management VRF on %s: %s", duthost.hostname, error)
        return False


def _add_custom_msg(request, key, value):
    from tests.common.helpers.custom_msg_utils import add_custom_msg

    add_custom_msg(request, key, value)


def _classify_curl_result(command_result):
    stdout = (command_result.get("stdout") or "").strip()
    return_code = command_result.get("rc")
    http_status = int(stdout) if re.fullmatch(r"[1-5][0-9][0-9]", stdout) else None

    if return_code == 0 and http_status == 200:
        return {
            "curl_rc": return_code,
            "http_status": http_status,
            "healthy": True,
            "failure_category": None,
        }

    if return_code == 0 and http_status is not None:
        category = "http_error"
    elif return_code == 28:
        category = "timeout"
    elif return_code == 7:
        category = "connection_error"
    elif return_code in (5, 6):
        category = "name_resolution_error"
    elif return_code in (35, 51, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91):
        category = "tls_error"
    elif return_code == 0:
        category = "invalid_http_status"
    else:
        category = "curl_error"

    classified = {
        "curl_rc": return_code,
        "http_status": http_status,
        "healthy": False,
        "failure_category": category,
    }
    error = (command_result.get("stderr") or "").strip()
    if error:
        classified["error"] = error[:256]
    return classified


def _curl_endpoint(
    duthost,
    endpoint_address,
    method,
    source_address=None,
    proxy_url=None,
    management_vrf=False,
):
    argv = []
    if management_vrf:
        argv.extend(("sudo", "ip", "vrf", "exec", "mgmt"))
    argv.extend(
        (
            "curl",
            "--silent",
            "--show-error",
            "--insecure",
            "--max-time",
            str(PROBE_TIMEOUT_SECONDS),
        )
    )
    if source_address:
        argv.extend(("--interface", source_address))
    if proxy_url:
        argv.extend(("--proxy", proxy_url, "--noproxy", ""))
    else:
        argv.extend(("--noproxy", "*"))
    argv.extend(
        (
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "https://[{}]:{}/healthz".format(endpoint_address, API_SERVER_PORT),
        )
    )

    command_result = duthost.command(
        argv=argv,
        module_ignore_errors=True,
        verbose=False,
    )
    attempt = _classify_curl_result(command_result)
    attempt["method"] = method
    return attempt


def _unbound_route(duthost, endpoint_address):
    route_result = duthost.command(
        argv=("ip", "-6", "route", "get", endpoint_address),
        module_ignore_errors=True,
        verbose=False,
    )
    route = (route_result.get("stdout") or "").strip()
    if route_result.get("rc") != 0:
        return route, False, "route_lookup_error"
    return route, bool(re.search(r"\bdev\s+{}(?:\s|$)".format(MGMT_INTERFACE), route)), None


def _set_final_result(result, attempt):
    result.update(
        {
            "curl_rc": attempt.get("curl_rc"),
            "http_status": attempt.get("http_status"),
            "healthy": attempt["healthy"],
            "failure_category": attempt.get("failure_category"),
            "method": attempt["method"],
        }
    )


def _validate_proxy_url(proxy_url):
    if not proxy_url:
        return None
    parsed = urlparse(proxy_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.path not in ("", "/"):
        raise ValueError("{} must be an HTTP(S) proxy URL without a path".format(CONNECT_PROXY_ENV))
    return proxy_url


def _probe_endpoint(duthost, endpoint_name, endpoint_address, proxy_url=None):
    result = _new_result(duthost, endpoint_name, endpoint_address)
    proxy_url = _validate_proxy_url(proxy_url)
    source_address, gateway = _get_mgmt_ipv6_path(duthost)
    management_vrf = _is_mgmt_vrf_enabled(duthost)
    result["source_address"] = source_address
    result["gateway"] = gateway
    result["management_vrf"] = management_vrf

    route, route_uses_mgmt, route_error = _unbound_route(duthost, endpoint_address)
    result["unbound_route"] = route
    if route_error:
        result["attempts"].append(
            {
                "method": "direct",
                "healthy": False,
                "failure_category": route_error,
            }
        )
    elif route_uses_mgmt:
        attempt = _curl_endpoint(duthost, endpoint_address, "direct")
        result["attempts"].append(attempt)
        if attempt["healthy"]:
            _set_final_result(result, attempt)
            return result
    else:
        result["attempts"].append(
            {
                "method": "direct",
                "healthy": False,
                "failure_category": "data_plane_route",
            }
        )

    if management_vrf:
        attempt = _curl_endpoint(
            duthost,
            endpoint_address,
            "management_vrf",
            management_vrf=True,
        )
        result["attempts"].append(attempt)
        if attempt["healthy"]:
            _set_final_result(result, attempt)
            return result

    if source_address:
        attempt = _curl_endpoint(
            duthost,
            endpoint_address,
            "management_bind",
            source_address=source_address,
        )
        result["attempts"].append(attempt)
        if attempt["healthy"]:
            _set_final_result(result, attempt)
            return result
    else:
        result["attempts"].append(
            {
                "method": "management_bind",
                "healthy": False,
                "failure_category": "missing_mgmt_ipv6",
            }
        )

    if proxy_url:
        attempt = _curl_endpoint(
            duthost,
            endpoint_address,
            "connect_proxy",
            proxy_url=proxy_url,
            management_vrf=management_vrf,
        )
        result["attempts"].append(attempt)

    _set_final_result(result, result["attempts"][-1])

    return result


@pytest.mark.parametrize(
    "endpoint_name,endpoint_address",
    API_SERVER_ENDPOINTS,
    ids=[endpoint[0] for endpoint in API_SERVER_ENDPOINTS],
)
def test_network_test_api_health(
    duthosts,
    enum_dut_hostname,
    request,
    endpoint_name,
    endpoint_address,
):
    duthost = duthosts[enum_dut_hostname]
    try:
        result = _probe_endpoint(
            duthost,
            endpoint_name,
            endpoint_address,
            proxy_url=os.environ.get(CONNECT_PROXY_ENV),
        )
    except Exception as error:  # Keep this telemetry probe non-blocking.
        result = _new_result(duthost, endpoint_name, endpoint_address)
        result["failure_category"] = "probe_error"
        result["error"] = str(error)[:256]

    try:
        _add_custom_msg(
            request,
            "kubesonic.network_test_api_health.{}.{}".format(
                duthost.hostname.replace(".", "_"),
                endpoint_name,
            ),
            result,
        )
    except Exception as error:
        logger.warning("Unable to publish Network-Test API CustomMsg: %s", error)
    log = logger.info if result["healthy"] else logger.warning
    log("%s %s", RESULT_LOG_PREFIX, json.dumps(result, sort_keys=True))
