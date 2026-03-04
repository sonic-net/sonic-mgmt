import json
import logging
import pytest

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnoi_tls_server",
                            "check_dut_timestamp")
]


def gnmi_path_to_proto(path_str):
    """
    Convert a sonic-db gNMI path string to a gNMI Path proto dict.

    Example:
        "/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"
        ->
        {
            "origin": "sonic-db",
            "elem": [
                {"name": "CONFIG_DB"},
                {"name": "localhost"},
                {"name": "DEVICE_METADATA"},
                {"name": "localhost"}
            ]
        }
    """
    # Strip origin prefix if present
    origin = ""
    if ":" in path_str.split("/")[1]:
        prefix, path_str = path_str.split(":", 1)
        origin = prefix.lstrip("/")

    # Split remaining path into elements, skip empty
    elems = [{"name": seg} for seg in path_str.split("/") if seg]

    path = {"elem": elems}
    if origin:
        path["origin"] = origin
    return path


def test_gnmi_configdb_get_metadata(duthosts, rand_one_dut_hostname, ptf_grpc):
    """
    Verify gNMI Get for CONFIG_DB DEVICE_METADATA using new grpcurl-based fixture.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Build gNMI GetRequest
    path = gnmi_path_to_proto("/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost")
    request = {
        "path": [path],
        "encoding": "JSON_IETF"
    }

    logger.info("Sending gNMI Get request: %s", json.dumps(request))
    response = ptf_grpc.call_unary("gnmi.gNMI", "Get", request)
    logger.info("gNMI Get response: %s", json.dumps(response))

    # Verify response contains notification with updates
    assert "notification" in response, "Missing 'notification' in GetResponse: %s" % response
    notifications = response["notification"]
    assert len(notifications) > 0, "Empty notifications in GetResponse"

    # Extract the value from the first notification's first update
    updates = notifications[0].get("update", [])
    assert len(updates) > 0, "No updates in notification: %s" % notifications[0]

    # The val should contain DEVICE_METADATA fields including bgp_asn
    val = updates[0].get("val", {})
    json_val = val.get("jsonIetfVal", "")
    if json_val:
        # grpcurl returns base64-encoded bytes for jsonIetfVal
        import base64
        decoded = base64.b64decode(json_val).decode("utf-8")
        result = json.loads(decoded)
    else:
        result = val

    logger.info("Decoded value: %s", result)
    # Check for bgp_asn in the result (could be nested under "localhost" or flat)
    result_str = json.dumps(result)
    assert "bgp_asn" in result_str, "bgp_asn not found in GetResponse value: %s" % result_str
