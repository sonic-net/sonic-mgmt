import grpc
import json
import tests.common.sai_validation.generated.github.com.openconfig.gnmi.proto.gnmi.gnmi_pb2 as gnmi_pb2
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def create_secure_channel(target, root_cert_path, client_cert_path, client_key_path):
    logger.debug("Creating secure channel with target: %s", target)
    try:
        # Load the root certificate
        with open(root_cert_path, 'rb') as f:
            root_cert = f.read()
        logger.debug("Loaded root certificate from: %s", root_cert_path)

        # Load the client certificate
        with open(client_cert_path, 'rb') as f:
            client_cert = f.read()
        logger.debug("Loaded client certificate from: %s", client_cert_path)

        # Load the client key
        with open(client_key_path, 'rb') as f:
            client_key = f.read()
        logger.debug("Loaded client key from: %s", client_key_path)

        # Create SSL credentials
        credentials = grpc.ssl_channel_credentials(
            root_certificates=root_cert,
            private_key=client_key,
            certificate_chain=client_cert
        )
        logger.debug("SSL credentials created successfully")

        # Create a secure channel
        channel = grpc.secure_channel(target, credentials)
        logger.debug("Secure channel created successfully")
        return channel
    except Exception as e:
        logger.error("Failed to create secure channel: %s", e)
        raise


def extract_json_ietf_as_dict(response) -> List[Dict]:
    """
    Extracts json_ietf_val values from a gNMI GetResponse as a list of dictionaries.

    Args:
        response: The gNMI GetResponse object.

    Returns:
        A list of dictionaries representing the json_ietf_val values.
        Returns an empty list if no json_ietf_val values are found or an error occurs.
    """
    result = []
    if not response or not response.notification:
        return result

    for notification in response.notification:
        for update in notification.update:
            if update.val.HasField("json_ietf_val"):
                try:
                    json_str = update.val.json_ietf_val.decode('utf-8')
                    data = json.loads(json_str)
                    result.append(data)
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON: {e}")
                except UnicodeDecodeError as ue:
                    print(f"Error decoding unicode: {ue}")
                except Exception as e:
                    print(f"An unexpected error occured: {e}")
    return result
