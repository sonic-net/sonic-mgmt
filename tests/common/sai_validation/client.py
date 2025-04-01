# import argparse
# import ssl
import grpc
import tests.common.sai_validation.gnmi_pb2 as gnmi_pb2
import tests.common.sai_validation.gnmi_pb2_grpc as gnmi_pb2_grpc
import logging
# import sys
import json
# import threading
# import queue

# To enable GRPC SSL Handshake Trace
# import os
#
# os.environ["GRPC_SSL_CIPHER_SUITES"] = "HIGH+ECDSA" # this line sometimes helps.
# os.environ["GRPC_TRACE"] = "all"
# os.environ["GRPC_VERBOSITY"] = "DEBUG"

logger = logging.getLogger(__name__)

# class Error(Exception):
#   """Module-level Exception class."""
#
#
# class JsonReadError(Error):
#   """Error parsing provided JSON file."""


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


def create_gnmi_stub(ip, port, secure=False, root_cert_path=None, client_cert_path=None, client_key_path=None):
    logger.debug("Creating gNMI stub for target: %s:%s, secure: %s", ip, port, secure)
    try:
        channel = None
        target = f"{ip}:{port}"
        if not secure:
            channel = gnmi_pb2_grpc.grpc.insecure_channel(target)
            logger.debug("Insecure channel created for target: %s", target)
        else:
            channel = create_secure_channel(target, root_cert_path, client_cert_path, client_key_path)
        stub = gnmi_pb2_grpc.gNMIStub(channel)
        logger.debug("gNMI stub created successfully")
        return channel, stub
    except Exception as e:
        logger.error("Failed to create gNMI stub: %s", e)
        raise


def get_gnmi_path(path_str):
    """Convert a string path to a gNMI Path object."""
    path_elems = [gnmi_pb2.PathElem(name=elem) for elem in path_str.split('/')]
    return gnmi_pb2.Path(elem=path_elems, origin="sonic-db")


def get_request(stub, path):
    logger.debug("Sending GetRequest to gNMI server with path: %s", path)
    try:
        prefix = gnmi_pb2.Path(origin="sonic-db")
        request = gnmi_pb2.GetRequest(prefix=prefix, path=[path], encoding=gnmi_pb2.Encoding.JSON_IETF)
        logger.debug("GetRequest created: %s", request)
        response = stub.Get(request)
        logger.debug("GetResponse received: %s", response)
        return response
    except grpc.RpcError as e:
        logger.error("gRPC Error during GetRequest: %s - %s", e.code(), e.details())
        raise
    except Exception as e:
        logger.error("Unexpected error during GetRequest: %s", e)
        raise


def set_gnmi_value_json_ietf(stub, path, value, origin="sonic-db"):
    """
    Sets a value for a given path using gNMI, with JSON_IETF encoding.

    Args:
        stub: gRPC stub for the gNMI service.
        path: String representing the gNMI path.
        value: The value to set (must be a JSON-serializable object).
        origin: The origin of the path (default: "sonic-db").

    Returns:
        The gNMI SetResponse, or None if an error occurred.
    """
    try:
        path_elements = [gnmi_pb2.PathElem(name=elem) for elem in path.split("/")]
        logger.debug(f"path_elements = {path_elements}")
        path_obj = gnmi_pb2.Path(elem=path_elements, origin=origin)
        logger.debug(f"path_obj = {path_obj}")

        update = gnmi_pb2.Update(path=path_obj)
        typed_value = gnmi_pb2.TypedValue()

        # Encode the JSON value using JSON_IETF
        logger.debug(f"type = {type(value)}, value = {value}")
        typed_value.json_ietf_val = json.dumps(value).encode('utf-8')
        logger.debug(f"typed_value.json_ietf_val = {typed_value.json_ietf_val}")

        update.val.CopyFrom(typed_value)
        set_request = gnmi_pb2.SetRequest(update=[update])
        response = stub.Set(set_request)
        return response

    except grpc.RpcError as e:
        print(f"gNMI Set failed: {e}")
        return None
    except json.JSONDecodeError as je:
        print(f"JSON Decode Error: {je}")
        return None
    except Exception as ex:
        print(f"An unexpected error occurred: {ex}")
        return None


def set_request(stub, path, value, data_type='json_val', origin="sonic-db"):
    logger.debug("Sending SetRequest to gNMI server with path: %s, value: %s, data_type: %s", path, value, data_type)
    try:
        path_elements = [gnmi_pb2.PathElem(name=elem) for elem in path.split("/")]
        path_obj = gnmi_pb2.Path(elem=path_elements, origin=origin)

        update = gnmi_pb2.Update(path=path_obj)
        typed_value = gnmi_pb2.TypedValue()

        if data_type == "json_val":
            typed_value.json_val = json.dumps(value).encode('utf-8')
        elif data_type == "string_val":
            typed_value.string_val = str(value)
        elif data_type == "int_val":
            typed_value.int_val = int(value)
        elif data_type == "bool_val":
            typed_value.bool_val = bool(value)
        else:
            raise ValueError("Unsupported value type")

        update.val.CopyFrom(typed_value)
        set_req = gnmi_pb2.SetRequest(update=[update])
        logger.debug("SetRequest created: %s", set_req)
        response = stub.Set(set_req)
        logger.debug("SetResponse received: %s", response)
        return response
    except grpc.RpcError as e:
        logger.error("gRPC Error during SetRequest: %s - %s", e.code(), e.details())
        raise
    except ValueError as ve:
        logger.error("Value Error during SetRequest: %s", ve)
        raise
    except Exception as ex:
        logger.error("Unexpected error during SetRequest: %s", ex)
        raise


def subscribe_gnmi(stub, paths,
                   subscription_mode=1,
                   origin="sonic-db",
                   watch_subtrees=False,
                   stop_event=None,
                   event_queue=None):
    """
    Subscribes to gNMI paths and pushes received notifications to a queue.

    Args:
        stub: gRPC stub for the gNMI service.
        paths: A list of strings representing the gNMI paths to subscribe to.
        subscription_mode: The subscription mode (default: 1 (STREAM)).
        origin: The origin of the path (default: "sonic-db").
        watch_subtrees: If True, subscribes to the entire subtree for each path.
        stop_event: A threading.Event object to signal the thread to stop.
        event_queue: A queue.Queue object to push received events.
    """
    try:
        subscriptions = []
        for path_str in paths:
            path_elements = [gnmi_pb2.PathElem(name=elem) for elem in path_str.split("/")]
            path_obj = gnmi_pb2.Path(elem=path_elements, origin=origin)
            subscription = gnmi_pb2.Subscription(path=path_obj, mode=subscription_mode)
            subscriptions.append(subscription)

        subscription_list = gnmi_pb2.SubscriptionList()
        subscription_list.subscription.extend(subscriptions)

        subscribe_request = gnmi_pb2.SubscribeRequest(subscribe=subscription_list)

        responses = stub.Subscribe(iter([subscribe_request]))

        for response in responses:
            if stop_event and stop_event.is_set():
                print("Subscription stopped.")
                break  # Exit the loop

            if response.sync_response:
                if event_queue:
                    event_queue.put({"type": "sync_response", "message": "Synchronization complete."})
            elif response.HasField("update"):
                notification = response.update
                for update in notification.update:
                    path_str = "/".join([elem.name for elem in update.path.elem])
                    value = None
                    value_type = None

                    if update.val.HasField("json_val"):
                        value = json.loads(update.val.json_val.decode('utf-8'))
                        value_type = "JSON"
                    elif update.val.HasField("string_val"):
                        value = update.val.string_val
                        value_type = "String"
                    elif update.val.HasField("int_val"):
                        value = update.val.int_val
                        value_type = "Int"
                    elif update.val.HasField("bool_val"):
                        value = update.val.bool_val
                        value_type = "Bool"
                    elif update.val.HasField("json_ietf_val"):
                        value = json.loads(update.val.json_ietf_val.decode('utf-8'))
                        value_type = "JSON_IETF"
                    else:
                        value = update.val
                        value_type = "Unknown"

                    if event_queue:
                        event_queue.put({"type": "update", "path": path_str, "value": value, "value_type": value_type})

            elif response.HasField("error"):
                if event_queue:
                    event_queue.put({"type": "error", "message": f"gNMI Subscribe error: {response.error}"})

    except grpc.RpcError as e:
        if event_queue:
            event_queue.put({"type": "error", "message": f"gNMI Subscribe failed: {e}"})
    except json.JSONDecodeError as je:
        if event_queue:
            event_queue.put({"type": "error", "message": f"JSON Decode Error: {je}"})
    except Exception as ex:
        if event_queue:
            event_queue.put({"type": "error", "message": f"An unexpected error occurred: {ex}"})


# def main():
#     parser = argparse.ArgumentParser(description="gNMI Client")
#     parser.add_argument("--ip", required=True, help="Target gNMI server IP address")
#     parser.add_argument("--port", required=True, help="Target gNMI server port")
#     parser.add_argument("--path", required=True, help="gNMI path to query")
#     parser.add_argument("--secure", action="store_true", help="Use secure channel")
#     parser.add_argument("--root_cert", help="Root certificate path")
#     parser.add_argument("--client_cert", help="Client certificate path")
#     parser.add_argument("--client_key", help="Client key path")
#     parser.add_argument("--operation", help="Operation to perform (get, set-string, subscribe)")
#     parser.add_argument("--value", help="Value to set (for set operation)")
#     parser.add_argument("--mode", help="Subscription mode (STREAM, ONCE, POLL). Default is STREAM", default="STREAM")
#     parser.add_argument("--trace", action="store_true", help="Enable debug-level logging")
#
#     args = parser.parse_args()
#
#     # Set logging level based on --trace option
#     if args.trace:
#         logger.setLevel(logging.DEBUG)
#         logger.debug("Debug-level logging enabled")
#     else:
#         logger.setLevel(logging.INFO)
#
#     logger.debug("Parsed arguments: %s", args)
#
#     try:
#         stub = create_gnmi_stub(args.ip, args.port, args.secure, args.root_cert, args.client_cert, args.client_key)
#
#         if args.operation == "get":
#             gnmi_path = get_gnmi_path(args.path)
#             response = get_request(stub, gnmi_path)
#             print("gNMI GetResponse:")
#             print(response)
#         elif args.operation == "set-string":
#             response = set_request(stub, args.path, args.value, data_type='string_val')
#             print("gNMI SetResponse:")
#             print(response)
#         elif args.operation == "set-json":
#             value = json.loads(args.value)
#             response = set_gnmi_value_json_ietf(stub, args.path, value)
#             print("gNMI SetResponse:")
#             print(response)
#         elif args.operation == "subscribe":
#             if args.mode == "STREAM":
#                 subscribe_gnmi(stub, [args.path], subscription_mode=1, watch_subtrees=True)
#             elif args.mode == "ONCE":
#                 subscribe_gnmi(stub, [args.path], subscription_mode=2)
#             elif args.mode == "POLL":
#                 subscribe_gnmi(stub, [args.path], subscription_mode=3)
#             else:
#                 logger.error("Invalid subscription mode: %s", args.mode)
#         else:
#             logger.error("Unsupported operation: %s", args.operation)
#     except Exception as e:
#         logger.error("Error in main: %s", e)
#         raise
#
#
# if __name__ == "__main__":
#     main()
