#!/usr/bin/env python3
import argparse
import grpc

from collections import namedtuple

import nic_simulator_grpc_service_pb2
import nic_simulator_grpc_service_pb2_grpc


class MetadataInterceptor(grpc.UnaryUnaryClientInterceptor):

    class _ClientCallDetails(
            namedtuple(
                '_ClientCallDetails',
                ('method', 'timeout', 'metadata', 'credentials')),
            grpc.ClientCallDetails):
        """Wrapper class for initializing a new ClientCallDetails instance.
        """
        pass

    def __init__(self, injected_meta):
        self.injected_meta = injected_meta

    def intercept_unary_unary(self, continuation, client_call_details, request):

        if client_call_details.metadata is None:
            metadata = []
        else:
            metadata = list(client_call_details.metadata)

        metadata.append(self.injected_meta)

        client_call_details = self._ClientCallDetails(
            client_call_details.method,
            client_call_details.timeout,
            metadata,
            client_call_details.credentials
        )
        return continuation(client_call_details, request)


def parse_args():
    parser = argparse.ArgumentParser(
        description="NiC simulator client"
    )
    parser.add_argument(
        "-s",
        "--server",
        required=True,
        help="gRPC server address"
    )
    parser.add_argument(
        "-p",
        "--server_port",
        required=True,
        help="gRPC server port"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    server = args.server
    port = args.server_port
    with grpc.insecure_channel("%s:%s" % (server, port)) as insecure_channel:
        metadata_interceptor = MetadataInterceptor(("grpc_server", "192.168.0.101"))
        with grpc.intercept_channel(insecure_channel, metadata_interceptor) as channel:
            stub = nic_simulator_grpc_service_pb2_grpc.DualTorServiceStub(channel)
            state = nic_simulator_grpc_service_pb2.AdminRequest(
                portid=[0, 1],
                state=[True, True]
            )
            state = stub.QueryAdminPortState(state)
            print(state)

            state = nic_simulator_grpc_service_pb2.AdminRequest(
                portid=[0, 1],
                state=[True, False]
            )
            state = stub.SetAdminPortState(state)
            print(state)


if __name__ == "__main__":
    main()
