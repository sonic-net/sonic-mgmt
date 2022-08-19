#!/usr/bin/env python3
import argparse
from urllib import response
import grpc

from collections import namedtuple

import nic_simulator_grpc_service_pb2
import nic_simulator_grpc_service_pb2_grpc
import nic_simulator_grpc_mgmt_service_pb2
import nic_simulator_grpc_mgmt_service_pb2_grpc


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
    parser.add_argument(
        "-m",
        "--test_mgmt",
        default=False,
        action="store_true",
        help="Test mgmt gRPC server"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    server = args.server
    port = args.server_port
    test_mgmt = args.test_mgmt
    with grpc.insecure_channel("%s:%s" % (server, port)) as channel:
        # metadata_interceptor = MetadataInterceptor(("grpc_server", "192.168.0.101"))
        # with grpc.intercept_channel(insecure_channel, metadata_interceptor) as channel:
        if test_mgmt:
            stub = nic_simulator_grpc_mgmt_service_pb2_grpc.DualTorMgmtServiceStub(channel)
            request = nic_simulator_grpc_mgmt_service_pb2.ListOfAdminRequest(
                nic_addresses=["192.168.0.3", "192.168.0.5"],
                admin_requests=[
                    nic_simulator_grpc_service_pb2.AdminRequest(
                        portid=[0, 1],
                        state=[True, True]
                    ),
                    nic_simulator_grpc_service_pb2.AdminRequest(
                        portid=[0, 1],
                        state=[True, True]
                    ),
                ]
            )
            response = stub.QueryAdminPortState(request)
            print(response)

            request = nic_simulator_grpc_mgmt_service_pb2.ListOfAdminRequest(
                nic_addresses=["192.168.0.3", "192.168.0.5"],
                admin_requests=[
                    nic_simulator_grpc_service_pb2.AdminRequest(
                        portid=[0, 1],
                        state=[False, True]
                    ),
                    nic_simulator_grpc_service_pb2.AdminRequest(
                        portid=[0, 1],
                        state=[True, False]
                    ),
                ]
            )
            response = stub.SetAdminPortState(request)
            print(response)

            request = nic_simulator_grpc_mgmt_service_pb2.ListOfAdminRequest(
                nic_addresses=["192.168.0.3", "192.168.0.5"],
                admin_requests=[
                    nic_simulator_grpc_service_pb2.AdminRequest(
                        portid=[0, 1],
                        state=[True, True]
                    ),
                    nic_simulator_grpc_service_pb2.AdminRequest(
                        portid=[0, 1],
                        state=[True, True]
                    ),
                ]
            )
            response = stub.QueryAdminPortState(request)
            print(response)
        else:
            stub = nic_simulator_grpc_service_pb2_grpc.DualToRActiveStub(channel)
            request = nic_simulator_grpc_service_pb2.AdminRequest(
                portid=[0, 1],
                state=[True, True]
            )
            response = stub.QueryAdminPortState(request)
            print(response)

            request = nic_simulator_grpc_service_pb2.AdminRequest(
                portid=[0, 1],
                state=[True, False]
            )
            response = stub.SetAdminPortState(request)
            print(response)


if __name__ == "__main__":
    main()
