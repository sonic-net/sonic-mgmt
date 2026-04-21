# (c) 2019 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
author: Ansible Networking Team
name: grpc
short_description: gRPC plugin for IOS-XR devices
description:
  - This gRPC plugin provides methods to connect and talk to Cisco IOS XR
    devices over gRPC protocol.
version_added: "3.3.0"
"""

import json
import os
import sys

from ansible_collections.ansible.netcommon.plugins.sub_plugins.grpc.base import (
    GrpcBase,
    ensure_connect,
)


class Grpc(GrpcBase):
    def __init__(self, connection):
        super(Grpc, self).__init__(connection)
        module_name = "ems_grpc_pb2"
        module_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "pb/ems_grpc_pb2.py",
        )
        if sys.version_info[0] == 3 and sys.version_info[1] >= 5:
            import importlib.util

            spec = importlib.util.spec_from_file_location(module_name, module_path)
            self._ems_grpc_pb2 = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self._ems_grpc_pb2)
        elif sys.version_info[0] == 3 and sys.version_info[1] < 5:
            import importlib.machinery

            loader = importlib.machinery.SourceFileLoader(module_name, module_path)
            self._ems_grpc_pb2 = loader.load_module()
        elif sys.version_info[0] == 2:
            import imp

            self._ems_grpc_pb2 = imp.load_source(module_name, module_path)

    def get_config(self, section=None):
        stub = self._ems_grpc_pb2.beta_create_gRPCConfigOper_stub(
            self._connection._channel,
        )
        message = self._ems_grpc_pb2.ConfigGetArgs(yangpathjson=section)
        responses = stub.GetConfig(
            message,
            self._connection._timeout,
            metadata=self._connection._login_credentials,
        )
        output = {"response": "", "error": ""}
        for response in responses:
            output["response"] += response.yangjson
            output["error"] += response.errors
        return output

    def get(self, section=None):
        stub = self._ems_grpc_pb2.beta_create_gRPCConfigOper_stub(
            self._connection._channel,
        )
        message = self._ems_grpc_pb2.GetOperArgs(yangpathjson=section)
        responses = stub.GetOper(
            message,
            self._connection._timeout,
            metadata=self._connection._login_credentials,
        )
        output = {"response": "", "error": ""}
        for response in responses:
            output["response"] += response.yangjson
            output["error"] += response.errors
        return output

    @ensure_connect
    def merge_config(self, path):
        """Merge grpc call equivalent  of PATCH RESTconf call
        :param data: JSON
        :type data: str
        :return: Return the response object
        :rtype: Response object
        """
        path = json.dumps(path)
        stub = self._ems_grpc_pb2.beta_create_gRPCConfigOper_stub(
            self._connection._channel,
        )
        message = self._ems_grpc_pb2.ConfigArgs(yangjson=path)
        response = stub.MergeConfig(
            message,
            self._connection._timeout,
            metadata=self._connection._login_credentials,
        )
        if response:
            return response.errors
        else:
            return None

    @ensure_connect
    def replace_config(self, path):
        """Replace grpc call equivalent  of PATCH RESTconf call
        :param data: JSON
        :type data: str
        :return: Return the response object
        :rtype: Response object
        """
        path = json.dumps(path)
        stub = self._ems_grpc_pb2.beta_create_gRPCConfigOper_stub(
            self._connection._channel,
        )
        message = self._ems_grpc_pb2.ConfigArgs(yangjson=path)
        response = stub.ReplaceConfig(
            message,
            self._connection._timeout,
            metadata=self._connection._login_credentials,
        )
        if response:
            return response.errors
        else:
            return None

    @ensure_connect
    def delete_config(self, path):
        """Delete grpc call equivalent  of PATCH RESTconf call
        :param data: JSON
        :type data: str
        :return: Return the response object
        :rtype: Response object
        """
        path = json.dumps(path)
        stub = self._ems_grpc_pb2.beta_create_gRPCConfigOper_stub(
            self._connection._channel,
        )
        message = self._ems_grpc_pb2.ConfigArgs(yangjson=path)
        response = stub.DeleteConfig(
            message,
            self._connection._timeout,
            metadata=self._connection._login_credentials,
        )
        if response:
            return response.errors
        else:
            return None

    @ensure_connect
    def run_cli(self, command=None, display=None):
        if command is None:
            raise ValueError("command value must be provided")

        output = {"response": "", "error": ""}
        stub = self._ems_grpc_pb2.beta_create_gRPCExec_stub(
            self._connection._channel,
        )

        message = self._ems_grpc_pb2.ShowCmdArgs(cli=command)
        if display == "text":
            responses = stub.ShowCmdTextOutput(
                message,
                self._connection._timeout,
                metadata=self._connection._login_credentials,
            )
            for response in responses:
                output["response"] += response.output
                output["error"] += response.errors
        else:
            responses = stub.ShowCmdJSONOutput(
                message,
                self._connection._timeout,
                metadata=self._connection._login_credentials,
            )
            for response in responses:
                output["response"] += response.jsonoutput
                output["error"] += response.errors
        return output

    @property
    def server_capabilities(self):
        capability = dict()
        capability["display"] = ["json", "text"]
        capability["data_type"] = ["config", "oper"]
        capability["supports_commit"] = True
        capability["supports_cli_command"] = True
        return capability

    @ensure_connect
    def get_capabilities(self):
        result = dict()
        result["rpc"] = self.__rpc__ + ["commit", "discard_changes"]
        result["network_api"] = "ansible.netcommon.grpc"
        result["server_capabilities"] = self.server_capabilities
        return result
