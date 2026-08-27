"""Unit tests for revoked-certificate gNMI error handling."""

import importlib.util
import sys
from pathlib import Path

import grpc
import pytest
from pygnmi.client import gNMIException

from tests.common.pygnmi_client import PygnmiClientCallError


MODULE_PATH = Path(__file__).resolve().parents[2] / "gnmi" / "test_gnmi_crl.py"


def _load_test_gnmi_crl():
    spec = importlib.util.spec_from_file_location(
        "unit_target_test_gnmi_crl", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _RpcError(grpc.RpcError):
    def code(self):
        return grpc.StatusCode.UNAUTHENTICATED


@pytest.mark.parametrize(
    "cause",
    [
        _RpcError(),
        gNMIException("Peer certificate revoked", _RpcError()),
    ],
)
def test_rpc_status_reads_direct_and_wrapped_grpc_errors(cause):
    test_gnmi_crl = _load_test_gnmi_crl()
    error = PygnmiClientCallError("gnmi set failed")
    error.__cause__ = cause

    assert test_gnmi_crl._rpc_status(error) == grpc.StatusCode.UNAUTHENTICATED
