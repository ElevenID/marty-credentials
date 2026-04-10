"""Regression tests for lazy protobuf package imports in marty-credentials."""

from __future__ import annotations

import importlib
import sys


def _clear_proto_modules() -> None:
    for name in list(sys.modules):
        if name == "marty_proto.v1" or name.startswith("marty_proto.v1."):
            sys.modules.pop(name, None)


class TestProtoPackageLazyImports:
    def test_package_import_does_not_eagerly_import_all_submodules(self):
        _clear_proto_modules()

        pkg = importlib.import_module("marty_proto.v1")

        assert pkg.__all__
        assert "marty_proto.v1.auth_service_pb2" not in sys.modules
        assert "marty_proto.v1.issuance_service_pb2" not in sys.modules

    def test_direct_from_import_for_issuance_stubs(self):
        _clear_proto_modules()

        namespace: dict[str, object] = {}
        exec(
            "from marty_proto.v1 import issuance_service_pb2 as pb2, issuance_service_pb2_grpc",
            namespace,
            namespace,
        )

        assert namespace["pb2"].__name__ == "marty_proto.v1.issuance_service_pb2"
        assert namespace["issuance_service_pb2_grpc"].__name__ == "marty_proto.v1.issuance_service_pb2_grpc"

    def test_multiple_stub_imports_share_same_package_instance(self):
        _clear_proto_modules()

        pkg = importlib.import_module("marty_proto.v1")
        issuance_pb2 = pkg.issuance_service_pb2
        auth_pb2 = pkg.auth_service_pb2

        assert issuance_pb2.__name__ == "marty_proto.v1.issuance_service_pb2"
        assert auth_pb2.__name__ == "marty_proto.v1.auth_service_pb2"
        assert sys.modules["marty_proto.v1"] is pkg
