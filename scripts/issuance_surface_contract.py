#!/usr/bin/env python3
"""Freeze the observable Python issuance surface for the native Rust cutover."""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ISSUANCE_ROOT = ROOT / "services" / "issuance"
MANIFEST = ROOT / "contracts" / "issuance-runtime-surface.json"
HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}


class ContractError(RuntimeError):
    """The issuance source cannot be represented by the frozen contract."""


@dataclass(frozen=True)
class PythonSource:
    path: Path
    relative: str
    tree: ast.Module


def _python_sources(root: Path = ISSUANCE_ROOT) -> list[PythonSource]:
    sources: list[PythonSource] = []
    for path in sorted(root.rglob("*.py")):
        if "tests" in path.parts or "migrations" in path.parts:
            continue
        sources.append(
            PythonSource(
                path=path,
                relative=path.relative_to(ROOT).as_posix(),
                tree=ast.parse(path.read_text(encoding="utf-8"), filename=str(path)),
            )
        )
    return sources


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _path_argument(call: ast.Call) -> str | None:
    node = call.args[0] if call.args else _keyword(call, "path")
    return _literal_string(node)


def _join_route(prefix: str, path: str) -> str:
    if not prefix:
        return path or "/"
    if not path:
        return prefix
    return f"{prefix.rstrip('/')}/{path.lstrip('/')}"


def _router_prefixes(sources: list[PythonSource]) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    for source in sources:
        for node in ast.walk(source.tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if not isinstance(value, ast.Call) or _call_name(value.func) != "APIRouter":
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [target.id for target in targets if isinstance(target, ast.Name)]
            prefix_node = _keyword(value, "prefix")
            prefix = _literal_string(prefix_node) if prefix_node is not None else ""
            if prefix is None:
                raise ContractError(f"dynamic APIRouter prefix at {source.relative}:{node.lineno}")
            for name in names:
                if name in prefixes and prefixes[name] != prefix:
                    raise ContractError(f"router {name} has conflicting prefixes")
                prefixes[name] = prefix
    return prefixes


def _registered_routers(main: PythonSource) -> set[str]:
    registered: set[str] = set()
    for node in ast.walk(main.tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "include_router" or not node.args:
            continue
        router = node.args[0]
        if not isinstance(router, ast.Name):
            raise ContractError(f"dynamic include_router call at {main.relative}:{node.lineno}")
        registered.add(router.id)
    return registered


def _api_route_methods(call: ast.Call, source: PythonSource, line: int) -> list[str]:
    methods_node = _keyword(call, "methods")
    if not isinstance(methods_node, (ast.List, ast.Tuple, ast.Set)):
        raise ContractError(f"api_route methods must be literal at {source.relative}:{line}")
    methods = [_literal_string(item) for item in methods_node.elts]
    if any(method is None for method in methods):
        raise ContractError(f"api_route method must be a string at {source.relative}:{line}")
    return sorted({method.upper() for method in methods if method is not None})


def _http_routes(sources: list[PythonSource]) -> list[dict[str, Any]]:
    prefixes = _router_prefixes(sources)
    main = next(source for source in sources if source.relative == "services/issuance/main.py")
    registered = _registered_routers(main)
    missing = sorted(registered - prefixes.keys())
    if missing:
        raise ContractError(f"registered routers have no static prefix: {', '.join(missing)}")

    routes: list[dict[str, Any]] = []
    for source in sources:
        for node in ast.walk(source.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) or not isinstance(
                    decorator.func, ast.Attribute
                ):
                    continue
                receiver = decorator.func.value
                if not isinstance(receiver, ast.Name):
                    continue
                router = receiver.id
                route_kind = decorator.func.attr.lower()
                if route_kind not in HTTP_METHODS | {"api_route"}:
                    continue
                if router != "app" and router not in registered:
                    continue
                path = _path_argument(decorator)
                if path is None:
                    raise ContractError(
                        f"dynamic route path at {source.relative}:{decorator.lineno}"
                    )
                methods = (
                    _api_route_methods(decorator, source, decorator.lineno)
                    if route_kind == "api_route"
                    else [route_kind.upper()]
                )
                prefix = "" if router == "app" else prefixes[router]
                for method in methods:
                    routes.append(
                        {
                            "method": method,
                            "path": _join_route(prefix, path),
                            "operation": node.name,
                            "router": router,
                            "source": source.relative,
                            "line": decorator.lineno,
                        }
                    )

    routes.sort(key=lambda route: (route["path"], route["method"], route["operation"]))
    identities: dict[tuple[str, str], list[str]] = {}
    for route in routes:
        key = (route["method"], route["path"])
        identities.setdefault(key, []).append(route["operation"])
    duplicates = {key: value for key, value in identities.items() if len(value) > 1}
    if duplicates:
        rendered = ", ".join(
            f"{method} {path}: {operations}"
            for (method, path), operations in sorted(duplicates.items())
        )
        raise ContractError(f"duplicate HTTP routes: {rendered}")
    return routes


def _grpc_methods() -> list[dict[str, Any]]:
    generated_path = ROOT / "packages" / "marty_proto" / "v1" / "issuance_service_pb2_grpc.py"
    adapter_path = ISSUANCE_ROOT / "infrastructure" / "adapters" / "grpc_adapter.py"
    generated = ast.parse(generated_path.read_text(encoding="utf-8"), filename=str(generated_path))
    adapter = ast.parse(adapter_path.read_text(encoding="utf-8"), filename=str(adapter_path))

    stub = next(
        node
        for node in generated.body
        if isinstance(node, ast.ClassDef) and node.name == "IssuanceServiceStub"
    )
    initializer = next(
        node for node in stub.body if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    )
    methods: list[dict[str, Any]] = []
    for statement in initializer.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if not (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Attribute)
        ):
            continue
        rpc_path = _literal_string(statement.value.args[0] if statement.value.args else None)
        if rpc_path is None:
            raise ContractError(f"dynamic gRPC path at {generated_path}:{statement.lineno}")
        request = _call_name(_keyword(statement.value, "request_serializer"))
        response = _call_name(_keyword(statement.value, "response_deserializer"))
        methods.append(
            {
                "method": target.attr,
                "path": rpc_path,
                "transport": statement.value.func.attr,
                "request": request,
                "response": response,
                "source": generated_path.relative_to(ROOT).as_posix(),
                "line": statement.lineno,
            }
        )

    adapter_class = next(
        node
        for node in adapter.body
        if isinstance(node, ast.ClassDef) and node.name == "IssuanceServiceGrpc"
    )
    implemented = {
        node.name: node.lineno
        for node in adapter_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    }
    declared = {method["method"] for method in methods}
    if declared != implemented.keys():
        raise ContractError(
            "generated and implemented gRPC methods differ: "
            f"declared_only={sorted(declared - implemented.keys())}, "
            f"implemented_only={sorted(implemented.keys() - declared)}"
        )
    adapter_source = adapter_path.relative_to(ROOT).as_posix()
    for method in methods:
        method["implementation_source"] = adapter_source
        method["implementation_line"] = implemented[method["method"]]
    methods.sort(key=lambda method: method["method"])
    return methods


def _environment_variables(sources: list[PythonSource]) -> tuple[list[str], list[dict[str, Any]]]:
    variables: set[str] = set()
    dynamic: list[dict[str, Any]] = []
    for source in sources:
        for node in ast.walk(source.tree):
            argument: ast.AST | None = None
            if isinstance(node, ast.Call):
                name = _call_name(node.func)
                if name in {"os.environ.get", "os.getenv"} and node.args:
                    argument = node.args[0]
            elif isinstance(node, ast.Subscript) and _call_name(node.value) == "os.environ":
                argument = node.slice
            if argument is None:
                continue
            value = _literal_string(argument)
            if value is None:
                dynamic.append({"source": source.relative, "line": node.lineno})
            else:
                variables.add(value)
    dynamic.sort(key=lambda item: (item["source"], item["line"]))
    return sorted(variables), dynamic


def _migration_graph() -> dict[str, Any]:
    versions = ISSUANCE_ROOT / "infrastructure" / "migrations" / "versions"
    revisions: list[dict[str, Any]] = []
    parents: set[str] = set()
    for path in sorted(versions.glob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        values: dict[str, ast.AST] = {}
        lines: dict[str, int] = {}
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id in {"revision", "down_revision"}:
                    values[target.id] = node.value
                    lines[target.id] = node.lineno
        revision = _literal_string(values.get("revision"))
        if revision is None:
            raise ContractError(f"migration has no literal revision: {path}")
        down_node = values.get("down_revision")
        down: list[str] = []
        if isinstance(down_node, ast.Constant) and down_node.value is None:
            pass
        elif (value := _literal_string(down_node)) is not None:
            down.append(value)
        elif isinstance(down_node, (ast.Tuple, ast.List)):
            for item in down_node.elts:
                value = _literal_string(item)
                if value is None:
                    raise ContractError(
                        f"dynamic migration parent: {path}:{lines['down_revision']}"
                    )
                down.append(value)
        else:
            raise ContractError(f"dynamic migration parent: {path}:{lines.get('down_revision', 0)}")
        parents.update(down)
        revisions.append(
            {
                "revision": revision,
                "down_revisions": down,
                "source": path.relative_to(ROOT).as_posix(),
                "line": lines["revision"],
            }
        )

    revision_ids = {item["revision"] for item in revisions}
    unknown = sorted(parents - revision_ids)
    if unknown:
        raise ContractError(f"migration graph references unknown parents: {unknown}")
    roots = sorted(item["revision"] for item in revisions if not item["down_revisions"])
    heads = sorted(revision_ids - parents)
    return {
        "revision_count": len(revisions),
        "roots": roots,
        "heads": heads,
        "revisions": revisions,
    }


def _runtime_modes(sources: list[PythonSource]) -> list[dict[str, Any]]:
    functions: dict[str, set[str]] = {}
    for source in sources:
        functions[source.relative] = {
            node.name
            for node in ast.walk(source.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
    required = {
        "services/issuance/main.py": {"create_app", "lifespan"},
        "services/issuance/canvas_worker.py": {"_main", "run_canvas_sync_worker_loop"},
    }
    for source, names in required.items():
        missing = names - functions.get(source, set())
        if missing:
            raise ContractError(f"runtime mode {source} is missing {sorted(missing)}")
    return [
        {
            "name": "api",
            "module": "main",
            "command": [
                "python",
                "-m",
                "uvicorn",
                "main:app",
                "--host",
                "0.0.0.0",
                "--port",
                "8005",
            ],
            "transports": ["http", "grpc"],
            "source": "services/issuance/main.py",
        },
        {
            "name": "canvas-sync-worker",
            "module": "issuance.canvas_worker",
            "command": ["python", "-m", "issuance.canvas_worker"],
            "transports": ["postgresql", "canvas-http"],
            "source": "services/issuance/canvas_worker.py",
        },
    ]


def build_contract() -> dict[str, Any]:
    """Build the deterministic issuance surface contract from the parity oracle."""
    sources = _python_sources()
    routes = _http_routes(sources)
    grpc = _grpc_methods()
    variables, dynamic = _environment_variables(sources)
    return {
        "schema": "marty.issuance-runtime-surface/v1",
        "purpose": "Language-neutral feature floor for the native Rust issuance cutover",
        "http": {"route_count": len(routes), "routes": routes},
        "grpc": {"method_count": len(grpc), "methods": grpc},
        "runtime": {"modes": _runtime_modes(sources)},
        "configuration": {
            "environment_variable_count": len(variables),
            "environment_variables": variables,
            "dynamic_lookups": dynamic,
        },
        "migrations": _migration_graph(),
    }


def _render(contract: dict[str, Any]) -> str:
    return json.dumps(contract, indent=2, sort_keys=True) + "\n"


def write_contract() -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(_render(build_contract()), encoding="utf-8")


def check_contract() -> None:
    expected = _render(build_contract())
    if not MANIFEST.exists():
        raise ContractError(f"missing issuance surface contract: {MANIFEST}")
    actual = MANIFEST.read_text(encoding="utf-8")
    if actual != expected:
        raise ContractError(
            "issuance surface contract drifted; review behavior changes and run "
            "`python scripts/issuance_surface_contract.py write`"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "write"))
    args = parser.parse_args()
    if args.command == "write":
        write_contract()
    else:
        check_contract()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
