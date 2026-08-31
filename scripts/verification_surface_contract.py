#!/usr/bin/env python3
"""Freeze the observable Python verification surface for Rust consolidation."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICE_ROOT = ROOT / "services" / "verification"
MANIFEST = ROOT / "contracts" / "verification-runtime-surface.json"
HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}
MODEL_NAMES = {
    "ClaimResult",
    "CreateSessionRequest",
    "PresentationDefinition",
    "SessionResponse",
    "SubmitPresentationRequest",
    "VerificationResult",
    "VerifyDirectRequest",
    "VerifyVdsNcRequest",
}
REQUIRED_CONFIGURATION = {
    "APP_ENV",
    "DATABASE_URL",
    "DID_WEB_ALLOWED_HOSTS",
    "ENVIRONMENT",
    "SIGNING_KEYS_INTERNAL_API_KEY",
    "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
    "SIGNING_KEYS_INTERNAL_URL",
    "VERIFICATION_GOVERNANCE_JSON",
    "VERIFICATION_PROCESSING_LEASE_SECONDS",
}


class ContractError(RuntimeError):
    """The Python source cannot be represented by the frozen contract."""


@dataclass(frozen=True)
class PythonSource:
    path: Path
    relative: str
    tree: ast.Module


def _sources(*, include_migrations: bool = False) -> list[PythonSource]:
    sources: list[PythonSource] = []
    for path in sorted(SERVICE_ROOT.rglob("*.py")):
        if not include_migrations and "migrations" in path.parts:
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
    return _literal_string(call.args[0] if call.args else _keyword(call, "path"))


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
            prefix_node = _keyword(value, "prefix")
            prefix = _literal_string(prefix_node) if prefix_node is not None else ""
            if prefix is None:
                raise ContractError(f"dynamic router prefix at {source.relative}:{node.lineno}")
            for target in targets:
                if isinstance(target, ast.Name):
                    prefixes[target.id] = prefix
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
            raise ContractError(f"dynamic router registration at {main.relative}:{node.lineno}")
        registered.add(router.id)
    return registered


def _http_routes(sources: list[PythonSource]) -> list[dict[str, Any]]:
    main = next(source for source in sources if source.relative == "services/verification/main.py")
    prefixes = _router_prefixes(sources)
    registered = _registered_routers(main)
    missing = sorted(registered - prefixes.keys())
    if missing:
        raise ContractError(f"registered routers have no static prefix: {missing}")

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
                method = decorator.func.attr.lower()
                if method not in HTTP_METHODS:
                    continue
                if router != "app" and router not in registered:
                    continue
                path = _path_argument(decorator)
                if path is None:
                    raise ContractError(f"dynamic route at {source.relative}:{decorator.lineno}")
                response_model = _call_name(_keyword(decorator, "response_model"))
                routes.append(
                    {
                        "method": method.upper(),
                        "path": _join_route("" if router == "app" else prefixes[router], path),
                        "operation": node.name,
                        "response_model": response_model,
                        "source": source.relative,
                        "line": decorator.lineno,
                    }
                )
    routes.sort(key=lambda route: (route["path"], route["method"]))
    identities = [(route["method"], route["path"]) for route in routes]
    if len(identities) != len(set(identities)):
        raise ContractError("duplicate HTTP method/path identity")
    return routes


def _environment(sources: list[PythonSource]) -> tuple[list[str], list[dict[str, Any]]]:
    names: set[str] = set()
    dynamic: list[dict[str, Any]] = []
    for source in sources:
        for node in ast.walk(source.tree):
            argument: ast.AST | None = None
            if isinstance(node, ast.Call):
                call = _call_name(node.func)
                if call in {"os.environ.get", "os.getenv"} and node.args:
                    argument = node.args[0]
            elif isinstance(node, ast.Subscript) and _call_name(node.value) == "os.environ":
                argument = node.slice
            if argument is None:
                continue
            name = _literal_string(argument)
            if name is None:
                dynamic.append({"source": source.relative, "line": node.lineno})
            else:
                names.add(name)
    names.update(REQUIRED_CONFIGURATION)
    dynamic.sort(key=lambda item: (item["source"], item["line"]))
    return sorted(names), dynamic


def _models(sources: list[PythonSource]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for source in sources:
        for node in source.tree.body:
            if not isinstance(node, ast.ClassDef) or node.name not in MODEL_NAMES:
                continue
            fields: list[dict[str, Any]] = []
            for item in node.body:
                if not isinstance(item, ast.AnnAssign) or not isinstance(item.target, ast.Name):
                    continue
                fields.append(
                    {
                        "name": item.target.id,
                        "annotation": ast.unparse(item.annotation),
                        "default": ast.unparse(item.value) if item.value is not None else None,
                        "required": item.value is None,
                        "line": item.lineno,
                    }
                )
            result.append(
                {
                    "name": node.name,
                    "fields": fields,
                    "source": source.relative,
                    "line": node.lineno,
                }
            )
    found = {model["name"] for model in result}
    if found != MODEL_NAMES:
        raise ContractError(f"DTO inventory drifted: missing={sorted(MODEL_NAMES - found)}")
    result.sort(key=lambda model: model["name"])
    return result


def _migration_graph() -> dict[str, Any]:
    versions = SERVICE_ROOT / "infrastructure" / "migrations" / "versions"
    revisions: list[dict[str, Any]] = []
    parents: set[str] = set()
    for path in sorted(versions.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        assignments: dict[str, tuple[ast.AST, int]] = {}
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id in {"revision", "down_revision"}:
                    assignments[target.id] = (node.value, node.lineno)
        revision = _literal_string(assignments.get("revision", (None, 0))[0])
        down_node = assignments.get("down_revision", (None, 0))[0]
        if revision is None:
            raise ContractError(f"migration lacks literal revision: {path}")
        if isinstance(down_node, ast.Constant) and down_node.value is None:
            down: list[str] = []
        else:
            parent = _literal_string(down_node)
            if parent is None:
                raise ContractError(f"migration has dynamic parent: {path}")
            down = [parent]
            parents.add(parent)
        revisions.append(
            {
                "revision": revision,
                "down_revisions": down,
                "source": path.relative_to(ROOT).as_posix(),
                "line": assignments["revision"][1],
            }
        )
    ids = {revision["revision"] for revision in revisions}
    unknown = parents - ids
    if unknown:
        raise ContractError(f"unknown migration parents: {sorted(unknown)}")
    return {
        "revision_count": len(revisions),
        "roots": sorted(item["revision"] for item in revisions if not item["down_revisions"]),
        "heads": sorted(ids - parents),
        "revisions": revisions,
    }


def _sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


def build_contract() -> dict[str, Any]:
    """Build the deterministic verification feature floor from the Python oracle."""
    sources = _sources()
    routes = _http_routes(sources)
    variables, dynamic = _environment(sources)
    source_lines = sum(
        len(source.path.read_text(encoding="utf-8").splitlines()) for source in sources
    )
    return {
        "schema": "marty.verification-runtime-surface/v1",
        "purpose": "Language-neutral feature floor for Python-image consolidation",
        "source": {"production_files": len(sources), "production_lines": source_lines},
        "http": {"route_count": len(routes), "routes": routes},
        "dto": {"models": _models(sources)},
        "configuration": {
            "environment_variable_count": len(variables),
            "environment_variables": variables,
            "dynamic_lookups": dynamic,
        },
        "runtime": {
            "modes": [
                {
                    "name": "api",
                    "command": [
                        "python",
                        "-m",
                        "uvicorn",
                        "main:app",
                        "--host",
                        "0.0.0.0",
                        "--port",
                        "8006",
                    ],
                    "transports": ["http", "postgresql", "signing-keys-http"],
                    "source": "services/verification/main.py",
                }
            ]
        },
        "governance": {
            "purposes": [
                "verification.direct",
                "verification.session.create",
                "verification.vds-nc",
            ],
            "processing_states": ["COMPLETED", "ERROR", "UNAVAILABLE", "UNSUPPORTED"],
            "contract_sha256": _sha256("services/verification/GOVERNANCE.md"),
        },
        "migrations": _migration_graph(),
        "packaging": {
            "dockerfile": "services/verification/Dockerfile",
            "dockerfile_sha256": _sha256("services/verification/Dockerfile"),
            "port": 8006,
            "health_path": "/health",
        },
    }


def _render(contract: dict[str, Any]) -> str:
    return json.dumps(contract, indent=2, sort_keys=True) + "\n"


def write_contract() -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(_render(build_contract()), encoding="utf-8")


def check_contract() -> None:
    expected = _render(build_contract())
    if not MANIFEST.exists() or MANIFEST.read_text(encoding="utf-8") != expected:
        raise ContractError(
            "verification surface drifted; review the change and run "
            "`python scripts/verification_surface_contract.py write`"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "write"))
    args = parser.parse_args()
    write_contract() if args.command == "write" else check_contract()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
