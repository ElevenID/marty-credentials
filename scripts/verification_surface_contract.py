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


def _model_names(sources: list[PythonSource]) -> set[str]:
    return {
        node.name
        for source in sources
        for node in source.tree.body
        if isinstance(node, ast.ClassDef)
        and any(_call_name(base) == "BaseModel" for base in node.bases)
    }


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
    model_names = _model_names(sources)

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
                positional = list(node.args.args)
                defaults = [None] * (len(positional) - len(node.args.defaults)) + list(
                    node.args.defaults
                )
                request_model = next(
                    (
                        ast.unparse(argument.annotation)
                        for argument, default in zip(positional, defaults, strict=True)
                        if argument.annotation is not None
                        and ast.unparse(argument.annotation) in model_names
                        and not (
                            isinstance(default, ast.Call) and _call_name(default.func) == "Depends"
                        )
                    ),
                    None,
                )
                dependencies = sorted(
                    {
                        _call_name(default.args[0])
                        for default in defaults
                        if isinstance(default, ast.Call)
                        and _call_name(default.func) == "Depends"
                        and default.args
                        and _call_name(default.args[0]) is not None
                    }
                )
                errors: list[dict[str, Any]] = []
                for call in ast.walk(node):
                    if not isinstance(call, ast.Call) or _call_name(call.func) != "HTTPException":
                        continue
                    status_node = call.args[0] if call.args else _keyword(call, "status_code")
                    detail_node = _keyword(call, "detail")
                    errors.append(
                        {
                            "status": ast.unparse(status_node) if status_node is not None else None,
                            "detail": _literal_string(detail_node),
                            "line": call.lineno,
                        }
                    )
                errors.sort(key=lambda error: error["line"])
                routes.append(
                    {
                        "method": method.upper(),
                        "path": _join_route("" if router == "app" else prefixes[router], path),
                        "operation": node.name,
                        "request_model": request_model,
                        "response_model": response_model,
                        "dependencies": dependencies,
                        "declared_errors": errors,
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
                if call == "_read_secret_value":
                    secret = _literal_string(node.args[0] if node.args else None)
                    if secret is not None:
                        names.update({secret, f"{secret}_FILE"})
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
    constants = _string_constants(sources)
    governance_env = constants.get("GOVERNANCE_ENV")
    if governance_env is not None:
        names.add(governance_env)
    dynamic.sort(key=lambda item: (item["source"], item["line"]))
    return sorted(names), dynamic


def _models(sources: list[PythonSource]) -> list[dict[str, Any]]:
    model_names = _model_names(sources)
    result: list[dict[str, Any]] = []
    for source in sources:
        for node in source.tree.body:
            if not isinstance(node, ast.ClassDef) or node.name not in model_names:
                continue
            fields: list[dict[str, Any]] = []
            model_config: str | None = None
            validators: list[dict[str, Any]] = []
            for item in node.body:
                if isinstance(item, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "model_config"
                    for target in item.targets
                ):
                    model_config = ast.unparse(item.value)
                    continue
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    isinstance(decorator, ast.Call)
                    and _call_name(decorator.func) == "model_validator"
                    for decorator in item.decorator_list
                ):
                    validators.append(
                        {
                            "name": item.name,
                            "function_sha256": hashlib.sha256(ast.dump(item).encode()).hexdigest(),
                            "decorators": [
                                ast.unparse(decorator) for decorator in item.decorator_list
                            ],
                            "line": item.lineno,
                        }
                    )
                    continue
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
                    "model_config": model_config,
                    "validators": validators,
                    "source": source.relative,
                    "line": node.lineno,
                }
            )
    found = {model["name"] for model in result}
    if found != model_names:
        raise ContractError(f"DTO inventory drifted: missing={sorted(model_names - found)}")
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
                "content_sha256": _normalized_text_sha256(path),
                "upgrade_sha256": _function_body_sha256(tree, "upgrade"),
                "downgrade_sha256": _function_body_sha256(tree, "downgrade"),
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
    return _normalized_text_sha256(ROOT / relative)


def _normalized_text_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _function_body_sha256(tree: ast.Module, name: str) -> str:
    function = _function_in_tree(tree, name)
    if function is None:
        raise ContractError(f"missing required function: {name}")
    normalized = ast.dump(ast.Module(body=function.body, type_ignores=[]))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _function_in_tree(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    return next(
        (
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
        ),
        None,
    )


def _required_function(
    sources: list[PythonSource], name: str
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    matches = [
        node for source in sources if (node := _function_in_tree(source.tree, name)) is not None
    ]
    if len(matches) != 1:
        raise ContractError(f"expected exactly one top-level function named {name}")
    return matches[0]


def _string_constants(sources: list[PythonSource]) -> dict[str, str]:
    constants: dict[str, str] = {}
    for source in sources:
        for node in source.tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = _literal_string(node.value)
            if value is None:
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = value
    return constants


def _literal_string_collection(node: ast.AST | None) -> list[str] | None:
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        values = [_literal_string(item) for item in node.elts]
        if all(value is not None for value in values):
            return sorted(value for value in values if value is not None)
    if isinstance(node, ast.Call) and _call_name(node.func) == "frozenset" and node.args:
        return _literal_string_collection(node.args[0])
    return None


def _collection_assignment(sources: list[PythonSource], name: str) -> list[str]:
    for source in sources:
        for node in source.tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
                continue
            values = _literal_string_collection(node.value)
            if values is None:
                raise ContractError(f"{name} must remain a literal string collection")
            return values
    raise ContractError(f"missing required collection: {name}")


def _governance_contract(sources: list[PythonSource]) -> dict[str, Any]:
    constants = _string_constants(sources)
    purposes = sorted(
        constants[name]
        for name in ("SESSION_CREATE_PURPOSE", "DIRECT_VERIFY_PURPOSE", "VDS_NC_VERIFY_PURPOSE")
    )
    required_checks_source = next(
        source for source in sources if source.relative.endswith("application/governance.py")
    )
    assignment = next(
        node
        for node in required_checks_source.tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "PURPOSE_REQUIRED_CHECKS"
            for target in node.targets
        )
    )
    return {
        "purposes": purposes,
        "required_checks_sha256": hashlib.sha256(ast.dump(assignment.value).encode()).hexdigest(),
        "processing_states": _collection_assignment(sources, "CANONICAL_PROCESSING_STATUSES"),
        "required_native_capabilities": _collection_assignment(
            sources, "REQUIRED_MARTY_RS_CAPABILITIES"
        ),
    }


def _authorization_contract(sources: list[PythonSource]) -> dict[str, Any]:
    constants = _string_constants(sources)
    authorize = _required_function(sources, "_authorize")
    arguments = [*authorize.args.args, *authorize.args.kwonlyargs]
    defaults: list[ast.AST | None] = [
        *([None] * (len(authorize.args.args) - len(authorize.args.defaults))),
        *authorize.args.defaults,
        *authorize.args.kw_defaults,
    ]
    header_alias: str | None = None
    for argument, default in zip(arguments, defaults, strict=True):
        if argument.arg != "x_api_key" or not isinstance(default, ast.Call):
            continue
        if _call_name(default.func) != "Header":
            raise ContractError("_authorize x_api_key must use FastAPI Header")
        header_alias = _literal_string(_keyword(default, "alias"))
    if header_alias is None:
        raise ContractError("_authorize must declare a literal x_api_key header alias")

    errors = sorted(
        {
            (
                ast.unparse(call.args[0] if call.args else _keyword(call, "status_code")),
                _literal_string(_keyword(call, "detail")),
            )
            for call in ast.walk(authorize)
            if isinstance(call, ast.Call)
            and _call_name(call.func) == "HTTPException"
            and (call.args or _keyword(call, "status_code") is not None)
        }
    )

    wrappers: dict[str, str] = {}
    for wrapper in (
        "_authorize_session_create",
        "_authorize_direct_verify",
        "_authorize_vds_nc_verify",
    ):
        function = _required_function(sources, wrapper)
        calls = [
            call
            for call in ast.walk(function)
            if isinstance(call, ast.Call) and _call_name(call.func) == "_authorize"
        ]
        if len(calls) != 1 or not calls[0].args or not isinstance(calls[0].args[0], ast.Name):
            raise ContractError(f"{wrapper} must call _authorize with one purpose constant")
        constant = calls[0].args[0].id
        if constant not in constants:
            raise ContractError(f"{wrapper} purpose must resolve to a string constant")
        wrappers[wrapper] = constants[constant]
    return {
        "api_key_header": header_alias,
        "errors": [{"status": status_code, "detail": detail} for status_code, detail in errors],
        "purpose_wrappers": wrappers,
    }


def _startup_hooks(sources: list[PythonSource]) -> list[str]:
    main = next(source for source in sources if source.relative == "services/verification/main.py")
    startup = next(
        node
        for node in main.tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "startup"
    )
    hooks = [
        name
        for call in ast.walk(startup)
        if isinstance(call, ast.Call)
        and (name := _call_name(call.func)) is not None
        and name.startswith(("validate_", "load_"))
    ]
    if not hooks:
        raise ContractError("verification startup has no validation hooks")
    return sorted(hooks)


def _docker_contract() -> dict[str, Any]:
    relative = "services/verification/Dockerfile"
    lines = (ROOT / relative).read_text(encoding="utf-8").splitlines()
    expose = next((line.split(maxsplit=1)[1] for line in lines if line.startswith("EXPOSE ")), None)
    command_text = next(
        (line.removeprefix("CMD ") for line in lines if line.startswith("CMD ")), None
    )
    health = next((line.strip() for line in lines if "curl -f http://" in line), None)
    if expose is None or command_text is None or health is None:
        raise ContractError("Dockerfile must declare EXPOSE, CMD, and HTTP health check")
    try:
        command = json.loads(command_text)
    except json.JSONDecodeError as exc:
        raise ContractError("Dockerfile CMD must use JSON exec form") from exc
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        raise ContractError("Dockerfile CMD must be a string array")
    return {
        "dockerfile": relative,
        "provenance_sha256": _sha256(relative),
        "expose": expose,
        "command": command,
        "health_command": health,
    }


def build_contract() -> dict[str, Any]:
    """Build the deterministic verification feature floor from the Python oracle."""
    sources = _sources()
    routes = _http_routes(sources)
    variables, dynamic = _environment(sources)
    packaging = _docker_contract()
    return {
        "schema": "marty.verification-runtime-surface/v1",
        "purpose": "Language-neutral feature floor for Python-image consolidation",
        "source": {"production_files": len(sources)},
        "http": {"route_count": len(routes), "routes": routes},
        "dto": {"models": _models(sources)},
        "configuration": {
            "environment_variable_count": len(variables),
            "environment_variables": variables,
            "dynamic_lookups": dynamic,
        },
        "runtime": {
            "startup_validation_hooks": _startup_hooks(sources),
            "modes": [
                {
                    "name": "api",
                    "command": packaging["command"],
                    "port": packaging["expose"],
                    "source": packaging["dockerfile"],
                }
            ],
        },
        "authorization": _authorization_contract(sources),
        "governance": _governance_contract(sources),
        "migrations": _migration_graph(),
        "packaging": packaging,
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
