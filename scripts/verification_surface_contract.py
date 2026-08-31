#!/usr/bin/env python3
"""Freeze the observable Python verification surface for Rust consolidation."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
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
    classes = {
        node.name: {_call_name(base) for base in node.bases}
        for source in sources
        for node in source.tree.body
        if isinstance(node, ast.ClassDef)
    }
    models = {name for name, bases in classes.items() if "BaseModel" in bases}
    while inherited := {
        name for name, bases in classes.items() if name not in models and bases & models
    }:
        models.update(inherited)
    return models


def _http_status(node: ast.AST | None) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if node is None:
        return None
    expression = ast.unparse(node)
    match = re.fullmatch(r"status\.HTTP_(\d{3})_[A-Z0-9_]+", expression)
    if match is None:
        raise ContractError(f"HTTP status must be a literal or Starlette constant: {expression}")
    return int(match.group(1))


def _literal_return_shape(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, Any] | None:
    returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Dict):
        return None
    shape: dict[str, Any] = {}
    for key, value in zip(returns[0].value.keys, returns[0].value.values, strict=True):
        name = _literal_string(key)
        if name is None:
            raise ContractError(f"dynamic response key in {function.name}")
        if isinstance(value, ast.Constant):
            shape[name] = {"literal": value.value}
        else:
            shape[name] = {"expression": ast.unparse(value)}
    return shape


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
                            "status": _http_status(status_node),
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
                        "literal_response_shape": _literal_return_shape(node),
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
                            "function_sha256": _ast_sha256(item),
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
                    "bases": [
                        name for base in node.bases if (name := _call_name(base)) is not None
                    ],
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
    by_name = {model["name"]: model for model in result}
    resolved: set[str] = set()

    def resolve(name: str, active: set[str]) -> None:
        if name in resolved:
            return
        if name in active:
            raise ContractError(f"cyclic DTO inheritance at {name}")
        model = by_name[name]
        inherited_fields: list[dict[str, Any]] = []
        inherited_validators: list[dict[str, Any]] = []
        inherited_config: str | None = None
        for base in model["bases"]:
            if base not in by_name:
                continue
            resolve(base, active | {name})
            parent = by_name[base]
            inherited_fields.extend(parent["fields"])
            inherited_validators.extend(parent["validators"])
            inherited_config = parent["model_config"] or inherited_config

        fields = {field["name"]: field for field in inherited_fields}
        fields.update({field["name"]: field for field in model["fields"]})
        validators = {validator["name"]: validator for validator in inherited_validators}
        validators.update({validator["name"]: validator for validator in model["validators"]})
        model["fields"] = list(fields.values())
        model["validators"] = list(validators.values())
        model["model_config"] = model["model_config"] or inherited_config
        resolved.add(name)

    for name in by_name:
        resolve(name, set())
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
    normalized = _canonical_ast_dump(ast.Module(body=function.body, type_ignores=[]))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _ast_sha256(node: ast.AST) -> str:
    return hashlib.sha256(_canonical_ast_dump(node).encode("utf-8")).hexdigest()


def _canonical_ast_dump(node: ast.AST) -> str:
    """Remove empty AST fields added by newer supported Python runtimes."""
    return ast.dump(node).replace(", type_params=[]", "")


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


def _integer_constants(sources: list[PythonSource]) -> dict[str, int]:
    constants: dict[str, int] = {}
    for source in sources:
        for node in source.tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, int):
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = node.value.value
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
        "required_checks_sha256": _ast_sha256(assignment.value),
        "processing_states": _collection_assignment(sources, "CANONICAL_PROCESSING_STATUSES"),
        "required_native_capabilities": _collection_assignment(
            sources, "REQUIRED_MARTY_RS_CAPABILITIES"
        ),
    }


def _header_contract(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, str]:
    arguments = [*function.args.args, *function.args.kwonlyargs]
    defaults: list[ast.AST | None] = [
        *([None] * (len(function.args.args) - len(function.args.defaults))),
        *function.args.defaults,
        *function.args.kw_defaults,
    ]
    for argument, default in zip(arguments, defaults, strict=True):
        if argument.arg != "x_api_key" or not isinstance(default, ast.Call):
            continue
        if _call_name(default.func) != "Header":
            raise ContractError(f"{function.name} x_api_key must use FastAPI Header")
        alias = _literal_string(_keyword(default, "alias"))
        default_value = default.args[0] if default.args else _keyword(default, "default")
        if alias is None or default_value is None:
            raise ContractError(f"{function.name} must declare a static API-key header")
        return {
            "alias": alias,
            "annotation": ast.unparse(argument.annotation),
            "default": ast.unparse(default_value),
        }
    raise ContractError(f"{function.name} must declare x_api_key as a Header")


def _authorization_contract(sources: list[PythonSource]) -> dict[str, Any]:
    constants = _string_constants(sources)
    authorize = _required_function(sources, "_authorize")
    helper_header = _header_contract(authorize)

    errors = sorted(
        {
            (
                _http_status(call.args[0] if call.args else _keyword(call, "status_code")),
                _literal_string(_keyword(call, "detail")),
            )
            for call in ast.walk(authorize)
            if isinstance(call, ast.Call)
            and _call_name(call.func) == "HTTPException"
            and (call.args or _keyword(call, "status_code") is not None)
        }
    )

    wrappers: dict[str, dict[str, Any]] = {}
    for wrapper in (
        "_authorize_session_create",
        "_authorize_direct_verify",
        "_authorize_vds_nc_verify",
    ):
        function = _required_function(sources, wrapper)
        if (
            len(function.body) != 1
            or not isinstance(function.body[0], ast.Return)
            or not isinstance(function.body[0].value, ast.Await)
            or not isinstance(function.body[0].value.value, ast.Call)
        ):
            raise ContractError(
                f"{wrapper} body must be exactly `return await _authorize(purpose, x_api_key)`"
            )
        returned_call = function.body[0].value.value
        calls = [
            call
            for call in ast.walk(function)
            if isinstance(call, ast.Call) and _call_name(call.func) == "_authorize"
        ]
        if (
            len(calls) != 1
            or calls[0] is not returned_call
            or len(calls[0].args) != 2
            or not isinstance(calls[0].args[0], ast.Name)
            or not isinstance(calls[0].args[1], ast.Name)
            or calls[0].args[1].id != "x_api_key"
        ):
            raise ContractError(f"{wrapper} must call _authorize with one purpose constant")
        constant = calls[0].args[0].id
        if constant not in constants:
            raise ContractError(f"{wrapper} purpose must resolve to a string constant")
        header = _header_contract(function)
        if header != helper_header:
            raise ContractError(f"{wrapper} header contract differs from _authorize")
        wrappers[wrapper] = {
            "purpose": constants[constant],
            "header": header,
            "forwarded_argument": calls[0].args[1].id,
        }
    return {
        "api_key_header": helper_header,
        "errors": [{"status": status_code, "detail": detail} for status_code, detail in errors],
        "purpose_wrappers": wrappers,
    }


def _configuration_semantics(sources: list[PythonSource]) -> dict[str, Any]:
    integers = _integer_constants(sources)
    secret_reader = _required_function(sources, "_read_secret_value")
    signing_url = _required_function(sources, "_internal_signing_base_url")
    lease = _required_function(sources, "processing_lease_seconds")
    did_web = _required_function(sources, "_did_web_url")
    database_url = _required_function(sources, "_database_url")
    sync_database_url = _required_function(sources, "_sync_database_url")
    ensure_version_schema = _required_function(sources, "ensure_version_schema")
    migration_config = _required_function(sources, "get_config")

    secret_lookups = [
        ast.unparse(call.args[0])
        for call in ast.walk(secret_reader)
        if isinstance(call, ast.Call) and _call_name(call.func) == "os.environ.get" and call.args
    ]
    signing_call = next(
        call
        for call in ast.walk(signing_url)
        if isinstance(call, ast.Call)
        and _call_name(call.func) == "os.environ.get"
        and _literal_string(call.args[0] if call.args else None) == "SIGNING_KEYS_INTERNAL_URL"
    )
    signing_default = _literal_string(signing_call.args[1] if len(signing_call.args) > 1 else None)
    if signing_default is None:
        raise ContractError("SIGNING_KEYS_INTERNAL_URL must have a literal default")

    did_environment_variables = sorted(
        {
            name
            for call in ast.walk(did_web)
            if isinstance(call, ast.Call)
            and _call_name(call.func) == "os.environ.get"
            and call.args
            if (name := _literal_string(call.args[0])) is not None
        }
    )
    did_literals = {
        node.value
        for node in ast.walk(did_web)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    production_aliases = sorted({"production", "prod"} & did_literals)
    if production_aliases != ["prod", "production"]:
        raise ContractError("did:web production aliases drifted")

    database_aliases = next(
        values
        for node in ast.walk(database_url)
        if (values := _literal_string_collection(node)) is not None and "postgresql" in values
    )

    def normalized_driver(function: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        for call in ast.walk(function):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr != "set":
                continue
            value = _literal_string(_keyword(call, "drivername"))
            if value is not None:
                return value
        raise ContractError(f"{function.name} must statically normalize a database driver")

    version_schema = _string_constants(sources).get("VERSION_SCHEMA")
    migration_env = (SERVICE_ROOT / "infrastructure" / "migrations" / "env.py").read_text(
        encoding="utf-8"
    )
    if version_schema is None or f'version_table_schema="{version_schema}"' not in migration_env:
        raise ContractError("migration version schema is not coherent")

    return {
        "processing_lease_seconds": {
            "environment_variable": "VERIFICATION_PROCESSING_LEASE_SECONDS",
            "default": integers["DEFAULT_PROCESSING_LEASE_SECONDS"],
            "minimum": integers["MIN_PROCESSING_LEASE_SECONDS"],
            "maximum": integers["MAX_PROCESSING_LEASE_SECONDS"],
            "behavior_sha256": _ast_sha256(lease),
        },
        "signing_keys": {
            "base_url_environment_variable": "SIGNING_KEYS_INTERNAL_URL",
            "base_url_default": signing_default,
            "api_key_precedence": secret_lookups,
            "secret_reader_sha256": _ast_sha256(secret_reader),
        },
        "did_web_egress": {
            "environment_variables": did_environment_variables,
            "production_aliases": production_aliases,
            "scheme": "https",
            "default_port": 443,
            "requires_production_allowlist": (
                "Production did:web resolution requires a configured egress allowlist"
                in did_literals
            ),
            "requires_production_default_https_port": (
                "Production did:web resolution requires the default HTTPS port" in did_literals
            ),
            "behavior_sha256": _ast_sha256(did_web),
        },
        "database": {
            "environment_variable": "DATABASE_URL",
            "missing_error": "DATABASE_URL environment variable is required",
            "api": {
                "accepted_postgresql_driver_aliases": database_aliases,
                "normalized_driver": normalized_driver(database_url),
                "behavior_sha256": _ast_sha256(database_url),
            },
            "migrations": {
                "normalized_driver": normalized_driver(sync_database_url),
                "version_schema": version_schema,
                "url_behavior_sha256": _ast_sha256(sync_database_url),
                "schema_behavior_sha256": _ast_sha256(ensure_version_schema),
                "config_behavior_sha256": _ast_sha256(migration_config),
                "environment_sha256": _normalized_text_sha256(
                    SERVICE_ROOT / "infrastructure" / "migrations" / "env.py"
                ),
            },
        },
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


def _migration_runtime_contract(sources: list[PythonSource]) -> dict[str, Any]:
    main = _required_function(sources, "main")
    command_argument = next(
        call
        for call in ast.walk(main)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "add_argument"
        and _literal_string(call.args[0] if call.args else None) == "command"
    )
    operations = _literal_string_collection(_keyword(command_argument, "choices"))
    if operations is None:
        raise ContractError("migration CLI choices must remain a literal string collection")
    documentation = (SERVICE_ROOT / "MIGRATIONS.md").read_text(encoding="utf-8")
    match = re.search(
        r"(?:DATABASE_URL=\S+ )?(python -m verification\.manage_migrations [a-z]+)",
        documentation,
    )
    if match is None:
        raise ContractError("MIGRATIONS.md must declare the deployment migration command")
    deployment_command = match.group(1).split()
    if deployment_command[-1] not in operations:
        raise ContractError("documented migration operation is not supported by the CLI")
    return {
        "name": "migrations",
        "command_prefix": ["python", "-m", "verification.manage_migrations"],
        "deployment_command": deployment_command,
        "supported_operations": operations,
        "source": "services/verification/manage_migrations.py",
        "documentation_sha256": _normalized_text_sha256(SERVICE_ROOT / "MIGRATIONS.md"),
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
            "semantics": _configuration_semantics(sources),
        },
        "runtime": {
            "startup_validation_hooks": _startup_hooks(sources),
            "modes": [
                {
                    "name": "api",
                    "command": packaging["command"],
                    "port": packaging["expose"],
                    "source": packaging["dockerfile"],
                },
                _migration_runtime_contract(sources),
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
