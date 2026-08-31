#!/usr/bin/env python3
"""Derive a canonical image-build matrix from a tag's release contract."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

SERVICE_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
SERVICE_DOCKERFILES = {
    "issuance": "services/Dockerfile",
    "verification": "services/verification/Dockerfile",
}


class ServiceHandoffError(RuntimeError):
    """The tag-scoped service contract cannot be handed to the workflow safely."""


def _parse_contract_services(contract: Path) -> tuple[str, ...]:
    if contract.is_symlink() or not contract.is_file():
        raise ServiceHandoffError("release contract must be a regular file")
    try:
        source = contract.read_text(encoding="utf-8")
        module = ast.parse(source, filename=str(contract))
    except (OSError, UnicodeError, SyntaxError) as error:
        raise ServiceHandoffError("release contract cannot be parsed") from error

    assignments = [
        statement
        for statement in module.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == "SERVICES"
    ]
    bindings = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Name)
        and node.id == "SERVICES"
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if len(assignments) != 1 or len(bindings) != 1:
        raise ServiceHandoffError("release contract must define SERVICES exactly once")

    value = assignments[0].value
    if not isinstance(value, ast.Tuple):
        raise ServiceHandoffError("release contract SERVICES must be a literal tuple")
    services: list[str] = []
    for item in value.elts:
        if not isinstance(item, ast.Constant) or type(item.value) is not str:
            raise ServiceHandoffError("release contract SERVICES entries must be literal strings")
        services.append(item.value)

    if not services:
        raise ServiceHandoffError("release contract SERVICES must not be empty")
    if len(set(services)) != len(services):
        raise ServiceHandoffError("release contract SERVICES must not contain duplicates")
    for service in services:
        if SERVICE_PATTERN.fullmatch(service) is None:
            raise ServiceHandoffError(f"release service name is invalid: {service!r}")
        if service not in SERVICE_DOCKERFILES:
            raise ServiceHandoffError(f"release service is not allowed: {service!r}")
    return tuple(sorted(services))


def build_service_matrix(repository: Path) -> dict[str, Any]:
    if repository.is_symlink() or not repository.is_dir():
        raise ServiceHandoffError("release repository must be a regular directory")
    contract = repository / "scripts" / "release_contract.py"
    services = _parse_contract_services(contract)
    include: list[dict[str, str]] = []
    for service in services:
        dockerfile = repository / SERVICE_DOCKERFILES[service]
        if dockerfile.is_symlink() or not dockerfile.is_file():
            raise ServiceHandoffError(f"release service {service!r} has no regular Dockerfile")
        include.append({"service": service, "dockerfile": SERVICE_DOCKERFILES[service]})
    return {"include": include}


def canonical_service_matrix(repository: Path) -> str:
    return json.dumps(
        build_service_matrix(repository),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        print(canonical_service_matrix(args.repository))
    except ServiceHandoffError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
