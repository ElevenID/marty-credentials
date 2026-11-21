"""Select the exact Core verification test executable from Cargo JSON output."""

import argparse
import json
from pathlib import Path


def locate(messages, core_checkout, target_directory):
    manifest = (core_checkout / "marty-verification" / "Cargo.toml").resolve(strict=True)
    target_directory = target_directory.resolve(strict=True)
    executables = []
    for line in messages.splitlines():
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact":
            continue
        if (
            message.get("target", {}).get("name") == "marty_verification"
            and message.get("target", {}).get("kind") == ["cdylib", "rlib"]
            and message.get("profile", {}).get("test") is True
            and message.get("executable")
            and Path(message.get("manifest_path", "")).resolve() == manifest
        ):
            executables.append(Path(message["executable"]))
    if len(executables) != 1:
        raise ValueError("Expected exactly one test executable from the pinned Core manifest")
    executable = executables[0]
    if executable.is_symlink():
        raise ValueError("The Core test executable must not be a symlink")
    executable = executable.resolve(strict=True)
    if not executable.is_file() or not executable.is_relative_to(target_directory):
        raise ValueError("The Core test executable is outside the dedicated target directory")
    if any(character in str(executable) for character in "\r\n"):
        raise ValueError("The Core test executable path cannot contain a line break")
    return executable


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--messages", type=Path, required=True)
    parser.add_argument("--core-checkout", type=Path, required=True)
    parser.add_argument("--target-directory", type=Path, required=True)
    args = parser.parse_args()
    print(locate(args.messages.read_text(), args.core_checkout, args.target_directory))
