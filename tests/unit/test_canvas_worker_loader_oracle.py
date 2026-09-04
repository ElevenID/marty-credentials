"""Observe legacy processor selection without making Python imports a Rust API."""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import AsyncMock, Mock

import pytest
from issuance import canvas_worker

MODULE_NAME = "_marty_canvas_processor_loader_oracle"


@pytest.fixture
def processor_module(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = ModuleType(MODULE_NAME)
    monkeypatch.setitem(sys.modules, MODULE_NAME, module)
    return module


@pytest.mark.parametrize("path", [None, "", " ", "\t\n"])
def test_unconfigured_processor_does_not_attempt_import(
    path: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    importer = Mock(side_effect=AssertionError("unconfigured loader attempted import"))
    monkeypatch.setattr(canvas_worker.importlib, "import_module", importer)
    assert canvas_worker.load_canvas_sync_processor(path) is None
    importer.assert_not_called()


@pytest.mark.parametrize("path", ["module", ":callback", "module:", ":"])
def test_malformed_selection_fails_before_import(
    path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    importer = Mock(side_effect=AssertionError("malformed selection attempted import"))
    monkeypatch.setattr(canvas_worker.importlib, "import_module", importer)
    with pytest.raises(ValueError, match="must use module:function syntax"):
        canvas_worker.load_canvas_sync_processor(path)
    importer.assert_not_called()


@pytest.mark.parametrize("kind", ["async", "sync", "callable-object"])
@pytest.mark.parametrize("surrounding_space", [False, True])
def test_loader_preserves_callable_identity_without_executing_it(
    kind: str, surrounding_space: bool, processor_module: ModuleType
) -> None:
    calls: list[str] = []

    async def async_processor(*_args):
        calls.append("async")

    def sync_processor(*_args):
        calls.append("sync")

    class CallableProcessor:
        def __call__(self, *_args):
            calls.append("callable-object")

    processor = {
        "async": AsyncMock(side_effect=async_processor),
        "sync": sync_processor,
        "callable-object": CallableProcessor(),
    }[kind]
    processor_module.callback = processor
    path = f"{MODULE_NAME}:callback"
    if surrounding_space:
        path = f" \t{path}\n "

    assert canvas_worker.load_canvas_sync_processor(path) is processor
    assert calls == []
    if kind == "async":
        processor.assert_not_called()


@pytest.mark.parametrize("value", [None, False, 17, "callback", {}, []])
def test_noncallable_selection_is_not_silently_disabled(
    value: object, processor_module: ModuleType
) -> None:
    processor_module.callback = value
    with pytest.raises(ValueError, match="processor is not callable"):
        canvas_worker.load_canvas_sync_processor(f"{MODULE_NAME}:callback")


@pytest.mark.parametrize("attribute", ["missing", "nested.callback", "callback:extra", " callback"])
def test_attribute_is_literal_and_not_implicitly_repaired(
    attribute: str, processor_module: ModuleType
) -> None:
    processor_module.callback = Mock()
    processor_module.nested = ModuleType("nested")
    processor_module.nested.callback = processor_module.callback
    with pytest.raises(ValueError, match="processor is not callable"):
        canvas_worker.load_canvas_sync_processor(f"{MODULE_NAME}:{attribute}")
    processor_module.callback.assert_not_called()


def test_missing_module_fails_through_the_real_importer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, MODULE_NAME, raising=False)
    with pytest.raises(ModuleNotFoundError) as error:
        canvas_worker.load_canvas_sync_processor(f"{MODULE_NAME}:callback")
    assert error.value.name == MODULE_NAME


@pytest.mark.parametrize("error_type", [ImportError, RuntimeError])
def test_module_initialization_failure_propagates_without_fallback(
    error_type: type[Exception], monkeypatch: pytest.MonkeyPatch
) -> None:
    failure = error_type("synthetic processor initialization failure")
    importer = Mock(side_effect=failure)
    monkeypatch.setattr(canvas_worker.importlib, "import_module", importer)
    with pytest.raises(error_type) as error:
        canvas_worker.load_canvas_sync_processor(f"{MODULE_NAME}:callback")
    assert error.value is failure
    importer.assert_called_once_with(MODULE_NAME)
