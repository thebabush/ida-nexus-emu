"""Unit tests for the lazy-mapping hook, run against a real Uc instance
(Unicorn needs no IDA to exist) with `_read_bytes` faked out -- no live IDA
database or ida-nexus server required.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import TYPE_CHECKING, Self, cast
from unittest.mock import Mock

import pytest
from ida_nexus import DatabaseHandle
from unicorn import UC_ARCH_X86, UC_MEM_FETCH_UNMAPPED, UC_MODE_64, Uc, UcError
from unicorn.x86_const import UC_X86_REG_RAX

import ida_nexus_emu._bridge as bridge_mod
from ida_nexus_emu import bind, on_unmapped

if TYPE_CHECKING:
    from collections.abc import Callable

    from ida_domain import Database


class _FakeHandle:
    def __init__(self) -> None:
        self.closed = False
        self.close_count = 0
        self.opened_path: str | None = None

    def close(self) -> None:
        self.closed = True
        self.close_count += 1

    @classmethod
    def open(cls, path: str) -> Self:
        handle = cls()
        handle.opened_path = path
        return handle


@pytest.fixture(autouse=True)
def _patch_database_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    # bind()'s isinstance(idb, DatabaseHandle) check and its DatabaseHandle.open()
    # call both need to resolve against this same fake class.
    monkeypatch.setattr(bridge_mod, "DatabaseHandle", _FakeHandle)


def test_on_unmapped_maps_and_fills_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    content = b"\x90" * 16
    monkeypatch.setattr(
        bridge_mod,
        "_read_bytes",
        lambda handle, addr, size: [{"address": addr, "content": content}],
    )

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    fake_handle = cast(DatabaseHandle, _FakeHandle())
    handled = on_unmapped(uc, UC_MEM_FETCH_UNMAPPED, 0x1000, 16, 0, fake_handle)

    assert handled is True
    assert uc.mem_read(0x1000, 16) == content


def test_on_unmapped_returns_false_when_nothing_at_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge_mod, "_read_bytes", lambda handle, addr, size: [])

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    fake_handle = cast(DatabaseHandle, _FakeHandle())
    handled = on_unmapped(uc, UC_MEM_FETCH_UNMAPPED, 0x2000, 16, 0, fake_handle)

    assert handled is False


def test_bind_with_existing_handle_does_not_close_it() -> None:
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    handle = _FakeHandle()

    bound = bind(uc, cast(DatabaseHandle, handle))
    bound.close()

    assert handle.closed is False


def test_bind_with_path_opens_and_owns_handle() -> None:
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    with bind(uc, "firmware.bin") as bound:
        assert isinstance(bound.handle, _FakeHandle)
        assert bound.handle.opened_path == "firmware.bin"
        assert bound.handle.closed is False

    assert bound.handle.closed is True


@pytest.mark.parametrize("mapped_page", [0x1000, 0x2000, None])
def test_cross_page_read_preserves_existing_memory(
    monkeypatch: pytest.MonkeyPatch,
    mapped_page: int | None,
) -> None:
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x4000, 0x1000)
    uc.mem_write(0x4000, b"\x48\xa1" + (0x1FFC).to_bytes(8, "little"))
    if mapped_page is not None:
        uc.mem_map(mapped_page, 0x1000)
        uc.mem_write(mapped_page, b"B" * 0x1000)
    reads: list[int] = []

    def read(handle: DatabaseHandle, address: int, size: int) -> list[bridge_mod.MemoryChunk]:
        reads.append(address)
        return [{"address": address, "content": b"A" * size}]

    monkeypatch.setattr(bridge_mod, "_read_bytes", read)
    with bind(uc, "firmware.bin"):
        uc.emu_start(0x4000, 0x400A)
    expected = (b"B" if mapped_page == 0x1000 else b"A") * 4
    expected += (b"B" if mapped_page == 0x2000 else b"A") * 4
    assert uc.reg_read(UC_X86_REG_RAX) == int.from_bytes(expected, "little")
    assert mapped_page not in reads
    if mapped_page is not None:
        assert uc.mem_read(mapped_page, 0x1000) == b"B" * 0x1000


def test_read_clips_segments_and_skips_unmapped_addresses() -> None:
    read = cast(
        "Callable[[Database, int, int], list[bridge_mod.MemoryChunk]]",
        inspect.unwrap(bridge_mod._read_bytes),
    )
    get_bytes = Mock(side_effect=lambda address, size: b"A" * size)
    db = cast(
        "Database",
        SimpleNamespace(
            segments=SimpleNamespace(
                get_all=lambda: iter(
                    [
                        SimpleNamespace(start_ea=0x1080, end_ea=0x1100),
                        SimpleNamespace(start_ea=0x1FF0, end_ea=0x2100),
                    ]
                )
            ),
            bytes=SimpleNamespace(get_bytes_at=get_bytes),
        ),
    )
    assert read(db, 0x1000, 0x1000) == [
        {"address": 0x1080, "content": b"A" * 0x80},
        {"address": 0x1FF0, "content": b"A" * 16},
    ]
    get_bytes.reset_mock()
    assert read(db, 0x3000, 0x1000) == []
    get_bytes.assert_not_called()


@pytest.mark.parametrize(
    "address, size, handled",
    [
        pytest.param(0x1080, 1, True, id="backed-access"),
        pytest.param(0x1000, 1, False, id="gap-before-segment"),
        pytest.param(0x10FF, 2, False, id="crosses-segment-end"),
    ],
)
def test_partial_page_requires_backing_for_fault(
    monkeypatch: pytest.MonkeyPatch,
    address: int,
    size: int,
    handled: bool,
) -> None:
    monkeypatch.setattr(
        bridge_mod,
        "_read_bytes",
        lambda handle, addr, size: [{"address": 0x1080, "content": b"A" * 0x80}],
    )
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    assert (
        on_unmapped(
            uc, UC_MEM_FETCH_UNMAPPED, address, size, 0, cast(DatabaseHandle, _FakeHandle())
        )
        is handled
    )
    if handled:
        assert uc.mem_read(0x1080, 0x80) == b"A" * 0x80
        assert uc.mem_read(0x1000, 0x80) == bytes(0x80)
    else:
        assert list(uc.mem_regions()) == []


def test_closed_binding_can_be_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    handles: list[DatabaseHandle] = []

    def read(handle: DatabaseHandle, address: int, size: int) -> list[bridge_mod.MemoryChunk]:
        handles.append(handle)
        return [{"address": address, "content": b"\x90" * size}]

    monkeypatch.setattr(bridge_mod, "_read_bytes", read)
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    with bind(uc, "first.bin") as first:
        pass
    first.close()
    assert isinstance(first.handle, _FakeHandle)
    assert first.handle.close_count == 1
    with bind(uc, "second.bin") as second:
        uc.emu_start(0x1000, 0x1001)
    assert handles == [second.handle]
    with pytest.raises(UcError):
        uc.emu_start(0x2000, 0x2001)
    assert handles == [second.handle]


def test_failed_hook_registration_closes_owned_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    handle = _FakeHandle()
    monkeypatch.setattr(_FakeHandle, "open", lambda path: handle)
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    monkeypatch.setattr(uc, "hook_add", Mock(side_effect=RuntimeError("hook failed")))
    with pytest.raises(RuntimeError, match="hook failed"):
        bind(uc, "firmware.bin")
    assert handle.close_count == 1
