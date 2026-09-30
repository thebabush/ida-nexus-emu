"""Lazy IDB-backed memory for Unicorn.

Two layers, deliberately:

- `on_unmapped` is a plain UC_HOOK_MEM_UNMAPPED-shaped callback. Register it
  yourself via uc.hook_add(..., user_data=handle) if you want to chain it with
  other unmapped-memory handling, restrict it to a begin/end range, or drive
  it from something other than `bind`.
- `bind` is the one-liner: give it a Uc and an IDB (path, or an already-open
  DatabaseHandle -- e.g. attached via discover_databases()), get the hook wired
  up on your `uc`.

Neither layer touches registers, the stack, calling convention, or how long
to run -- that stays entirely in the caller's own emulation script. This is
self-contained against the current public `ida_nexus` API (`DatabaseHandle`,
`remote_ida`); it does not assume any future addition to ida-nexus itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

from ida_nexus import DatabaseHandle, remote_ida
from unicorn import UC_HOOK_MEM_UNMAPPED, UC_PROT_ALL, Uc

if TYPE_CHECKING:
    from ida_domain import Database

PAGE_SIZE = 0x1000

__all__ = ["BoundIdb", "bind", "on_unmapped"]


class MemoryChunk(TypedDict):
    address: int
    content: bytes


@dataclass
class _PendingPage:
    address: int
    content: bytearray


@remote_ida(operation_label="ida-nexus-emu: read_bytes")
def _read_bytes(db: Database, address: int, size: int) -> list[MemoryChunk]:
    chunks: list[MemoryChunk] = []
    for segment in db.segments.get_all():
        start = max(address, segment.start_ea)
        end = min(address + size, segment.end_ea)
        if start < end:
            content = db.bytes.get_bytes_at(start, end - start)
            if content:
                chunks.append({"address": start, "content": content})
    return chunks


def on_unmapped(
    uc: Uc,
    access: int,
    address: int,
    size: int,
    value: int,
    handle: DatabaseHandle,
) -> bool:
    """UC_HOOK_MEM_UNMAPPED callback: lazily map the faulting range from `handle`.

    Register as `uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped, user_data=handle)`.

    Returns False (letting Unicorn raise its normal *_UNMAPPED error) when the
    live IDB does not cover the faulting access. Mapping is page-granular:
    gaps outside that access in an otherwise backed page are zero-filled.
    No separate cache: once mapped, Unicorn itself never re-enters
    this hook for that range, so there is nothing here to invalidate or
    size-bound.
    """
    start = address & ~(PAGE_SIZE - 1)
    end = (address + max(size, 1) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    regions = list(uc.mem_regions())
    pages: list[_PendingPage] = []
    for page in range(start, end, PAGE_SIZE):
        if any(low <= page and page + PAGE_SIZE - 1 <= high for low, high, _ in regions):
            continue
        chunks = sorted(_read_bytes(handle, page, PAGE_SIZE), key=lambda chunk: chunk["address"])
        required = max(address, page)
        required_end = min(address + max(size, 1), page + PAGE_SIZE)
        content = bytearray(PAGE_SIZE)
        for chunk in chunks:
            chunk_start = chunk["address"]
            offset = chunk_start - page
            content[offset : offset + len(chunk["content"])] = chunk["content"]
            if chunk_start <= required:
                required = max(required, chunk_start + len(chunk["content"]))
        if required < required_end:
            return False
        pages.append(_PendingPage(page, content))

    for pending in pages:
        uc.mem_map(pending.address, PAGE_SIZE, UC_PROT_ALL)
        uc.mem_write(pending.address, bytes(pending.content))
    return True


class BoundIdb:
    """Removes the hook on exit; closes the handle only if bind() opened it."""

    def __init__(self, handle: DatabaseHandle, owns_handle: bool, uc: Uc, hook: int) -> None:
        self.handle = handle
        self._owns_handle = owns_handle
        self._uc = uc
        self._hook: int | None = hook

    def close(self) -> None:
        if self._hook is None:
            return
        self._uc.hook_del(self._hook)
        self._hook = None
        if self._owns_handle:
            self.handle.close()

    def __enter__(self) -> BoundIdb:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def bind(uc: Uc, idb: str | Path | DatabaseHandle) -> BoundIdb:
    """Wire a lazy-mapping UC_HOOK_MEM_UNMAPPED hook onto `uc`, backed by `idb`.

    `idb` may be:
    - a path to an executable or .i64 (opened via DatabaseHandle.open and
      owned -- closed automatically if the result is used as a context
      manager, or by calling .close() yourself)
    - an already-open DatabaseHandle (e.g. from DatabaseHandle.attach() to a
      discovered instance) -- never closed here, you keep owning it

    Deliberately does not accept a bare record_id: resolve that
    yourself with ida_nexus.discover_databases()/DatabaseHandle.attach() and
    pass the handle, so this function has exactly one job.
    """
    handle: DatabaseHandle
    owns_handle: bool
    if isinstance(idb, DatabaseHandle):
        handle, owns_handle = idb, False
    else:
        handle, owns_handle = DatabaseHandle.open(str(idb)), True

    try:
        hook = uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped, user_data=handle)
    except Exception:
        if owns_handle:
            handle.close()
        raise
    return BoundIdb(handle, owns_handle, uc, hook)
