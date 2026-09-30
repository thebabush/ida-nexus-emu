# ida-nexus-emu

Lazy IDA-backed memory for [Unicorn](https://github.com/unicorn-engine/unicorn):
emulate code from a live IDA database without hand-copying bytes into a
memory map.

Builds on [ida-nexus](https://github.com/HexRaysSA/ida-nexus). Kept as a
separate package specifically so plain `ida-nexus` (and anything that depends
on it, like `ida-mcp`) never pulls in a `unicorn` dependency it doesn't need.

## Why

Driving Unicorn against code IDA has already analyzed usually means manually
reading bytes out of IDA and stitching together a memory map by hand, once
per script. This package only solves that one problem: a
`UC_HOOK_MEM_UNMAPPED` hook that lazily fetches the faulting range from the
live IDB over `ida-nexus`'s RPC, the moment Unicorn actually needs it.

It does not own registers, the stack, calling convention, hooks, or how long
to run — that's still entirely your script. See `on_unmapped`/`bind` in
`ida_nexus_emu/_bridge.py` for the two-tier contract.

## Install

Not published on PyPI. Download the wheel attached to the latest GitHub
release, then install it:

```bash
pip install ./ida_nexus_emu-0.1.0-py3-none-any.whl
```

Or with uv:

```bash
uv add ./ida_nexus_emu-0.1.0-py3-none-any.whl
```

## Usage

```python
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from ida_nexus_emu import bind

uc = Uc(UC_ARCH_X86, UC_MODE_64)
with bind(uc, "/path/to/binary") as bound:
    # registers, stack, additional hooks, instruction budget: all yours
    uc.emu_start(entry, stop_ea)
```

`bind` attaches to the instance already open for that path, and only spawns a
new IDA worker if there is none. It owns the handle it opened and closes it on
`__exit__`.

If you already hold a `DatabaseHandle` (for example from
`DatabaseHandle.attach()`), pass that instead. `bind` then leaves it open for
you to close:

```python
with bind(uc, handle) as bound:
    ...
```

## Development

```bash
uv sync
uv run pytest
uv run ruff check ida_nexus_emu tests
uv run ruff format --check ida_nexus_emu tests
uv run ty check ida_nexus_emu tests
```

`tests/test_bridge.py` runs against a real `Uc` instance (Unicorn needs no
IDA to exist) with the IDB-read call faked out — no live IDA database or
ida-nexus server required.

## Status

Experimental (alpha, 0.x): the API may change between releases.

Requires a local IDA installation and a running ida-nexus instance. This
package does not bundle IDA.

Mappings use 4 KiB pages with read/write/execute permissions. A fault is
handled only when IDB bytes cover the requested access in each missing page.
Other gaps within a mapped page are zero-filled and subsequent accesses to
those gaps do not fault. Existing Unicorn mappings and emulated writes are
preserved. Closing a binding removes its hook but leaves mapped memory intact.

The automated tests use mocked IDB reads. The live RPC integration against a
real IDA database is not covered by automated tests.
