"""Lazy IDA-backed memory for Unicorn.

    from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
    from ida_nexus_emu import bind

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    with bind(uc, handle) as bound:  # or bind(uc, "firmware.bin")
        ...  # registers, stack, hooks, instruction budget: all yours
        uc.emu_start(entry, stop_ea)

See `_bridge.py` for the two-tier contract (`on_unmapped` + `bind`).
"""

from ._bridge import BoundIdb, bind, on_unmapped

__all__ = ["BoundIdb", "bind", "on_unmapped"]
