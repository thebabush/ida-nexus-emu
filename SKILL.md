---
name: ida-nexus-emu
description: Use when writing a Unicorn emulation script against code from a binary already open in IDA (via ida-mcp/ida-nexus) -- e.g. "emulate this function", "decode this loop with Unicorn", "run this shellcode snippet", "step through this obfuscated routine". Teaches ida_nexus_emu.bind(uc, idb), which lazily maps missing code/data pages from the live IDA database into your own Unicorn instance instead of you hand-copying bytes out of the decompiler.
---

# Emulating IDA-analyzed code with Unicorn

You already know how to write a Unicorn harness: architecture/mode, entry
point, registers, stack, hooks, stop condition. The one part worth *not*
hand-rolling against a binary open in IDA is the memory map -- don't copy
bytes out of the decompiler/disassembly by hand. `ida_nexus_emu.bind` wires a
lazy `UC_HOOK_MEM_UNMAPPED` hook that fetches the faulting range straight
from the live IDB the moment Unicorn touches it.

## Steps

1. Get the path of the database you're already working in: the path you
   passed to `open_database` this session (or the one `list_databases`
   reported). Don't use the MCP `instance_id` -- it is not ida-nexus's
   `record_id`, and you don't need it.
2. Build your `Uc` as you normally would, then bind it by path. `bind`
   attaches to the instance already open for that path and only spawns a new
   IDA worker if there is none:

   ```python
   from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, Uc
   from ida_nexus_emu import bind

   uc = Uc(UC_ARCH_X86, UC_MODE_64)
   with bind(uc, path) as bound:
       # your registers, stack, calling convention, stop condition here
       uc.emu_start(entry, stop_ea)
   ```

   If you already hold a `DatabaseHandle`, pass it instead of the path; `bind`
   then leaves it open for you.

3. **Always add your own instruction budget.** `bind` only answers "what's at
   this address" -- it does not bound execution. Unknown/obfuscated code can
   loop forever. Add a `UC_HOOK_CODE` hook that counts instructions and calls
   `uc.emu_stop()` past a cap, every time, even for "small" snippets.

## What you get and don't get

- Reads only. Writes during emulation stay in Unicorn's local memory; they
  are never pushed back into the IDB. If you want to patch a result back,
  do that explicitly and separately (e.g. via `execute_python`'s patch-bytes
  capability), not implicitly through this hook.
- No permission enforcement yet: mapped pages are `UC_PROT_ALL`, not IDA's
  actual segment permissions. A write to what IDA marked read-only won't
  fault.
- One RPC round-trip per previously-unmapped page, not per instruction. Once
  a range is mapped, Unicorn never re-enters the hook for it.
- If you also have `unicorn` installed in an environment separate from where
  you run your agent scripts, note this hook talks to IDA over the same
  loopback ida-nexus RPC your MCP session uses -- it needs network access to
  that instance, i.e. it must run on the same box/trust boundary as IDA.

## When not to reach for this

For a tiny, already-fully-visible snippet (a handful of bytes you can just
paste), plain Unicorn with a manual `mem_map`/`mem_write` is simpler and has
no dependency on a live IDA session. Reach for `bind()` once you'd otherwise
be reading multiple ranges out of IDA by hand, or don't know up front which
addresses the code will touch (data-dependent jumps, calls into other
functions, unresolved strings/tables).
