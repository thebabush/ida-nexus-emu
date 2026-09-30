# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-30

### Added

- Initial release.
- `bind(uc, idb)`: wires a lazy-mapping `UC_HOOK_MEM_UNMAPPED` hook onto a
  Unicorn instance, backed by either a path to an executable or `.i64`
  (opened and owned by `bind`) or an already-open `ida_nexus.DatabaseHandle`
  (left open for the caller).
- `on_unmapped`: the `UC_HOOK_MEM_UNMAPPED` callback, usable on its own with
  `uc.hook_add(..., user_data=handle)`. Returns `False`, so Unicorn raises its
  normal unmapped-memory error, when the IDB does not cover the faulting access.
- `BoundIdb`: the object returned by `bind`. Usable as a context manager;
  `close()` removes the hook and closes the handle only if `bind` opened it.
- Lazy page mapping from a live IDB via `UC_HOOK_MEM_UNMAPPED`: 4 KiB pages
  are mapped read/write/execute on first access, with bytes fetched over
  ida-nexus RPC. Existing mappings are left untouched.
