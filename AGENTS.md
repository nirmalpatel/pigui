# AGENTS.md

Read `PIGUI.md` first: it summarizes this branch and links the full design in
`pigui/README.md`.

## Directory split

- `/` (repository root) = upstream Snort 3 core. Treat it as a dependency and
  reference. Do not modify Snort core unless explicitly asked.
- `pigui/` = the main project (PIGUI). All PIGUI work happens here: Rust
  crates, Tauri GUI, config, packaging, scripts, tests.

## Working boundaries

- PIGUI consumes Snort as an external process; keep it independent of Snort
  C++ internals.
- Dev Snort binary: `../build/src/snort`; override with `PIGUI_SNORT_BIN`.
  Defaults live in `pigui/.env.example`.
- Keep runtime/state under `pigui/var/`; never write into the parent tree.
- Do not add PIGUI to the root CMake build.
- Do not install Snort system-wide during development.
