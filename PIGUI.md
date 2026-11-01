# PIGUI

PIGUI is a macOS-first network security application built alongside Snort 3 on
the `pigui` branch. It runs Snort as an external passive sensor and adds
process attribution, a manager daemon, a privileged firewall helper, and an
Activity Monitor-style GUI.

- Status: early implementation; Phase 1 vertical slice is complete
- Project directory: `pigui/`
- Full design and architecture: `pigui/README.md`
- Phase 1 runs the daemon against an `alert_json` fixture and serves a minimal
  Tauri alerts/destinations window under `pigui/`

PIGUI does not link against Snort C++ internals and is not part of the
top-level Snort CMake build. Snort is consumed as an external process.
