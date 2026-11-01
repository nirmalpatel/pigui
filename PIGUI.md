# PIGUI

PIGUI is a macOS-first network security application built alongside Snort 3 on
the `pigui` branch. It runs Snort as an external passive sensor and adds
process attribution, a manager daemon, a privileged firewall helper, and an
Activity Monitor-style GUI.

- Status: early implementation; Phase 1 and Phase 2 are complete
- Project directory: `pigui/`
- Full design and architecture: `pigui/docs/README.md`
- Phase 1 runs the daemon against an `alert_json` fixture and serves a minimal
  Tauri alerts/destinations window under `pigui/`
- Phase 2 adds live Snort capture, extractor ingestion, nettop-based process
  attribution, and processes/connections/destinations tabs (`run-live.sh`)

PIGUI does not link against Snort C++ internals and is not part of the
top-level Snort CMake build. Snort is consumed as an external process.
