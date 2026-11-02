# PIGUI

PIGUI is a cross-platform network security application built alongside Snort 3
on the `pigui` branch. It runs Snort as an external passive sensor and adds
process attribution, a manager daemon, a privileged firewall helper, and an
Activity Monitor-style GUI.

- Status: early implementation; live Snort capture and the GUI are implemented
- Platform support: macOS currently; Linux and Windows in progress
- Project directory: `pigui/`
- Full design and architecture: `pigui/docs/README.md`
- The development app runs Snort, the daemon, and the Tauri GUI together via
  `scripts/run-dev.sh`
- Automated tests use recorded fixtures under `tests/fixtures/`

PIGUI does not link against Snort C++ internals and is not part of the
top-level Snort CMake build. Snort is consumed as an external process.
