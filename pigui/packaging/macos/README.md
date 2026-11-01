# macOS packaging

This directory builds the self-contained, signed, notarized `PIGUI.app` and
its root helper. It is intentionally separate from the development scripts in
`pigui/scripts/`.

## Requirements

- macOS 14 or newer on arm64
- Xcode command line tools with Swift
- Rust workspace toolchain from `rust-toolchain.toml`
- Node.js and the GUI dependencies
- A Snort build at `../build/src/snort` or `PIGUI_SNORT_BIN`
- Developer ID Application certificate for signing releases
- A `notarytool` keychain profile for notarization

## Get the signing certificates

You need an **Apple Developer Program** account for Example Corp with Account Holder or Admin access.

### 1. Developer ID Application certificate

This is the certificate that signs the app and its LaunchDaemon. It is
different from Apple Development and Apple Distribution certificates.

1. Open <https://developer.apple.com/account/resources/certificates/list>.
2. Click **+**.
3. Under **Software**, choose **Developer ID Application**.
4. In **Keychain Access**, choose
   **Certificate Assistant > Request a Certificate From a Certificate
   Authority**.
5. Enter the Apple ID email and your name, leave the CA email blank, choose
   **Saved to disk**, and save the CSR.
6. Upload the CSR in the Apple Developer portal and download the generated
   `.cer`.
7. Double-click the `.cer` to install it in your login keychain.
8. Verify:

```bash
security find-identity -v -p codesigning \
  | grep "Developer ID Application"
```

You do **not** need **Developer ID Installer** for the DMG workflow. It is only
needed if you later ship a signed `.pkg`.

### 2. Notarization credentials

Create an app-specific password at <https://appleid.apple.com> under
**Sign-In and Security > App-Specific Passwords**, then store it in the
keychain:

```bash
xcrun notarytool store-credentials "pigui-notary" \
  --apple-id "you@example.com" \
  --team-id "ABCDE12345"
```

`notarytool` prompts for the app-specific password securely. Do not put the
password in a shell argument or commit it.

Alternatively use an App Store Connect API key:

```bash
xcrun notarytool store-credentials "pigui-notary" \
  --key /path/to/AuthKey_XXXXXXXXXX.p8 \
  --key-id XXXXXXXXXX \
  --issuer 00000000-0000-0000-0000-000000000000
```

Never commit `.p8` keys, `.cer`, `.p12`, or app-specific passwords.

### 3. Check and build

```bash
./packaging/macos/check-signing.sh
```

Then build:

```bash
PIGUI_SIGN_IDENTITY="Developer ID Application: Example Corp (ABCDE12345)" \
PIGUI_TEAM_ID="ABCDE12345" \
PIGUI_NOTARY_PROFILE="pigui-notary" \
PIGUI_NOTARIZE=1 \
./packaging/macos/build-app.sh
```

The script signs every nested binary, notarizes and staples the app bundle
itself, then creates the DMG, notarizes and staples that, and verifies
Gatekeeper. The app-level ticket is required before macOS will launch the
`SMAppService` helper as a LaunchDaemon.

## Notarization is per build

A notarization ticket is bound to the exact signed artifact. Rebuilding the app
or DMG changes signatures, timestamps, or metadata, so the old ticket no longer
applies. You may reuse a ticket only for the exact same DMG file that was
already notarized and stapled.

Do not rebuild a release DMG after notarization. If anything changes, bump the
version and notarize a new artifact. Do not notarize every local development
build; use the development scripts unless you are testing the packaged helper.

The release flow performs two submissions: the app archive first, then the DMG.
Both need to succeed. The app ticket is what allows launchd to launch the root
helper; a DMG-only ticket is not enough for `SMAppService`.

Release artifacts and their metadata live under `releases/`. Do not commit the
DMG itself.

## Release checklist

1. Commit and tag the source that produced the build.
2. Run formatting, tests, Clippy, and the GUI check.
3. Run `./packaging/macos/check-signing.sh`; both checks must be OK.
4. Build with `PIGUI_NOTARIZE=1` (notarizes the app and the DMG).
5. Confirm `stapler validate` and `spctl -a -vvv -t install`.
6. Record the app and DMG SHA-256 values, both notarization submission IDs,
   Snort version, and build environment in `releases/<version>.md`.
7. Publish that exact DMG and its SHA-256.
8. If the build changes, bump the version and repeat.

If `stapler staple` fails with a transient CloudKit/network error, retry it.
Do not rebuild just because stapling failed.

## Build

```bash
cd pigui
./packaging/macos/build-app.sh
```

The unsigned app is written to `target/macos/PIGUI.app`. A signed build without
`PIGUI_NOTARIZE=1` still produces a signed app and DMG, but Gatekeeper will
report `Unnotarized Developer ID` until the DMG is submitted and stapled.

Useful environment variables:

| Variable | Purpose |
|---|---|
| `PIGUI_SNORT_BIN` | Snort binary to bundle |
| `PIGUI_SNORT_LUA_PATH` | Source Lua tree to bundle |
| `PIGUI_BUILD_DIR` | Output directory |
| `PIGUI_SKIP_GUI` | Set to `1` to reuse an existing Tauri app bundle |
| `PIGUI_SIGN_IDENTITY` | Developer ID Application identity |
| `PIGUI_TEAM_ID` | Apple Developer team identifier |
| `PIGUI_NOTARY_PROFILE` | `notarytool` keychain profile |
| `PIGUI_NOTARIZE` | Set to `1` to notarize and staple the DMG |

## Enable live capture (packaged app)

The packaged helper is a LaunchDaemon and must be registered with
`SMAppService`. Apple requires the app to be code signed and, for LaunchDaemons,
notarized. The recommended install location is `/Applications`.

In PIGUI:

1. Open the **Capture** tab.
2. Click **Register helper**.
3. Click **Open Login Items settings** and approve PIGUI.
4. Click **Check again** until the helper shows `enabled`.
5. Enter the capture interface, usually `en0`, and click **Enable capture**.

PIGUI never asks for a password. macOS owns the approval dialog, and the helper
never receives a credential.

After installing, verify the installed copy:

```bash
./packaging/macos/verify-installed.sh /Applications/PIGUI.app
```

The app must have its own notarization ticket (`stapler validate`), not just the
enclosing DMG. Otherwise launchd can reject the helper with
`OS_REASON_CODESIGNING`.

An unsigned local build cannot complete this flow. It may return
`Operation not permitted`. For development, use `scripts/run-live.sh`, which
runs Snort with `sudo` outside the packaged helper path.

Do not use `sfltool resetbtm` to clear a single app. It resets the whole
background-task-management database and affects all apps. Use the PIGUI
unregister commands or System Settings instead.

## Release output

After signing, the script produces:

```text
target/macos/PIGUI.app
target/macos/PIGUI-<version>.dmg
```

The DMG path is excluded by `.gitignore`. Record its checksum in the release
note instead. The current release record is
[`releases/0.1.0.md`](releases/0.1.0.md); start new releases from
[`releases/TEMPLATE.md`](releases/TEMPLATE.md).

## What the app contains

- `Contents/MacOS/PIGUI` - Tauri shell
- `Contents/MacOS/pigui-daemon` - unprivileged manager
- `Contents/MacOS/pigui-cli` - headless client
- `Contents/MacOS/pigui-helper` - root XPC helper
- `Contents/MacOS/pigui-servicectl` - SMAppService registration utility
- `Contents/MacOS/snort` - bundled Snort 3
- `Contents/Frameworks` - bundled Snort dylibs
- `Contents/Resources/snort` - Lua config and rules
- `Contents/Library/LaunchAgents/com.pigui.daemon.plist`
- `Contents/Library/LaunchDaemons/com.pigui.helper.plist`

The production app never invokes `sudo`. The user daemon is registered with
`SMAppService.agent`; the root helper is registered with
`SMAppService.daemon` and approved by an administrator through System Settings.

The helper verifies XPC clients by code signature. It allows the signed daemon
(`com.pigui.daemon`) and the signed in-bundle diagnostic client
(`com.pigui.helperctl`), both anchored to the app's Developer ID team.

The helper stages the signed Snort payload into a root-owned directory before
executing it:

```text
/Library/Application Support/PIGUI/payload/<payload-id>/
```

Audit records are written to:

```text
/Library/Logs/PIGUI/audit.log
```
