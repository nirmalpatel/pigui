# PIGUI 0.1.0 - macOS arm64 release record

## Artifact

```text
File:               PIGUI-0.1.0-macos-arm64.dmg
Path:               target/macos/PIGUI-0.1.0-macos-arm64.dmg
SHA-256:            118210aee2f02fcc35324bb1f2e14c8ce930bd05d596230a72d936fc6fb4d473
Arch:               arm64
Min macOS:          14.0
App build commit:   ff712f1e0
Release tag:        pigui-v0.1.0
```

The DMG contains the signed, notarized, and stapled `PIGUI.app`. The app bundle
and every nested Mach-O are signed with the Developer ID Application identity
below.

The app bundle is the verified v0.1.0 build. It is reused unchanged for this
release; its existing notarization ticket remains valid. The DMG was regenerated
to add the `/Applications` shortcut and was notarized and stapled separately.

## Signing and notarization

```text
Team ID:                 HQ9NP5ZSL5
Signing identity:        Developer ID Application: EDOPTIMIZE SOLUTIONS PRIVATE LIMITED (HQ9NP5ZSL5)
App notary submission:   6b9150d3-7654-4256-a68b-8d1de36c5019
DMG notary submission:   5a10a86b-bdca-4044-bf4f-e96474a3bd2b
App notary status:       Accepted
DMG notary status:       Accepted
App staple:              verified
DMG staple:              verified
App Gatekeeper:          accepted, source=Notarized Developer ID
DMG Gatekeeper:          accepted, source=Notarized Developer ID
```

Both the app and the DMG are notarized and stapled. The app-level ticket is
required for launchd to accept the `SMAppService` LaunchDaemon. The helper
accepts the signed daemon and the signed in-bundle diagnostic client
(`com.pigui.helperctl`) through the app's `PIGUIHelperClientRequirement`.

Earlier DMG-only submissions from the 0.1.0 preparation run are superseded by
the artifact hashes above.

## Build environment

```text
macOS:       15.5
Arch:        arm64
Xcode/Swift: Swift 6.1 (swiftlang-6.1.0.110.21 clang-1700.0.13.3)
Rust:        1.99.1
Snort:       3.12.4.0
```

## Verification

```bash
shasum -a 256 -c SHA256SUMS
xcrun stapler validate target/macos/PIGUI.app
xcrun stapler validate target/macos/PIGUI-0.1.0-macos-arm64.dmg
spctl -a -vvv -t exec target/macos/PIGUI.app
spctl -a -vvv -t install target/macos/PIGUI-0.1.0-macos-arm64.dmg
./packaging/macos/verify-bundle.sh target/macos/PIGUI.app
```

After installing in `/Applications`:

```bash
./packaging/macos/verify-installed.sh /Applications/PIGUI.app
```

## Notarization policy

These tickets apply only to the artifacts with the hashes above. Any rebuild
changes the artifacts and requires a new version, submissions, and staples.
