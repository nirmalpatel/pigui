# PIGUI 0.1.1 - macOS arm64 release record

## Artifact

```text
File:               PIGUI-0.1.1-macos-arm64.dmg
Path:               target/macos/PIGUI-0.1.1-macos-arm64.dmg
SHA-256:            5cd3e1988b7142842be45915fedb44b6707da549cb613587f071e3d9a03e0824
Size:               37698448 bytes
Arch:               arm64
Min macOS:          14.0
App build commit:   c155d85d1
Release tag:        pigui-v0.1.1
```

The DMG contains the signed, notarized, and stapled `PIGUI.app`. The app bundle
and every nested Mach-O are signed with the Developer ID Application identity
below.

Earlier v0.1.1 builds were notarized but not published. They are superseded
by this rebuild; only the artifact and hashes above are released.

## Signing and notarization

```text
Team ID:                 HQ9NP5ZSL5
Signing identity:        Developer ID Application: EDOPTIMIZE SOLUTIONS PRIVATE LIMITED (HQ9NP5ZSL5)
App notary submission:   0922d8d7-8fe6-430c-aff3-daf26a9fa17a
DMG notary submission:   6b16e888-556c-4e4a-a9a0-bdacc61fe52b
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

## Build environment

```text
macOS:       15.5
Arch:        arm64
Xcode/Swift: Xcode 16.3; Swift 6.1 (swiftlang-6.1.0.110.21 clang-1700.0.13.3)
Rust:        1.99.1
Snort:       3.12.4.0
```

## Verification

```bash
shasum -a 256 -c SHA256SUMS
xcrun stapler validate target/macos/PIGUI.app
xcrun stapler validate target/macos/PIGUI-0.1.1-macos-arm64.dmg
spctl -a -vvv -t exec target/macos/PIGUI.app
spctl -a -vvv -t install target/macos/PIGUI-0.1.1-macos-arm64.dmg
./packaging/macos/verify-bundle.sh target/macos/PIGUI.app
```

After installing in `/Applications`:

```bash
./packaging/macos/verify-installed.sh /Applications/PIGUI.app
```

## Notarization policy

These tickets apply only to the artifacts with the hashes above. Any rebuild
changes the artifacts and requires a new version, submissions, and staples.
