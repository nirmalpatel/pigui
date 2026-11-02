# PIGUI <version> - macOS arm64 release record

## Artifact

```text
File:               PIGUI-<version>-macos-arm64.dmg
Path:               target/macos/PIGUI-<version>-macos-arm64.dmg
SHA-256:            <sha256>
Arch:               arm64
Min macOS:          14.0
App build commit:   <commit>
Release tag:        pigui-v<version>
```

## Signing and notarization

```text
Team ID:                 <team-id>
Signing identity:        <Developer ID Application identity>
App notary submission:   <app-submission-id>
DMG notary submission:   <dmg-submission-id>
App notary status:       Accepted
DMG notary status:       Accepted
App staple:              verified
DMG staple:              verified
App Gatekeeper:          accepted, source=Notarized Developer ID
DMG Gatekeeper:          accepted, source=Notarized Developer ID
```

## Build environment

```text
macOS:       <version>
Arch:        arm64
Xcode/Swift: <version>
Rust:        <version>
Snort:       <version>
```

## Verification

```bash
shasum -a 256 -c SHA256SUMS
xcrun stapler validate target/macos/PIGUI.app
xcrun stapler validate target/macos/PIGUI-<version>-macos-arm64.dmg
spctl -a -vvv -t exec target/macos/PIGUI.app
spctl -a -vvv -t install target/macos/PIGUI-<version>-macos-arm64.dmg
./packaging/macos/verify-bundle.sh target/macos/PIGUI.app
```

## Notes

- Do not rebuild this release after notarization.
- Any changed artifact requires a new version, submission, and staple.
