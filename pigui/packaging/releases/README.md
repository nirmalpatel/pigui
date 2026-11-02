# Release records

Each PIGUI release has a versioned directory:

```text
releases/
  v<version>/
    notes.md             public GitHub release body
    manifest.json        machine-readable artifact metadata
    SHA256SUMS           checksums of published artifacts
    NOTICE               license and bundled-component notice
    macos-<arch>.md      macOS signing and notarization record
```

Start a new release from `TEMPLATE/`:

```bash
mkdir -p releases/v0.2.0
cp TEMPLATE/notes.md releases/v0.2.0/notes.md
cp TEMPLATE/manifest.json releases/v0.2.0/manifest.json
cp TEMPLATE/macos-arm64.md releases/v0.2.0/macos-arm64.md
```

Fill the placeholders after the signed artifact is built. Do not commit the
DMG, ZIP, or other binary artifacts; attach them to the GitHub release and
commit only their checksums and metadata.

Artifact names include the platform and architecture so future Linux packages
can join the same release:

```text
PIGUI-<version>-macos-arm64.dmg
PIGUI-<version>-linux-x86_64.deb
PIGUI-<version>-linux-x86_64.rpm
```

The tag for the release is `pigui-v<version>`.
