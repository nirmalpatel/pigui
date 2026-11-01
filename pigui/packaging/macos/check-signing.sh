#!/usr/bin/env bash
set -euo pipefail

TEAM_ID="${PIGUI_TEAM_ID:-}"
NOTARY_PROFILE="${PIGUI_NOTARY_PROFILE:-pigui-notary}"

if [ -z "$TEAM_ID" ]; then
  TEAM_ID="$(security find-identity -v -p codesigning 2>/dev/null \
    | sed -n 's/.*(\([A-Z0-9][A-Z0-9]*\))".*/\1/p' \
    | head -1)"
fi

echo "macOS code-signing identities:"
security find-identity -v -p codesigning || true
echo

if [ -z "$TEAM_ID" ]; then
  echo "Could not determine your Apple team ID."
  echo "Set PIGUI_TEAM_ID to the 10-character team identifier from Apple Developer."
  exit 1
fi
echo "Using team ID: $TEAM_ID"
echo

if security find-identity -v -p codesigning 2>/dev/null \
  | grep -q "Developer ID Application:.*($TEAM_ID)"
then
  echo "OK: Developer ID Application certificate is installed."
else
  echo "MISSING: Developer ID Application certificate for team $TEAM_ID."
  echo
  echo "Create it with an Account Holder or Admin account:"
  echo "  1. https://developer.apple.com/account/resources/certificates/list"
  echo "  2. Click + and choose Developer ID Application."
  echo "  3. Keychain Access > Certificate Assistant >"
  echo "     Request a Certificate From a Certificate Authority."
  echo "  4. Upload the generated CSR, download the .cer, and double-click it."
  echo "  5. Re-run this script."
fi
echo

if xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
  echo "OK: notarytool keychain profile '$NOTARY_PROFILE' works."
else
  echo "MISSING or invalid notarytool profile '$NOTARY_PROFILE'."
  echo
  echo "Create one with either an app-specific password:"
  echo "  xcrun notarytool store-credentials \"$NOTARY_PROFILE\" \\"
  echo "    --apple-id \"you@example.com\" --team-id \"$TEAM_ID\""
  echo "  (notarytool prompts for the app-specific password securely)"
  echo
  echo "or an App Store Connect API key:"
  echo "  xcrun notarytool store-credentials \"$NOTARY_PROFILE\" \\"
  echo "    --key /path/to/AuthKey_XXXXXXXXXX.p8 \\"
  echo "    --key-id XXXXXXXXXX --issuer 00000000-0000-0000-0000-000000000000"
fi
echo

echo "Build command:"
echo "  PIGUI_SIGN_IDENTITY=\"Developer ID Application: YOUR COMPANY ($TEAM_ID)\" \\"
echo "  PIGUI_TEAM_ID=\"$TEAM_ID\" \\"
echo "  PIGUI_NOTARY_PROFILE=\"$NOTARY_PROFILE\" \\"
echo "  PIGUI_NOTARIZE=1 ./packaging/macos/build-app.sh"
