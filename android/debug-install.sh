#!/usr/bin/env bash
set -Eeuo pipefail
APP_ID="com.promptworks.sudoauth.secure"
ACTIVITY="com.promptworks.authenticator.MainActivity"
command -v adb >/dev/null || { echo "ERROR: adb is not installed." >&2; exit 1; }
[[ -x ./gradlew ]] || { echo "ERROR: run this from the android directory containing gradlew." >&2; exit 1; }
STATE="$(adb get-state 2>/dev/null || true)"
if [[ "$STATE" != "device" ]]; then
  echo "ERROR: No authorized Android device. Unlock the Pixel, accept USB debugging, then run: adb devices" >&2
  exit 1
fi
./gradlew installDebug
adb shell am force-stop "$APP_ID"
adb shell am start -n "$APP_ID/$ACTIVITY"
echo "Prompt-Works-Sudo-Auth debug build installed and launched."
