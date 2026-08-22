## Summary

Describe the change and the user or contributor problem it solves.

## Testing

List the checks performed. Include the macOS version and Mac architecture for
manual Wi-Fi testing, but do not include SSIDs, BSSIDs, credentials, complete
scan exports, or Keychain output.

## Checklist

- [ ] The change is focused and has no unrelated formatting or generated files.
- [ ] `xcrun swift-format lint --recursive --strict App` passes.
- [ ] `BSSID_PICKER_SIGNING_IDENTITY=- ./BuildTools/build-app.sh` passes.
- [ ] User-visible behavior and documentation are updated together, when applicable.
- [ ] New storage, network access, permissions, entitlements, or private APIs are documented and justified.
- [ ] Strict BSSID changes remain isolated from the public CoreWLAN path and fail closed.
- [ ] Logs, screenshots, fixtures, and descriptions contain no private network or credential data.

Closes #
