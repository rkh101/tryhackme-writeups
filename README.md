## Techniques

| Technique | Root Cause | Result | Write-up |
|---|---|---|---|
| Weak Autorun Permissions | `Everyone` had `FILE_ALL_ACCESS` over an executable referenced by a machine-wide Run key | Payload executed under the privileged logon account | [Read Write-up](weak-autorun-permissions/README.md) |
| AlwaysInstallElevated | Windows Installer elevation enabled in both `HKLM` and `HKCU` | Malicious MSI executed as `NT AUTHORITY\SYSTEM` | [Read Write-up](always-install-elevated/README.md) |
