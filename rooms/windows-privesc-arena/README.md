# Windows PrivEsc Arena — TryHackMe

> **Platform:** TryHackMe  
> **Category:** Windows Local Privilege Escalation  
> **Operating System:** Windows 7 Professional  

This room focuses on common Windows privilege-escalation weaknesses caused by insecure permissions, unsafe policies, and misconfigured services.

Each task is documented separately with the attack flow, technical explanation, evidence, impact, detection, and remediation.

## Tasks

| Task | Technique | Result | Write-up |
|---:|---|---|---|
| 1 | Weak Autorun Permissions | Code executed under a privileged user context | [Read Write-up](01-weak-autorun-permissions/README.md) |
| 2 | AlwaysInstallElevated | MSI payload executed as `NT AUTHORITY\SYSTEM` | [Read Write-up](02-always-install-elevated/README.md) |
| 3 | Weak Service Registry Permissions | The local user was added to Administrators | [Read Write-up](03-weak-service-registry-permissions/README.md) |
| 4 | Weak Service File Permissions | The replacement service binary added the user to Administrators | [Read Write-up](04-weak-service-file-permissions/README.md) |

## Main Concepts

- Autorun executable permissions
- Windows Installer policy abuse
- Windows service Registry ACLs
- Privileged execution paths
- Detection and remediation

## Ethical Use

All activity was performed inside an authorized TryHackMe laboratory.

IP addresses, credentials, flags, and payload files have been removed or sanitized.
