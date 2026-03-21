# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use [GitHub Private Security Advisories](https://github.com/mikeh-22/iscsid-mac/security/advisories/new) to report vulnerabilities privately. This lets us coordinate a fix before public disclosure.

Include as much of the following as you can:

- Description of the vulnerability and its potential impact
- Steps to reproduce or proof-of-concept
- Affected versions
- Any suggested mitigations

You can expect an acknowledgement within 72 hours and a status update within 7 days.

## Scope

This project is a userspace iSCSI daemon. Security-relevant areas include:

- **Authentication**: CHAP-MD5 and CHAP-SHA256 credential handling (`src/daemon/auth.c`)
- **IPC**: Unix domain socket command dispatch (`src/daemon/ipc.c`)
- **Network I/O**: TCP session and PDU handling (`src/daemon/connection.c`, `pdu.c`)
- **Configuration**: Parsing of `iscsid.conf` and initiator name files (`src/daemon/config.c`)

Out of scope: the DriverKit extension stub (`dext/`) is not yet deployed and carries no security surface.

## Supported Versions

This project is in active development; only the latest commit on `main` receives security fixes.

## Disclosure Policy

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure): fixes are prepared privately, then the vulnerability and fix are disclosed publicly together once a patch is available.
