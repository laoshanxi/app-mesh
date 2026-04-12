# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.2.x   | Yes                |
| < 2.2   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in App Mesh, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **GitHub Private Vulnerability Reporting**: Use [GitHub's security advisory feature](https://github.com/laoshanxi/app-mesh/security/advisories/new) to report vulnerabilities privately.
2. **Email**: Send details to the maintainer via the contact information on the [GitHub profile](https://github.com/laoshanxi).

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 3 business days
- **Initial Assessment**: Within 7 business days
- **Fix or Mitigation**: Depends on severity; critical issues are prioritized

### Disclosure Policy

- We follow coordinated disclosure. Please allow reasonable time for a fix before public disclosure.
- Credit will be given to reporters in the release notes (unless anonymity is preferred).

## Security Measures

This project employs the following security practices:

- **Static Analysis**: CodeQL and Coverity scans on every PR and weekly schedules
- **Dependency Scanning**: Dependabot alerts and dependency review on pull requests
- **SBOM**: Software Bill of Materials generated with each release (SPDX format)
- **Build Provenance**: Artifact attestations for release builds
- **OpenSSF Scorecard**: Continuous security posture monitoring
- **Secret Detection**: gitleaks pre-commit hook to prevent credential leaks
- **Package Signing**: GPG-signed deb/rpm packages
