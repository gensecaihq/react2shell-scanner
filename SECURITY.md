# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in react2shell-guard, please report it responsibly.

### How to Report

1. **Do NOT create a public GitHub issue** for security vulnerabilities
2. Email the maintainers directly with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 7 days
- **Resolution Timeline**: We aim to resolve critical issues within 30 days
- **Credit**: We will credit reporters in the release notes (unless you prefer anonymity)

## Security Best Practices

When using react2shell-guard:

1. **Keep Updated**: Always use the latest version
2. **Verify Installation**: Install from official npm registry
3. **Review Outputs**: Validate scan results before taking action
4. **Secure CI/CD**: Protect npm tokens and API keys in CI/CD pipelines

## Scope

This security policy covers:

- The react2shell-guard npm package
- The CLI tool
- The MCP server
- The middleware components

### Out of Scope

- Third-party dependencies (report to respective maintainers)
- User misconfiguration
- Denial of service through normal usage

## CVE Tracking

react2shell-guard itself is designed to detect CVE-2025-55182 in React/Next.js applications. For vulnerabilities in the tool itself:

- We will request CVE IDs for confirmed vulnerabilities
- Security advisories will be published on GitHub
- Updates will be released as patch versions

## Acknowledgments

We thank all security researchers who responsibly disclose vulnerabilities.
