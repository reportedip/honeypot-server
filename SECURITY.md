# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the ReportedIP Honeypot Server, please report it responsibly.

**Email**: [1@reportedip.de](mailto:1@reportedip.de)

**Please include**:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix or mitigation**: Depending on severity, typically within 14 days for critical issues

## What Qualifies as a Security Vulnerability

- Authentication or authorization bypass
- SQL injection, XSS, or other injection attacks against the admin panel
- Session hijacking or CSRF bypass
- Information disclosure (e.g., leaking config data, API keys)
- Path traversal allowing access to files outside the project
- Denial of service against the honeypot server itself

## What Does NOT Qualify

- Attacks detected by the honeypot (that is its purpose)
- Social engineering or phishing
- Vulnerabilities in dependencies not shipped with this project
- Feature requests or general bugs (please use [GitHub Issues](https://github.com/reportedip/honeypot-server/issues))

## Responsible Disclosure

We kindly ask that you:

1. **Do not** publicly disclose the vulnerability until a fix is available
2. **Do not** exploit the vulnerability beyond what is necessary to demonstrate it
3. **Do not** access or modify data belonging to other users

We are committed to working with security researchers and will credit you in the release notes (unless you prefer to remain anonymous).
