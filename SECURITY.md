# Security Policy

`deadbolt` is an authentication library. Security is the product, so we treat every report seriously.

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

Report privately via GitHub's [private vulnerability reporting](https://github.com/ruban-s/deadbolt/security/advisories/new)
(Security → Advisories → *Report a vulnerability*).

Please include: affected version(s), a description, reproduction steps or a proof of concept, and the
impact you foresee.

## Response targets

- **Acknowledgement:** within 3 business days.
- **Triage & severity assessment:** within 7 business days.
- **Fix & coordinated disclosure:** timeline shared after triage, prioritised by severity.

We follow coordinated disclosure and will credit reporters who wish to be named.

## Supported versions

Until `1.0.0`, only the latest released version receives security fixes.

| Version | Supported |
| ------- | --------- |
| latest  | ✅        |
| < latest| ❌        |

## Scope

In scope: the `deadbolt` library and its official integration/adapter modules. Out of scope: issues
in third-party dependencies (report upstream; we will bump once fixed) and misconfigurations in
downstream applications.
