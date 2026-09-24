# Security Policy

## Reporting a vulnerability

Report a suspected vulnerability privately, through GitHub's private vulnerability
reporting: on this repository's **Security** tab, choose **Report a vulnerability**
(<https://github.com/davidchaiken/vcrd/security/advisories/new>). Please do not open a
public issue, pull request or discussion about it.

Include the vcrd version or commit, the command or library call, and an input that
reproduces the problem. **Use a synthetic credential, never a real one.** Verifiable
credentials can carry personal data, and a report is shared with the people who work on
the fix.

## What to report

vcrd checks credentials from parties it does not trust. Its threat model is in
[REQUIREMENTS.md §12](REQUIREMENTS.md#12-security-posture). Reports in scope include:

- vcrd reporting a credential as verified when it should not, for example through
  algorithm confusion, key substitution or a weak key.
- An input that makes vcrd panic, crash, or consume time or memory out of proportion to
  its size.
- A claim value reaching vcrd's output without having been revealed on purpose
  ([REQUIREMENTS.md §8](REQUIREMENTS.md#8-cli-design)).
- A weakness in how vcrd is built, tested or released: its CI workflows, its
  dependencies, or its release artifacts.

## What to expect

vcrd has one maintainer and has not reached 1.0. Reports are handled on a best-effort
basis, with no guaranteed response time. You will be told when your report has been read,
and the fix and any advisory are coordinated with you through the private report.

## Supported versions

While vcrd is before 1.0, only the `main` branch is supported. Fixes land on `main`, and
nothing is backported.

## Reliance on vcrd's results

vcrd is pre-1.0 software. Do not rely on it for production trust decisions. Its licences
([MIT](LICENSE-MIT), [Apache-2.0](LICENSE-APACHE)) disclaim any warranty, but that is only
the legal floor: vcrd is still being built and reviewed against the standards it
implements, and its results may be wrong. Even when they are right, vcrd reports facts
about a credential — that it parses, that it conforms to its data model, that it verifies
against particular key material — and does not judge whether the credential should be
trusted for any purpose ([REQUIREMENTS.md §1](REQUIREMENTS.md#1-vision--goals)).
