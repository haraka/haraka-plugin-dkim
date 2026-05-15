# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

### [1.2.0] - 2026-05-15

- dep(address-rfc2822) -> @haraka/email-address

### [1.1.2] - 2026-05-10

- fix: unpipe message-stream on error

### [1.1.1] - 2026-04-16

- fix: update the config and README to match the code

### [1.1.0] - 2026-04-12

- feat: add support for body_canon=simple
- feat: add ed25519 validation
- test: if opendkim installed, round trip test against it
- fix: don't allow rsa-sha1, RFC 8301 3.2
- fix: don't allow subsequent fail to overwrite a pass
- fix: don't discard valid signatures when DNS has > 1 acceptable hash
- fix: don't truncate DNS p= value, may have base64 = padding
- fix: enforce DNS record uniqueness per RFC 6376 3.6.2.2
- fix: correctly handle header canonicalization ws
- fix: corrected simple body canonicalization for empty bodies
- fix: correct a flawed suffix check
- deps: bump all to latest
- style: more es6/7 patterns
- update publish & ci workflow triggers #18

### [1.0.11] - 2025-02-06

- results: shed duplicate result fields

### [1.0.10] - 2025-02-02

- deps(all): bump versions to latest

### [1.0.9] - 2025-01-26

- dep(eslint): upgrade to eslint 9

### [1.0.8] - 2024-10-01

- dep(nopt): 8.0.0
- dep(async): 3.2.6
- dep(haraka-email-message): 1.2.4
- dep(haraka-test-fixtures): 1.3.8

### [1.0.7] - 2024-09-02

- fix(dkim_key_gen.sh): remove unused variable

### [1.0.6] - 2024-08-23

- fix: avoid crash by ensuring appropriate context for load_key

### [1.0.4] - 2024-05-21

- populate [bin] in package.json
- deps: bump versions

### [1.0.3] - 2024-04-15

- config: add `verify.enabled` setting

### [1.0.2] - 2024-04-10

- fix: properly scope the logdebug injections

### 1.0.0 - 2024-04-09

- repackaged from haraka/Haraka

[1.0.0]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.0
[1.0.2]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.2
[1.0.3]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.3
[1.0.4]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.4
[1.0.5]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.5
[1.0.6]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.6
[1.0.7]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.7
[1.0.8]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.8
[1.0.9]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.9
[1.0.10]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.10
[1.0.11]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.0.11
[1.1.0]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.1.0
[1.1.1]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.1.1
[1.1.2]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.1.2
[1.2.0]: https://github.com/haraka/haraka-plugin-dkim/releases/tag/v1.2.0
