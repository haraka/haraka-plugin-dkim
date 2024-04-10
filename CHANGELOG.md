# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

### [1.0.6] - 2024-04-08

- dep: eslint-plugin-haraka -> @haraka/eslint-config
- lint: remove duplicate / stale rules from .eslintrc
- populate [files] in package.json. Delete .npmignore.
- doc: Changes.md -> CHANGELOG.md
- test: switch to node --test

### 1.0.5 - 2023-12-12

- ci: run tests on PR
- ci(publish): add on.release trigger
- deps(dev\*): pin versions

### [1.0.3] - 2022-06-05

- ci: replace hard coded vers with node-lts-versions
- ci(publish): add secrets: inherit
- ci: use reusable workflows (#18)

### [1.0.2] - 2022-05-23

- ci: replace hard coded node vers with node-lts-versions
- ci(publish): add secrets: inherit
- ci: use reusable workflows (#18)
- packaging updates

### [1.0.1] - 2021-02-04

- test: added example tests that set up conn/txn
- ci: add automated package publishing
- ci(GHA): consolidate \*nix & win tests

### 1.0.0 - 2017-02-02

- initial release

[1.0.1]: https://github.com/haraka/haraka-plugin-template/releases/tag/1.0.1
[1.0.2]: https://github.com/haraka/haraka-plugin-template/releases/tag/1.0.2
[1.0.3]: https://github.com/haraka/haraka-plugin-template/releases/tag/1.0.3
[1.0.6]: https://github.com/haraka/haraka-plugin-template/releases/tag/v1.0.6
