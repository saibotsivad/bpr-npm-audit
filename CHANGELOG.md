# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

Change categories are:

* `Added` for new features.
* `Changed` for changes in existing functionality.
* `Deprecated` for once-stable features removed in upcoming releases.
* `Removed` for deprecated features removed in this release.
* `Fixed` for any bug fixes.
* `Security` to invite users to upgrade in case of vulnerabilities.

## [1.3.0-1.4.2] - 2023-01-20

### Added

- Support for [npm@7's new audit output](https://github.com/npm/cli/blob/latest/changelogs/CHANGELOG-7.md#npm-audit).
- The flag `BPR_LOG` to limit what level of audit entries get added to the report.
- Fixed error when pushing annotations which contain a `/` in the `id`

## [1.2.0] - 2021-09-04

### Added

- Ability to set the maximum buffer size of the spawned thread thanks to @pevel 💪

## [1.1.2] - 2021-09-01

### Fixed

- Truncate report details to 2000 chars per Bitbucket maximum character limit. Thanks @TheBrockEllis ❤️

## [1.1.1] - 2021-03-17

### Fixed

- Drop use of nullish coalescing operator (`??`) to support older versions of Node (only available in Node@14+).

## [1.1.0] - 2021-03-17

### Fixed

- Added support for npm@7 thanks to @pevel 🎉

## [1.0.0] - 2020-05-06

Initial v1 release, with things working as expected.

[Unreleased]: https://github.com/saibotsivad/bpr-npm-audit/compare/v1.1.0...HEAD
[1.3.0-1.4.2]: https://github.com/saibotsivad/bpr-npm-audit/compare/v1.2.0...v1.4.2
[1.2.0]: https://github.com/saibotsivad/bpr-npm-audit/compare/v1.1.1...v1.2.0
[1.1.2]: https://github.com/saibotsivad/bpr-npm-audit/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/saibotsivad/bpr-npm-audit/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/saibotsivad/bpr-npm-audit/compare/v1.0.0...v1.1.0
