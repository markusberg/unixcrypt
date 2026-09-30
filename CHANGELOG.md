# Changelog

All notable changes to this project will be documented in this file.

## [4.0.1] - 2026-09-30

- chore: replace Prettier with oxlint and oxfmt
- chore: remove the unused `baseUrl` from tsconfig.json

## [4.0.0] - 2026-09-30

- BREAKING fix: incorrect hashes for passwords whose length in bytes is an exact multiple of the digest size (32, 64, 96... bytes for SHA-256, and 64, 128... bytes for SHA-512). Hashes of such passwords created by earlier versions no longer pass `verify()`. See "Hashes created by version 3.0.4 or earlier" in README.md for how to migrate them
- BREAKING fix: the hash type must be exactly `$5` or `$6`. Variants such as `$05$`, `$6.0$` and `$0x6$` used to be accepted, and now throw
- feat: add `verifyLegacy()` for verifying, and migrating, hashes affected by the password length fix above
- feat: salt parsing now follows the spec, and accepts salts that used to throw. The salt may contain any character except `$`, including multibyte characters, and is truncated to 16 bytes. A misspelled or non-numeric rounds prefix is part of the salt, so `$6$round=5000$salt` uses the salt `round=5000`. Hashes of salts that were accepted before are unchanged
- fix: `encrypt()` accepts a complete hash including `rounds=` as salt, such as `$6$rounds=5000$salt$hash`. It used to throw
- fix: `verify()` returns `false` instead of throwing a `RangeError` when the hash has the wrong length, for example when it is truncated or empty
- fix: memory use no longer grows with the number of rounds. Large round counts, up to the spec maximum of 999,999,999, used to run out of memory
- fix: random salts never contained the character `z`, which slightly reduced their entropy
- docs: document the salt format and migration from 3.x in README.md, and make the TypeScript examples compile
- chore: update packages

## [3.0.4] - 2025-12-14

- Update packages

## [3.0.3] - 2025-10-20

- Bump package version

## [3.0.2] - 2025-10-18

- Improve JSDoc documentation
- Remove last vitest reference from README.md

## [3.0.1] - 2025-09-28

- Remove references to vitest from README.md

## [3.0.0] - 2025-09-21

- feat: minimum required version of Node.Js is 20.x
- chore: update all packages
- test: replace vitest with built-in node test runner

## [2.0.0] - 2024-02-18

- feat: minimum required version of Node.js is 18.x
- chore: update all packages
- test: replace test runner with vitest
- test: use built-in node:assert module

## [1.2.0] - 2023-04-16

- feat: minimum required version of Node.js is 14.x
- fix: properly generate hash with empty salt
- chore: update dependencies
- ci: migrate to GitHub actions for CI and some of the badges

## [1.1.0] - 2022-03-22

- Upgrade most dependencies
- Minimum required version of Node.js is now 12.19.0

## [1.0.3] - 2019-07-19

### Added

- Dependency on prettier for consistent code formatting
- Pre-commit hook for pretty-quick

### Changed

- Updated dependencies of jest

### Removed

- Devdependency on ts-node
