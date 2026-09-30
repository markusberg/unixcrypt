# Changelog

All notable changes to this project will be documented in this file.

## [4.0.0] - 2026-09-30

- BREAKING fix: incorrect hashes for passwords whose length in bytes is an exact multiple of the digest size (32, 64, 96... bytes for SHA-256, and 64, 128... bytes for SHA-512). Hashes of such passwords created by earlier versions no longer pass `verify()`
- feat: add `verifyLegacy()` for verifying, and migrating, hashes affected by the above

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
