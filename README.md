# Unixcrypt for Node.js

[![node.js build](https://github.com/markusberg/unixcrypt/actions/workflows/badges.yaml/badge.svg)](https://github.com/markusberg/unixcrypt/actions/workflows/badges.yaml)
[![coverage](https://markusberg.github.io/unixcrypt/badges/coverage-4.0.0.svg)](https://github.com/markusberg/unixcrypt/actions)
[![version](https://img.shields.io/npm/v/unixcrypt.svg)](https://www.npmjs.com/package/unixcrypt)
[![license](https://img.shields.io/github/license/markusberg/unixcrypt.svg)](./LICENSE)
[![downloads](https://img.shields.io/npm/dt/unixcrypt.svg)](http://npm-stat.com/charts.html?package=unixcrypt)

A Node.js module for encrypting and verifying passwords according to the SHA-256 and SHA-512 Crypt standard:
https://www.akkadia.org/drepper/SHA-crypt.txt

## Dependencies

This package has no external dependencies. It uses the cryptographic facilities built into Node.js. Since version 2.0 this package is ESModule only. If you require CommonJS functionality, you can still use the 1.x version.

For development, there are dependencies on TypeScript, and Node.js v24.

## Goals and motivation

I needed an implementation of SHA-512-crypt for another project (for compatibility purposes with an older project), and I wasn't happy with any of the already available packages. Another motivation was that I wanted to write a Node.js module in TypeScript. This seemed a perfect candidate as it's:

- something that I need
- a well known standard
- plenty of tests already written

## Installation

```sh
$ npm install unixcrypt
```

## Usage

### JavaScript

The JavaScript usage is identical to the TypeScript below. The package is ESM only, so use `import` rather than `require()`.

### TypeScript

```typescript
import { encrypt, verify } from "unixcrypt"

const plaintextPassword = "password"

// without providing salt, SHA-512 is used with a random salt and the default number of rounds
const pwHash = encrypt(plaintextPassword)
// $6$nixlMJ5Ot/aqjEIE$uPwK/os2MbhxkPXlsEV8J7NXTtFDD/wpWavpYG7zPsPF888lxOkgez7Kw7Z4NEMm1d/mizjkcwhclbAQSW6hi.

// verify password with generated hash
console.log(verify(plaintextPassword, pwHash))
// true

// specify number of rounds
const moreRounds = encrypt(plaintextPassword, "$6$rounds=10000")
// $6$rounds=10000$iqCiJgtSFGKr/TKQ$WPgUmrD08llHSbrBbnIQYPuXBcVymch9HmDySDTMdDm9AAfGwQSs14RXKqy/sYBhwuBtLdmIFza1q6j9fGEMM/
console.log(verify(plaintextPassword, moreRounds))
// true

// provide custom salt
const customSalt = encrypt(plaintextPassword, "$6$salt")
// $6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.
console.log(verify(plaintextPassword, customSalt))
// true

// or provide both rounds and salt
const customRoundsAndSalt = encrypt(plaintextPassword, "$6$rounds=10000$salt")
// $6$rounds=10000$salt$dE5fLfpn2uXfkz.eouwYK/BjrHRu.piovQPjwlE06fDJHwMlg2l.IqEBUIfWBzf7YPXOAddB3FM7rnXHHKVNt.
console.log(verify(plaintextPassword, customRoundsAndSalt))
// true

// you can also use SHA-256
const sha256 = encrypt(plaintextPassword, "$5")
// $5$Joama98FiN5zL7zN$bQvLuqChyXvRCU2X1VXbAECsxfqAskaoypzmZEvQuA2
console.log(verify(plaintextPassword, sha256))
// true

// a wrong password doesn't verify
console.log(verify("wrong password", pwHash))
// false
```

### Salt format

The salt follows the [spec](https://www.akkadia.org/drepper/SHA-crypt.txt): it may contain any character except `$`, and only the first 16 bytes are used. Note that multibyte characters take up more than one byte each, and `encrypt()` throws if truncating the salt would split one. A complete hash may also be passed as salt, in which case only its salt part is used.

As a convenience, `$6$rounds=10000` without a trailing `$` means 10000 rounds with a random salt. The spec would instead treat `rounds=10000` as the salt itself. Use `$6$rounds=10000$` for an empty salt.

`verify()` returns `false` for a hash that doesn't match, including a malformed one, but throws if the hash is not a SHA-256 or SHA-512 hash.

### Hashes created by version 3.0.4 or earlier

Versions up to and including 3.0.4 produced incorrect hashes for passwords whose length in bytes is an exact multiple of the digest size: 32, 64, 96... bytes for SHA-256, and 64, 128... bytes for SHA-512. Such hashes no longer pass `verify()`. For all other password lengths the hashes are unchanged.

Use `verifyLegacy()` as a fallback, and re-hash the password when it succeeds:

```typescript
import { encrypt, verify, verifyLegacy } from "unixcrypt"

/**
 * Check a password against its stored hash. Returns false if the password is
 * wrong, and otherwise the hash to store, which is a new one if the stored
 * hash was created by an older version
 */
function checkPassword(password: string, storedHash: string): string | false {
  if (verify(password, storedHash)) {
    return storedHash
  }
  if (verifyLegacy(password, storedHash)) {
    return encrypt(password)
  }
  return false
}
```

Note that `encrypt(password)` creates a SHA-512 hash with the default number of rounds. Pass a salt such as `"$5"` or `"$6$rounds=10000"` to keep the type or rounds of the stored hash.

## Test

The tests are written with the built-in [node:assert](https://nodejs.org/api/assert.html) module, and are run in the Node.js test runner. The test runner didn't get good enough coverage reporting until v24, so that's the reason for the minimum required version of v24 for building and testing.

```sh
$ npm test
```

or

```sh
$ npm run test:watch
```

to get automatic re-tests when files are changed.
