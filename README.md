# Unixcrypt for Node.js

[![node.js build](https://github.com/markusberg/unixcrypt/actions/workflows/master.yaml/badge.svg)](https://github.com/markusberg/unixcrypt/actions/workflows/master.yaml)
[![coverage](https://markusberg.github.io/unixcrypt/badges/coverage-3.0.1.svg)](https://github.com/markusberg/unixcrypt/actions)
![version](https://img.shields.io/npm/v/unixcrypt.svg)
[![license](https://img.shields.io/github/license/markusberg/unixcrypt.svg)](https://www.apache.org/licenses/LICENSE-2.0)

A Node.js module for encrypting and verifying passwords according to the SHA-256 and SHA-512 Crypt standard:
https://www.akkadia.org/drepper/SHA-crypt.txt

## Dependencies

This package has no external dependencies. It uses the cryptographic facilities built into Node.js. Since version 2.0 this package is ESModule only. If you require CommonJS functionality, you can still use the 1.x version.

For development, there are dependencies on TypeScript, and Node.Js v24.

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

The JavaScript usage should be identical to the TypeScript below.

### TypeScript

```typescript
import { encrypt, verify } from "unixcrypt"

const plaintextPassword = "password"

// without providing salt, random salt is used, and default number of rounds
const pwHash = encrypt(plaintextPassword)

// verify password with generated hash
console.log(verify(plaintextPassword, pwHash))
// true

// specify number of rounds
const moreRounds = encrypt(plaintextPassword, "$6$rounds=10000")
console.log(verify(plaintextPassword, moreRounds))
// true

// provide custom salt
const customSalt = encrypt(plaintextPassword, "$6$salt")
console.log(verify(plaintextPassword, customSalt))
// true

// or provide both rounds and salt
const customRoundsAndSalt = encrypt(plaintextPassword, "$6$rounds=10000$salt")
console.log(verify(plaintextPassword, customRoundsAndSalt))
// true

// you can also use SHA-256
const sha256 = encrypt(plaintextPassword, "$5")
console.log(verify(plaintextPassword, sha256))
// true
```

## Test

The tests are written with the built-in [node:assert](https://nodejs.org/api/assert.html) module, and are run in the Node.Js test runner. The test runner didn't get good enough coverage reporting until v24, so that's the reason for the minimum required version of v24 for building and testing.

```sh
$ npm test
```

or

```sh
$ npm run test:watch
```

to get automatic re-tests when files are changed.
