# Unixcrypt for Node.js

[![travis build](https://img.shields.io/travis/markusberg/unixcrypt.svg)](https://travis-ci.org/markusberg/unixcrypt)
[![codecov coverage](https://img.shields.io/codecov/c/github/markusberg/unixcrypt/master.svg)](https://codecov.io/github/markusberg/unixcrypt)
[![version](https://img.shields.io/npm/v/unixcrypt.svg)](https://codecov.io/github/markusberg/unixcrypt)
[![license](https://img.shields.io/github/license/markusberg/unixcrypt.svg)](https://www.apache.org/licenses/LICENSE-2.0)

A Node.js module for encrypting and verifying passwords according to the SHA-256 and SHA-512 Crypt standard:
https://www.akkadia.org/drepper/SHA-crypt.txt

## Dependencies

This package has no external dependencies. It uses the cryptographic facilities built into Node.js.

For development, there are dependencies on TypeScript, Jest, Chai, ts-node.

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

The JavaScript usage is similar to the TypeScript below, but you'll want to use the `require("unixcrypt")` construct instead of `import ...`

```javascript
var unixcrypt = require("unixcrypt")

const plaintextPassword = "password"
const pwhash = unixcrypt.encrypt(plaintextPassword)

// verify password with generated hash
console.log(unixcrypt.verify(plaintextPassword, pwHash))
// true
```

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

The tests are written with [Chai](http://www.chaijs.com/), and [Jest](https://jestjs.io/) by way of [ts-jest](https://github.com/kulshekhar/ts-jest).

```sh
$ npm test
```

or

```sh
$ npm run test:watch
```

to get automatic re-tests when files are changed.
