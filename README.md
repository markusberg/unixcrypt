# Unixcrypt for Node.js
A Node.js module for encrypting and verifying passwords according to the SHA-256 and SHA-512 Crypt standard:
https://www.akkadia.org/drepper/SHA-crypt.txt

## Dependencies
This package has no external dependencies. It uses the cryptographic facilities built into Node.js.

For development, there are dependencies on TypeScript, Jest, Chai, ts-node.

## Goals and motivation
I needed an implementation of SHA-512-crypt for another project (for compatibility purposes with an older project), and I wasn't happy with any of the already available packages. Another motivation was that I wanted to write a Node.js module in TypeScript. This seemed a perfect candidate as it's:
* something that I need
* a well known standard
* plenty of tests already written

## Installation
```sh
$ npm install unixcrypt
```

## Usage
### TypeScript
This is TypeScript, but it should work the same in modern JavaScript.
```typescript
import { encrypt, verify } from "unixcrypt";

const plaintextPassword = "password";

// without providing salt, random salt is used, and default number of rounds
const pwhash = encrypt(plaintextPassword);

// verify password with generated hash
console.log(verify(plaintextPassword, pwHash));
// true

// provide number of rounds
const moreRounds = encrypt(plaintextPassword, "$6$rounds=10000");
console.log(verify(plaintextPassword, moreRounds));
// true

// provide custom salt
const customSalt = encrypt(plaintextPassword, "$6$salt");
console.log(verify(plaintextPassword, customSalt));
// true

// or provide both rounds and salt
const customRoundsAndSalt = encrypt(plaintextPassword, "$6$rounds=10000$salt");
console.log(verify(plaintextPassword, moreRounds));
// true

// you can also use SHA-256
const sha256 = encrypt(plaintextPassword, "$5");
console.log(verify(plaintextPassword, sha256));
// true
```

## Test
The tests are written with [Chai](http://www.chaijs.com/), and [Jest](https://jestjs.io/) by way of [ts-jest](https://github.com/kulshekhar/ts-jest).
```sh
$ npm test
```
or
```sh
$ npm test:watch
```
to get automatic re-tests when files are changed.
