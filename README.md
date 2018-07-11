# Sha512Crypt for nodejs
A Node.js module for encrypting and verifying passwords according to the Sha512Crypt standard:
https://www.akkadia.org/drepper/SHA-crypt.txt

## Goals and motivation
There's already a sha512crypt project published on [npmjs.com](https://www.npmjs.com/package/sha512crypt-node), but it's javascript only, and it comes bundled with its own sha512 implementation. That project is under the two-clause BSD-license, while this one is under Apache-2.0.

My motivations for starting this project were:
* Write a node module in TypeScript
* Implement an existing standard
* Test-driven development

## Installation
```sh
npm install sha512crypt
```

## Usage
### TypeScript
```typescript
import { sha512crypt, verifyPassword } from "sha512crypt";
```

## Test
```sh
npm run test
```
