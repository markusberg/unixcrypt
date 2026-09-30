import { createHash, timingSafeEqual, randomInt } from 'node:crypto'
import { Buffer } from 'node:buffer'

interface IConf {
  id: HashType
  saltString: string
  rounds: number
  specifyRounds: boolean
}

type HashType = 5 | 6
type Algorithm = 'sha256' | 'sha512'

const HashMap: Record<HashType, { algorithm: Algorithm; digestSize: number }> =
  {
    5: { algorithm: 'sha256', digestSize: 32 },
    6: { algorithm: 'sha512', digestSize: 64 },
  }

const dictionary =
  './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

// oxfmt-ignore
const shuffleMap: Record<Algorithm, number[]> = {
  sha256: [
    20, 10,  0,
    11,  1, 21,
     2, 22, 12,
    23, 13,  3,
    14,  4, 24,
     5, 25, 15,
    26, 16,  6,
    17,  7, 27,
     8, 28, 18,
    29, 19,  9,
    30, 31
  ],
  sha512: [
    42, 21,  0,
    1,  43, 22,
    23,  2, 44,
    45, 24,  3,
    4,  46, 25,
    26,  5, 47,
    48, 27,  6,
    7,  49, 28,
    29,  8, 50,
    51, 30,  9,
    10, 52, 31,
    32, 11, 53,
    54, 33, 12,
    13, 55, 34,
    35, 14, 56,
    57, 36, 15,
    16, 58, 37,
    38, 17, 59,
    60, 39, 18,
    19, 61, 40,
    41, 20, 62,
    63,
  ]
}
const roundsDefault = 5000

/**
 * Generate a random string
 * @param length Length of salt
 */
function getRandomString(length: number): string {
  let result = ''
  for (let i = 0; i < length; i++) {
    result += dictionary[randomInt(dictionary.length)]
  }
  return result
}

/**
 * Normalize salt for use with hash, for example: "$6$rounds=1234&saltsalt" or "$6$saltsalt"
 * @param conf The separate parts of id, rounds, specifyRounds, and saltString
 */
function normalizeSalt(conf: IConf): string {
  const parts = ['', conf.id]
  if (conf.specifyRounds || conf.rounds !== roundsDefault) {
    parts.push(`rounds=${conf.rounds}`)
  }
  parts.push(conf.saltString)
  return parts.join('$')
}

/**
 * Parse salt into pieces, performs sanity checks, and returns proper
 * defaults for missing values
 * @param salt Standard salt, "$6$rounds=1234$saltsalt", "$6$saltsalt", "$6", "$6$rounds=1234", "$6$",
 *   or a complete hash, "$6$rounds=1234$saltsalt$hash"
 */
function parseSalt(salt?: string): IConf {
  const roundsMin = 1000
  const roundsMax = 999999999
  const saltMaxBytes = 16

  const conf: IConf = {
    id: 6,
    saltString: getRandomString(16),
    rounds: roundsDefault,
    specifyRounds: false,
  }

  if (salt) {
    const prefix = salt.match(/^\$([56])(\$|$)/)
    if (!prefix) {
      throw new Error('Only sha256 and sha512 is supported by this library')
    }
    conf.id = Number(prefix[1]) as HashType

    // "$6" only specifies the hash type
    if (prefix[2] === '$') {
      let rest = salt.slice(prefix[0].length)
      const rounds = rest.match(/^rounds=(\d*)(\$|$)/)

      if (rounds) {
        // number of rounds has been specified
        conf.rounds = Number(rounds[1])
        conf.specifyRounds = true
        rest = rest.slice(rounds[0].length)
      }

      // "$6$rounds=1234" without a trailing "$" keeps the random salt. The
      // spec would treat "rounds=1234" as the salt, but this is a deliberate
      // convenience of this library
      if (!rounds || rounds[2] === '$') {
        // the salt may contain any character except "$", which terminates it
        conf.saltString = rest.split('$')[0]
      }
    }
  }

  // sanity-check rounds
  if (conf.rounds < roundsMin) {
    conf.rounds = roundsMin
  } else if (conf.rounds > roundsMax) {
    conf.rounds = roundsMax
  }

  // sanity-check saltString: the spec limits it to 16 bytes, not characters
  const saltBytes = Buffer.from(conf.saltString)
  if (saltBytes.length > saltMaxBytes) {
    const truncated = saltBytes.subarray(0, saltMaxBytes).toString()
    if (Buffer.byteLength(truncated) !== saltMaxBytes) {
      throw new Error(
        'Invalid salt string: truncating it to 16 bytes would split a multibyte character',
      )
    }
    conf.saltString = truncated
  }

  return conf
}

/**
 * Upper bound for the "for each block of 32 or 64 bytes" loops in steps 9 and 16a.
 * Versions up to and including 3.0.4 stopped one block short when the password
 * length was an exact multiple of the digest size, which `legacy` reproduces
 * @param plaintextByteLength
 * @param legacy
 */
function blockLimit(plaintextByteLength: number, legacy: boolean): number {
  return legacy ? plaintextByteLength - 1 : plaintextByteLength
}

/**
 * Steps 1-12 in the spec
 * @param plaintext
 * @param conf
 * @param legacy Reproduce the behaviour of 3.0.4 and earlier, see blockLimit()
 */
function generateDigestA(
  plaintext: string,
  conf: IConf,
  legacy: boolean,
): Buffer {
  const algorithm: Algorithm = HashMap[conf.id].algorithm
  const digestSize: number = HashMap[conf.id].digestSize

  // steps 1-8
  const hashA = createHash(algorithm)
  hashA.update(plaintext)
  hashA.update(conf.saltString)

  const hashB = createHash(algorithm)
  hashB.update(plaintext)
  hashB.update(conf.saltString)
  hashB.update(plaintext)
  const digestB = hashB.digest()

  // step 9
  const plaintextByteLength = Buffer.byteLength(plaintext)
  for (
    let offset = 0;
    offset + digestSize <= blockLimit(plaintextByteLength, legacy);
    offset += digestSize
  ) {
    hashA.update(digestB)
  }

  // step 10
  const remainder = plaintextByteLength % digestSize
  hashA.update(digestB.slice(0, remainder))

  // step 11
  plaintextByteLength
    .toString(2)
    .split('')
    .reverse()
    .forEach((num) => {
      hashA.update(num === '0' ? plaintext : digestB)
    })

  // step 12
  return hashA.digest()
}

function generateHash(plaintext: string, conf: IConf, legacy = false): string {
  const algorithm: Algorithm = HashMap[conf.id].algorithm
  const digestSize: number = HashMap[conf.id].digestSize

  // steps 1-12
  const digestA = generateDigestA(plaintext, conf, legacy)

  // steps 13-15
  const plaintextByteLength = Buffer.byteLength(plaintext)
  const hashDP = createHash(algorithm)
  for (let i = 0; i < plaintextByteLength; i++) {
    hashDP.update(plaintext)
  }
  const digestDP = hashDP.digest()

  // step 16a
  const p = Buffer.alloc(plaintextByteLength)
  for (
    let offset = 0;
    offset + digestSize <= blockLimit(plaintextByteLength, legacy);
    offset += digestSize
  ) {
    p.set(digestDP, offset)
  }

  // step 16b
  const remainder = plaintextByteLength % digestSize
  p.set(digestDP.slice(0, remainder), plaintextByteLength - remainder)

  // step 17-19
  const hashDS = createHash(algorithm)
  const step18 = 16 + digestA[0]
  for (let i = 0; i < step18; i++) {
    hashDS.update(conf.saltString)
  }
  const digestDS = hashDS.digest()

  // step 20
  const saltByteLength = Buffer.byteLength(conf.saltString)
  const s = Buffer.alloc(saltByteLength)

  // step 20a
  // Isn't this step redundant? The salt string doesn't have 32 or 64 bytes. It's truncated to 16 bytes
  for (
    let offset = 0;
    offset + digestSize <= saltByteLength;
    offset += digestSize
  ) {
    s.set(digestDS, offset)
  }

  // step 20b
  const saltRemainder = saltByteLength % digestSize
  s.set(digestDS.slice(0, saltRemainder), saltByteLength - saltRemainder)

  // step 21
  let digestC = digestA
  for (let idx = 0; idx < conf.rounds; idx++) {
    const hashC = createHash(algorithm)

    // steps b-c
    if (idx % 2 === 0) {
      hashC.update(digestC)
    } else {
      hashC.update(p)
    }

    // step d
    if (idx % 3 !== 0) {
      hashC.update(s)
    }

    // step e
    if (idx % 7 !== 0) {
      hashC.update(p)
    }

    // steps f-g
    if (idx % 2 !== 0) {
      hashC.update(digestC)
    } else {
      hashC.update(p)
    }

    digestC = hashC.digest()
  }

  // step 22
  return base64Encode(digestC, shuffleMap[algorithm])
}

function base64Encode(digest: Buffer, shuffleMap: number[]): string {
  let hash = ''
  for (let idx = 0; idx < digest.length; idx += 3) {
    const buf = Buffer.alloc(3)
    buf[0] = digest[shuffleMap[idx]]
    buf[1] = digest[shuffleMap[idx + 1]]
    buf[2] = digest[shuffleMap[idx + 2]]

    hash += bufferToBase64(buf)
  }

  // adjust hash length by stripping trailing zeroes induced by base64-encoding
  return hash.slice(0, digest.length === 32 ? -1 : -2)
}

/**
 * Encode buffer to base64 using our dictionary
 * @param buf Buffer of bytes to be encoded
 */
function bufferToBase64(buf: Buffer): string {
  const first = buf[0] & parseInt('00111111', 2)
  const second =
    ((buf[0] & parseInt('11000000', 2)) >>> 6) |
    ((buf[1] & parseInt('00001111', 2)) << 2)
  const third =
    ((buf[1] & parseInt('11110000', 2)) >>> 4) |
    ((buf[2] & parseInt('00000011', 2)) << 4)
  const fourth = (buf[2] & parseInt('11111100', 2)) >>> 2
  return (
    dictionary.charAt(first) +
    dictionary.charAt(second) +
    dictionary.charAt(third) +
    dictionary.charAt(fourth)
  )
}

/**
 * Create a SHA-256 or SHA-512 hash of a plaintext password using the unixcrypt format.
 *
 * @param plaintext - The password to encrypt
 * @param salt - Optional salt string in Unix crypt format. Examples:
 *   - "$6$salt" - Use SHA-512 with default rounds
 *   - "$6$rounds=10000$salt" - Use SHA-512 with 10000 rounds
 *   - "$5$salt" - Use SHA-256 with default rounds
 *   - "$6" or "$6$rounds=10000" - Use a random salt
 *   - "$6$rounds=10000$salt$hash" - A complete hash, of which only the salt part is used
 *   If omitted, generates SHA-512 hash with random salt
 * @returns The complete hash string in Unix crypt format
 * @throws If the salt is not for SHA-256 or SHA-512, or if truncating it to 16 bytes
 *   would split a multibyte character
 * @example
 * // Generate SHA-512 hash with random salt
 * encrypt("mypassword")
 * // -> "$6$WHT0QXyF$LQv3c1yqBWVHxkd0LHAkC..."
 *
 * // Generate SHA-512 hash with specific salt and rounds
 * encrypt("mypassword", "$6$rounds=10000$saltvalue")
 * // -> "$6$rounds=10000$saltvalue$LQv3c1yq..."
 */
export function encrypt(plaintext: string, salt?: string): string {
  const conf = parseSalt(salt)
  const hash = generateHash(plaintext, conf)
  return normalizeSalt(conf) + '$' + hash
}

/**
 * Verify a plaintext password against an existing unixcrypt hash.
 *
 * @param plaintext - The password to verify
 * @param hash - The complete hash string to verify against (including salt and rounds)
 * @returns True if the plaintext matches the hash, false otherwise
 * @throws If the hash is not a SHA-256 or SHA-512 hash
 * @example
 * // Verify password against hash
 * verify("mypassword", "$6$WHT0QXyF$LQv3c1yqBWVHxkd0LHAkC...")
 * // -> true or false
 */
export function verify(plaintext: string, hash: string): boolean {
  return verifyHash(plaintext, hash, false)
}

/**
 * Verify a plaintext password against a hash created by unixcrypt 3.0.4 or earlier.
 *
 * Those versions produced incorrect hashes for passwords whose length in bytes is
 * an exact multiple of the digest size (32, 64, 96... bytes for SHA-256, and
 * 64, 128... bytes for SHA-512). For all other lengths the result is identical
 * to {@link verify}. Use it as a fallback when {@link verify} fails, and re-hash
 * the password with {@link encrypt} when it succeeds.
 *
 * @param plaintext - The password to verify
 * @param hash - The complete hash string to verify against (including salt and rounds)
 * @returns True if the plaintext matches the hash using the legacy algorithm, false otherwise
 * @throws If the hash is not a SHA-256 or SHA-512 hash
 * @example
 * if (verify(password, storedHash)) {
 *   // ok
 * } else if (verifyLegacy(password, storedHash)) {
 *   // ok, but the stored hash was created by an older version
 *   storedHash = encrypt(password)
 * }
 */
export function verifyLegacy(plaintext: string, hash: string): boolean {
  return verifyHash(plaintext, hash, true)
}

function verifyHash(plaintext: string, hash: string, legacy: boolean): boolean {
  const conf = parseSalt(hash.slice(0, hash.lastIndexOf('$')))
  const computedHash =
    normalizeSalt(conf) + '$' + generateHash(plaintext, conf, legacy)

  const computed = Buffer.from(computedHash, 'utf8')
  const expected = Buffer.from(hash, 'utf8')

  // timingSafeEqual throws on buffers of different length, for example a truncated hash
  return (
    computed.length === expected.length && timingSafeEqual(computed, expected)
  )
}
