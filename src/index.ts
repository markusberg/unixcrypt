import { createHash, timingSafeEqual, randomInt } from "node:crypto"
import { Buffer } from "node:buffer"

interface IConf {
  id: HashType
  saltString: string
  rounds: number
  specifyRounds: boolean
}

type HashType = 5 | 6
type Algorithm = "sha256" | "sha512"

const HashMap: Record<HashType, { algorithm: Algorithm; digestSize: number }> =
  {
    5: { algorithm: "sha256", digestSize: 32 },
    6: { algorithm: "sha512", digestSize: 64 },
  }

const dictionary =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// prettier-ignore
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
};
const roundsDefault = 5000

/**
 * Generate a random string
 * @param length Length of salt
 */
function getRandomString(length: number): string {
  let result = ""
  for (let i = 0; i < length; i++) {
    result += dictionary[randomInt(0, dictionary.length - 1)]
  }
  return result
}

/**
 * Normalize salt for use with hash, for example: "$6$rounds=1234&saltsalt" or "$6$saltsalt"
 * @param conf The separate parts of id, rounds, specifyRounds, and saltString
 */
function normalizeSalt(conf: IConf): string {
  const parts = ["", conf.id]
  if (conf.specifyRounds || conf.rounds !== roundsDefault) {
    parts.push(`rounds=${conf.rounds}`)
  }
  parts.push(conf.saltString)
  return parts.join("$")
}

/**
 * Parse salt into pieces, performs sanity checks, and returns proper
 * defaults for missing values
 * @param salt Standard salt, "$6$rounds=1234$saltsalt", "$6$saltsalt", "$6", "$6$rounds=1234", "$6$"
 */
function parseSalt(salt?: string): IConf {
  const roundsMin = 1000
  const roundsMax = 999999999

  const conf: IConf = {
    id: 6,
    saltString: getRandomString(16),
    rounds: roundsDefault,
    specifyRounds: false,
  }

  if (salt) {
    const parts = salt.split("$")
    conf.id = Number(parts[1]) as HashType

    if (!HashMap[conf.id]) {
      throw new Error("Only sha256 and sha512 is supported by this library")
    }

    if (parts.length < 2 || parts.length > 4) {
      throw new Error("Invalid salt string")
    }

    if (parts.length > 2) {
      const rounds = parts[2].match(/^rounds=(\d*)$/)

      if (rounds) {
        // number of rounds has been specified
        conf.rounds = Number(rounds[1])
        conf.specifyRounds = true

        if (parts[3] || parts[3] === "") {
          conf.saltString = parts[3]
        }
      } else {
        // default number of rounds has already been set
        conf.saltString = parts[2]
      }
    }
  }

  // sanity-check rounds
  if (conf.rounds < roundsMin) {
    conf.rounds = roundsMin
  } else if (conf.rounds > roundsMax) {
    conf.rounds = roundsMax
  }

  // sanity-check saltString
  conf.saltString = conf.saltString.substring(0, 16)

  if (conf.saltString.match("[^./0-9A-Za-z]")) {
    throw new Error("Invalid salt string")
  }

  return conf
}

/**
 * Steps 1-12 in the spec
 * @param plaintext
 * @param conf
 */
function generateDigestA(plaintext: string, conf: IConf): Buffer {
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
    offset + digestSize < plaintextByteLength;
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
    .split("")
    .reverse()
    .forEach((num) => {
      hashA.update(num === "0" ? plaintext : digestB)
    })

  // step 12
  return hashA.digest()
}

function generateHash(plaintext: string, conf: IConf): string {
  const algorithm: Algorithm = HashMap[conf.id].algorithm
  const digestSize: number = HashMap[conf.id].digestSize

  // steps 1-12
  const digestA = generateDigestA(plaintext, conf)

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
    offset + digestSize < plaintextByteLength;
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
  const s = Buffer.alloc(conf.saltString.length)

  // step 20a
  // Isn't this step redundant? The salt string doesn't have 32 or 64 bytes. It's truncated to 16 characters
  const saltByteLength = Buffer.byteLength(conf.saltString)
  for (
    let offset = 0;
    offset + digestSize < saltByteLength;
    offset += digestSize
  ) {
    s.set(digestDS, offset)
  }

  // step 20b
  const saltRemainder = saltByteLength % digestSize
  s.set(digestDS.slice(0, saltRemainder), saltByteLength - saltRemainder)

  // step 21
  const rounds = Array(conf.rounds).fill(0)
  const digestC: Buffer = rounds.reduce((acc, curr, idx) => {
    const hashC = createHash(algorithm)

    // steps b-c
    if (idx % 2 === 0) {
      hashC.update(acc)
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
      hashC.update(acc)
    } else {
      hashC.update(p)
    }

    return hashC.digest()
  }, digestA)

  // step 22
  return base64Encode(digestC, shuffleMap[algorithm])
}

function base64Encode(digest: Buffer, shuffleMap: number[]): string {
  let hash = ""
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
  const first = buf[0] & parseInt("00111111", 2)
  const second =
    ((buf[0] & parseInt("11000000", 2)) >>> 6) |
    ((buf[1] & parseInt("00001111", 2)) << 2)
  const third =
    ((buf[1] & parseInt("11110000", 2)) >>> 4) |
    ((buf[2] & parseInt("00000011", 2)) << 4)
  const fourth = (buf[2] & parseInt("11111100", 2)) >>> 2
  return (
    dictionary.charAt(first) +
    dictionary.charAt(second) +
    dictionary.charAt(third) +
    dictionary.charAt(fourth)
  )
}

/**
 * Create sha256 or sha512 crypt of plaintext password
 * @param plaintext The plaintext password
 * @param salt optional salt, for example "$6$salt" or "$6$rounds=10000$salt"
 */
function encrypt(plaintext: string, salt?: string): string {
  const conf = parseSalt(salt)
  const hash = generateHash(plaintext, conf)
  return normalizeSalt(conf) + "$" + hash
}

/**
 * Verify plaintext password against expected hash
 * @param plaintext The plaintext password
 * @param hash The expected hash
 */
function verify(plaintext: string, hash: string): boolean {
  const salt = hash.slice(0, hash.lastIndexOf("$"))
  const computedHash = encrypt(plaintext, salt)

  return timingSafeEqual(
    Buffer.from(computedHash, "utf8"),
    Buffer.from(hash, "utf8"),
  )
}

export { encrypt, verify }
