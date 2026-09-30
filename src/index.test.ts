import { strict as assert } from "node:assert"
import { describe, it } from "node:test"

import { encrypt, verify, verifyLegacy } from "./index.js"

/**
 * These tests are copied from the Public Domain reference implementation by Ulrich Drepper
 * https://www.akkadia.org/drepper/SHA-crypt.txt
 */
const tests2 = [
  [
    "$6$saltstring",
    "Hello world!",
    "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
  ],
  [
    "$6$rounds=10000$saltstringsaltstring",
    "Hello world!",
    "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
  ],
  [
    "$6$rounds=5000$toolongsaltstring",
    "This is just a test",
    "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
  ],
  [
    "$6$rounds=1400$anotherlongsaltstring",
    `a very much longer text to encrypt.  This one even stretches over morethan one line.`,
    "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
  ],
  [
    "$6$rounds=77777$short",
    "we have a short salt string but not a short password",
    "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0",
  ],
  [
    "$6$rounds=123456$asaltof16chars..",
    "a short string",
    "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1",
  ],
  [
    "$6$rounds=10$roundstoolow",
    "the minimum number is still observed",
    "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
  ],
]

describe("The standard and extended test suites", () => {
  it("Should pass standard test suite", () => {
    const data = tests2[0]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  // Tests collected from other sources
  it("Should pass extended test suite", () => {
    const data = [
      "$6$salt",
      "pass",
      "$6$salt$3aEJgflnzWuw1O3tr0IYSmhUY0cZ7iBQeBP392T7RXjLP3TKKu3ddIapQaCpbD4p9ioeGaVIjOHaym7HvCuUm0",
    ]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  it("Should pass extended test suite with rounds specified", () => {
    const data = [
      "$6$rounds=1000$salt",
      "pass",
      "$6$rounds=1000$salt$NqhXojlgP5NLvJojBnjQD87i66jhb8s3bZord3hSZoIgbCJqUfJdp7pclsLBBqgn02fAtd/vn4lieLeX5J.h90",
    ]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })
})

describe("salt handling", () => {
  it("Should properly truncate too long salt strings", () => {
    const data = tests2[1]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  it("Should properly truncate too long salt strings, and propagate rounds-string even if it's the default", () => {
    const data = tests2[2]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  it("Should handle long salt and long password", () => {
    const data = tests2[3]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  it("Should handle short salt with long password", () => {
    const data = tests2[4]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  it("Should handle short salt with shorter password", () => {
    const data = tests2[5]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  describe("proper handling of a salt value of empty string", () => {
    it("should properly handle a default number of rounds", () => {
      const plaintext = "Plaintext password"
      const salt = "$5$"
      const computed = encrypt(plaintext, salt)

      // generated via python3 passlib
      const expected = "$5$$N4LFaQGbHo.i9hNn66aHdu9x4vZPEBTPaQLsHflcuz6"

      assert.equal(verify(plaintext, expected), true)
      assert.equal(computed, expected)
    })

    it("should handle a custom number of rounds", () => {
      const plaintext = "Plaintext password"
      const salt = "$5$rounds=4000$"
      const computed = encrypt(plaintext, salt)

      // generated via python3 passlib
      const expected =
        "$5$rounds=4000$$CHEsdlQ9TAiLmI4PkGkez4Ny1dIgHa.4ZTzCYGhRzK0"

      assert.equal(verify(plaintext, expected), true)
      assert.equal(computed, expected)
    })
  })
})

describe("sha256 crypt handling", () => {
  it("Should handle sha256crypt as well", () => {
    const data = [
      "$5$rounds=5000$3a1afb28e54a0391",
      "super password",
      "$5$rounds=5000$3a1afb28e54a0391$0d6RupbpABtxCaH8WWOemYwEcToDVZXX/tHpIy6O1U3",
    ]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  it("Should handle sha256crypt with additional rounds", () => {
    const data = [
      "$5$rounds=10000$b2c0a3ef466b2ec7",
      "super password",
      "$5$rounds=10000$b2c0a3ef466b2ec7$2.jZTNfaxIRW5CbTLoXiga/oUEA3bE9E1jgdquXq5R.",
    ]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  it("Should handle sha256crypt with short salt", () => {
    const data = [
      "$5$salt",
      "super password",
      "$5$salt$hiNtIdUiCzVfs12fahM0sjQcF6XU0yE5G46VOsYmS4D",
    ]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  it("Should handle sha256crypt with long salt", () => {
    const data = [
      "$5$averylongsaltstring",
      "super password",
      "$5$averylongsaltstr$Tm/C6ErlCKkargHckqaFwBcFTdUdps1p.B3SFRCBue8",
    ]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })
})

describe("Miscellaneous", () => {
  it("Should not allow rounds fewer than 1000", () => {
    const data = tests2[6]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  it("Should handle multibyte characters", () => {
    const data = [
      "$6$a7a5dc2fa314dda0",
      "asdf£",
      "$6$a7a5dc2fa314dda0$E1GTcgT52oJFvhETaKwBk26Gy0GIzNQu2Mv4.UZwXp00CQi/8vC3IQKcrmpqbUaM2jFMOcDoShcxo1Mrt/Z5k/",
    ]
    const compute = encrypt(data[1], data[0])
    assert.equal(compute, data[2])
    assert.equal(verify(data[1], data[2]), true)
  })

  it("Should be possible to only specify the SHA-type", () => {
    const plaintext = "Plaintext password"
    const salt = "$6"
    // this should not throw an exception
    const compute = encrypt(plaintext, salt)
    assert.equal(verify(plaintext, compute), true)
  })

  it("Should be possible to only specify the SHA-type, and the number of rounds", () => {
    const plaintext = "Plaintext password"
    const salt = "$6$rounds=10000"
    // this should not throw an exception
    const compute = encrypt(plaintext, salt)
    assert.equal(verify(plaintext, compute), true)
  })

  it("Should be possible to not specify a salt at all", () => {
    const plaintext = "Plaintext password"
    // this should not throw an exception
    const compute = encrypt(plaintext)
    assert.equal(verify(plaintext, compute), true)
  })
})

// Expected values generated with `openssl passwd -5/-6 -salt saltstring`
describe("Passwords whose length is a multiple of the digest size", () => {
  const tests = [
    [
      "$5$saltstring",
      "a".repeat(32),
      "$5$saltstring$rjMPH2qyAsLvASQeJUKQQdHLfa3DC3Q9NLllO3sQ6m2",
    ],
    [
      "$5$saltstring",
      "This password is exactly sixty-four bytes long, a SHA-256 block!",
      "$5$saltstring$fnBIGxWGUNweicujOKoRLCffZNmNL0Sr9bmWxoo3R//",
    ],
    [
      "$6$saltstring",
      "This password is exactly sixty-four bytes long, a SHA-512 block!",
      "$6$saltstring$UFnGMvEv/ExHbhrh1p8r9tKg7tZbQTFcstyXePZrrnz.6CDlNZtV45fmqPSPR5q82aosPAs.OJmcJn.MVQ4kr0",
    ],
    [
      "$6$saltstring",
      "b".repeat(128),
      "$6$saltstring$Tw3xWHrnyiIt9arzqxpai6SFj9TEKpnyC71SDoJMitzwo3Yjq2ShkuBSBLMe75Wr4/ZtXQLBjpFjE3A9y7L2F.",
    ],
  ]

  tests.forEach(([salt, plaintext, expected]) => {
    it(`Should match openssl for ${salt} with a ${plaintext.length} byte password`, () => {
      assert.equal(encrypt(plaintext, salt), expected)
      assert.equal(verify(plaintext, expected), true)
    })
  })
})

// Hashes produced by unixcrypt 3.0.4 and earlier for the passwords above
describe("verifyLegacy", () => {
  const tests = [
    [
      "This password is exactly sixty-four bytes long, a SHA-256 block!",
      "$5$saltstring$AfAzTEis76QhBQHnyrsL.oxSUbg31IQ5MOsPbNlCUa7",
      "$5$saltstring$fnBIGxWGUNweicujOKoRLCffZNmNL0Sr9bmWxoo3R//",
    ],
    [
      "This password is exactly sixty-four bytes long, a SHA-512 block!",
      "$6$saltstring$nRQG2MWG1gXD0tl29EAJs0qZhVgZfeLhyei7IsIqCQOIpYUSXFeZeVNN4JvHeL74gcx6bPrwd1vkroUkbgdM7.",
      "$6$saltstring$UFnGMvEv/ExHbhrh1p8r9tKg7tZbQTFcstyXePZrrnz.6CDlNZtV45fmqPSPR5q82aosPAs.OJmcJn.MVQ4kr0",
    ],
  ]

  tests.forEach(([plaintext, legacyHash, correctHash]) => {
    it(`Should verify a legacy ${legacyHash.slice(0, 3)} hash only with verifyLegacy`, () => {
      assert.equal(verify(plaintext, legacyHash), false)
      assert.equal(verifyLegacy(plaintext, legacyHash), true)
      assert.equal(verifyLegacy(plaintext, correctHash), false)
      assert.equal(verifyLegacy("wrong password", legacyHash), false)
    })
  })

  it("Should behave like verify for unaffected password lengths", () => {
    const data = tests2[0]
    assert.equal(verifyLegacy(data[1], data[2]), true)
    assert.equal(verifyLegacy("wrong password", data[2]), false)
  })
})

// Expected values generated with the reference implementation in the spec
describe("Salt parsing according to the spec", () => {
  const tests = [
    [
      "any character except '$' is allowed",
      "$6$invalid-salt",
      "asdf£",
      "$6$invalid-salt$9hBRjPTWXr9ugdlEbHI/g1W25HTgpoNGjoG2iYJmsKmtZ5ZYU9h3GitcUMHIzXnmCuUKSQLjhPmtrNaqa0.zJ.",
    ],
    [
      "any character except '$' is allowed",
      "$5$a:b",
      "pass",
      "$5$a:b$jm848QFHYm5Y1UJDyiGAVJI.gHjjUB9acincJfi1y3A",
    ],
    [
      "multibyte characters are allowed",
      "$5$sält",
      "pass",
      "$5$sält$fb8sMdKzymXCfTtFJZK/zkHyOmo4Jan5Xawe88mh.P6",
    ],
    [
      "the salt is truncated to 16 bytes, not characters",
      "$5$ääääääääx",
      "pass",
      "$5$ääääääää$sgmKJcJp75ffVNqce.BE4gmT.NC9j71xHiH8qIpKWf6",
    ],
    [
      "a misspelled rounds prefix is part of the salt",
      "$6$round=5000$salt",
      "pass",
      "$6$round=5000$r.6WcwQwdVp8KqQ2hW5kGePLR1.RwfhD9QWPg6ryzzdIibncaQCj.mkhY0A08pr2D1P8rInxTQgG.oL/vsw3u.",
    ],
    [
      "a non-numeric rounds value is part of the salt",
      "$6$rounds=abc$ab",
      "pass",
      "$6$rounds=abc$XWyva6LXKvSIPUhdyadjgXKKcf67JElgNkNVzYqgpltgmUKJZE8njTOlQqp.zWE6PIEPz3QwAKmbcagB/UCd01",
    ],
    [
      "an empty rounds value means the minimum number of rounds",
      "$6$rounds=$ab",
      "pass",
      "$6$rounds=1000$ab$ogitAVNxwr5P8ir8qXXHl/YJ1NmEXGfNP5RYqkcGKFUvOE5juZBskuRBytzvtlUsfdIjWBSSN7eM2Vmm7Bxdn.",
    ],
    [
      "a complete hash may be used as salt",
      "$6$rounds=5000$salt$hash",
      "pass",
      "$6$rounds=5000$salt$3aEJgflnzWuw1O3tr0IYSmhUY0cZ7iBQeBP392T7RXjLP3TKKu3ddIapQaCpbD4p9ioeGaVIjOHaym7HvCuUm0",
    ],
  ]

  tests.forEach(([label, salt, plaintext, expected]) => {
    it(`Should handle ${salt}: ${label}`, () => {
      assert.equal(encrypt(plaintext, salt), expected)
      assert.equal(verify(plaintext, expected), true)
    })
  })

  it("Should reproduce a complete hash when it is used as salt", () => {
    for (const salt of ["$6$salt", "$5$rounds=1000$salt"]) {
      const hash = encrypt("pass", salt)
      assert.equal(encrypt("pass", hash), hash)
    }
  })

  it("Should use all 64 characters when generating a random salt", () => {
    const seen = new Set<string>()
    for (let i = 0; i < 500; i++) {
      for (const c of encrypt("pass", "$5$rounds=1000").split("$")[3]) {
        seen.add(c)
      }
    }
    assert.equal(seen.size, 64)
  })
})

describe("verify", () => {
  it("Should return false instead of throwing for a hash of the wrong length", () => {
    assert.equal(verify("pass", ""), false)
    assert.equal(verify("pass", "$6$saltstring$abc"), false)
    assert.equal(verifyLegacy("pass", "$6$saltstring$abc"), false)
  })
})

describe("Invalid inputs", () => {
  it("Should throw an exception when used with any other crypto than sha256 or sha512", () => {
    const data = ["$1$4WZnIm8V", "pass", "$1$4WZnIm8V$Sg8KVWIq4rKfNz3Z23jZK0"]
    assert.throws(
      () => encrypt(data[1], data[0]),
      Error,
      "Only sha256 and sha512 is supported by this library",
    )
    assert.throws(
      () => verify(data[1], data[2]),
      Error,
      "Only sha256 and sha512 is supported by this library",
    )
  })

  it("Should throw an exception when the hash type is malformed", () => {
    for (const salt of [
      "$05$salt",
      "$6.0$salt",
      "$0x6$salt",
      "$6x$salt",
      "6$salt",
    ]) {
      assert.throws(() => encrypt("pass", salt), /Only sha256 and sha512/)
    }
  })

  it("Should throw an exception when truncating the salt would split a multibyte character", () => {
    // 15 bytes of "ä" and "x", followed by a 2-byte "ä"
    assert.throws(
      () => encrypt("pass", "$5$äääääääxä"),
      /split a multibyte character/,
    )
  })

  // Not testable: 999,999,999 rounds no longer runs out of memory, but still takes close to an hour
  // it("Should be reduce the number of rounds if larger than 999,999,999", () => {
  //   const plaintext = "Plaintext password"
  //   const salt = "$6$rounds=1000000000$salt"
  //   const hash = ""
  //   const compute = encrypt(plaintext, salt)
  //   assert.equal(compute, hash)
  //   assert.equal(verify(plaintext, hash), true)
  // })
})
