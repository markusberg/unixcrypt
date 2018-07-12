import { expect } from "chai";
import { sha512crypt } from "../";

/**
 * These tests are copied from the Public Domain reference implementation by Ulrich Drepper
 * https://www.akkadia.org/drepper/SHA-crypt.txt
 */
const tests2 = [
  [ "$6$saltstring",
    "Hello world!",
    "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1" ],
  [ "$6$rounds=10000$saltstringsaltstring",
    "Hello world!",
    "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v." ],
  [ "$6$rounds=5000$toolongsaltstring",
    "This is just a test",
    "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0" ],
  [ "$6$rounds=1400$anotherlongsaltstring",
    `a very much longer text to encrypt.  This one even stretches over more
than one line.`,
    "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1" ],
  [ "$6$rounds=77777$short",
    "we have a short salt string but not a short password",
    "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0" ],
  [ "$6$rounds=123456$asaltof16chars..",
    "a short string",
    "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1" ],
  [ "$6$rounds=10$roundstoolow",
    "the minimum number is still observed",
    "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX." ],
];


describe("Encryption", () => {
  it("Should pass standard test suite", () => {
    tests2.forEach(testdata => {
      const hash = sha512crypt.crypt(testdata[1], testdata[0]);
      expect(hash).to.equal(hash);
    })
  })
});
