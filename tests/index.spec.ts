import { expect } from "chai";
import { sha512crypt, verifyPassword } from "../";

describe("Encryption", () => {
  it("Should use correct default values", () => {
    let crypto = sha512crypt("pass");
    expect(crypto).to.equal("apa");
  })
});
