-- crypto_spec.lua
-- Confirms the pure-Lua crypto used by the test harness is actually correct,
-- so a handler test failure can never be blamed on the stand-in.

local crypto = require "spec.crypto"

describe("crypto stand-in", function()
  it("computes SHA-256 (NIST vectors)", function()
    assert.equal(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      crypto.to_hex(crypto.sha256(""))
    )
    assert.equal(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      crypto.to_hex(crypto.sha256("abc"))
    )
    assert.equal(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      crypto.to_hex(crypto.sha256(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
    )
  end)

  it("computes HMAC-SHA256 (RFC 4231 case 2)", function()
    assert.equal(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      crypto.to_hex(crypto.hmac_sha256("Jefe", "what do ya want for nothing?"))
    )
  end)

  it("base64-encodes", function()
    assert.equal("", crypto.base64_encode(""))
    assert.equal("Zg==", crypto.base64_encode("f"))
    assert.equal("Zm8=", crypto.base64_encode("fo"))
    assert.equal("Zm9v", crypto.base64_encode("foo"))
    assert.equal("Zm9vYmFy", crypto.base64_encode("foobar"))
  end)
end)
