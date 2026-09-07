-- crypto.lua
-- Minimal, dependency-free SHA-256 / HMAC-SHA256 / base64 in pure Lua (5.3+).
-- Used only by the test suite to stand in for `resty.openssl.hmac`, which is
-- only available inside an OpenResty runtime. Verified against RFC 4231 vectors
-- in spec/crypto_spec.lua.

-- Lua 5.3+ has native bitwise operators (&, |, ~, <<, >>); everything below
-- masks back to 32 bits with MASK after each arithmetic step.
local MASK = 0xFFFFFFFF

local function rrotate(x, n)
  return ((x >> n) | (x << (32 - n))) & MASK
end

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

-- Returns the raw 32-byte SHA-256 digest of `message`.
local function sha256(message)
  local H = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  }

  local bitlen = #message * 8
  message = message .. "\128"
  while (#message % 64) ~= 56 do
    message = message .. "\0"
  end
  for i = 7, 0, -1 do
    message = message .. string.char((bitlen >> (i * 8)) & 0xFF)
  end

  for chunk = 1, #message, 64 do
    local w = {}
    for i = 0, 15 do
      local b1, b2, b3, b4 = string.byte(message, chunk + i * 4, chunk + i * 4 + 3)
      w[i] = ((b1 << 24) | (b2 << 16) | (b3 << 8) | b4) & MASK
    end
    for i = 16, 63 do
      local s0 = rrotate(w[i - 15], 7) ~ rrotate(w[i - 15], 18) ~ (w[i - 15] >> 3)
      local s1 = rrotate(w[i - 2], 17) ~ rrotate(w[i - 2], 19) ~ (w[i - 2] >> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK
    end

    local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
    for i = 0, 63 do
      local S1 = rrotate(e, 6) ~ rrotate(e, 11) ~ rrotate(e, 25)
      local ch = (e & f) ~ ((~e & MASK) & g)
      local temp1 = (h + S1 + ch + K[i + 1] + w[i]) & MASK
      local S0 = rrotate(a, 2) ~ rrotate(a, 13) ~ rrotate(a, 22)
      local maj = (a & b) ~ (a & c) ~ (b & c)
      local temp2 = (S0 + maj) & MASK
      h = g
      g = f
      f = e
      e = (d + temp1) & MASK
      d = c
      c = b
      b = a
      a = (temp1 + temp2) & MASK
    end

    H[1] = (H[1] + a) & MASK
    H[2] = (H[2] + b) & MASK
    H[3] = (H[3] + c) & MASK
    H[4] = (H[4] + d) & MASK
    H[5] = (H[5] + e) & MASK
    H[6] = (H[6] + f) & MASK
    H[7] = (H[7] + g) & MASK
    H[8] = (H[8] + h) & MASK
  end

  local out = {}
  for i = 1, 8 do
    out[i] = string.char((H[i] >> 24) & 0xFF, (H[i] >> 16) & 0xFF, (H[i] >> 8) & 0xFF, H[i] & 0xFF)
  end
  return table.concat(out)
end

-- Returns the raw 32-byte HMAC-SHA256 of `msg` under `key`.
local function hmac_sha256(key, msg)
  local blocksize = 64
  if #key > blocksize then
    key = sha256(key)
  end
  key = key .. string.rep("\0", blocksize - #key)

  local o_key_pad = (key:gsub(".", function(ch) return string.char(string.byte(ch) ~ 0x5c) end))
  local i_key_pad = (key:gsub(".", function(ch) return string.char(string.byte(ch) ~ 0x36) end))

  return sha256(o_key_pad .. sha256(i_key_pad .. msg))
end

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function base64_encode(data)
  local out = {}
  for i = 1, #data, 3 do
    local b1, b2, b3 = string.byte(data, i, i + 2)
    local n = (b1 << 16) | ((b2 or 0) << 8) | (b3 or 0)
    local c1 = (n >> 18) & 0x3F
    local c2 = (n >> 12) & 0x3F
    local c3 = (n >> 6) & 0x3F
    local c4 = n & 0x3F
    out[#out + 1] = B64:sub(c1 + 1, c1 + 1)
    out[#out + 1] = B64:sub(c2 + 1, c2 + 1)
    out[#out + 1] = b2 and B64:sub(c3 + 1, c3 + 1) or "="
    out[#out + 1] = b3 and B64:sub(c4 + 1, c4 + 1) or "="
  end
  return table.concat(out)
end

local function to_hex(data)
  return (data:gsub(".", function(ch) return string.format("%02x", string.byte(ch)) end))
end

return {
  sha256 = sha256,
  hmac_sha256 = hmac_sha256,
  base64_encode = base64_encode,
  to_hex = to_hex,
}
