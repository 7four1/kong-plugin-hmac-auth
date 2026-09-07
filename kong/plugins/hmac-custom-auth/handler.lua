-- handler.lua
-- Verifies an HMAC-SHA256 signature on inbound requests.
-- Expected client behavior:
--   string_to_sign = method .. "\n" .. path .. "\n" .. timestamp
--   signature      = base64( HMAC_SHA256(secret, string_to_sign) )
--   headers sent   : X-Client-Id, X-Timestamp, X-Signature

local openssl_hmac = require "resty.openssl.hmac"

local kong = kong
local ngx_time = ngx.time

local HmacCustomAuthHandler = {
  -- PRIORITY: must run BEFORE rate-limiting (900) and ACL (950) so that an
  -- unauthenticated request never consumes a rate-limit slot or gets an
  -- ACL decision. Runs AFTER built-in key-auth-style plugins in a typical
  -- stack if both are present, but here it stands alone as the identity plugin.
  PRIORITY = 1000,

  -- VERSION is required by Kong's plugin loader for compatibility checks.
  VERSION = "1.0.0",
}

-- Small helper: constant-time-ish compare isn't strictly implemented here
-- via string.equal (Lua doesn't provide one natively); in production, use
-- a proper constant-time comparison to avoid timing attacks. Noted below.
local function compute_signature(secret, string_to_sign)
  local hmac, err = openssl_hmac.new(secret, "sha256")
  if not hmac then
    return nil, err
  end
  local ok, err2 = hmac:update(string_to_sign)
  if not ok then
    return nil, err2
  end
  local digest, err3 = hmac:final()
  if not digest then
    return nil, err3
  end
  return ngx.encode_base64(digest)
end

function HmacCustomAuthHandler:access(conf)
  local client_id = kong.request.get_header(conf.client_id_header)
  local timestamp  = kong.request.get_header(conf.timestamp_header)
  local signature  = kong.request.get_header(conf.signature_header)

  -- 1. Presence checks
  if not client_id or not timestamp or not signature then
    return kong.response.exit(401, { message = "Missing authentication headers" })
  end

  -- 2. Look up the shared secret for this client
  local secret = conf.secrets[client_id]
  if not secret then
    kong.log.warn("hmac-custom-auth: unknown client_id '", client_id, "'")
    return kong.response.exit(401, { message = "Invalid client credentials" })
  end

  -- 3. Replay protection: reject stale timestamps
  local ts_num = tonumber(timestamp)
  if not ts_num then
    return kong.response.exit(401, { message = "Invalid timestamp" })
  end
  local skew = math.abs(ngx_time() - ts_num)
  if skew > conf.clock_skew_seconds then
    kong.log.warn("hmac-custom-auth: timestamp outside allowed skew (", skew, "s)")
    return kong.response.exit(401, { message = "Request expired" })
  end

  -- 4. Recompute the expected signature and compare
  local method = kong.request.get_method()
  local path   = kong.request.get_path()
  local string_to_sign = method .. "\n" .. path .. "\n" .. timestamp

  local expected_signature, err = compute_signature(secret, string_to_sign)
  if not expected_signature then
    kong.log.err("hmac-custom-auth: failed computing signature: ", err)
    return kong.response.exit(500, { message = "Internal error validating signature" })
  end

  if expected_signature ~= signature then
    return kong.response.exit(401, { message = "Signature verification failed" })
  end

  -- 5. Success: annotate the request so downstream plugins/upstream know who this is.
  --    This is the equivalent of "authenticating" the consumer without a
  --    Kong Consumer entity attached, useful for machine-to-machine clients.
  kong.service.request.set_header("X-Authenticated-Client-Id", client_id)
  kong.ctx.shared.authenticated_client_id = client_id
end

return HmacCustomAuthHandler
