-- handler_spec.lua
-- Exercises the `access` phase of kong/plugins/hmac-custom-auth/handler.lua.

local SECRET = "super-secret-value-rotate-me"

-- Build a fully-signed, currently-valid request for the default client.
local function signed_request(opts)
  opts = opts or {}
  local method = opts.method or "GET"
  local path = opts.path or "/partner/orders"
  local ts = tostring(opts.timestamp or ngx.time())
  local secret = opts.secret or SECRET
  local sig = opts.signature or helpers.sign(secret, method, path, ts)
  return {
    method = method,
    path = path,
    headers = {
      ["X-Client-Id"] = opts.client_id or "partner-a",
      ["X-Timestamp"] = ts,
      ["X-Signature"] = sig,
    },
  }
end

describe("hmac-custom-auth access()", function()
  before_each(function()
    ngx.__now = 1735689600
  end)

  describe("happy path", function()
    it("accepts a correctly signed request and does not exit", function()
      local res = helpers.run_access(helpers.default_conf(), signed_request())
      assert.is_false(res.exited)
    end)

    it("injects X-Authenticated-Client-Id for the upstream", function()
      local res = helpers.run_access(helpers.default_conf(), signed_request())
      assert.equal("partner-a", res.service_headers["X-Authenticated-Client-Id"])
    end)

    it("records the client id in kong.ctx.shared", function()
      local res = helpers.run_access(helpers.default_conf(), signed_request())
      assert.equal("partner-a", res.ctx_shared.authenticated_client_id)
    end)

    it("accepts a timestamp within the clock skew window", function()
      local res = helpers.run_access(helpers.default_conf(),
        signed_request({ timestamp = ngx.time() - 299 }))
      assert.is_false(res.exited)
    end)
  end)

  describe("missing headers -> 401", function()
    for _, h in ipairs({ "X-Client-Id", "X-Timestamp", "X-Signature" }) do
      it("rejects when " .. h .. " is absent", function()
        local req = signed_request()
        req.headers[h] = nil
        local res = helpers.run_access(helpers.default_conf(), req)
        assert.is_true(res.exited)
        assert.equal(401, res.status)
        assert.equal("Missing authentication headers", res.body.message)
      end)
    end
  end)

  describe("credentials", function()
    it("rejects an unknown client id", function()
      local res = helpers.run_access(helpers.default_conf(),
        signed_request({ client_id = "partner-x" }))
      assert.is_true(res.exited)
      assert.equal(401, res.status)
      assert.equal("Invalid client credentials", res.body.message)
    end)

    it("logs a warning naming the unknown client id", function()
      local res = helpers.run_access(helpers.default_conf(),
        signed_request({ client_id = "partner-x" }))
      assert.matches("partner%-x", table.concat(res.logs.warn, "|"))
    end)
  end)

  describe("timestamp / replay protection", function()
    it("rejects a non-numeric timestamp", function()
      local req = signed_request()
      req.headers["X-Timestamp"] = "not-a-number"
      local res = helpers.run_access(helpers.default_conf(), req)
      assert.is_true(res.exited)
      assert.equal(401, res.status)
      assert.equal("Invalid timestamp", res.body.message)
    end)

    it("rejects a stale timestamp (older than skew)", function()
      local res = helpers.run_access(helpers.default_conf(),
        signed_request({ timestamp = ngx.time() - 301 }))
      assert.is_true(res.exited)
      assert.equal(401, res.status)
      assert.equal("Request expired", res.body.message)
    end)

    it("rejects a timestamp too far in the future (abs skew)", function()
      local res = helpers.run_access(helpers.default_conf(),
        signed_request({ timestamp = ngx.time() + 301 }))
      assert.is_true(res.exited)
      assert.equal(401, res.status)
      assert.equal("Request expired", res.body.message)
    end)

    it("honours a custom clock_skew_seconds", function()
      local res = helpers.run_access(helpers.default_conf({ clock_skew_seconds = 3600 }),
        signed_request({ timestamp = ngx.time() - 1800 }))
      assert.is_false(res.exited)
    end)
  end)

  describe("signature verification", function()
    it("rejects a garbage signature", function()
      local res = helpers.run_access(helpers.default_conf(),
        signed_request({ signature = "not-the-real-signature" }))
      assert.is_true(res.exited)
      assert.equal(401, res.status)
      assert.equal("Signature verification failed", res.body.message)
    end)

    it("rejects a signature made with the wrong secret", function()
      local res = helpers.run_access(helpers.default_conf(),
        signed_request({ secret = "wrong-secret" }))
      assert.is_true(res.exited)
      assert.equal("Signature verification failed", res.body.message)
    end)

    it("is bound to the HTTP method", function()
      -- sign as GET, send as POST
      local req = signed_request({ method = "GET" })
      req.method = "POST"
      local res = helpers.run_access(helpers.default_conf(), req)
      assert.is_true(res.exited)
      assert.equal("Signature verification failed", res.body.message)
    end)

    it("is bound to the request path", function()
      local req = signed_request({ path = "/partner/orders" })
      req.path = "/partner/admin"
      local res = helpers.run_access(helpers.default_conf(), req)
      assert.is_true(res.exited)
      assert.equal("Signature verification failed", res.body.message)
    end)

    it("is bound to the timestamp value", function()
      local ts = tostring(ngx.time())
      local req = signed_request({ timestamp = ts })
      -- keep signature, bump timestamp to another still-in-window value
      req.headers["X-Timestamp"] = tostring(ngx.time() - 10)
      local res = helpers.run_access(helpers.default_conf(), req)
      assert.is_true(res.exited)
      assert.equal("Signature verification failed", res.body.message)
    end)
  end)

  describe("configurable header names", function()
    it("reads signature/timestamp/client-id from custom headers", function()
      local conf = helpers.default_conf({
        signature_header = "Sig",
        timestamp_header = "Ts",
        client_id_header = "Cid",
      })
      local ts = tostring(ngx.time())
      local req = {
        method = "GET",
        path = "/partner/orders",
        headers = {
          ["Cid"] = "partner-a",
          ["Ts"] = ts,
          ["Sig"] = helpers.sign(SECRET, "GET", "/partner/orders", ts),
        },
      }
      local res = helpers.run_access(conf, req)
      assert.is_false(res.exited)
      assert.equal("partner-a", res.service_headers["X-Authenticated-Client-Id"])
    end)
  end)

  describe("interop with the README's Python signer", function()
    local ok = os.execute("command -v python3 >/dev/null 2>&1")
    local python = ok == true or ok == 0

    it("accepts a signature generated by Python's hmac module", function()
      if not python then
        pending("python3 not available")
        return
      end
      local ts = tostring(ngx.time())
      local method, path = "GET", "/partner/orders"
      -- Join with "\n" inside Python so no literal newline crosses the shell.
      local script = string.format(
        [[python3 -c '
import hmac, hashlib, base64
secret, method, path, ts = %q, %q, %q, %q
sts = "\n".join([method, path, ts])
print(base64.b64encode(hmac.new(secret.encode(), sts.encode(), hashlib.sha256).digest()).decode())
']],
        SECRET, method, path, ts)
      local pipe = assert(io.popen(script))
      local py_sig = pipe:read("*l")
      pipe:close()

      assert.is_string(py_sig)
      assert.equal(helpers.sign(SECRET, method, path, ts), py_sig)

      local res = helpers.run_access(helpers.default_conf(), {
        method = method,
        path = path,
        headers = {
          ["X-Client-Id"] = "partner-a",
          ["X-Timestamp"] = ts,
          ["X-Signature"] = py_sig,
        },
      })
      assert.is_false(res.exited)
    end)
  end)
end)
