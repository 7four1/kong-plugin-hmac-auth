-- spec_helper.lua
-- Loaded by busted before any spec. Installs stand-ins for the OpenResty /
-- Kong runtime so handler.lua can be exercised as a plain Lua module, and
-- exposes helpers for driving its `access` phase.

package.path = "./?.lua;./?/init.lua;" .. package.path

local crypto = require "spec.crypto"

-- ---------------------------------------------------------------------------
-- Fake `resty.openssl.hmac` (real one needs the OpenResty FFI runtime).
-- ---------------------------------------------------------------------------
package.loaded["resty.openssl.hmac"] = {
  new = function(secret, algo)
    if algo ~= "sha256" then
      return nil, "unsupported algo: " .. tostring(algo)
    end
    local buf = {}
    return {
      update = function(_, s)
        buf[#buf + 1] = s
        return true
      end,
      final = function()
        return crypto.hmac_sha256(secret, table.concat(buf))
      end,
    }
  end,
}

-- ---------------------------------------------------------------------------
-- Fake `ngx`
-- ---------------------------------------------------------------------------
_G.ngx = _G.ngx or {}
ngx.__now = 1735689600 -- overridden per-test
ngx.time = function() return ngx.__now end
ngx.encode_base64 = crypto.base64_encode

-- ---------------------------------------------------------------------------
-- Fake `kong` — rebuilt fresh for every request via helpers.build_kong().
-- ---------------------------------------------------------------------------
local M = {}

-- Sign a string_to_sign the same way a well-behaved client would.
function M.sign(secret, method, path, timestamp)
  local string_to_sign = method .. "\n" .. path .. "\n" .. timestamp
  return crypto.base64_encode(crypto.hmac_sha256(secret, string_to_sign))
end

-- Build a `kong` table bound to a single simulated request.
-- req = { method=, path=, headers={} }
local function build_kong(req)
  local service_headers = {}
  local ctx_shared = {}
  local logs = { warn = {}, err = {}, info = {}, debug = {} }

  local function log_sink(level)
    return function(...)
      local parts = {}
      for i = 1, select("#", ...) do
        parts[i] = tostring((select(i, ...)))
      end
      logs[level][#logs[level] + 1] = table.concat(parts)
    end
  end

  local kong = {
    request = {
      get_header = function(name) return req.headers[name] end,
      get_method = function() return req.method end,
      get_path = function() return req.path end,
    },
    response = {
      -- Real Kong's exit() aborts the phase; emulate with a tagged error.
      exit = function(status, body)
        error({ __exit = true, status = status, body = body }, 0)
      end,
    },
    service = {
      request = {
        set_header = function(name, value) service_headers[name] = value end,
      },
    },
    log = {
      warn = log_sink("warn"),
      err = log_sink("err"),
      info = log_sink("info"),
      debug = log_sink("debug"),
    },
    ctx = { shared = ctx_shared },
  }

  return kong, { service_headers = service_headers, ctx_shared = ctx_shared, logs = logs }
end

-- Run the handler's access() phase against a simulated request.
-- Returns a result table:
--   { exited = true, status = , body = }                       -- kong.response.exit called
--   { exited = false, service_headers = , ctx_shared = , logs= } -- fell through (authenticated)
function M.run_access(conf, req)
  req = req or {}
  req.method = req.method or "GET"
  req.path = req.path or "/partner/orders"
  req.headers = req.headers or {}

  local kong, captured = build_kong(req)
  _G.kong = kong

  -- Fresh copy of the handler each run (cheap, keeps state clean).
  package.loaded["kong.plugins.hmac-custom-auth.handler"] = nil
  local handler = require "kong.plugins.hmac-custom-auth.handler"

  local ok, err = pcall(handler.access, handler, conf)
  if ok then
    return {
      exited = false,
      service_headers = captured.service_headers,
      ctx_shared = captured.ctx_shared,
      logs = captured.logs,
    }
  end

  if type(err) == "table" and err.__exit then
    err.exited = true
    err.logs = captured.logs
    return err
  end

  error(err) -- a real, unexpected Lua error — let the test fail loudly
end

-- Default config matching schema.lua defaults + one known client.
function M.default_conf(overrides)
  local conf = {
    signature_header = "X-Signature",
    timestamp_header = "X-Timestamp",
    client_id_header = "X-Client-Id",
    clock_skew_seconds = 300,
    secrets = { ["partner-a"] = "super-secret-value-rotate-me" },
  }
  for k, v in pairs(overrides or {}) do
    conf[k] = v
  end
  return conf
end

_G.helpers = M
return M
