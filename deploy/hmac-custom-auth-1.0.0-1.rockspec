-- Optional: package the plugin as a LuaRocks rock instead of COPYing files.
-- Build in the Dockerfile with:  RUN luarocks make deploy/hmac-custom-auth-1.0.0-1.rockspec
package = "hmac-custom-auth"
version = "1.0.0-1"

source = {
  -- For `luarocks make` (local build) the url is not fetched; set it properly
  -- if you ever publish to a rocks server.
  url = "git+https://example.com/your-org/kong-plugin-hmac-auth.git",
  tag = "1.0.0",
}

description = {
  summary = "HMAC-SHA256 request signature authentication for Kong",
  detailed = "Verifies X-Client-Id / X-Timestamp / X-Signature headers in the access phase.",
  license = "MIT",
}

dependencies = {
  "lua >= 5.1",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.hmac-custom-auth.handler"] = "kong/plugins/hmac-custom-auth/handler.lua",
    ["kong.plugins.hmac-custom-auth.schema"]  = "kong/plugins/hmac-custom-auth/schema.lua",
  },
}
