# Custom Kong image with the hmac-custom-auth plugin baked in.
# Used for BOTH the control-plane and data-plane deployments in hybrid mode.
#
#   docker build -f deploy/Dockerfile -t <acr>.azurecr.io/kong-hmac:3.9-hmac-1.0.0 .
#   docker push        <acr>.azurecr.io/kong-hmac:3.9-hmac-1.0.0
#
# Match KONG_VERSION to the version your cluster already runs.
ARG KONG_VERSION=3.9
FROM kong:${KONG_VERSION}

USER root

# Kong 3.x already bundles lua-resty-openssl, so handler.lua's
# `require "resty.openssl.hmac"` resolves with no extra rock to install.
# Drop the plugin where Kong's default LUA_PACKAGE_PATH already looks,
# so no KONG_LUA_PACKAGE_PATH override is needed.
COPY kong/plugins/hmac-custom-auth \
     /usr/local/share/lua/5.1/kong/plugins/hmac-custom-auth

# Fail the build early if the files aren't where Kong expects them, and
# syntax-check them with the bundled LuaJIT when it's on PATH.
RUN set -eux; \
    P=/usr/local/share/lua/5.1/kong/plugins/hmac-custom-auth; \
    test -f "$P/handler.lua"; \
    test -f "$P/schema.lua"; \
    if command -v luajit >/dev/null 2>&1; then \
      luajit -bl "$P/handler.lua" /dev/null; \
      luajit -bl "$P/schema.lua" /dev/null; \
    fi; \
    kong version

USER kong
