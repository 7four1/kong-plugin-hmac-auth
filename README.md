# hmac-custom-auth — Custom Kong Plugin

A custom authentication plugin that verifies HMAC-SHA256 request signatures.
Built as a portfolio piece for demonstrating custom Kong plugin development
in a senior/architect interview.

## Why this plugin (interview framing)

Kong's OSS distribution no longer ships a built-in `hmac-auth` plugin in
recent versions, but HMAC request signing is still a common requirement for
server-to-server / machine-to-machine integrations (webhooks, partner APIs)
where you want origin authenticity + tamper detection without full OAuth2
overhead. This is a realistic, defensible reason to write a custom plugin
rather than compose existing ones.

## Structure

```
kong-plugin-hmac-auth/
├── kong/
│   └── plugins/
│       └── hmac-custom-auth/
│           ├── handler.lua   # runtime logic (the `access` phase)
│           └── schema.lua    # config schema + validation
├── spec/                     # busted unit tests (see "Testing" below)
│   ├── crypto.lua            #   pure-Lua HMAC-SHA256/base64 stand-in
│   ├── spec_helper.lua       #   kong / ngx mocks + access() driver
│   ├── crypto_spec.lua       #   verifies the stand-in vs NIST/RFC vectors
│   └── handler_spec.lua      #   the plugin behaviour tests
├── .luacheckrc               # lint config (Kong globals; busted std for spec/)
├── .github/workflows/        # CI/CD — see "CI/CD" below
│   ├── ci.yml                #   lint + unit tests + image build, every push/PR
│   └── release.yml           #   build & push the image on a version tag
└── deploy/                            # ship it to a real cluster (see "Deploying" below)
    ├── Dockerfile                     #   custom Kong image with the plugin baked in
    ├── hmac-custom-auth-1.0.0-1.rockspec  #   optional LuaRocks packaging
    ├── values-controlplane.yaml       #   Helm overlay for the CP release
    ├── values-dataplane.yaml          #   Helm overlay for the DP release
    ├── kong.yaml                      #   decK state file example
    └── README.md                      #   full step-by-step for hybrid mode on AKS
```

The `kong/plugins/...` layout mirrors Kong's expected plugin directory
convention: `kong/plugins/<plugin-name>/{handler,schema}.lua`

## How it works

Client signs each request:
```
string_to_sign = METHOD + "\n" + PATH + "\n" + TIMESTAMP
signature       = base64( HMAC_SHA256(shared_secret, string_to_sign) )
```

And sends:
```
X-Client-Id: partner-a
X-Timestamp: 1735689600
X-Signature: <base64 hmac>
```

The plugin, in the `access` phase:
1. Confirms all three headers are present.
2. Looks up the shared secret for `X-Client-Id`.
3. Rejects requests with a timestamp outside `clock_skew_seconds` (replay protection).
4. Recomputes the expected signature server-side and compares it to the one supplied.
5. On success, injects `X-Authenticated-Client-Id` so downstream plugins/upstream
   services can trust the identity without re-verifying.

## Installing it into a Kong node

The plugin must be discoverable on Lua's package path as
`kong.plugins.hmac-custom-auth.*`, and the plugin name must be added to Kong's
`plugins` directive (keep `bundled` or you lose every built-in plugin).

**Option A — via `LUA_PACKAGE_PATH` (dev/test)**
```bash
export KONG_LUA_PACKAGE_PATH="/path/to/kong-plugin-hmac-auth/?.lua;;"
export KONG_PLUGINS="bundled,hmac-custom-auth"
```

**Option B — via LuaRocks (packaged for reuse across environments)**
```bash
luarocks make deploy/hmac-custom-auth-1.0.0-1.rockspec
# then: plugins = bundled,hmac-custom-auth
```

**Option C — custom container image** (how you'd actually ship it — the
Dockerfile in [`deploy/`](deploy/) copies the plugin into
`/usr/local/share/lua/5.1/kong/plugins/` so no path override is needed):
```bash
docker build -f deploy/Dockerfile --build-arg KONG_VERSION=3.9 \
  -t <acr>.azurecr.io/kong-hmac:3.9-hmac-1.0.0 .
```

**Option D — Declarative (DB-less) config**, `kong.yml`:
```yaml
_format_version: "3.0"
services:
  - name: partner-api
    url: http://upstream-service:8080
    routes:
      - name: partner-route
        paths: ["/partner"]
    plugins:
      - name: hmac-custom-auth
        config:
          clock_skew_seconds: 300
          secrets:
            partner-a: "super-secret-value-rotate-me"
```

## Testing

### Unit tests (no Kong required)

The [`spec/`](spec/) suite exercises `handler.lua`'s `access` phase as a plain
Lua module: it mocks the `kong` and `ngx` globals and swaps
`resty.openssl.hmac` (OpenResty-only) for a pure-Lua HMAC-SHA256 that is itself
verified against NIST / RFC 4231 vectors.

```bash
brew install lua luarocks          # one-time
luarocks install busted            # one-time

cd kong-plugin-hmac-auth
busted                             # reads .busted, runs everything in spec/
```

Useful variants:
```bash
busted --verbose                   # print every test name
busted spec/handler_spec.lua       # one file
busted --filter "replay"           # tests whose description matches
busted --list                      # list without running
```

Expected: `23 successes / 0 failures / 0 errors / 0 pending`.

What's covered: happy path (signature accepted, `X-Authenticated-Client-Id`
injected, `kong.ctx.shared` set), each missing header → 401, unknown client id,
non-numeric / stale / future timestamps, wrong secret, tampered
method/path/timestamp, custom header names, and interop with the Python signer
below.

### Manual test against a running Kong

```bash
kong start -c kong.conf
```

Generate a signed request (example in Python):
```python
import hmac, hashlib, base64, time, requests

secret = "super-secret-value-rotate-me"
method, path = "GET", "/partner/orders"
ts = str(int(time.time()))
string_to_sign = f"{method}\n{path}\n{ts}"
sig = base64.b64encode(hmac.new(secret.encode(), string_to_sign.encode(), hashlib.sha256).digest()).decode()

requests.get(
    "http://localhost:8000/partner/orders",
    headers={"X-Client-Id": "partner-a", "X-Timestamp": ts, "X-Signature": sig},
)
```

Same thing with `curl` + `openssl`:
```bash
TS=$(date +%s)
SIG=$(printf 'GET\n/partner/orders\n%s' "$TS" \
      | openssl dgst -sha256 -hmac "super-secret-value-rotate-me" -binary | base64)
curl -i localhost:8000/partner/orders \
  -H "X-Client-Id: partner-a" -H "X-Timestamp: $TS" -H "X-Signature: $SIG"
```

## Deploying to a hybrid-mode Kong on AKS

Full walkthrough with ready-to-edit files: [`deploy/README.md`](deploy/README.md).

**The rule for hybrid mode:** a custom plugin must be present on **both** the
control plane and the data plane — the CP loads `schema.lua` to validate config
and render what it pushes to data planes; the DP runs `handler.lua` on live
traffic. If the two roles' `plugins` lists disagree, the DP rejects the config
push. So use **one custom image for both roles**.

1. **Build & push one image** ([`deploy/Dockerfile`](deploy/Dockerfile)) to your
   registry (e.g. ACR).
2. **Roll out the control plane first**
   ([`deploy/values-controlplane.yaml`](deploy/values-controlplane.yaml)) with
   that image + `plugins: bundled,hmac-custom-auth`. Verify:
   ```bash
   curl -s localhost:8001/schemas/plugins/hmac-custom-auth      # 200 + schema
   curl -s localhost:8001/ | jq '.plugins.available_on_server["hmac-custom-auth"]'
   ```
   CP first matters: pushing config for a plugin the CP can't load fails the sync.
3. **Roll out the data plane**
   ([`deploy/values-dataplane.yaml`](deploy/values-dataplane.yaml)) with the
   *same* image and same `plugins` value.
4. **Apply config with decK** against the CP admin API — custom-plugin config
   can only be fully validated online:
   ```bash
   deck gateway validate deploy/kong.yaml --kong-addr https://<cp-admin>:8001
   deck gateway diff     deploy/kong.yaml --kong-addr https://<cp-admin>:8001
   deck gateway sync     deploy/kong.yaml --kong-addr https://<cp-admin>:8001
   ```
5. **Smoke test** through the data-plane LB with the signed `curl` above.

**Upgrading later:** bump the plugin version → new image tag → `helm upgrade` the
CP, then the DP, then `deck gateway sync`. Don't let CP and DP run different
plugin code across a schema change.

**Secrets:** `config.secrets` values sit in `deploy/kong.yaml` and CP storage in
plaintext. Configure a Kong Vault backend (env, Azure Key Vault, …) on **both**
CP and DP and switch to `"{vault://...}"` references.

## CI/CD (GitHub Actions)

Two workflows in [`.github/workflows/`](.github/workflows/):

### `ci.yml` — every push / pull request

| Job | What it does |
|-----|--------------|
| `lint` | `luacheck kong spec` against [`.luacheckrc`](.luacheckrc) |
| `unit-tests` | `busted` on a Lua **5.3** and **5.4** matrix |
| `image-build` | Builds [`deploy/Dockerfile`](deploy/Dockerfile) (no push) so a broken Dockerfile fails the PR |
| `integration-pongo` | Wired but `if: false` — flip it on once Pongo-style (`spec.helpers`) specs exist |

### `release.yml` — on a `vX.Y.Z` tag

```bash
git tag v1.0.0 && git push origin v1.0.0
```

Re-runs lint + tests, then builds a multi-arch (`amd64` + `arm64`) image and
pushes it to **GHCR** (`ghcr.io/<owner>/<repo>`) with tags `1.0.0`, `1.0`,
`kong3.9-<sha>`. Also pushes to **ACR** when these repo secrets are set:

| Secret | Example |
|--------|---------|
| `ACR_LOGIN_SERVER` | `myregistry.azurecr.io` |
| `ACR_USERNAME` / `ACR_PASSWORD` | an ACR token or service principal |

The job summary prints the published tags — plug one into
`deploy/values-*.yaml` and roll out CP → DP → `deck gateway sync`.

To gate `deck gateway sync` behind this pipeline too, add a `deploy` job that
runs after `image`, connects to the cluster (e.g. `azure/aks-set-context`),
port-forwards the CP admin API, and runs `deck gateway diff` / `sync` against
[`deploy/kong.yaml`](deploy/kong.yaml) — kept out of the default workflow since
it needs cluster credentials.

## Known production hardening gaps (good to mention proactively in interview)

Naming these unprompted signals seniority — it shows you know the difference
between "makes a demo work" and "ready for production":

1. **Timing attack on signature comparison** — `expected_signature ~= signature`
   is a standard Lua string compare, not constant-time. Swap for a
   constant-time byte comparison (e.g. via `ngx.hmac_sha1`-style helpers or a
   manual XOR-accumulate loop) to avoid leaking signature bytes through
   response-time side channels.
2. **Secrets in plugin config** — storing `secrets` as plain config works for
   a demo but leaks secrets into declarative config files / git. In
   production, back this with Kong's **Vault integration**
   (`{vault://...}` references) or move secret storage to a Consumer
   custom-credential table looked up via `kong.db`.
3. **No nonce store** — timestamp-window replay protection alone allows
   replay within the skew window. A production version would add a
   short-TTL nonce cache (shared dict or Redis) to reject exact-duplicate
   requests even within the allowed clock skew.
4. **Priority tuning** — `PRIORITY = 1000` was chosen to run before
   rate-limiting (900) and ACL (950), but if this coexists with Kong's other
   auth plugins, priorities need explicit reconciliation to avoid two auth
   plugins both trying to set the "authenticated consumer" context.

## Talking points if asked to extend this

- "How would you make this consumer-aware instead of static config?" →
  Use `kong.db.credentials` pattern like built-in auth plugins: create a
  custom credential entity tied to a `Consumer`, so `kong.client.authenticate()`
  can be called to formally attach the request to a Consumer (unlocking
  ACL, consumer-scoped rate-limiting, etc.).
- "How would you test this in CI?" → two layers. Fast unit layer is already
  here in [`spec/`](spec/) (busted, mocked `kong`/`ngx`, no Kong process) and
  runs in ~0.1s. Integration layer would use Kong's `spec.helpers` /
  [Pongo](https://github.com/Kong/kong-pongo) to spin up a real Kong node with
  the plugin loaded and drive HTTP requests through it.
- "How would you version/ship this across environments?" → Package as a
  LuaRocks rock, pin the version in your Kong Docker image build, and treat
  plugin upgrades like any other dependency bump with a changelog.
