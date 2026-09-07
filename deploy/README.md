# Deploying hmac-custom-auth to a hybrid-mode Kong on AKS

Config is managed with **decK**; control plane is **self-managed** (you run the
CP pods). A custom plugin in hybrid mode must exist on **both** roles:

| Role | Needs | Why |
|------|-------|-----|
| Control plane | `schema.lua` + `handler.lua` + `KONG_PLUGINS` entry | Loads the schema, validates decK config, renders the config pushed to DPs |
| Data plane | `schema.lua` + `handler.lua` + `KONG_PLUGINS` entry | Runs `access()` on live traffic. Rejects the CP config push if its plugin list doesn't match |

The clean way to satisfy both: **one custom image**, used by both deployments.

---

## 1. Build and push the image

> In CI this is done for you by [`.github/workflows/release.yml`](../.github/workflows/release.yml)
> on a `vX.Y.Z` tag — it publishes to GHCR (and ACR if `ACR_*` secrets are set).
> The manual steps below are the equivalent for a local build.

```bash
ACR=<your-registry>.azurecr.io
TAG=3.9-hmac-1.0.0          # <kong-version>-hmac-<plugin-version>

az acr login -n <your-registry>

# run from the repo root (build context = repo root)
docker build -f deploy/Dockerfile --build-arg KONG_VERSION=3.9 \
  -t $ACR/kong-hmac:$TAG .

docker push $ACR/kong-hmac:$TAG
```

Make sure the AKS nodes / kubelet identity can pull from ACR
(`az aks update -n <cluster> -g <rg> --attach-acr <your-registry>`), or add an
`imagePullSecret` to the chart values.

## 2. Roll out the control plane FIRST

Edit [values-controlplane.yaml](values-controlplane.yaml) with your `$ACR` and `$TAG`, then:

```bash
helm upgrade --install kong-cp kong/kong -n kong -f deploy/values-controlplane.yaml
kubectl -n kong rollout status deploy/kong-cp-kong
```

Verify the CP knows the plugin:

```bash
kubectl -n kong port-forward deploy/kong-cp-kong 8001:8001 &
curl -s localhost:8001/schemas/plugins/hmac-custom-auth | head    # 200 + schema JSON
curl -s localhost:8001/ | jq '.plugins.available_on_server["hmac-custom-auth"]'  # true
```

CP first matters: if you push config referencing a plugin the CP can't load, the
decK sync fails.

## 3. Roll out the data plane

Edit [values-dataplane.yaml](values-dataplane.yaml) the same way, then:

```bash
helm upgrade --install kong-dp kong/kong -n kong -f deploy/values-dataplane.yaml
kubectl -n kong rollout status deploy/kong-dp-kong
kubectl -n kong logs deploy/kong-dp-kong | grep -i "hmac-custom-auth\|plugin"
```

The DP log should show it connecting to the CP and receiving config with no
"plugin 'hmac-custom-auth' not installed / enabled" errors.

## 4. Apply the config with decK

```bash
CP=https://<cp-admin-api-host>:8001    # or: kubectl port-forward + http://localhost:8001

# Custom-plugin config can only be fully validated against a live CP:
deck gateway validate deploy/kong.yaml --kong-addr $CP
deck gateway diff     deploy/kong.yaml --kong-addr $CP
deck gateway sync     deploy/kong.yaml --kong-addr $CP
```

(decK < 1.30 syntax: `deck validate --online -s deploy/kong.yaml` / `deck sync -s ...`.)

## 5. Smoke test through the data plane

```bash
PROXY=http://<data-plane-lb-ip>        # the DP Service EXTERNAL-IP / ingress host
SECRET="super-secret-value-rotate-me"
TS=$(date +%s)
SIG=$(printf 'GET\n/partner/orders\n%s' "$TS" \
      | openssl dgst -sha256 -hmac "$SECRET" -binary | base64)

curl -i "$PROXY/partner/orders" \
  -H "X-Client-Id: partner-a" \
  -H "X-Timestamp: $TS" \
  -H "X-Signature: $SIG"
# expect: upstream 200, and the upstream sees X-Authenticated-Client-Id: partner-a

curl -i "$PROXY/partner/orders"                       # 401 Missing authentication headers
curl -i "$PROXY/partner/orders" -H 'X-Client-Id: partner-a' \
     -H "X-Timestamp: $TS" -H 'X-Signature: wrong'    # 401 Signature verification failed
```

---

## Upgrading the plugin later

1. Bump the plugin version, build a new image tag (`3.9-hmac-1.1.0`).
2. `helm upgrade` the **CP** to the new tag, wait for rollout.
3. `helm upgrade` the **DP** to the new tag.
4. `deck gateway sync` any config changes.

Never let CP and DP run different plugin *code* for long — schema changes on one
side but not the other cause config-push rejections.

## Notes

- **Secrets**: `config.secrets` values land in `deploy/kong.yaml` and in the CP
  database/config. Configure a [Kong Vault backend](https://docs.konghq.com/gateway/latest/kong-enterprise/secrets-management/)
  (env, Azure Key Vault, ...) on **both** CP and DP, then use
  `"{vault://...}"` references instead of literals.
- **`bundled`**: keep it in the `plugins` list or you lose every built-in plugin.
- If you prefer packaging over `COPY`, swap the Dockerfile's `COPY` for
  `RUN luarocks make deploy/hmac-custom-auth-1.0.0-1.rockspec`.
