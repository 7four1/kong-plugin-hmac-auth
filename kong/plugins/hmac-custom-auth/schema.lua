-- schema.lua
-- Defines and validates the plugin's configuration fields.
-- Kong validates every field here before the config is ever
-- allowed to be saved (DB mode) or loaded (declarative/DB-less).

local typedefs = require "kong.db.schema.typedefs"

return {
  name = "hmac-custom-auth",
  fields = {
    -- "consumer" and "protocols" are standard Kong plugin scoping fields
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- Name of the header carrying the client-supplied signature
          { signature_header = { type = "string", default = "X-Signature" } },

          -- Name of the header carrying the timestamp used in the signed string
          { timestamp_header = { type = "string", default = "X-Timestamp" } },

          -- Name of the header identifying which client/key signed the request
          { client_id_header = { type = "string", default = "X-Client-Id" } },

          -- Map of client_id -> shared secret. In production, swap this for
          -- a Consumer custom-credential lookup instead of static config.
          { secrets = {
              type = "map",
              keys = { type = "string" },
              values = { type = "string" },
              required = true,
            }
          },

          -- Reject requests whose timestamp is older than this, to block replay attacks
          { clock_skew_seconds = { type = "integer", default = 300 } },
        },
      },
    },
  },
}
