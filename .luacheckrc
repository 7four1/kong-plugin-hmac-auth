std = "lua54"
max_line_length = 120

-- Globals owned by the Kong / OpenResty runtime. Mutable because plugins
-- legitimately write through them (e.g. kong.ctx.shared.x = ...).
globals = { "kong", "ngx" }

-- `function Handler:phase(conf)` keeps the method form for clarity even when
-- `self` is unused — that's idiomatic Kong, not a mistake.
ignore = { "212/self" }

-- The test harness deliberately builds fakes for the runtime and exposes `helpers`.
files["spec/"] = {
  std = "lua54+busted",
  globals = { "kong", "ngx", "helpers" },
}

exclude_files = { ".luarocks/", "lua_modules/" }
