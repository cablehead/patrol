# Run:
#   http-nu eval --store /tmp/patrol-test ./test.nu
#
# Side-effect-based: count `threats` frames before/after each call and
# assert that auth/IP failures don't append.

use std/assert

const script_dir = path self | path dirname

# Source loads serve.nu's preamble (reads config.toml) and returns the
# trailing closure so we can drive it directly with `do`.
let handler = source ($script_dir | path join serve.nu)
let cfg = open ($script_dir | path join "config.toml")
let token = $cfg.bearer_tokens | first

print "1. /threats from allowed IP, no Authorization -> no frame (401)"
let before = .cat | where topic == "threats" | length
'{"event":"x"}' | do $handler {
  method: "POST" path: "/threats" headers: {}
  trusted_ip: "127.0.0.1" query: {}
}
let after = .cat | where topic == "threats" | length
assert equal $after $before "missing auth should not append a frame"
print "   ok"

print "2. /threats from allowed IP, wrong bearer -> no frame (401)"
let before = .cat | where topic == "threats" | length
'{"event":"x"}' | do $handler {
  method: "POST" path: "/threats"
  headers: {authorization: "Bearer not-the-real-token"}
  trusted_ip: "127.0.0.1" query: {}
}
let after = .cat | where topic == "threats" | length
assert equal $after $before "wrong token should not append a frame"
print "   ok"

print "3. /threats from disallowed IP with valid bearer -> no frame (403)"
# IP gate runs before token check, so a public IP is rejected even with a
# valid token.
let before = .cat | where topic == "threats" | length
'{"event":"x"}' | do $handler {
  method: "POST" path: "/threats"
  headers: {authorization: $"Bearer ($token)"}
  trusted_ip: "8.8.8.8" query: {}
}
let after = .cat | where topic == "threats" | length
assert equal $after $before "disallowed IP should not append"
print "   ok"

print "4. /threats from CIDR-allowed IP with valid bearer -> frame appended"
let before = .cat | where topic == "threats" | length
'{"event":"intrusion","src":"10.0.0.5"}' | do $handler {
  method: "POST" path: "/threats"
  headers: {authorization: $"Bearer ($token)"}
  trusted_ip: "10.0.0.5" query: {}
}
let frames = .cat | where topic == "threats"
assert equal ($frames | length) ($before + 1) "valid request should append exactly one frame"
let captured = .cas ($frames | last | get hash) | from json
assert equal $captured.event "intrusion"
assert equal $captured.src "10.0.0.5"
print "   ok"

print "5. /threats from exact-match IP with valid bearer -> frame appended"
let before = .cat | where topic == "threats" | length
'{"event":"local"}' | do $handler {
  method: "POST" path: "/threats"
  headers: {authorization: $"Bearer ($token)"}
  trusted_ip: "127.0.0.1" query: {}
}
let frames = .cat | where topic == "threats"
assert equal ($frames | length) ($before + 1)
print "   ok"

print "6. /threats from a disallowed IP just outside the CIDR -> no frame"
# 10.0.0.0/8 covers 10.x.x.x; 11.0.0.1 is one block over.
let before = .cat | where topic == "threats" | length
'{"event":"x"}' | do $handler {
  method: "POST" path: "/threats"
  headers: {authorization: $"Bearer ($token)"}
  trusted_ip: "11.0.0.1" query: {}
}
let after = .cat | where topic == "threats" | length
assert equal $after $before "11.0.0.1 is outside 10.0.0.0/8"
print "   ok"

print "7. unrelated route -> no frame on threats"
let before = .cat | where topic == "threats" | length
do $handler {method: "GET" path: "/" headers: {} trusted_ip: "127.0.0.1" query: {}}
let after = .cat | where topic == "threats" | length
assert equal $after $before "unrelated routes should not touch threats"
print "   ok"

print "\nAll tests passed."
