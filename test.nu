# Run:
#   http-nu eval --store /tmp/patrol-test ./test.nu
#
# Side-effect-based: count `threats` frames before/after each call and
# assert that auth failures don't append.

use std/assert

const script_dir = path self | path dirname

# Source loads serve.nu's preamble (reads .env) and returns the trailing
# closure so we can drive it directly with `do`.
let handler = source ($script_dir | path join serve.nu)

# Read the same .env the handler did so the test never falls out of sync
# when the token rotates.
let bearer = (open --raw ($script_dir | path join ".env"))
  | lines
  | where { $in | str starts-with "BEARER_TOKEN=" }
  | first
  | str replace "BEARER_TOKEN=" ""

print "1. POST /threats with no Authorization header -> no frame"
let before = .cat | where topic == "threats" | length
'{"event":"x"}' | do $handler {method: "POST" path: "/threats" headers: {} query: {}}
let after = .cat | where topic == "threats" | length
assert equal $after $before "missing auth should not append a frame"
print "   ok"

print "2. POST /threats with wrong bearer -> no frame"
let before = .cat | where topic == "threats" | length
'{"event":"x"}' | do $handler {
  method: "POST"
  path: "/threats"
  headers: {authorization: "Bearer not-the-real-token"}
  query: {}
}
let after = .cat | where topic == "threats" | length
assert equal $after $before "wrong token should not append a frame"
print "   ok"

print "3. POST /threats with correct bearer -> frame appended, body in CAS"
let before = .cat | where topic == "threats" | length
'{"event":"intrusion","src":"10.0.0.5"}' | do $handler {
  method: "POST"
  path: "/threats"
  headers: {authorization: $"Bearer ($bearer)"}
  query: {}
}
let frames = .cat | where topic == "threats"
assert equal ($frames | length) ($before + 1) "valid request should append exactly one frame"
let captured = .cas ($frames | last | get hash) | from json
assert equal $captured.event "intrusion"
assert equal $captured.src "10.0.0.5"
print "   ok"

print "4. unrelated route -> no frame on threats"
let before = .cat | where topic == "threats" | length
do $handler {method: "GET" path: "/" headers: {} query: {}}
let after = .cat | where topic == "threats" | length
assert equal $after $before "unrelated routes should not touch threats"
print "   ok"

print "\nAll tests passed."
