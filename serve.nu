# patrol: capture UniFi controller webhook alerts into a 'threats' topic.
#
# Run:
#   http-nu --store ./store :3001 -w ./serve.nu
#
# UniFi (or any client) POSTs to /threats with:
#   Authorization: Bearer <token>
# Token must match one of `bearer_tokens` in config.toml; the source IP must
# fall in one of `allowed_ips` (CIDR list). Bodies are appended verbatim --
# we don't yet know UniFi's payload shape, so let it stream untouched and
# inspect later via `.cat threats`.

const script_dir = path self | path dirname

use http-nu/router *

let CFG = open ($script_dir | path join "config.toml")

# Parse a dotted IPv4 string into a u32, or null if malformed. IPv6 inputs
# return null too -- callers treat null as deny, which is the safe default
# since `allowed_ips` is currently IPv4-only.
def parse-ipv4 [ip: string]: nothing -> any {
  let parts = $ip | split row "."
  if ($parts | length) != 4 { return null }
  let bytes = $parts | each { try { into int } catch { -1 } }
  if ($bytes | any {|b| $b < 0 or $b > 255 }) { return null }
  $bytes | reduce -f 0 {|byte, acc| ($acc * 256) + $byte }
}

# Test whether ip falls inside a CIDR block. Bare IPs (no /n) are treated
# as /32. Anything that fails to parse returns false.
def cidr-contains [cidr: string ip: string]: nothing -> bool {
  let parts = $cidr | split row "/"
  let network = parse-ipv4 $parts.0
  let ip_int = parse-ipv4 $ip
  if $network == null or $ip_int == null { return false }
  let prefix_len = if ($parts | length) >= 2 { $parts.1 | into int } else { 32 }
  if $prefix_len == 0 { return true }
  let block = 2 ** (32 - $prefix_len)
  ($ip_int - ($ip_int mod $block)) == ($network - ($network mod $block))
}

# Pull the bearer token off the request, or null. Accepts only the
# "Authorization: Bearer <token>" form.
def bearer-token [req: record]: nothing -> any {
  let h = $req.headers? | default {} | get -i authorization | default ""
  if ($h | str starts-with "Bearer ") { $h | str substring 7.. } else { null }
}

{|req|
  dispatch $req [
    (route {method: "POST" path: "/threats"} {|req ctx|
      let raw = $in
      let ip = $req.trusted_ip? | default ""

      # `return (X | metadata set Y)` drops the metadata before http-nu sees
      # it -- fall-through as last expression preserves it.
      if not ($CFG.allowed_ips | any {|cidr| cidr-contains $cidr $ip }) {
        "forbidden" | metadata set { merge {'http.response': {status: 403}} }
      } else if not ((bearer-token $req) in $CFG.bearer_tokens) {
        "unauthorized" | metadata set { merge {'http.response': {status: 401}} }
      } else {
        $raw | .append threats | ignore
        "" | metadata set { merge {'http.response': {status: 204}} }
      }
    })

    (route true {|req ctx|
      "Not Found" | metadata set { merge {'http.response': {status: 404}} }
    })
  ]
}
