# patrol: capture UniFi controller webhook alerts into a 'threats' topic.
#
# Run:
#   http-nu --store ./store :3001 -w ./serve.nu
#
# UniFi (or any client) POSTs to /threats with:
#   Authorization: Bearer <token>
# The token is matched against BEARER_TOKEN in ./.env, loaded once at
# startup. Bodies are appended verbatim as frames -- we don't yet know
# UniFi's payload shape, so let it stream untouched and inspect later
# via `.cat threats`.

const script_dir = path self | path dirname

use http-nu/router *

# Parse a KEY=VALUE .env file into a record. Skips blank lines and
# # comments. Values are not unquoted -- keep the file literal so tokens
# round-trip unchanged.
def load-env [path: path]: nothing -> record {
  open --raw $path
  | lines
  | each { str trim }
  | where {|l| ($l | str length) > 0 and (not ($l | str starts-with "#")) }
  | reduce -f {} {|line, acc|
    let kv = $line | split row "="
    if ($kv | length) >= 2 {
      $acc | upsert ($kv | first | str trim) ($kv | skip 1 | str join "=" | str trim)
    } else { $acc }
  }
}

let BEARER_TOKEN = (load-env ($script_dir | path join ".env")).BEARER_TOKEN

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

      if (bearer-token $req) != $BEARER_TOKEN {
        return ("unauthorized" | metadata set { merge {'http.response': {status: 401}} })
      }

      $raw | .append threats | ignore
      "" | metadata set { merge {'http.response': {status: 204}} }
    })

    (route true {|req ctx|
      "Not Found" | metadata set { merge {'http.response': {status: 404}} }
    })
  ]
}
