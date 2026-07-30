#!/bin/sh
# SecretVault break-glass admin recovery (SV-030).
#
# Resets a user's password (and optionally wipes their 2FA factors and revokes
# active sessions) from inside the runtime container. This is the documented
# emergency recovery path; it is intentionally noninteractive — the password
# must arrive via --password-file or stdin (preferred), and --confirm must be
# set, so a stray `docker exec` cannot reset credentials. The password is fed
# to the CLI on stdin only; it never appears in the Node child's argv
# (SV-AUD-007). --password is retained for the parent invocation but is piped
# through rather than forwarded as a Node argument.
#
# Invocation (see docs/ops.md §2):
#   docker exec secretvault-mcp secretvault-break-glass \
#     --username admin --password 'NewSecurePassword123!' --confirm
#
#   # or read the password from a file / stdin to keep it out of shell history:
#   docker exec -i secretvault-mcp secretvault-break-glass \
#     --username admin --confirm --password-stdin < newpass.txt
set -eu

prog="secretvault-break-glass"
username=""
password=""
password_file=""
password_stdin=0
confirm=0
reset_2fa=0

usage() {
  cat >&2 <<EOF
Usage: $prog --username <user> --confirm \\
       (--password <pw> | --password-file <path> | --password-stdin) [--reset-2fa]

  --username <user>          account to recover (default: admin)
  --password <pw>            new password (DEPRECATED; prefer a file or stdin —
                             it is piped to the CLI, never passed as a Node arg)
  --password-file <path>     read new password from the first line of <path>
  --password-stdin           read new password from stdin
  --reset-2fa                also wipe the user's WebAuthn/TOTP factors
  --confirm                  required acknowledgement that this is destructive

The container must have SECRETVAULT_SUPABASE_URL and
SECRETVAULT_SUPABASE_SERVICE_KEY set (they are baked into the image env).
Every run records a high-severity audit event
(access_type: emergency_cli_password_reset) and prints confirmation to stdout.
EOF
  exit "${1:-1}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --username) username="${2:-}"; shift 2 ;;
    --password) password="${2:-}"; shift 2 ;;
    --password-file) password_file="${2:-}"; shift 2 ;;
    --password-stdin) password_stdin=1; shift ;;
    --reset-2fa) reset_2fa=1; shift ;;
    --confirm) confirm=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "$prog: unknown argument: $1" >&2; usage 1 ;;
  esac
done

[ "$confirm" -eq 1 ] || { echo "$prog: refusing to run without --confirm" >&2; usage 1; }
[ -n "$username" ] || username="admin"

# Exactly one password source, and never on the command line by accident.
sources=0
[ -n "$password" ] && sources=$((sources + 1))
[ -n "$password_file" ] && sources=$((sources + 1))
[ "$password_stdin" -eq 1 ] && sources=$((sources + 1))
if [ "$sources" -ne 1 ]; then
  echo "$prog: provide exactly one of --password, --password-file, --password-stdin" >&2
  usage 1
fi

if [ -n "$password_file" ]; then
  [ -r "$password_file" ] || { echo "$prog: cannot read --password-file: $password_file" >&2; exit 1; }
  password="$(head -n 1 "$password_file" || true)"
fi
if [ "$password_stdin" -eq 1 ]; then
  password="$(head -n 1 || true)"
fi

[ -n "$password" ] || { echo "$prog: password is empty" >&2; exit 1; }

# Locate the bundled CLI. The runtime image serves it at this path; do not
# depend on npm or a root package.json (neither exists in the image).
cli="/app/packages/mcp-server/dist/cli.js"
[ -f "$cli" ] || cli="$(dirname "$0")/../packages/mcp-server/dist/cli.js"
[ -f "$cli" ] || { echo "$prog: cannot find cli.js" >&2; exit 1; }

# SV-AUD-007: pass the password to Node via stdin, never as a --password
# argument (which would expose it in /proc/<pid>/cmdline and ps). The CLI reads
# the first line of stdin when --password-stdin is given.
set -- node "$cli" --username "$username" --password-stdin
[ "$reset_2fa" -eq 1 ] && set -- "$@" --reset-2fa

# Run noninteractively. The CLI validates env + length, performs the reset,
# revokes sessions, optionally wipes factors, records the audit event, and
# prints the [break-glass] confirmation. The password is piped on stdin only.
printf '%s\n' "$password" | "$@"
