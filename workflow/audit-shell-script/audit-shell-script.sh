#!/usr/bin/env bash
# audit-script.sh: static review of a shell script BEFORE you run it.
#
#   bash audit-script.sh run.sh              audit, then ask before running
#   bash audit-script.sh --check run.sh      audit only, never runs anything
#   pbpaste | bash audit-script.sh -         audit the clipboard (check only)
#
# Exit codes with --check: 0 = no HIGH/WARN, 1 = WARN found, 2 = HIGH found.
#
# This is pattern matching, not a sandbox. It cannot see commands built from
# variables, files that one script writes and another runs, or what a called
# binary does internally. Read the flagged lines; do not treat "clean" as safe.
#
# It needs no chmod: it is run with `bash`, and it runs the audited script the
# same way, from a snapshot, so the bytes you reviewed are the bytes that run.

set -u

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

MODE=run
FILE=""
for arg in "$@"; do
  case "$arg" in
    --check) MODE=check ;;
    -h|--help) usage; exit 0 ;;
    *) FILE="$arg" ;;
  esac
done
[ -z "$FILE" ] && { usage; exit 64; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/audit.XXXXXX") || exit 70
trap 'rm -rf "$TMP"' EXIT

if [ "$FILE" = "-" ]; then
  cat > "$TMP/stdin.sh"
  FILE="$TMP/stdin.sh"
  MODE=check
fi
[ -r "$FILE" ] || { echo "Cannot read: $FILE" >&2; exit 66; }

COLOR=0
[ -t 1 ] && COLOR=1

# ---------------------------------------------------------------------------
# Rules. Format: LEVEL@@category@@regex@@description@@unless@@scope
#   <S> / <E>  = start / end of a command word
#   unless     = skip the rule when the line also matches this regex
#   scope      = "sh" only top-level shell lines, "*" also embedded code
# ---------------------------------------------------------------------------
cat > "$TMP/rules" <<'RULES'
# --- network ---
HIGH@@network@@<S>(curl|wget|nc|ncat|netcat|telnet|ftp|sftp|scp|ssh|rsync|socat)<E>@@opens network connections@@@@*
HIGH@@network@@/dev/(tcp|udp)/@@opens a raw network socket@@@@*
HIGH@@network@@<S>git[[:space:]]+(push|pull|fetch|clone|ls-remote|submodule)@@git talks to a remote@@@@*
HIGH@@network@@<S>(npm|pnpm|yarn|bun)[[:space:]]+(install|i|add|update|up|upgrade|dlx|create|publish|login|ci)<E>@@installs or downloads packages@@@@*
HIGH@@network@@<S>npx<E>@@npx can download and run a package@@--no-install|--no[[:space:]]@@*
HIGH@@network@@<S>(pip|pip3|brew|gem|cargo|go|apt|apt-get)[[:space:]]+(install|get|add|update|upgrade)<E>@@installs software@@@@*
HIGH@@network@@(fetch|axios|got|XMLHttpRequest|WebSocket)[[:space:]]*\(@@HTTP call from embedded code@@@@*
HIGH@@network@@(require\(|from[[:space:]]+|import[[:space:]]*\()["'](node:)?(https?|net|tls|dns|dgram|http2)["']@@imports a network module@@@@*
HIGH@@network@@(urllib|requests\.|http\.client|socket\.socket|aiohttp)@@Python network call@@@@*
WARN@@network@@https?://@@contains a URL, check that nothing contacts it@@https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)@@*
WARN@@network@@<S>(ping|nslookup|dig|traceroute)<E>@@sends network probes@@@@*
WARN@@network@@<S>open[[:space:]]@@opens a file, app or URL@@@@sh
# --- permissions ---
HIGH@@permissions@@<S>(chmod|chown|chgrp|chflags|setfacl|xattr)<E>@@changes permissions or ownership@@@@*
HIGH@@permissions@@fs\.(chmod|chown|lchmod)@@changes permissions from embedded code@@@@*
HIGH@@permissions@@<S>(sudo|su|doas)<E>@@privilege escalation@@@@*
WARN@@permissions@@<S>umask<E>@@changes default file permissions@@@@*
# --- system ---
HIGH@@system@@<S>(launchctl|crontab|systemctl|pmset|networksetup|spctl|csrutil|scutil|dscl|sysctl|diskutil|hdiutil|tccutil|mdutil)<E>@@changes system configuration@@@@*
HIGH@@system@@<S>defaults[[:space:]]+(write|delete|import)<E>@@changes macOS preferences@@@@*
HIGH@@system@@<S>security[[:space:]]+(find|add|delete|import|export|dump|unlock)@@touches the macOS keychain@@@@*
HIGH@@system@@<S>osascript<E>@@runs AppleScript@@@@*
WARN@@system@@<S>(kill|killall|pkill)<E>@@stops processes@@@@*
WARN@@system@@<S>(nohup|disown)<E>@@leaves a process running@@@@*
WARN@@system@@[^&]&[[:space:]]*$@@starts a background process@@@@sh
# --- secrets ---
HIGH@@secrets@@(^|[^[:alnum:]_])\.env([.][[:alnum:]_-]+)?([^[:alnum:]_.-]|$)@@touches an .env file (including .env.example)@@@@*
HIGH@@secrets@@\.dev\.vars|\.npmrc|\.netrc|\.pgpass|\.pypirc|\.pem([^[:alnum:]]|$)|\.p12|\.pfx|\.keystore|id_(rsa|ed25519|ecdsa|dsa)|\.ssh/|\.aws/|\.gnupg|\.kube/|\.docker/config|\.config/gcloud|\.git-credentials|\.gitconfig@@touches a credentials or key file@@@@*
HIGH@@secrets@@[Kk]eychain|credentials\.json|secrets?\.(json|ya?ml|toml)|\.vault@@touches a secrets store@@@@*
WARN@@secrets@@<S>(printenv|env)[[:space:]]*($|[|;>])@@dumps the whole environment@@@@*
WARN@@secrets@@\$\{?[A-Za-z_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PEPPER|PRIVATE_KEY)[A-Za-z_]*@@references a secret-looking variable@@@@*
WARN@@secrets@@process\.env|os\.environ|Deno\.env|Bun\.env@@reads environment variables from embedded code@@@@*
WARN@@secrets@@wrangler\.toml|\.git/config|\.git/hooks@@reads config that can hold ids or hooks@@@@*
INFO@@clipboard@@<S>pbpaste<E>@@reads the clipboard@@@@*
INFO@@clipboard@@<S>(pbcopy|xclip|wl-copy|clip\.exe)<E>@@copies output to the clipboard, check what feeds it@@@@*
# --- destructive ---
HIGH@@destructive@@<S>rm[[:space:]]+(-[a-zA-Z]*[rR]|--recursive)@@recursive delete@@@@*
WARN@@destructive@@<S>rm<E>@@deletes files@@-[a-zA-Z]*[rR]@@sh
HIGH@@destructive@@<S>(dd|mkfs|fdisk|shred|truncate|srm)<E>@@low-level or irreversible write@@@@*
HIGH@@destructive@@<S>git[[:space:]]+(reset[[:space:]]+--hard|clean|filter-branch|rebase|branch[[:space:]]+-D|stash[[:space:]]+(drop|clear))@@discards git history or work@@@@*
HIGH@@destructive@@<S>git[[:space:]]+push[[:space:]].*(--force|[[:space:]]-f)@@force push@@@@*
HIGH@@destructive@@-delete([[:space:]]|$)|-exec[[:space:]]+rm|xargs[[:space:]]+(-[^[:space:]]+[[:space:]]+)*rm@@bulk delete@@@@*
HIGH@@destructive@@fs\.(rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)|shutil\.rmtree|os\.remove@@deletes files from embedded code@@@@*
WARN@@destructive@@<S>mv<E>@@moves or overwrites files@@@@sh
WARN@@destructive@@(<S>sed[[:space:]]+(-[a-zA-Z]*i|--in-place)|<S>perl[[:space:]]+-[a-zA-Z0-9]*i)@@edits files in place@@@@sh
WARN@@destructive@@fs\.(writeFile|writeFileSync|appendFile|appendFileSync|rename|renameSync|copyFile|copyFileSync|mkdir|mkdirSync)@@writes files from embedded code@@@@*
WARN@@destructive@@(^|[^0-9&>=-])>>?[[:space:]]*["$~./A-Za-z_]@@redirects output into a file (> overwrites)@@>[[:space:]]*/dev/(null|stderr|stdout)|>&@@sh
WARN@@git@@<S>git[[:space:]]+(commit|add|checkout|restore|stash|merge|cherry-pick|tag|switch|apply|am|config)<E>@@changes git state@@@@*
# --- running other code ---
HIGH@@exec@@<S>eval<E>@@evaluates a string as code@@@@*
HIGH@@exec@@\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da|k)?sh([[:space:]]|$)@@pipes content into a shell@@@@*
HIGH@@exec@@base64[[:space:]]+(-d|-D|--decode)|xxd[[:space:]]+-r|openssl[[:space:]]+enc@@decodes hidden content@@@@*
HIGH@@exec@@source[[:space:]]+<\(|<\((curl|wget)|\$\((curl|wget)@@runs downloaded content@@@@*
HIGH@@exec@@child_process|execSync|spawnSync|execFile|[^[:alnum:]_.]exec\(|[[:space:](]spawn\(|os\.system|subprocess|popen@@embedded code runs other commands@@@@*
WARN@@exec@@<S>(node|python[0-9.]*|perl|ruby|php|deno|bun|tsx|ts-node)[[:space:]]+[^-<[:space:]]@@runs another file that is not audited here@@@@sh
WARN@@exec@@(<S>(bash|sh|zsh|source)[[:space:]]+[^-<[:space:]]|<S>\.[[:space:]]+[~/.$])@@runs another script that is not audited here@@@@sh
WARN@@exec@@<S>(npm|pnpm|yarn|npx)[[:space:]]+(run|exec|test|build|lint|dev|start|--no-install|tsc|eslint|vitest)@@runs a package script or local binary@@@@*
WARN@@exec@@-exec[[:space:]]@@find runs a command per match@@-exec[[:space:]]+rm@@*
# --- paths ---
WARN@@paths@@(^|[[:space:]"'=(])(/etc|/usr|/bin|/sbin|/var|/Library|/System|/opt|/private|~/|\$HOME|\$\{HOME\}|/Users/[^/[:space:]]+/)@@touches a path outside the repo@@^#!|/dev/null@@*
WARN@@paths@@<S>cd[[:space:]]+(/|~|\.\.|\$HOME)@@changes directory outside the repo@@@@sh
RULES

cat > "$TMP/audit.awk" <<'AWK'
function paint(s, L) {
  if (!color) return s
  if (L == "HIGH") return "\033[1;31m" s "\033[0m"
  if (L == "WARN") return "\033[1;33m" s "\033[0m"
  return "\033[2m" s "\033[0m"
}
BEGIN {
  S = "(^|[[:space:];|(`])"
  E = "([[:space:];|)`]|$)"
  n = 0
  while ((getline rule < rules) > 0) {
    if (rule ~ /^[[:space:]]*(#|$)/) continue
    k = split(rule, f, "@@")
    if (k < 4) continue
    n++
    lvl[n] = f[1]; cat[n] = f[2]
    re = f[3]; gsub(/<S>/, S, re); gsub(/<E>/, E, re)
    rx[n] = re; dsc[n] = f[4]; unl[n] = f[5]; scp[n] = f[6]
  }
  close(rules)
  inhd = 0; h = 0; w = 0; inf = 0
}
{
  raw = $0
  if (inhd) {
    t = raw
    if (hdtab) sub(/^\t+/, "", t)
    if (t == delim) { inhd = 0; next }
    ctx = hdkind
  } else {
    ctx = "sh"
    if (raw !~ /<<</ && match(raw, /<<-?[[:space:]]*["']?[A-Za-z_][A-Za-z0-9_]*["']?/)) {
      tok = substr(raw, RSTART, RLENGTH)
      hdtab = (tok ~ /^<<-/)
      sub(/^<<-?[[:space:]]*["']?/, "", tok); sub(/["']$/, "", tok)
      delim = tok; inhd = 1
      writes = (raw ~ /(^|[[:space:];|(])(cat|tee)[[:space:]]/) &&
               (raw ~ /(^|[^0-9&>=-])>>?[[:space:]]*[^&[:space:]]/ || raw ~ /(^|[[:space:]])tee[[:space:]]/)
      hdkind = writes ? "data" : "code"
    }
  }
  if (raw ~ /^[[:space:]]*#/) next
  for (j = 1; j <= n; j++) {
    if (scp[j] == "sh" && ctx != "sh") continue
    if (raw !~ rx[j]) continue
    if (unl[j] != "" && raw ~ unl[j]) continue
    L = lvl[j]; tag = ""
    if (ctx == "data") { L = "INFO"; tag = "  (in a file being written, not executed)" }
    else if (ctx == "code") tag = "  (embedded code that WILL run)"
    if (L == "HIGH") h++; else if (L == "WARN") w++; else inf++
    txt = raw; sub(/^[[:space:]]+/, "", txt)
    if (length(txt) > 96) txt = substr(txt, 1, 93) "..."
    printf "  %s line %-4d [%s] %s%s\n", paint(sprintf("%-4s", L), L), NR, cat[j], dsc[j], tag
    printf "       | %s\n", txt
  }
}
END { print h, w, inf > out; close(out) }
AWK

echo "Auditing: $FILE ($(wc -l < "$FILE" | tr -d ' ') lines)"
echo "sha256:   $(shasum -a 256 "$FILE" 2>/dev/null | cut -d' ' -f1)"
echo

SYNTAX=$(bash -n "$FILE" 2>&1) || { echo "SYNTAX ERROR (bash -n):"; echo "$SYNTAX"; echo; SYNTAX_BAD=1; }
SYNTAX_BAD=${SYNTAX_BAD:-0}

awk -v rules="$TMP/rules" -v out="$TMP/counts" -v color="$COLOR" -f "$TMP/audit.awk" "$FILE"
read -r H W I < "$TMP/counts"

if ! grep -q 'rev-parse --show-toplevel' "$FILE"; then
  echo "  WARN  [paths] never cds to the repo root, so relative paths depend on where you run it"
  W=$((W + 1))
fi

echo
echo "Summary: HIGH $H   WARN $W   INFO $I"
echo "Limits: pattern match only. It cannot see variable-built commands,"
echo "        files other scripts create and run later, or what binaries do inside."

if [ "$MODE" = check ]; then
  [ "$H" -gt 0 ] && exit 2
  [ "$W" -gt 0 ] && exit 1
  exit 0
fi

[ "$SYNTAX_BAD" = 1 ] && echo "Not running: fix the syntax error first." && exit 65

cp "$FILE" "$TMP/snapshot.sh"

ask() {
  local prompt="$1" ans
  while :; do
    printf '%s ' "$prompt" > /dev/tty 2>/dev/null || return 1
    read -r ans < /dev/tty || return 1
    case "$ans" in
      v|V) cat -n "$TMP/snapshot.sh" | ${PAGER:-less} ;;
      *) printf '%s' "$ans"; return 0 ;;
    esac
  done
}

echo
if [ "$H" -gt 0 ]; then
  ans=$(ask "HIGH-risk patterns found. Type 'run' to execute, 'v' to view the script, anything else cancels:")
  [ "$ans" = "run" ] || { echo "Cancelled."; exit 130; }
else
  label="No HIGH findings."
  [ "$W" -gt 0 ] && label="WARN findings only."
  ans=$(ask "$label Run it? [y/N/v=view]:")
  case "$ans" in y|Y|yes) ;; *) echo "Cancelled."; exit 130 ;; esac
fi

echo "--- running snapshot ---"
bash "$TMP/snapshot.sh"
