#!/usr/bin/env bash
#
# campus-sso-login.sh - headless campus-network login for the HSTC Dr.COM portal
# that fronts the school CAS single sign-on ("unified identity").
#
#   portal : http://rz.hstc.edu.cn/    (same host as http://192.168.2.34/)
#   CAS    : https://hscas.hstc.edu.cn/cas/
#
# How the flow was derived (from the portal's own JavaScript, not guesswork):
#
#   1) While unauthenticated, http://connect.rom.miui.com/generate_204 is
#      intercepted and answered with 200 + a redirect page:
#        <script>top.self.location.href='https://rz.hstc.edu.cn/a79.htm
#          ?wlanuserip=..&usermac=..&wlanacip=..&wlanacname=..&...'</script>
#      Those four values identify this client. The backend does NOT validate
#      them (it echoes whatever you send), so they must come from the real
#      redirect, otherwise the session gets bound to the wrong IP/MAC.
#
#   2) The portal page template registers an authorisation link:
#        GET {portal_api}cas/create?login_method=1
#              &wlan_user_ip=..&wlan_user_mac=..&wlan_ac_ip=..&wlan_ac_name=..
#        -> {"result":1,"authorize_uri":"https://.../cas/login?service=<urlenc>"}
#
#   3) CAS serves its login page with a per-session `execution` token. The RSA
#      public key is at /cas/jwt/publicKey; the password is encrypted with
#      PKCS#1 v1.5 and prefixed with "__RSA__" (that is what JSEncrypt does).
#      Form fields: username, password, execution, _eventId=submit,
#      geolocation, mfaState, currentMenu=1, failN=-1
#
#   4) A successful POST redirects to  service?ticket=ST-...  and the portal
#      then completes the network authentication.
#
# Logging out is NOT the usual /drcom/logout. A HAR capture of this deployment's
# own portal page showed that with unBindMac=1 it calls user.unbind_mac() instead:
#      GET <portal>:802/eportal/portal/mac/unbind
#            ?user_account=..&wlan_user_mac=000000000000&wlan_user_ip=..
#            &wlan_user_ipv6=::&unbind_type=1&...
#      GET <portal>:802/eportal/portal/cas/logout?wlan_user_ip=..
#            -> then follow the returned switch_uri to clear the CAS session
# /drcom/logout answers "Logout Error(no webmode)" for a session created via CAS.
#
# If CAS already trusts this client (IP-level SSO, or the authorisation link it
# just registered) it returns a ticket straight away, with no login form at all.
# That path is handled as well, and needs no credentials.
#
# Usage:
#   ./campus-sso-login.sh            login if not already online
#   ./campus-sso-login.sh --menu     force the interactive menu (also shown
#                                    automatically when run with no arguments
#                                    from a terminal)
#   ./campus-sso-login.sh --check    only report the online state
#   ./campus-sso-login.sh --logout   log out (unbind MAC, then CAS sign-off)
#   ./campus-sso-login.sh --logout --relogin
#                                    ... and log straight back in afterwards, so
#                                    you are never left stranded offline
#   ./campus-sso-login.sh --force    ignore the online state
#   ./campus-sso-login.sh --dry-run  walk the chain, never submit a password
#   ./campus-sso-login.sh --sms 138xxxxxxxx
#                                    log in with an SMS code instead of a password
#                                    (interactive: the code is sent to your phone)
#
# Configuration: campus.conf next to this script, or environment variables
#   CAMPUS_USER / CAMPUS_PASS. Credentials are only requested when the CAS login
#   form is actually needed (prompted on a TTY, password is not echoed).
#   Nothing is written to disk: the password only ever lives in this process,
#   and the cookie jar is deleted on exit.
#
set -u
umask 077                      # cookie jar and dumps stay private to this user

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF="${CAMPUS_CONF:-$SELF_DIR/campus.conf}"
# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"

USERNAME="${CAMPUS_USER:-}"
PASSWORD="${CAMPUS_PASS:-}"
FORCE_REDIRECT="${CAMPUS_REDIRECT:-}"
PROBE="${CAMPUS_PROBE:-http://connect.rom.miui.com/generate_204}"
PORTAL="${CAMPUS_PORTAL:-https://rz.hstc.edu.cn}"
# Terminal type reported to the portal: 1 = phone, 0 = anything else.
# The page computes mac_type = (term.type == 2 ? 1 : 0), where term.type is
# 1 PC / 2 phone / 3 tablet, and the value is carried into the CAS "state"
# (second field), which is what the self-service backend displays.
MAC_TYPE="${CAMPUS_MAC_TYPE:-1}"
EP_HTTP_PORT="${CAMPUS_EP_HTTP_PORT:-801}"
EP_HTTPS_PORT="${CAMPUS_EP_HTTPS_PORT:-802}"
CAS_BASE="${CAMPUS_CAS:-https://hscas.hstc.edu.cn/cas}"
UA="${CAMPUS_UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36}"
WORK="${CAMPUS_WORK:-/tmp/campus-sso}"
LOG="${CAMPUS_LOG:-/tmp/campus-sso-login.log}"
PAGE_PROGRAM=""      # filled in from loadConfig on demand
PAGE_INDEX=""

CHECK=0; FORCE=0; DRY=0; LOGOUT=0; RELOGIN=0; SMS=0; SMS_MOBILE=""; MENU=0
# No arguments and a terminal => show the menu. Anything else keeps the old
# non-interactive behaviour, so timers and systemd units are unaffected.
[ $# -eq 0 ] && [ -t 0 ] && MENU=1
[ "${CAMPUS_MENU:-0}" = 1 ] && MENU=1
while [ $# -gt 0 ]; do
  case "$1" in
    --menu)    MENU=1 ;;
    --login)   : ;;
    --check)   CHECK=1 ;;
    --logout)  LOGOUT=1 ;;
    --relogin) RELOGIN=1 ;;
    --force)   FORCE=1 ;;
    --dry-run) DRY=1; FORCE=1 ;;
    --sms)
      SMS=1
      shift
      case "${1:-}" in
        ""|--*) ;;
        *) SMS_MOBILE="$1"; shift ;;
      esac
      continue
      ;;
    -h|--help) awk 'NR>1 && /^set -u/{exit} NR>1{print}' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

log(){ printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
die(){ log "ERROR: $*"; exit 1; }

command -v curl    >/dev/null 2>&1 || die "curl not found"
command -v openssl >/dev/null 2>&1 || die "openssl not found"
command -v base64  >/dev/null 2>&1 || die "base64 not found"

mkdir -p "$WORK"; chmod 700 "$WORK" 2>/dev/null
JAR="$WORK/cookies.txt"; rm -f "$JAR"
# The jar can hold a CAS session cookie, which is a reusable credential.
trap 'rm -f "$JAR" 2>/dev/null' EXIT

online(){ [ "$(curl -s -o /dev/null -w '%{http_code}' -m 8 -A "$UA" "$PROBE" 2>/dev/null)" = "204" ]; }

local_ip(){
  if command -v ip >/dev/null 2>&1; then
    ip route get 1.1.1.1 2>/dev/null | LC_ALL=C grep -oE 'src [0-9.]+' | awk '{print $2}'
  else
    ipconfig getifaddr en0 2>/dev/null \
      || ifconfig 2>/dev/null | awk '/inet /{print $2}' | LC_ALL=C grep -v '^127\.' | head -1
  fi
}

# Every portal jsonp call carries program_index / page_index / v / lang on top of
# callback+jsVersion (see util._jsonp). The two indices come from loadConfig; note
# that wlan_ac_ip and wlan_user_ipv6 must be present even when empty.
page_indices(){
  local base="$1" ip="$2"
  PAGE_PROGRAM=""; PAGE_INDEX=""
  [ -n "$ip" ] || return 1
  local b64; b64="$(printf '%s' "$ip" | base64 | tr -d '\n')"
  local r
  r="$(curl -sS --connect-timeout 4 -m 8 -A "$UA" \
       "$base/page/loadConfig?callback=cb&program_index=&wlan_user_ip=$b64&wlan_ac_ip=&wlan_user_ipv6=&jsVersion=4.1" 2>/dev/null)"
  PAGE_PROGRAM="$(printf '%s' "$r" | sed -n 's/.*"program_index":"\([^"]*\)".*/\1/p')"
  PAGE_INDEX="$(printf '%s' "$r" | sed -n 's/.*"page_index":"\([^"]*\)".*/\1/p')"
}

# ---------------------------------------------------------------- logout
logout_now(){
  local host="${PORTAL#*//}"; host="${host%%/*}"
  local base="https://$host:$EP_HTTPS_PORT/eportal/portal"
  local ref="https://$host/"
  local rnd; rnd=$((RANDOM % 9000 + 1000))
  page_indices "$base" "$(local_ip)"

  # The portal tells us who we are: uid is the account, ss5 is the client IP as
  # the portal itself sees it. Both are needed by the unbind call below.
  local st uid cip
  st="$(curl -sS -m 10 -A "$UA" "$PORTAL/drcom/chkstatus?callback=cb&jsVersion=4.2.2" 2>/dev/null)"
  uid="$(printf '%s' "$st" | LC_ALL=C sed -n 's/.*"uid":"\([^"]*\)".*/\1/p')"
  cip="$(printf '%s' "$st" | LC_ALL=C sed -n 's/.*"ss5":"\([^"]*\)".*/\1/p')"
  [ -n "$cip" ] || cip="$(local_ip)"
  log "portal sees us as uid=${uid:-?} ip=${cip:-?}"

  # 1) Unbind the terminal MAC. THIS is the call that actually drops the session.
  #    (The web-mode /drcom/logout endpoint is never used by this deployment:
  #     with unBindMac=1 the page calls user.unbind_mac() instead, which posts
  #     unbind_type=1 here.)
  local r1
  r1="$(curl -sS -m 12 -A "$UA" -H "Referer: $ref" -G "$base/mac/unbind" \
        --data-urlencode "callback=dr$rnd" \
        --data-urlencode "user_account=${uid:-}" \
        --data-urlencode "wlan_user_mac=000000000000" \
        --data-urlencode "wlan_user_ip=$cip" \
        --data-urlencode "wlan_user_ipv6=::" \
        --data-urlencode "unbind_type=1" \
        --data-urlencode "jsVersion=4.2.2" \
        --data-urlencode "program_index=$PAGE_PROGRAM" \
        --data-urlencode "page_index=$PAGE_INDEX" \
        --data-urlencode "v=$((RANDOM % 10000 + 500))" \
        --data-urlencode "lang=zh-cn" 2>/dev/null)"
  log "mac/unbind   -> $r1"

  sleep 2
  if ! online; then log "logged out"; return 0; fi

  # 2) CAS single sign-on sign-off, then follow the returned switch_uri.
  local r2
  r2="$(curl -sS -m 12 -A "$UA" -H "Referer: $ref" -G "$base/cas/logout" \
        --data-urlencode "callback=dr$((rnd + 1))" \
        --data-urlencode "wlan_user_ip=$cip" \
        --data-urlencode "jsVersion=4.2.2" \
        --data-urlencode "program_index=$PAGE_PROGRAM" \
        --data-urlencode "page_index=$PAGE_INDEX" \
        --data-urlencode "v=$((RANDOM % 10000 + 500))" \
        --data-urlencode "lang=zh-cn" 2>/dev/null)"
  log "cas/logout   -> $r2"

  local sw
  sw="$(printf '%s' "$r2" | LC_ALL=C sed -n 's/.*"switch_uri":"\([^"]*\)".*/\1/p' | sed 's#\\/#/#g')"
  if [ -n "$sw" ]; then
    log "cas logout redirect -> $sw"
    curl -sS -m 12 -A "$UA" -o /dev/null "$sw" 2>/dev/null
  fi

  sleep 3
  if online; then
    log "still online after logout"
    return 2
  fi
  log "logged out"
  return 0
}

if [ "$LOGOUT" = 1 ]; then
  logout_now; rc=$?
  if [ "$RELOGIN" = 1 ]; then
    log "logging back in (--relogin)"
    "$SELF_DIR/campus-sso-login.sh" --force
  fi
  exit $rc
fi

# ---------------------------------------------------------------- 0. menu
# A thin wrapper: every entry just re-runs this script with the equivalent
# flags in a child process, so the prompts (password / SMS code) keep working.
menu_loop(){
  local self="$SELF_DIR/$(basename "$0")"
  while :; do
    printf '\n  campus-sso-login\n  --------------------------------------------------\n'
    if online 2>/dev/null; then printf '   network : ONLINE\n'
    else printf '   network : offline (not authenticated)\n'; fi
    printf '   portal  : %s\n' "$PORTAL"
    printf '  --------------------------------------------------\n'
    printf '   1) login                (skip if already online)\n'
    printf '   2) login with an SMS code\n'
    printf '   3) check status\n'
    printf '   4) logout\n'
    printf '   5) logout, then log back in\n'
    printf '   6) force re-authenticate\n'
    printf '   0) quit\n\n'
    printf '  choice [0-6]: '
    read -r pick || return 1
    case "$pick" in
      1) CAMPUS_MENU=0 "$self" --login ;;
      2) CAMPUS_MENU=0 "$self" --sms ;;
      3) CAMPUS_MENU=0 "$self" --check ;;
      4) CAMPUS_MENU=0 "$self" --logout ;;
      5) CAMPUS_MENU=0 "$self" --logout --relogin ;;
      6) CAMPUS_MENU=0 "$self" --login --force ;;
      0|q|quit) return 0 ;;
      *) printf '  not an option\n' >&2 ;;
    esac
    printf '\n  ---- press Enter to return to the menu ----' >&2
    read -r _ || return 1
  done
}

if [ "$MENU" = 1 ]; then menu_loop; exit $?; fi

if [ "$CHECK" = 1 ]; then
  if online; then log "online"; exit 0; fi
  log "not online"; exit 1
fi
if [ "$FORCE" = 0 ] && online; then log "already online, nothing to do"; exit 0; fi

# Credentials are deliberately NOT collected here: cas/create does not need
# them. They are only requested further down, if CAS really serves a login form.

# ---------------------------------------------------------------- 1. client params
if [ -n "$FORCE_REDIRECT" ]; then
  REDIR="$FORCE_REDIRECT"
else
  # The captive portal either answers with a Location header or with a 200 page
  # whose body contains the redirect. Only accept a URL that carries the client
  # parameters - otherwise some unrelated URL in an error/XML page gets picked up.
  CODE="$(curl -s -m 8 -A "$UA" -D "$WORK/probe.hdr" -o "$WORK/probe.body" \
          -w '%{http_code}' "$PROBE" 2>/dev/null)"
  if [ "$CODE" = "204" ]; then log "already online, nothing to do"; exit 0; fi
  REDIR="$(LC_ALL=C grep -i '^location:' "$WORK/probe.hdr" 2>/dev/null | head -1 \
           | sed 's/^[Ll]ocation:[[:space:]]*//' | tr -d '\r')"
  if [ -z "$REDIR" ]; then
    REDIR="$(LC_ALL=C grep -oE "https?://[^'\"<> ]*wlanuserip=[^'\"<> ]*" "$WORK/probe.body" 2>/dev/null | head -1)"
  fi
  if [ -z "$REDIR" ]; then
    log "probe returned HTTP ${CODE:-?} but no portal redirect was found"
    log "first bytes: $(head -c 160 "$WORK/probe.body" 2>/dev/null | tr -d '\n')"
    die "this machine does not look like it is on the campus network (ip $(local_ip 2>/dev/null))"
  fi
fi
log "portal redirect: $REDIR"

getq(){ printf '%s' "$1" | sed -n "s/.*[?&]$2=\([^&]*\).*/\1/p"; }
# The portal page itself declares the eportal ports (epHTTPPort / enHTTPSPort).
# Do not assume 801/802: some VLANs refuse those but serve the page on port 80.
page_ports(){
  local html
  html="$(curl -sS --connect-timeout 5 -m 8 -A "$UA" "$REDIR" 2>/dev/null)"
  local h t
  h="$(printf '%s' "$html" | LC_ALL=C sed -n 's/.*epHTTPPort *= *\([0-9][0-9]*\).*/\1/p' | head -1)"
  t="$(printf '%s' "$html" | LC_ALL=C sed -n 's/.*enHTTPSPort *= *\([0-9][0-9]*\).*/\1/p' | head -1)"
  [ -n "$h" ] && EP_HTTP_PORT="$h"
  [ -n "$t" ] && EP_HTTPS_PORT="$t"
  if [ -n "$h" ] || [ -n "$t" ]; then
    log "portal page declares: http port ${EP_HTTP_PORT}, https port ${EP_HTTPS_PORT}"
  else
    log "could not read the portal page; using default ports ${EP_HTTP_PORT}/${EP_HTTPS_PORT}"
  fi
}

# Some ACs hand out the parameters URL-encoded (wlanssid=HSTC%5FWIFI,
# wlanacname=AC1%5FMaster, wlanacip=172%2E16%2E100%2E11), others do not.
urldecode(){ printf '%b' "$(printf '%s' "$1" | sed 's/%/\\x/g')"; }
SCHEME="$(printf '%s' "$REDIR" | sed -E 's#^(https?)://.*#\1#')"
PHOST="$(printf '%s' "$REDIR" | sed -E 's#^https?://([^/]+).*#\1#' | sed -E 's#:[0-9]+$##')"
WIP="$(urldecode "$(getq "$REDIR" wlanuserip)")"
# The client MAC is called usermac on some ACs and wlanusermac on others.
UMAC="$(getq "$REDIR" usermac)"
[ -n "$UMAC" ] || UMAC="$(getq "$REDIR" wlanusermac)"
ACIP="$(urldecode "$(getq "$REDIR" wlanacip)")"
ACNAME="$(urldecode "$(getq "$REDIR" wlanacname)")"
UMAC="$(printf '%s' "$UMAC" | tr -d ':-' | tr 'A-F' 'a-f')"
[ -n "$WIP" ] && [ -n "$UMAC" ] || die "redirect is missing wlanuserip and usermac/wlanusermac: $REDIR"
log "ip=$WIP mac=$UMAC ac=$ACIP/$ACNAME portal=$SCHEME://$PHOST"
page_ports

# The eportal API is served in plain HTTP on 801 for both the hostname and the
# bare IP, which also sidesteps any certificate trouble on port 802.
# ---------------------------------------------------------------- 2. cas/create
# Which eportal base answers depends on the AC/VLAN the client sits on, so try
# the plain-HTTP and HTTPS variants of both the discovered host and the domain.
AUTHZ=""
for base in "http://$PHOST:$EP_HTTP_PORT/eportal/portal" \
            "https://$PHOST:$EP_HTTPS_PORT/eportal/portal" \
            "http://$PHOST/eportal/portal" \
            "http://rz.hstc.edu.cn:$EP_HTTP_PORT/eportal/portal" \
            "https://rz.hstc.edu.cn:$EP_HTTPS_PORT/eportal/portal"; do
    page_indices "$base" "$WIP"
    rm -f "$WORK/create.body" "$WORK/create.hdr" "$WORK/create.err"
    CODE="$(curl -sS -o "$WORK/create.body" -D "$WORK/create.hdr" -w '%{http_code}' \
      --connect-timeout 5 -m 10 -A "$UA" -H "Referer: $REDIR" -G "$base/cas/create" \
      --data-urlencode "callback=cb" \
      --data-urlencode "program_index=$PAGE_PROGRAM" \
      --data-urlencode "page_index=$PAGE_INDEX" \
      --data-urlencode "v=$((RANDOM % 10000 + 500))" \
      --data-urlencode "lang=zh-cn" \
      --data-urlencode "login_method=1" \
      --data-urlencode "wlan_user_ip=$WIP" \
      --data-urlencode "wlan_user_mac=$UMAC" \
      --data-urlencode "wlan_ac_ip=$ACIP" \
      --data-urlencode "wlan_ac_name=$ACNAME" \
      --data-urlencode "mac_type=$MAC_TYPE" \
      --data-urlencode "jsVersion=4.1" 2>"$WORK/create.err")"
    [ -s "$WORK/create.hdr" ] || { log "  -> unreachable, skipping"; continue; }
    CREATE="$(cat "$WORK/create.body" 2>/dev/null)"
    log "cas/create @ $base -> HTTP ${CODE:-000}, ${#CREATE} bytes, indices=${PAGE_PROGRAM:-none}/${PAGE_INDEX:-none}"
    [ -s "$WORK/create.err" ] && log "  curl: $(tr -d '\n' < "$WORK/create.err")"
    [ -n "$CREATE" ] && log "  body: $(printf '%s' "$CREATE" | head -c 220)"
    AUTHZ="$(printf '%s' "$CREATE" | sed -n 's/.*"authorize_uri":"\([^"]*\)".*/\1/p' | sed 's#\\/#/#g')"
    [ -n "$AUTHZ" ] && break
done
[ -n "$AUTHZ" ] || die "cas/create failed on every endpoint (see $WORK/create.body / create.err)"
log "authorize_uri: $AUTHZ"

# ---------------------------------------------------------------- 3. CAS entry
# CAS often answers 302 first (to drop a session cookie) before serving the
# login page, so follow a few hops manually and keep the cookie jar.
CAS_URL="$AUTHZ"; CAS_PAGE=""; TICKET_SEEN=0
for _hop in 1 2 3 4 5 6; do
  rm -f "$WORK/cas.hdr" "$WORK/cas.body" "$WORK/cas.err"
  curl -sS -m 15 -A "$UA" -c "$JAR" -b "$JAR" -D "$WORK/cas.hdr" -o "$WORK/cas.body" "$CAS_URL" 2>"$WORK/cas.err"
  CAS_PAGE="$(cat "$WORK/cas.body" 2>/dev/null)"
  [ -s "$WORK/cas.hdr" ] || { log "cas page: unreachable"; break; }
  ST="$(LC_ALL=C head -1 "$WORK/cas.hdr" 2>/dev/null | sed -n 's#^HTTP/[0-9.]* \([0-9]*\).*#\1#p')"
  LOC="$(LC_ALL=C grep -i '^location:' "$WORK/cas.hdr" 2>/dev/null | head -1 | sed 's/^[Ll]ocation:[[:space:]]*//' | tr -d '\r')"
  log "cas page: HTTP ${ST:-?}, ${#CAS_PAGE} bytes, first hdr line: $(LC_ALL=C head -1 "$WORK/cas.hdr" 2>/dev/null | tr -d "\r")"
  case "$ST" in 30*) ;; *) break ;; esac
  [ -n "$LOC" ] || break
  case "$LOC" in *ticket=ST-*) TICKET_SEEN=1 ;; esac
  case "$LOC" in
    http*) ;;
    /*) LOC="$(printf '%s' "$CAS_URL" | sed -E 's#^(https?://[^/]+).*#\1#')$LOC" ;;
    *)  LOC="$(printf '%s' "$CAS_URL" | sed -E 's#^(https?://[^/]+).*#\1#')/$LOC" ;;
  esac
  log "  -> following Location: $LOC"
  CAS_URL="$LOC"
done
printf '%s' "$CAS_PAGE" > "$WORK/cas-login.html"

if [ -z "$CAS_PAGE" ]; then
  log "CAS page is empty, curl said: $(tr -d '\n' < "$WORK/cas.err" 2>/dev/null)"
  log "authorize_uri = [$AUTHZ]"
  die "CAS server was not reached (details in $WORK/cas.err)"
fi

if [ "$TICKET_SEEN" = 1 ]; then
  log "CAS issued a ticket without asking for credentials"
  sleep 2
  if online; then log "login OK, network is up"; exit 0; fi
  log "ticket was seen but the probe is still not 204 - falling back to the login form"
fi

EXEC="$(printf '%s' "$CAS_PAGE" | tr '>' '\n' \
        | LC_ALL=C grep -o 'name="execution"[[:space:]]\+value="[^"]*"' \
        | sed -n 's/.*value="\([^"]*\)".*/\1/p' | LC_ALL=C grep -v '\$' | head -1)"
[ -n "$EXEC" ] || die "no execution token (page saved at $WORK/cas-login.html)"
log "execution: ${EXEC:0:32}..."

# ---------------------------------------------------------------- 4a. SMS login
# The SMS code is delivered to the phone, so this path is interactive by nature.
# Flow: POST /cas/passwordlessTokenSend (username=<mobile>), then submit the fm2
# form with _eventId=submitPasswordlessToken and the code in the "password" field.
if [ "$SMS" = 1 ]; then
  if [ -z "$SMS_MOBILE" ] && [ -t 0 ]; then
    printf 'Mobile number: ' >&2
    read -r SMS_MOBILE
  fi
  [ -n "$SMS_MOBILE" ] || die "no mobile number given"

  if [ "$DRY" = 1 ]; then
    log "dry-run: reached the SMS branch, would send a code to $SMS_MOBILE and stop"
    exit 0
  fi

  log "requesting an SMS code for $SMS_MOBILE"
  rm -f "$WORK/sms.body" "$WORK/sms.err"
  SEND="$(curl -sS --connect-timeout 5 -m 15 -A "$UA" -b "$JAR" -c "$JAR" \
        -H "Referer: $AUTHZ" -H "X-Requested-With: XMLHttpRequest" \
        -o "$WORK/sms.body" -X POST "$CAS_BASE/passwordlessTokenSend" \
        --data-urlencode "username=$SMS_MOBILE" 2>"$WORK/sms.err")"
  SEND="$(cat "$WORK/sms.body" 2>/dev/null)"
  log "passwordlessTokenSend -> $SEND"
  [ -s "$WORK/sms.err" ] && log "  curl: $(tr -d '\n' < "$WORK/sms.err")"
  case "$SEND" in
    *'"error"'*) die "the portal refused to send a code: $SEND" ;;
  esac

  printf 'SMS code from your phone: ' >&2
  read -r SMS_CODE
  [ -n "$SMS_CODE" ] || die "no SMS code entered"

  HDR="$WORK/post.hdr"; OUT="$WORK/post.html"
  rm -f "$HDR" "$OUT" "$WORK/post.err"
  curl -sS --connect-timeout 5 -m 25 -A "$UA" -b "$JAR" -c "$JAR" -L --max-redirs 10 \
    -H "Referer: $AUTHZ" -H "Origin: ${CAS_BASE%/cas}" \
    -D "$HDR" -o "$OUT" 2>"$WORK/post.err" \
    --data-urlencode "username=$SMS_MOBILE" \
    --data-urlencode "password=$SMS_CODE" \
    --data-urlencode "captcha=" \
    --data-urlencode "currentMenu=2" \
    --data-urlencode "_eventId=submitPasswordlessToken" \
    --data-urlencode "execution=$EXEC" \
    --data-urlencode "geolocation=" \
    --data-urlencode "failN=-1" \
    "$AUTHZ"

  [ -s "$WORK/post.err" ] && log "post curl said: $(tr -d '\n' < "$WORK/post.err")"
  if LC_ALL=C grep -qi 'ticket=ST-' "$HDR"; then
    log "CAS issued a ticket"
  else
    log "no ticket seen (see $OUT)"
  fi
  sleep 2
  if online; then log "login OK, network is up"; exit 0; fi
  log "still offline. dumps: $HDR  $OUT"
  exit 2
fi

# ---------------------------------------------------------------- 4. RSA encrypt
# Reaching this point means CAS really wants the login form filled in, so this
# is where credentials become necessary.
if [ -z "$USERNAME" ] && [ -t 0 ]; then printf 'Student/Staff ID: ' >&2; read -r USERNAME; fi
if [ -z "$PASSWORD" ] && [ -t 0 ]; then printf 'Unified-auth password (not echoed): ' >&2; read -rs PASSWORD; echo >&2; fi
[ -n "$USERNAME" ] || die "account required: set CAMPUS_USER in $CONF or type it in"
[ -n "$PASSWORD" ] || die "password required: set CAMPUS_PASS in $CONF or type it in"

PUB="$WORK/cas_pub.pem"
curl -sS -m 15 -A "$UA" "$CAS_BASE/jwt/publicKey" -o "$PUB" 2>/dev/null
LC_ALL=C grep -q 'BEGIN PUBLIC KEY' "$PUB" || die "could not fetch the CAS public key"
ENC="$(printf '%s' "$PASSWORD" \
      | openssl pkeyutl -encrypt -pubin -inkey "$PUB" -pkeyopt rsa_padding_mode:pkcs1 2>/dev/null \
      | base64 | tr -d '\n')"
[ -n "$ENC" ] || die "RSA encryption failed"
log "password RSA-encrypted ($(printf '%s' "$ENC" | wc -c | tr -d ' ') base64 chars)"

if [ "$DRY" = 1 ]; then
  log "dry-run finished: the whole chain parsed fine, no password was submitted"
  log "would submit: username=$USERNAME password=__RSA__<hidden> execution=${EXEC:0:20}... _eventId=submit currentMenu=1 failN=-1"
  exit 0
fi

# ---------------------------------------------------------------- 5. POST to CAS
# The encrypted password is fed through stdin (--data-urlencode password@-) so it
# never shows up in the process list.
HDR="$WORK/post.hdr"; OUT="$WORK/post.html"
rm -f "$HDR" "$OUT"
printf '%s' "__RSA__$ENC" | curl -sS -m 25 -A "$UA" -b "$JAR" -c "$JAR" -L --max-redirs 10 \
  -H "Referer: $AUTHZ" -H "Origin: ${CAS_BASE%/cas}" \
  -D "$HDR" -o "$OUT" 2>"$WORK/post.err" \
  --data-urlencode "username=$USERNAME" \
  --data-urlencode "password@-" \
  --data-urlencode "execution=$EXEC" \
  --data-urlencode "_eventId=submit" \
  --data-urlencode "geolocation=" \
  --data-urlencode "mfaState=" \
  --data-urlencode "currentMenu=1" \
  --data-urlencode "failN=-1" \
  "$AUTHZ" 2>/dev/null

if [ -s "$WORK/post.err" ]; then
  log "post curl said: $(tr -d '\n' < "$WORK/post.err")"
fi
log "post: HTTP $(LC_ALL=C head -1 "$HDR" 2>/dev/null | tr -d '\r'), $(wc -c < "$OUT" 2>/dev/null | tr -d ' ') bytes"

if LC_ALL=C grep -qi 'ticket=ST-' "$HDR"; then
  log "CAS issued a ticket"
else
  MSG="$(LC_ALL=C grep -oE 'id="loginError1"[^>]*>[^<]*|msg["'\'': ]+[^,}"<]{2,60}' "$OUT" 2>/dev/null | head -2 | tr '\n' ' ')"
  log "no ticket seen, CAS probably rejected this login. hint: ${MSG:-none}"
fi

# ---------------------------------------------------------------- 6. verify
sleep 2
if online; then log "login OK, network is up"; exit 0; fi
log "still offline. dumps: $HDR  $OUT"
exit 2
