# campus-sso-login.ps1  (ASCII-ONLY, curl.exe based)
# Headless campus-network login for Hanshan Normal University (hstc)
#   Dr.COM portal + school CAS unified identity (hscas.hstc.edu.cn)
#
# HTTP : curl.exe (built into Windows 10 1803+; no .NET web stack quirks)
# RSA  : .NET RSACryptoServiceProvider, PKCS#1 v1.5 (no openssl needed)
#
# Usage:
#   .\campus-sso-login.ps1 -Check      just report online state
#   .\campus-sso-login.ps1 -DryRun     parse the whole chain, do NOT submit password
#   .\campus-sso-login.ps1             login if not already online
#   .\campus-sso-login.ps1 -Force      ignore online state
#   .\campus-sso-login.ps1 -Redirect "<portal redirect url>"   skip auto-discovery
#
# Credentials: -User/-Pass, env CAMPUS_USER/CAMPUS_PASS, campus.conf.ps1,
#              otherwise prompt in the terminal (password is not echoed)

[CmdletBinding()]
param(
    [string]$User = $env:CAMPUS_USER,
    [string]$Pass = $env:CAMPUS_PASS,
    [string]$Redirect = $env:CAMPUS_REDIRECT,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$Check,
    [switch]$Logout,
    [switch]$Sms,
    [string]$Mobile = '',
    [switch]$Menu,
    [switch]$Login,
    [switch]$Help,
    [switch]$Init
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Any unhandled error: print the line number and the offending source line.
trap {
    Write-Host ''
    Write-Host ("UNHANDLED ERROR at line {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message) -ForegroundColor Red
    if ($_.InvocationInfo.Line) { Write-Host ("  >> " + $_.InvocationInfo.Line.Trim()) -ForegroundColor DarkGray }
    Remove-Item $Jar -ErrorAction SilentlyContinue
    exit 1
}

$Probe    = 'http://connect.rom.miui.com/generate_204'
$Portal   = 'https://rz.hstc.edu.cn'
$CasBase  = 'https://hscas.hstc.edu.cn/cas'
# Terminal type reported to the portal: 1 = phone, 0 = anything else.
# The page computes mac_type = (term.type == 2 ? 1 : 0), where term.type is
# 1 PC / 2 phone / 3 tablet, and the value is carried into the CAS "state"
# (second field), which is what the self-service backend displays.
$MacType  = 1
$EpPort   = 801
$EpHttpsPort = 802
$UA       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
$WorkDir  = Join-Path $env:TEMP 'campus-sso'
$Jar      = Join-Path $WorkDir 'cookies.txt'
$Hdr      = Join-Path $WorkDir 'last.hdr'
$Body     = Join-Path $WorkDir 'last.body'

$ConfFile = Join-Path $PSScriptRoot 'campus.conf.ps1'
if (Test-Path $ConfFile) {
    . $ConfFile
    if (-not $User -and $CAMPUS_USER) { $User = $CAMPUS_USER }
    if (-not $Pass -and $CAMPUS_PASS) { $Pass = $CAMPUS_PASS }
    # Optional overrides; the defaults above are a desktop UA and a phone terminal.
    if ($CAMPUS_UA) { $UA = $CAMPUS_UA }
    if ($CAMPUS_MAC_TYPE) { $MacType = [int]$CAMPUS_MAC_TYPE }
}

function Say([string]$m) { Write-Host ("{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }
function Bye([int]$Code) { Remove-Item $Jar -ErrorAction SilentlyContinue; exit $Code }
function Die([string]$m) { Write-Host ("ERROR: {0}" -f $m) -ForegroundColor Red; Bye 1 }

if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    Die 'curl.exe not found (needs Windows 10 1803+)'
}
# Windows' bundled curl uses Schannel, which by default insists on a certificate
# revocation check. On a campus network that is not yet authenticated the CRL/OCSP
# endpoints are unreachable, so the TLS handshake fails with curl exit 35.
# --ssl-no-revoke disables that check. It only exists on Schannel builds.
$script:CurlVer     = ((& curl.exe --version 2>$null) -join ' ')
$script:SslNoRevoke = ($script:CurlVer -match 'Schannel')

# ---------------------------------------------------------------- HTTP helpers
function RunCurl {
    param([string[]]$Extra, [string]$Label = 'curl', [string]$Referer = '')
    Remove-Item $Hdr, $Body -ErrorAction SilentlyContinue
    $errFile = Join-Path $WorkDir 'curl.err'
    Remove-Item $errFile -ErrorAction SilentlyContinue
    $a = @('-sS','-D',$Hdr,'-o',$Body,'--max-time','25','-A',$UA)
    if ($script:SslNoRevoke) { $a += '--ssl-no-revoke' }
    if ($Referer) { $a += @('-H', "Referer: $Referer") }
    $a += $Extra
    & curl.exe @a 2>$errFile | Out-Null
    $script:CurExit = $LASTEXITCODE
    if (Test-Path $errFile) { $script:CurErr = ([IO.File]::ReadAllText($errFile)).Trim() } else { $script:CurErr = '' }
    if (Test-Path $Body)    { $script:CurSize = (Get-Item $Body).Length }              else { $script:CurSize = 0 }
}
function Status {
    $l = Get-Content $Hdr -TotalCount 1 -ErrorAction SilentlyContinue
    if ($l -match 'HTTP/\S+\s+(\d{3})') { return [int]$Matches[1] }
    return 0
}
function HdrVal([string]$Name) {
    $m = Select-String -Path $Hdr -Pattern ("^" + $Name + ":") -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($m) { return ($m.Line -replace ("^" + $Name + ":\s*"), '').Trim() }
    return $null
}
# read bytes 1:1 (Latin-1) so ASCII patterns survive whatever charset the portal uses
function BodyText {
    if (Test-Path $Body) { return [IO.File]::ReadAllText($Body, [Text.Encoding]::GetEncoding(28591)) }
    return ''
}
function Test-Online {
    RunCurl -Extra @($Probe) -Label 'probe'
    return ((Status) -eq 204)
}

# ---------------------------------------------------------------- logout
# This deployment's portal does not use /drcom/logout: with unBindMac=1 its page
# calls user.unbind_mac(), which posts to mac/unbind with unbind_type=1. Taken
# from the page's own traffic:
#   GET :802/eportal/portal/mac/unbind?user_account=..&wlan_user_mac=000000000000
#       &wlan_user_ip=..&wlan_user_ipv6=::&unbind_type=1&...
#   GET :802/eportal/portal/cas/logout?wlan_user_ip=..  -> follow the switch_uri
function Get-LocalIp {
    try {
        return (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.IPAddress -notlike '127.*' } |
                Select-Object -First 1).IPAddress
    } catch { return '' }
}

$script:PageProgram = ''
$script:PageIndex   = ''
# Every portal jsonp call carries program_index / page_index / v / lang on top of
# callback+jsVersion (see util._jsonp). wlan_ac_ip and wlan_user_ipv6 have to be
# present even when empty, otherwise loadConfig answers with an error.
function Get-PageIndices([string]$Base, [string]$ClientIp) {
    $script:PageProgram = ''
    $script:PageIndex   = ''
    if (-not $ClientIp -or -not $Base) { return }
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ClientIp))
    RunCurl -Extra @("$Base/page/loadConfig?callback=cb&program_index=&wlan_user_ip=$b64&wlan_ac_ip=&wlan_user_ipv6=&jsVersion=4.1") -Label 'loadConfig'
    $r  = BodyText
    $m1 = [regex]::Match($r, '"program_index":"([^"]*)"')
    $m2 = [regex]::Match($r, '"page_index":"([^"]*)"')
    if ($m1.Success) { $script:PageProgram = $m1.Groups[1].Value }
    if ($m2.Success) { $script:PageIndex   = $m2.Groups[1].Value }
}

function Do-Logout {
    $h    = ([regex]::Match($Portal, '^https?://([^/]+)')).Groups[1].Value -replace ':\d+$', ''
    $base = "https://${h}:$EpHttpsPort/eportal/portal"
    $ref  = "https://${h}/"
    $rnd  = Get-Random -Minimum 1000 -Maximum 9999

    # Ask the portal who we are: uid is the account, ss5 is the client IP as the
    # portal itself sees it. Both are needed by the unbind call below.
    RunCurl -Extra @("$Portal/drcom/chkstatus?callback=cb&jsVersion=4.2.2") -Label 'chkstatus'
    $st  = BodyText
    $uid = ([regex]::Match($st, '"uid":"([^"]*)"')).Groups[1].Value
    $cip = ([regex]::Match($st, '"ss5":"([^"]*)"')).Groups[1].Value
    if (-not $cip) { $cip = Get-LocalIp }
    Get-PageIndices $base $cip
    Say "portal sees us as uid=$(if ($uid) { $uid } else { '?' }) ip=$(if ($cip) { $cip } else { '?' })"

    # 1) Unbind the terminal MAC - this is the call that actually drops the session.
    RunCurl -Extra @('-G', "$base/mac/unbind",
        '--data-urlencode', "callback=dr$rnd",
        '--data-urlencode', "user_account=$uid",
        '--data-urlencode', 'wlan_user_mac=000000000000',
        '--data-urlencode', "wlan_user_ip=$cip",
        '--data-urlencode', 'wlan_user_ipv6=::',
        '--data-urlencode', 'unbind_type=1',
        '--data-urlencode', 'jsVersion=4.2.2',
        '--data-urlencode', "program_index=$($script:PageProgram)",
        '--data-urlencode', "page_index=$($script:PageIndex)",
        '--data-urlencode', "v=$((Get-Random -Minimum 500 -Maximum 10500))",
        '--data-urlencode', 'lang=zh-cn') -Label 'mac/unbind' -Referer $ref
    Say "mac/unbind   -> $(BodyText)"

    Start-Sleep -Seconds 2
    if (-not (Test-Online)) { Say 'logged out'; Bye 0 }

    # 2) CAS single sign-on sign-off, then follow the returned switch_uri.
    RunCurl -Extra @('-G', "$base/cas/logout",
        '--data-urlencode', "callback=dr$($rnd + 1)",
        '--data-urlencode', "wlan_user_ip=$cip",
        '--data-urlencode', 'jsVersion=4.2.2',
        '--data-urlencode', "program_index=$($script:PageProgram)",
        '--data-urlencode', "page_index=$($script:PageIndex)",
        '--data-urlencode', "v=$((Get-Random -Minimum 500 -Maximum 10500))",
        '--data-urlencode', 'lang=zh-cn') -Label 'cas/logout' -Referer $ref
    $r2 = BodyText
    Say "cas/logout   -> $r2"
    $sw = ([regex]::Match($r2, '"switch_uri":"([^"]*)"')).Groups[1].Value -replace '\\/', '/'
    if ($sw) {
        Say "cas logout redirect -> $sw"
        RunCurl -Extra @($sw) -Label 'cas logout'
    }

    Start-Sleep -Seconds 3
    if (Test-Online) { Say 'still online after logout'; Bye 2 }
    Say 'logged out'
    Bye 0
}

# ---------------------------------------------------------------- entry
if ($Logout) { Do-Logout }
$Interactive = -not [Console]::IsInputRedirected


# ---------------------------------------------------------------- init
function Esc-Dq([string]$v) {
    return $v.Replace('`', '``').Replace('"', '`"').Replace('$', '`$')
}

function Do-Init {
    $conf = Join-Path $PSScriptRoot 'campus.conf.ps1'
    if (Test-Path $conf) {
        $a = Read-Host "$conf already exists. Overwrite it? [y/N]"
        if ($a -notmatch '^(?i:y|yes)$') { Say 'aborted, nothing changed'; return }
    }
    $u = Read-Host 'Student/Staff ID'
    $sec = Read-Host 'Unified-auth password (not echoed)' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try   { $pw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if (-not $u -or -not $pw) { Say 'both fields are required, nothing changed'; return }
    $body = "# created by -Init; never commit this file`r`n" +
            "`$CAMPUS_USER = `"$((Esc-Dq $u))`"`r`n" +
            "`$CAMPUS_PASS = `"$((Esc-Dq $pw))`"`r`n"
    [IO.File]::WriteAllText($conf, $body, [Text.Encoding]::UTF8)
    Say "wrote $conf"
    Say 'note: the password is stored in plain text - keep the file private'
}

if ($Init) {
    Do-Init
    Bye 0
}

if ($Help) {
    Write-Host ''
    Write-Host '  usage: .\\campus-sso-login.cmd [option]'
    Write-Host ''
    Write-Host '    (no option)     log in; skip if already online'
    Write-Host '    -Menu           interactive menu'
    Write-Host '    -Sms <mobile>   log in with an SMS code sent to your phone'
    Write-Host '    -Check          only report the online state'
    Write-Host '    -Init           create campus.conf.ps1 (writes your password to disk)'
    Write-Host '    -Logout         log out (unbind MAC, then CAS sign-off)'
    Write-Host '    -Force          ignore the online state'
    Write-Host '    -DryRun         walk the chain but never submit a password'
    Write-Host '    -Help           show this list'
    Write-Host ''
    Bye 0
}

# ---------------------------------------------------------------- 0. menu
# Same idea as the shell script: each entry re-runs this script with the
# equivalent switch in a child process, so the prompts keep working.
function Show-Menu {
    $self = $PSCommandPath
    while ($true) {
        Write-Host ''
        Write-Host '  hstc-campus-sso-login'
        Write-Host '  --------------------------------------------------'
        if (Test-Online) { Write-Host '   network : ONLINE' }
        else             { Write-Host '   network : offline (not authenticated)' }
        Write-Host ("   portal  : {0}" -f $Portal)
        Write-Host '  --------------------------------------------------'
        Write-Host '   1) login                (skip if already online)'
        Write-Host '   2) login with an SMS code'
        Write-Host '   3) check status'
        Write-Host '   4) logout'
        Write-Host '   5) re-authenticate      (logout, then login again)'
        Write-Host '   7) create campus.conf.ps1  (saves your password to disk)'
        Write-Host '   h) all options'
        Write-Host '   0) quit'
        Write-Host ''
        $pick = Read-Host '  choice'
        if ($pick -eq '0') { return }
        switch ($pick) {
            '1' { & $self -Login }
            '2' { & $self -Sms }
            '3' { & $self -Check }
            '4' { & $self -Logout }
            '5' { & $self -Logout; & $self -Login }
            '7' { & $self -Init }
            'h' { & $self -Help }
            default { Write-Host '  not an option'; continue }
        }
        $null = Read-Host '  ---- press Enter to return to the menu ----'
    }
}

if ($Menu) {
    Show-Menu
    Bye 0
}

if (-not $Force -and (Test-Online)) { Say 'Already online, nothing to do'; Bye 0 }
if ($Check) { Say 'Not online'; Bye 1 }
if ($DryRun) { $Force = $true }


if (-not $User -and $Interactive) {
    $u = Read-Host 'Student/Staff ID'
    if ($u) { $User = $u.Trim() }
}
if (-not $Pass -and $Interactive) {
    $sec  = Read-Host 'Unified-auth password' -AsSecureString
    $Pass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}
if (-not $User) { Die 'No account (-User / CAMPUS_USER / campus.conf.ps1 / prompt)' }
if (-not $Pass) { Die 'No password (-Pass / CAMPUS_PASS / campus.conf.ps1 / prompt)' }

# ---------------------------------------------------------------- 1. portal redirect
if ($Redirect) {
    $redir = $Redirect
}
else {
    RunCurl -Extra @($Probe) -Label 'probe'
    $pc = Status
    if ($pc -eq 204) { Say 'Already online, nothing to do'; Bye 0 }
    $redir = HdrVal 'Location'
    # Only accept a URL that carries the client parameters; otherwise an unrelated
    # URL from an error/XML page would be picked up (e.g. an XML namespace).
    if (-not $redir) { $redir = ([regex]::Match((BodyText), "https?://[^'`"<> ]*wlanuserip=[^'`"<> ]*")).Value }
    if (-not $redir) {
        $b = BodyText
        if ($b.Length -gt 160) { $b = $b.Substring(0, 160) }
        Say ("probe HTTP status = {0}" -f $pc)
        Say ("probe first bytes = [{0}]" -f $b)
        Say ("curl exit = {0}" -f $script:CurExit)
        Say ("curl stderr = " + $(if ($script:CurErr) { $script:CurErr } else { '(empty)' }))
        Say ("this host's ip = " + (Get-LocalIp))
        Die 'this machine does not look like it is on the campus network (use -Redirect to override)'
    }
}
Say "Portal redirect: $redir"

function Get-Q([string]$u, [string]$n) {
    $m = [regex]::Match($u, "[?&]$([regex]::Escape($n))=([^&]*)")
    if ($m.Success) { return $m.Groups[1].Value } else { return $null }
}

$scheme = ([regex]::Match($redir, '^(https?)://')).Groups[1].Value
$phost  = ([regex]::Match($redir, '^https?://([^/]+)')).Groups[1].Value -replace ':\d+$', ''
# Some ACs hand out the parameters URL-encoded (wlanssid=HSTC%5FWIFI,
# wlanacname=AC1%5FMaster, wlanacip=172%2E16%2E100%2E11), others do not.
function URL-Dec([string]$s) { if ($s) { return [uri]::UnescapeDataString($s) } return $s }
$wip    = URL-Dec (Get-Q $redir 'wlanuserip')
# The client MAC is called usermac on some ACs and wlanusermac on others.
$umac   = (Get-Q $redir 'usermac') -replace '[:-]', ''
if (-not $umac) { $umac = (Get-Q $redir 'wlanusermac') -replace '[:-]', '' }
$acip   = URL-Dec (Get-Q $redir 'wlanacip')
$acname = URL-Dec (Get-Q $redir 'wlanacname')
if (-not $wip -or -not $umac) { Die "Redirect missing wlanuserip and usermac/wlanusermac: $redir" }
Say "ip=$wip mac=$umac ac=$acip/$acname portal=${scheme}://${phost}"

# The portal page itself declares the eportal ports (epHTTPPort / enHTTPSPort).
# Read them instead of assuming 801/802, then fall back to the defaults.
$pageHtml = ''
RunCurl -Extra @($redir) -Label 'portal page'
$pageHtml = BodyText
if ($pageHtml) {
    $mh = [regex]::Match($pageHtml, 'epHTTPPort\s*=\s*(\d+)')
    $mt = [regex]::Match($pageHtml, 'enHTTPSPort\s*=\s*(\d+)')
    if ($mh.Success) { $EpPort = [int]$mh.Groups[1].Value }
    if ($mt.Success) { $EpHttpsPort = [int]$mt.Groups[1].Value }
    Say "portal page declares: http port $EpPort, https port $EpHttpsPort"
} else {
    Say "could not read the portal page; using default ports $EpPort/$EpHttpsPort"
}

# ---------------------------------------------------------------- 2. cas/create
# Which eportal base answers depends on the AC/VLAN, so try several and report
# what each one said. Referer matches what the a79 page would send.
$bases = @(
    "http://${phost}:$EpPort/eportal/portal",
    "https://${phost}:$EpHttpsPort/eportal/portal",
    "http://${phost}/eportal/portal",
    "http://rz.hstc.edu.cn:$EpPort/eportal/portal",
    "https://rz.hstc.edu.cn:$EpHttpsPort/eportal/portal"
)
$authz = ''; $create = ''
foreach ($base in $bases) {
    Get-PageIndices $base $wip
    RunCurl -Extra @('-G', "$base/cas/create",
        '--data-urlencode', 'callback=cb',
        '--data-urlencode', "program_index=$($script:PageProgram)",
        '--data-urlencode', "page_index=$($script:PageIndex)",
        '--data-urlencode', "v=$((Get-Random -Minimum 500 -Maximum 10500))",
        '--data-urlencode', 'lang=zh-cn',
        '--data-urlencode', 'login_method=1',
        '--data-urlencode', "wlan_user_ip=$wip",
        '--data-urlencode', "wlan_user_mac=$umac",
        '--data-urlencode', "wlan_ac_ip=$acip",
        '--data-urlencode', "wlan_ac_name=$acname",
        '--data-urlencode', "mac_type=$MacType",
        '--data-urlencode', 'jsVersion=4.1') -Label 'cas/create' -Referer $redir
    $create = BodyText
    $st     = Status
    Say ("cas/create @ {0} -> HTTP {1}, {2} chars, indices={3}/{4}" -f $base, $st, $create.Length, $(if ($script:PageProgram) { $script:PageProgram } else { 'none' }), $(if ($script:PageIndex) { $script:PageIndex } else { 'none' }))
    if ($script:CurErr) { Say ("  curl: " + $script:CurErr) }
    if ($create) {
        if ($create.Length -gt 220) { Say ("  body: " + $create.Substring(0, 220)) } else { Say ("  body: " + $create) }
    }
    $m = [regex]::Match($create, '"authorize_uri":"([^"]*)"')
    if ($m.Success) { $authz = $m.Groups[1].Value -replace '\\/', '/'; break }
}
if (-not $authz) { Die 'cas/create failed on every endpoint' }
Say "authorize_uri: $authz"

# ---------------------------------------------------------------- 3. execution token
# CAS often answers 302 first (dropping a session cookie) before serving the login
# page, so follow a few hops manually and keep the cookie jar.
$casUrl  = $authz
$casPage = ''
$ticketSeen = $false
for ($hop = 0; $hop -lt 6; $hop++) {
    RunCurl -Extra @('-c', $Jar, '-b', $Jar, $casUrl) -Label 'cas page' | Out-Null
    $st      = Status
    $casPage = BodyText
    Say ("cas page: HTTP {0}, {1} bytes, curl exit={2}" -f $st, $casPage.Length, $script:CurExit)
    if ($st -ge 300 -and $st -lt 400) {
        $loc = HdrVal 'Location'
        if ($loc -match 'ticket=ST-') { $ticketSeen = $true }
        if (-not $loc) { break }
        if ($loc -notmatch '^https?://') {
            $origin = ([regex]::Match($casUrl, '^https?://[^/]+')).Value
            if ($loc.StartsWith('/')) { $loc = $origin + $loc } else { $loc = $origin + '/' + $loc }
        }
        Say ("  -> following Location: {0}" -f $loc)
        $casUrl = $loc
        continue
    }
    break
}
[IO.File]::WriteAllText((Join-Path $WorkDir 'cas-login.html'), $casPage, [Text.Encoding]::UTF8)

if (-not $casPage) {
    Say ("curl exit    : {0}" -f $script:CurExit)
    Say ("curl stderr  : " + $(if ($script:CurErr) { $script:CurErr } else { '(empty)' }))
    Say ("curl version : " + $script:CurlVer)
    Say ("ssl-no-revoke: " + $script:SslNoRevoke)
    Say ("authorize_uri = [" + $authz + "]")
    Die 'CAS page is empty - the CAS server was not reached'
}

# If CAS already trusted this client (IP-level SSO, or the authorization link that
# cas/create just registered) it hands out a ticket immediately and there is no
# login form at all. In that case go straight to the connectivity check.
if ($ticketSeen) {
    Say 'CAS issued a ticket without prompting for credentials'
    Start-Sleep -Seconds 2
    if (Test-Online) { Say 'Login OK, network is up'; Bye 0 }
    Say 'Ticket was seen but the probe is still not 204; falling back to the login form'
}

$m = [regex]::Match($casPage, 'name="execution"\s+value="([^"]+)"')
if (-not $m.Success) {
    Say ("CAS response head: " + $casPage.Substring(0, [Math]::Min(300, $casPage.Length)))
    Die "No execution token (see $WorkDir\cas-login.html)"
}
$exec = $m.Groups[1].Value
Say ("execution: " + $exec.Substring(0, [Math]::Min(32, $exec.Length)) + '...')

# ---------------------------------------------------------------- 4a. SMS login
# The code is delivered to the phone, so this path is interactive by nature.
# Flow: POST /cas/passwordlessTokenSend (username=<mobile>), then submit the fm2
# form with _eventId=submitPasswordlessToken and the code in the "password" field.
if ($Sms) {
    $mob = $Mobile
    if (-not $mob -and $Interactive) { $mob = (Read-Host 'Mobile number').Trim() }
    if (-not $mob) { Die 'no mobile number given (-Sms 138xxxxxxxx)' }

    if ($DryRun) {
        Say "dry-run: reached the SMS branch, would send a code to $mob and stop"
        Bye 0
    }

    Say "requesting an SMS code for $mob"
    RunCurl -Extra @('-X', 'POST', "$CasBase/passwordlessTokenSend",
        '-H', 'X-Requested-With: XMLHttpRequest',
        '--data-urlencode', "username=$mob") -Label 'passwordlessTokenSend' -Referer $authz
    $send = BodyText
    Say "passwordlessTokenSend -> $send"
    if ($script:CurErr) { Say ("  curl: " + $script:CurErr) }
    if ($send -match '"error"') { Die "the portal refused to send a code: $send" }

    $smsCode = Read-Host 'SMS code from your phone'
    if (-not $smsCode) { Die 'no SMS code entered' }

    RunCurl -Extra @('-L', '--max-redirs', '10',
        '-H', ("Origin: " + ($CasBase -replace '/cas$', '')),
        '--data-urlencode', "username=$mob",
        '--data-urlencode', "password=$smsCode",
        '--data-urlencode', 'captcha=',
        '--data-urlencode', 'currentMenu=2',
        '--data-urlencode', '_eventId=submitPasswordlessToken',
        '--data-urlencode', "execution=$exec",
        '--data-urlencode', 'geolocation=',
        '--data-urlencode', 'failN=-1',
        $authz) -Label 'sms login' -Referer $authz

    $smsBody = BodyText
    if ($script:CurErr) { Say ("  curl: " + $script:CurErr) }
    $allHdr = Get-Content $Hdr -Raw -ErrorAction SilentlyContinue
    if ($allHdr -match 'ticket=ST-') { Say 'CAS issued a ticket' }
    else { Say 'no ticket seen (see last.hdr)' }
    if ($smsBody -and $smsBody.Length -gt 300) { $smsBody = $smsBody.Substring(0, 300) }
    if ($smsBody) { Say ("  body: " + $smsBody) }

    Start-Sleep -Seconds 2
    if (Test-Online) { Say 'login OK, network is up'; Bye 0 }
    Say 'still offline'
    Bye 2
}

# ---------------------------------------------------------------- 4. RSA encrypt
RunCurl -Extra @("$CasBase/jwt/publicKey") -Label 'public key'
$pem = BodyText
if ($pem -notmatch 'BEGIN PUBLIC KEY') { Die 'Failed to fetch CAS public key' }

$b64 = ($pem -replace '-----[^-]+-----', '') -replace '\s', ''
$der = [Convert]::FromBase64String($b64)

function Get-DerLen { param([byte[]]$d, [ref]$i)
    $l = $d[$i.Value]; $i.Value++
    if ($l -band 0x80) {
        $n = $l -band 0x7F; $l = 0
        for ($k = 0; $k -lt $n; $k++) { $l = ($l -shl 8) -bor $d[$i.Value]; $i.Value++ }
    }
    return $l
}

$i = 0
if ($der[$i] -ne 0x30) { Die 'Public key is not SPKI' }; $i++
$null = Get-DerLen $der ([ref]$i)
if ($der[$i] -ne 0x30) { Die 'Missing AlgorithmIdentifier' }; $i++
$algLen = Get-DerLen $der ([ref]$i); $i += $algLen
if ($der[$i] -ne 0x03) { Die 'Missing BIT STRING' }; $i++
$null = Get-DerLen $der ([ref]$i); $i++          # skip the unused-bits byte
if ($der[$i] -ne 0x30) { Die 'Missing RSAPublicKey' }; $i++
$null = Get-DerLen $der ([ref]$i)
if ($der[$i] -ne 0x02) { Die 'Missing modulus' }; $i++
$mLen = Get-DerLen $der ([ref]$i)
$modulus = New-Object byte[] $mLen
[Array]::Copy($der, $i, $modulus, 0, $mLen); $i += $mLen
if ($der[$i] -ne 0x02) { Die 'Missing exponent' }; $i++
$eLen = Get-DerLen $der ([ref]$i)
$exponent = New-Object byte[] $eLen
[Array]::Copy($der, $i, $exponent, 0, $eLen)
if ($modulus[0] -eq 0) { $modulus = $modulus[1..($modulus.Length - 1)] }

$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
$rsa.PersistKeyInCsp = $false
$rp = New-Object System.Security.Cryptography.RSAParameters
$rp.Modulus  = $modulus
$rp.Exponent = $exponent
$rsa.ImportParameters($rp)
$encB64 = [Convert]::ToBase64String($rsa.Encrypt([Text.Encoding]::UTF8.GetBytes($Pass), $false))
Say ("Password RSA-encrypted ({0} chars base64)" -f $encB64.Length)

if ($DryRun) {
    Say 'dry-run done: whole chain parsed OK, password NOT submitted'
    Say "Would submit: username=$User password=__RSA__<hidden> execution=$($exec.Substring(0,20))... _eventId=submit"
    Bye 0
}

# ---------------------------------------------------------------- 5. submit to CAS
$uri    = $authz
$method = 'POST'
$final  = $null
$sawTicket = $false

for ($hop = 0; $hop -lt 10; $hop++) {
    if ($method -eq 'POST') {
        RunCurl -Extra @('-c', $Jar, '-b', $Jar,
            '--data-urlencode', "username=$User",
            '--data-urlencode', "password=__RSA__$encB64",
            '--data-urlencode', "execution=$exec",
            '--data-urlencode', '_eventId=submit',
            '--data-urlencode', 'geolocation=',
            '--data-urlencode', 'mfaState=',
            '--data-urlencode', 'currentMenu=1',
            '--data-urlencode', 'failN=-1',
            $uri) -Label 'cas post' -Referer $redir
    } else {
        RunCurl -Extra @('-c', $Jar, '-b', $Jar, $uri) -Label 'redirect'
    }

    $code = Status
    if ($script:CurErr) { Say ("  curl: " + $script:CurErr) }
    if ($code -ge 300 -and $code -lt 400) {
        $loc = HdrVal 'Location'
        if ($loc -match 'ticket=ST-') { $sawTicket = $true }
        Say ("  [{0}] -> {1}" -f $code, $loc)
        $uri = $loc; $method = 'GET'; continue
    }
    $final = @{ Code = $code; Body = (BodyText) }
    break
}

if ($sawTicket) { Say 'CAS issued a ticket' }
else            { Say 'No ticket seen; CAS may have rejected this login' }

if ($final) {
    Say ("final HTTP status = {0}" -f $final.Code)
    if ($final.Body) {
        [IO.File]::WriteAllText((Join-Path $WorkDir 'post.html'), $final.Body, [Text.Encoding]::UTF8)
        $err = [regex]::Match($final.Body, 'id="loginError1"[^>]*>\s*([^<]{2,80})')
        if ($err.Success) { Say ("CAS says: " + $err.Groups[1].Value.Trim()) }
    }
}

# ---------------------------------------------------------------- 6. verify
Start-Sleep -Seconds 2
if (Test-Online) { Say 'Login OK, network is up'; Bye 0 }
Say "Still offline. Dump dir: $WorkDir"
Bye 2
