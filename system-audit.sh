#!/bin/bash
# ============================================================
#  System Audit: security & health check
#  Debian / Ubuntu (graceful fallback for other distros)
#  Read-only: the script changes nothing, only reports.
#
#  Exit codes:
#    0  no FAIL verdicts (clean, or warnings only)
#    1  at least one FAIL verdict (the audit found a problem)
#    2  the script itself could not run a step (distinct from a finding)
# ============================================================

set -uo pipefail
export LC_ALL=C LANG=C       # keep parsed command output locale-independent

# ── Config ───────────────────────────────────────────────────
LOG_FILE="/var/log/system-audit.log"
UPTIME_WARN_DAYS=180      # warn if the box hasn't rebooted in this long
APT_STALE_DAYS=7          # warn if package metadata is older than this
MEM_WARN_PCT=90           # warn if memory usage reaches this
LOGIN_WARN_COUNT=100      # warn if failed SSH logins (24h) reach this
TEMP_WARN_C=80            # warn if any sensor reaches this (°C)
TEMP_CRIT_C=90            # fail if any sensor reaches this (°C)
LOAD_WARN_RATIO=1.0       # warn if 5-min loadavg per core reaches this
LOAD_FAIL_RATIO=2.0       # fail if 5-min loadavg per core reaches this
JOURNAL_WARN_MB=5120      # warn if the journal grows past this (MB)

# ── Decide colour from the REAL stdout, before any redirection ──
if [ -t 1 ]; then USE_COLOR=1; else USE_COLOR=0; fi

# ── Logging ──────────────────────────────────────────────────
# Colour stream goes live to the terminal; an ANSI-stripped copy is
# appended to the log. A single background "tee | sed" pipeline is used
# so that one wait() at exit flushes everything (no lost final lines).
LOG_PID=""
LOG_ACTIVE=0
if { mkdir -p "$(dirname "$LOG_FILE")" && : >> "$LOG_FILE"; } 2>/dev/null; then
    fifo=$(mktemp -u 2>/dev/null) || fifo=""
    if [ -n "$fifo" ] && mkfifo "$fifo" 2>/dev/null; then
        exec 3>&1
        ( tee /dev/fd/3 < "$fifo" | sed -E 's/\x1b\[[0-9;?]*[a-zA-Z]//g' >> "$LOG_FILE" ) &
        LOG_PID=$!
        exec > "$fifo" 2>&1
        rm -f "$fifo"
        LOG_ACTIVE=1
    fi
fi
[ "$LOG_ACTIVE" -eq 1 ] || LOG_FILE="(disabled — no write access)"

# shellcheck disable=SC2317  # invoked indirectly via `trap cleanup EXIT`
cleanup() {
    local rc=$?
    if [ "$LOG_ACTIVE" -eq 1 ]; then
        exec >&3 2>&3 3>&- 2>/dev/null || true   # close the fifo, let tee see EOF
        if [ -n "$LOG_PID" ]; then wait "$LOG_PID" 2>/dev/null || true; fi
    fi
    exit "$rc"
}
trap cleanup EXIT

echo ""
echo "════ Start: $(date '+%Y-%m-%d %H:%M:%S') ════"

# ── Colours (empty when not a TTY, so logs/pipes stay clean) ──
if [ "$USE_COLOR" -eq 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
    BOLD='\033[1m';   CYAN='\033[0;36m';  GRAY='\033[0;90m';   NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; CYAN=''; GRAY=''; NC=''
fi

# ── Verdict counters ─────────────────────────────────────────
OK_COUNT=0; WARN_COUNT=0; FAIL_COUNT=0

info()    { echo -e "${BLUE}[*]${NC} $1"; }
pass()    { echo -e "${GREEN}[✓]${NC} $1"; OK_COUNT=$((OK_COUNT+1)); }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; WARN_COUNT=$((WARN_COUNT+1)); }
fail()    { echo -e "${RED}[✗]${NC} $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }
skip()    { echo -e "${CYAN}[~]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 2; }   # fatal: script could not run
header()  { echo -e "\n${BOLD}${BLUE}══ $1 ══${NC}"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# NOTE: no `set -e` and no fatal ERR trap. This is a read-only audit: a stray
# non-zero from one stat/grep/awk must not abort the whole report. Each check
# is self-contained and reports its own verdict; the process exit code (above)
# stays meaningful for monitoring.

# ── Hard requirements (the only fatal path → exit 2) ─────────
for _t in awk grep sed date stat; do
    have "$_t" || error "Required tool '$_t' not found — cannot run audit"
done

# ── Globals filled by init ───────────────────────────────────
IS_ROOT=0
PRETTY_NAME="unknown"
SSH_CFG=""

init() {
    [ "${EUID:-$(id -u)}" -eq 0 ] && IS_ROOT=1 || IS_ROOT=0
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        source /etc/os-release
    fi
    return 0
}

# ── Shared helpers ───────────────────────────────────────────
# sshd applies the FIRST matching keyword and switches scope at the first
# Match block. The file fallback emulates that: stop at the first Match,
# take the first occurrence, ignore comments (it cannot resolve Match-scoped
# directives — those are reported by `sshd -T` only, which needs root).
get_ssh() {  # get_ssh <param-lowercase>
    if [ -n "$SSH_CFG" ]; then
        printf '%s\n' "$SSH_CFG" | awk -v k="$1" 'tolower($1)==k {print tolower($2); exit}'
    else
        awk -v k="$1" '
            tolower($1)=="match" { exit }
            tolower($1)==k       { print tolower($2); exit }
        ' /etc/ssh/sshd_config 2>/dev/null
    fi
    return 0
}

check_perm() {  # check_perm <path> <expected-mode> [expected-owner=root]
    local path="$1" want="$2" owner="${3:-root}" perm cur
    [ -e "$path" ] || { skip "$path missing"; return 0; }
    perm=$(stat -c '%a' "$path" 2>/dev/null || echo "?")
    cur=$(stat -c '%U' "$path" 2>/dev/null || echo "?")
    if [ "$perm" = "$want" ] && [ "$cur" = "$owner" ]; then
        pass "$path = $perm ($cur)"
    else
        warn "$path = $perm ($cur), expected $want ($owner)"
    fi
    return 0
}

check_no_world() {  # file must not be accessible by 'others'
    local path="$1" perm other
    [ -e "$path" ] || { skip "$path missing"; return 0; }
    perm=$(stat -c '%a' "$path" 2>/dev/null || echo "000")
    other=$(( perm % 10 ))
    if [ "$other" -eq 0 ]; then
        pass "$path = $perm (no access for others)"
    else
        fail "$path = $perm (accessible by other users!)"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════
print_banner() {
    [ "$USE_COLOR" -eq 1 ] && { clear 2>/dev/null || true; }
    echo -e "${BOLD}${BLUE}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║        System Audit — security check     ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  Host: ${GREEN}$(hostname)${NC}"
    echo -e "  OS:   ${GREEN}${PRETTY_NAME}${NC}"
    echo -e "  Date: ${GREEN}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "  Log:  ${GREEN}${LOG_FILE}${NC}"
    [ "$IS_ROOT" -eq 0 ] && warn "Running without root — some checks will be partial (sshd -T, smartctl, fail2ban, wg, lastb, docker)"
    return 0
}

# ══════════════════════════════════════════════════════════════
# 1. OPEN PORTS
# ══════════════════════════════════════════════════════════════
check_ports() {
    header "Open ports"
    if ! have ss; then warn "ss not found — skipping port scan"; return 0; fi

    local listen netid laddr process name port addr
    local ssh_found=0 ssh_exposed=0
    listen=$(ss -H -tulpn 2>/dev/null || true)
    if [ -z "$listen" ]; then
        info "No listening sockets found (or insufficient privileges)"
        return 0
    fi

    while read -r netid _ _ _ laddr _ process; do
        [ -n "$netid" ] || continue
        # Extract program name from users:(("name",pid=..,fd=..))
        name=$(printf '%s' "$process" | sed -nE 's/.*\(\("([^"]+)".*/\1/p')
        [ -z "$name" ] && name="-"
        # Colour passed as args, never embedded in the format string.
        printf '    %s%-4s %-24s %s%s\n' "$GRAY" "$netid" "$laddr" "$name" "$NC"

        # SSH exposure is judged on the LOCAL bind address/port ONLY.
        # (Parsing the whole line is wrong: every socket shows peer 0.0.0.0:*.)
        port="${laddr##*:}"
        addr="${laddr%:*}"
        if [ "$port" = "22" ]; then
            ssh_found=1
            case "$addr" in
                0.0.0.0|'*'|'[::]'|'::') ssh_exposed=1 ;;
            esac
        fi
    done <<< "$listen"

    if [ "$ssh_found" -eq 1 ]; then
        if [ "$ssh_exposed" -eq 1 ]; then
            warn "Port 22 exposed (SSH bound to a wildcard address)"
        else
            pass "SSH bound to specific/loopback addresses only"
        fi
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 2. FIREWALL
# ══════════════════════════════════════════════════════════════
check_firewall() {
    header "Firewall"
    if have ufw; then
        # Capture first, then match: piping ufw into head/grep can SIGPIPE
        # under pipefail and be misread as inactive. Anchor to avoid the
        # 'inactive' substring matching 'active'.
        local st
        st=$(ufw status 2>/dev/null || true)
        if printf '%s\n' "$st" | grep -qiE '^Status:[[:space:]]+active'; then
            pass "UFW active"
        else
            fail "UFW inactive"
        fi
    elif have nft; then
        if nft list ruleset 2>/dev/null | grep -qE 'chain|rule'; then
            pass "nftables: ruleset loaded"
        else
            fail "nftables: empty ruleset"
        fi
    elif have iptables; then
        local rules
        rules=$(iptables -S 2>/dev/null | grep -cvE '^-P|^$' || true)
        if [ "${rules:-0}" -gt 0 ]; then
            pass "iptables: $rules custom rule(s)"
        else
            warn "iptables: default policies only, no rules"
        fi
    else
        fail "No firewall found (ufw / nftables / iptables)"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 3. SSH
# ══════════════════════════════════════════════════════════════
check_ssh() {
    header "SSH"
    if [ "$IS_ROOT" -eq 1 ] && have sshd; then
        SSH_CFG=$(sshd -T 2>/dev/null || true)
    fi

    if [ -z "$SSH_CFG" ] && [ ! -r /etc/ssh/sshd_config ]; then
        warn "SSH config not readable"
        return 0
    fi
    [ -z "$SSH_CFG" ] && info "Using sshd_config fallback (Match blocks not resolved; run as root for sshd -T)"

    local prl pwauth empty port
    prl=$(get_ssh permitrootlogin)
    case "$prl" in
        no)                                  pass "PermitRootLogin: no" ;;
        prohibit-password|without-password)  warn "PermitRootLogin: $prl (root via key allowed)" ;;
        yes)                                 fail "PermitRootLogin: yes (root via password allowed)" ;;
        "")                                  warn "PermitRootLogin: undefined (default = prohibit-password)" ;;
        *)                                   warn "PermitRootLogin: $prl" ;;
    esac

    pwauth=$(get_ssh passwordauthentication)
    case "$pwauth" in
        no)  pass "SSH password auth disabled" ;;
        yes) fail "SSH password authentication enabled" ;;
        "")  warn "PasswordAuthentication: undefined" ;;
        *)   warn "PasswordAuthentication: $pwauth" ;;
    esac

    empty=$(get_ssh permitemptypasswords)
    [ "$empty" = "yes" ] && fail "PermitEmptyPasswords: yes (empty passwords allowed!)"

    port=$(get_ssh port)
    { [ -n "$port" ] && [ "$port" != "22" ]; } && info "SSH port changed to $port"
    return 0
}

# ══════════════════════════════════════════════════════════════
# 4. FAILED SSH LOGINS (last 24h)
# ══════════════════════════════════════════════════════════════
check_failed_logins() {
    header "Failed SSH logins (24h)"
    local n="" src="" since
    if have journalctl; then
        n=$(journalctl -u ssh -u sshd --since "24 hours ago" --no-pager 2>/dev/null \
            | grep -ciE 'Failed password|Invalid user|authentication failure' || true)
        src="journal"
        [ "$IS_ROOT" -eq 0 ] && src="journal — may undercount without root"
    elif have lastb && [ "$IS_ROOT" -eq 1 ]; then
        since=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)
        if [ -n "$since" ] && lastb --since "$since" >/dev/null 2>&1; then
            n=$(lastb --since "$since" 2>/dev/null | grep -cvE '^$|^btmp' || true)
            src="btmp, last 24h"
        else
            n=$(lastb 2>/dev/null | grep -cvE '^$|^btmp' || true)
            src="btmp, all time"
        fi
    else
        skip "journalctl/lastb unavailable — skipping"
        return 0
    fi

    n=${n:-0}
    if [ "$n" -eq 0 ]; then
        pass "No failed SSH logins ($src)"
    elif [ "$n" -ge "$LOGIN_WARN_COUNT" ]; then
        warn "Failed SSH logins: $n ($src) — possible brute force, check fail2ban"
    else
        info "Failed SSH logins: $n ($src)"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 5. UPDATES (cache-only: the script never hits the network)
# ══════════════════════════════════════════════════════════════
check_updates() {
    header "Available updates"
    if have apt-get; then
        local sim upd sec
        sim=$(apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null || true)
        upd=$(printf '%s\n' "$sim" | grep -cE '^Inst ' || true)
        sec=$(printf '%s\n' "$sim" | grep -E '^Inst ' | grep -ic -- '-security' || true)
        if [ "${upd:-0}" -eq 0 ]; then
            pass "System up to date (no upgradable packages)"
        elif [ "${sec:-0}" -gt 0 ]; then
            fail "Updates available: $upd (security: $sec)"
        else
            warn "Updates available: $upd"
        fi
        [ -f /var/run/reboot-required ] && warn "Reboot required (/var/run/reboot-required)"
    elif have dnf; then
        if dnf -C -q check-update >/dev/null 2>&1; then
            pass "System up to date (per local cache)"
        else
            local cnt
            cnt=$(dnf -C -q check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]' || true)
            warn "Updates available: ${cnt:-?} (cache; run 'dnf check-update' to refresh)"
        fi
    elif have pacman; then
        local cnt
        cnt=$(pacman -Qu 2>/dev/null | grep -c . || true)
        if [ "${cnt:-0}" -eq 0 ]; then
            pass "System up to date (per local DB)"
        else
            warn "Updates available: $cnt (local DB; sync with 'pacman -Sy')"
        fi
    elif have zypper; then
        local cnt
        cnt=$(zypper -q --no-refresh list-updates 2>/dev/null | grep -cE '^v ' || true)
        if [ "${cnt:-0}" -eq 0 ]; then
            pass "System up to date (per cache)"
        else
            warn "Updates available: $cnt"
        fi
    else
        info "Package manager not recognized — skipping update check"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 6. PACKAGE METADATA AGE
# ══════════════════════════════════════════════════════════════
check_update_age() {
    header "Package metadata age"
    local ts now age stamp
    now=$(date +%s)
    if have apt-get; then
        if [ -f /var/lib/apt/periodic/update-success-stamp ]; then
            stamp=/var/lib/apt/periodic/update-success-stamp
        else
            stamp=/var/lib/apt/lists
        fi
        ts=$(stat -c %Y "$stamp" 2>/dev/null || echo 0)
    elif have dnf; then
        ts=$(stat -c %Y /var/cache/dnf 2>/dev/null || echo 0)
    else
        skip "no apt/dnf — skipping metadata age"
        return 0
    fi

    if [ "${ts:-0}" -eq 0 ]; then
        info "Update timestamp unknown"
        return 0
    fi
    age=$(( (now - ts) / 86400 ))
    if [ "$age" -ge "$APT_STALE_DAYS" ]; then
        warn "Package metadata outdated: last refresh ${age}d ago"
    else
        pass "Package metadata fresh (refreshed ${age}d ago)"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 7. FILE PERMISSIONS
# ══════════════════════════════════════════════════════════════
check_permissions() {
    header "File permissions"
    check_perm     /etc/passwd          644
    check_no_world /etc/shadow
    check_no_world /etc/gshadow
    check_perm     /etc/sudoers         440
    check_perm     /etc/ssh/sshd_config 600
    return 0
}

# ══════════════════════════════════════════════════════════════
# 8. SUDO USERS
# ══════════════════════════════════════════════════════════════
check_sudo_users() {
    header "Sudo users"
    local grp m users direct zerouid
    users=""
    for grp in sudo wheel admin; do
        if getent group "$grp" >/dev/null 2>&1; then
            m=$(getent group "$grp" | awk -F: '{print $4}')
            [ -n "$m" ] && users="$users$m,"
        fi
    done
    users=$(printf '%s' "$users" | tr ',' '\n' | sed '/^$/d' | sort -u)

    if [ -n "$users" ]; then
        info "Group members (sudo/wheel/admin):"
        printf '%s\n' "$users" | sed 's/^/        - /'
    else
        info "Groups sudo/wheel/admin are empty or absent"
    fi

    # Best-effort: direct user grants in sudoers / sudoers.d (needs read access)
    direct=$(grep -rhE '^[[:space:]]*[A-Za-z0-9._-]+[[:space:]]+ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
        | grep -vE '^[[:space:]]*#|^[[:space:]]*Defaults|^[[:space:]]*%' | awk '{print $1}' | sort -u)
    [ -n "$direct" ] && { info "Direct sudoers grants:"; printf '%s\n' "$direct" | sed 's/^/        - /'; }
    info "(group membership + direct grants only; users with a sudo/wheel primary GID are not resolved)"

    zerouid=$(awk -F: '$3==0 {print $1}' /etc/passwd | grep -v '^root$')
    if [ -n "$zerouid" ]; then
        fail "Unexpected UID=0 accounts: $(printf '%s' "$zerouid" | paste -sd, -)"
    else
        pass "UID=0 belongs to root only"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 9. FAIL2BAN
# ══════════════════════════════════════════════════════════════
check_fail2ban() {
    header "fail2ban"
    if have fail2ban-client; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            pass "fail2ban running"
            if [ "$IS_ROOT" -eq 1 ]; then
                local jails
                jails=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' || true)
                [ -n "$jails" ] && info "Active jails: $jails"
            fi
        else
            fail "fail2ban installed but not running"
        fi
    else
        warn "fail2ban not installed"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 10. WIREGUARD
# ══════════════════════════════════════════════════════════════
check_wireguard() {
    header "WireGuard"
    if ! have wg; then info "WireGuard (wg) not installed — skipping"; return 0; fi
    if [ "$IS_ROOT" -ne 1 ]; then warn "WireGuard check needs root"; return 0; fi

    local ifaces i peers
    ifaces=$(wg show interfaces 2>/dev/null || true)
    if [ -n "$ifaces" ]; then
        pass "WireGuard active: $ifaces"
        for i in $ifaces; do
            peers=$(wg show "$i" peers 2>/dev/null | grep -c . || true)
            info "  $i: peers — $peers"
        done
    else
        info "WireGuard installed, no active interfaces"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 11. FAILED SYSTEMD UNITS
# ══════════════════════════════════════════════════════════════
check_failed_units() {
    header "Failed systemd units"
    if ! have systemctl; then skip "systemd not present"; return 0; fi

    local failed
    failed=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | sed '/^$/d')
    if [ -n "$failed" ]; then
        fail "Failed services detected:"
        printf '%s\n' "$failed" | sed 's/^/        - /'
    else
        pass "No failed systemd units"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 12. OOM / KERNEL ERRORS
# ══════════════════════════════════════════════════════════════
check_oom() {
    header "OOM / kernel errors"
    local oom kerr
    if have journalctl; then
        oom=$(journalctl -k -b --no-pager 2>/dev/null | grep -ciE 'out of memory|oom-killer|killed process' || true)
        if [ "${oom:-0}" -gt 0 ]; then
            fail "OOM killer events this boot: $oom"
        else
            pass "No OOM events this boot"
        fi
        kerr=$(journalctl -k -b -p err --no-pager 2>/dev/null | grep -c . || true)
        [ "${kerr:-0}" -gt 0 ] && warn "Kernel error-level messages this boot: $kerr"
    elif [ -r /var/log/kern.log ]; then
        oom=$(grep -ciE 'out of memory|oom-killer' /var/log/kern.log 2>/dev/null || true)
        if [ "${oom:-0}" -gt 0 ]; then
            fail "OOM events in kern.log: $oom"
        else
            pass "No OOM events in kern.log"
        fi
    else
        skip "journalctl/kern.log unavailable"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 13. MEMORY  (single `free` call, reused)
# ══════════════════════════════════════════════════════════════
check_memory() {
    header "Memory"
    if ! have free; then skip "free not available"; return 0; fi

    local mem mline sline total used avail used_eff pct stot sused spct
    mem=$(free -m 2>/dev/null || true)
    [ -n "$mem" ] || { skip "could not read memory"; return 0; }
    mline=$(printf '%s\n' "$mem" | awk '/^Mem:/{print}')
    sline=$(printf '%s\n' "$mem" | awk '/^Swap:/{print}')

    total=$(printf '%s\n' "$mline" | awk '{print $2}')
    used=$(printf  '%s\n' "$mline" | awk '{print $3}')
    avail=$(printf '%s\n' "$mline" | awk '{print $7}')
    { [ -n "${total:-}" ] && [ "${total:-0}" -gt 0 ]; } || { skip "could not read memory"; return 0; }

    if printf '%s' "${avail:-}" | grep -qE '^[0-9]+$'; then
        used_eff=$(( total - avail ))
    else
        used_eff=${used:-0}
    fi
    pct=$(( used_eff * 100 / total ))

    if [ "$pct" -ge "$MEM_WARN_PCT" ]; then
        warn "Memory usage high: ${used_eff}/${total} MB (${pct}%)"
    else
        pass "Memory: ${used_eff}/${total} MB (${pct}%)"
    fi

    stot=$(printf  '%s\n' "$sline" | awk '{print $2}')
    sused=$(printf '%s\n' "$sline" | awk '{print $3}')
    if [ "${stot:-0}" -gt 0 ]; then
        spct=$(( sused * 100 / stot ))
        if [ "$spct" -ge 50 ]; then
            warn "Swap usage: ${sused}/${stot} MB (${spct}%)"
        else
            info "Swap: ${sused}/${stot} MB (${spct}%)"
        fi
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 14. LOAD AVERAGE
# ══════════════════════════════════════════════════════════════
check_load() {
    header "Load average"
    local l1 l5 l15 cores verdict
    if ! read -r l1 l5 l15 _ < /proc/loadavg 2>/dev/null; then
        skip "/proc/loadavg unreadable"
        return 0
    fi
    cores=$(nproc 2>/dev/null || echo 1)
    info "Load average: $l1 $l5 $l15  (${cores} core(s))"

    verdict=$(awk -v l="$l5" -v c="$cores" -v w="$LOAD_WARN_RATIO" -v f="$LOAD_FAIL_RATIO" \
        'BEGIN{ if(c<=0)c=1; r=l/c; if(r>=f) print "fail"; else if(r>=w) print "warn"; else print "ok" }')
    case "$verdict" in
        fail) fail "High load average (5-min ${l5} over ${cores} core(s))" ;;
        warn) warn "Elevated load average (5-min ${l5} over ${cores} core(s))" ;;
        *)    pass "Load within normal range" ;;
    esac
    return 0
}

# ══════════════════════════════════════════════════════════════
# 15. TEMPERATURES
# ══════════════════════════════════════════════════════════════
check_temperatures() {
    header "Temperatures"
    local max=0 shown=0 t lbl chip ti z

    if compgen -G "/sys/class/hwmon/hwmon*/temp*_input" >/dev/null 2>&1; then
        for ti in /sys/class/hwmon/hwmon*/temp*_input; do
            [ -r "$ti" ] || continue
            t=$(cat "$ti" 2>/dev/null || echo "")
            [[ "$t" =~ ^[0-9]+$ ]] || continue
            t=$(( t / 1000 ))
            [ "$t" -le 0 ] && continue
            chip=$(cat "$(dirname "$ti")/name" 2>/dev/null || echo "sensor")
            if [ -r "${ti%_input}_label" ]; then
                lbl=$(cat "${ti%_input}_label" 2>/dev/null || echo "$chip")
            else
                lbl="$chip"
            fi
            info "  ${lbl}: ${t}°C"
            [ "$t" -gt "$max" ] && max=$t
            shown=1
        done
    fi

    if [ "$shown" -eq 0 ] && compgen -G "/sys/class/thermal/thermal_zone*/temp" >/dev/null 2>&1; then
        for z in /sys/class/thermal/thermal_zone*; do
            [ -r "$z/temp" ] || continue
            t=$(cat "$z/temp" 2>/dev/null || echo "")
            [[ "$t" =~ ^[0-9]+$ ]] || continue
            t=$(( t / 1000 ))
            lbl=$(cat "$z/type" 2>/dev/null || echo "zone")
            info "  ${lbl}: ${t}°C"
            [ "$t" -gt "$max" ] && max=$t
            shown=1
        done
    fi

    if [ "$shown" -eq 0 ]; then
        skip "No temperature sensors (bare metal needed; lm-sensors gives more)"
        return 0
    fi
    if [ "$max" -ge "$TEMP_CRIT_C" ]; then
        fail "Peak temperature ${max}°C (critical)"
    elif [ "$max" -ge "$TEMP_WARN_C" ]; then
        warn "Peak temperature ${max}°C (high)"
    else
        pass "Peak temperature ${max}°C"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 16. UPTIME
# ══════════════════════════════════════════════════════════════
check_uptime() {
    header "Uptime"
    local up days
    up=""
    have uptime && up=$(uptime -p 2>/dev/null | sed 's/^up //' || true)
    [ -z "${up:-}" ] && up=$(awk '{d=int($1/86400); h=int(($1%86400)/3600); printf "%dd %dh", d, h}' /proc/uptime 2>/dev/null || true)
    info "System uptime: ${up:-unknown}"

    days=$(awk '{print int($1/86400)}' /proc/uptime 2>/dev/null || echo 0)
    [ "${days:-0}" -ge "$UPTIME_WARN_DAYS" ] && warn "Uptime ${days}d — consider rebooting for kernel/security updates"
    return 0
}

# ══════════════════════════════════════════════════════════════
# 17. TIME SYNCHRONIZATION
# ══════════════════════════════════════════════════════════════
check_timesync() {
    header "Time synchronization"
    if have timedatectl; then
        local ntp synced
        ntp=$(timedatectl show -p NTP --value 2>/dev/null || true)
        synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
        if [ "$synced" = "yes" ]; then
            pass "Clock synchronized (NTP active)"
        elif [ "$ntp" = "no" ]; then
            warn "NTP synchronization disabled"
        else
            warn "Clock not synchronized"
        fi
    elif have chronyc; then
        if chronyc tracking >/dev/null 2>&1; then
            pass "chrony tracking active"
        else
            warn "chrony present but not tracking"
        fi
    else
        skip "timedatectl/chrony not present"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 18. DOCKER
# ══════════════════════════════════════════════════════════════
check_docker() {
    header "Docker"
    if ! have docker; then info "Docker not installed — skipping"; return 0; fi

    if systemctl is-active --quiet docker 2>/dev/null; then
        pass "Docker service active"
    else
        warn "Docker installed but service not active"
        return 0
    fi

    if ! docker ps >/dev/null 2>&1; then
        info "Cannot query containers (need root or docker group)"
        return 0
    fi

    local running total unhealthy
    running=$(docker ps -q 2>/dev/null | grep -c . || true)
    total=$(docker ps -aq 2>/dev/null | grep -c . || true)
    info "Containers: ${running:-0} running / ${total:-0} total"

    unhealthy=$(docker ps --filter health=unhealthy -q 2>/dev/null | grep -c . || true)
    [ "${unhealthy:-0}" -gt 0 ] && warn "Unhealthy containers: $unhealthy"
    return 0
}

# ══════════════════════════════════════════════════════════════
# 19. DISK SPACE
# ══════════════════════════════════════════════════════════════
check_disk_space() {
    header "Disk space"
    local line use mnt
    while read -r line; do
        use=$(printf '%s' "$line" | awk '{gsub(/%/,"",$5); print $5}')
        mnt=$(printf '%s' "$line" | awk '{print $6}')
        [[ "$use" =~ ^[0-9]+$ ]] || continue
        if   [ "$use" -ge 90 ]; then fail "Partition $mnt is ${use}% full"
        elif [ "$use" -ge 80 ]; then warn "Partition $mnt is ${use}% full"
        else                         pass "Partition $mnt: ${use}% used"
        fi
    done < <(df -hP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | awk 'NR>1')
    return 0
}

# ══════════════════════════════════════════════════════════════
# 20. JOURNAL SIZE
# ══════════════════════════════════════════════════════════════
check_journal() {
    header "Journal size"
    if ! have journalctl; then skip "journalctl not present"; return 0; fi

    local raw tok mb
    raw=$(journalctl --disk-usage 2>/dev/null || true)
    tok=$(printf '%s' "$raw" | grep -oE '[0-9]+(\.[0-9]+)?[KMGTP]' | tail -1)
    if [ -z "$tok" ]; then
        info "Journal size unknown"
        return 0
    fi
    mb=$(awk -v t="$tok" 'BEGIN{
        u=substr(t,length(t),1); v=substr(t,1,length(t)-1)+0;
        if(u=="K")      print int(v/1024);
        else if(u=="M") print int(v);
        else if(u=="G") print int(v*1024);
        else if(u=="T") print int(v*1024*1024);
        else            print int(v);
    }')
    if [ "${mb:-0}" -ge "$JOURNAL_WARN_MB" ]; then
        warn "Journal size ${tok} exceeds threshold (${JOURNAL_WARN_MB} MB) — try 'journalctl --vacuum-size=500M'"
    else
        pass "Journal size: ${tok}"
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# 21. DISK SMART
# ══════════════════════════════════════════════════════════════
check_smart() {
    header "Disk SMART"
    if ! have smartctl; then info "smartctl (smartmontools) not installed — skipping SMART"; return 0; fi
    if [ "$IS_ROOT" -ne 1 ]; then warn "SMART check needs root"; return 0; fi

    local dev health found=0
    while read -r dev; do
        [ -b "/dev/$dev" ] || continue
        found=1
        health=$(smartctl -H "/dev/$dev" 2>/dev/null | grep -iE 'overall-health|SMART Health Status' || true)
        if printf '%s' "$health" | grep -qiE 'PASSED|OK'; then
            pass "/dev/$dev SMART: PASSED"
        elif [ -n "$health" ]; then
            fail "/dev/$dev SMART: ${health##*: }"
        else
            info "/dev/$dev: SMART unavailable (virtual disk or unsupported)"
        fi
    done < <(lsblk -dno NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}')
    [ "$found" -eq 0 ] && info "No physical disks found for SMART check"
    return 0
}

# ══════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════
show_summary() {
    echo -e "\n${BOLD}${BLUE}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║                 Summary                  ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${GREEN}OK:   $OK_COUNT${NC}"
    echo -e "  ${YELLOW}WARN: $WARN_COUNT${NC}"
    echo -e "  ${RED}FAIL: $FAIL_COUNT${NC}"
    echo ""
    echo "════ Finished: $(date '+%Y-%m-%d %H:%M:%S') ════"

    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo -e "${RED}${BOLD}Critical issues found — attention required.${NC}"
        exit 1
    elif [ "$WARN_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}${BOLD}Warnings present — review recommended.${NC}"
        exit 0
    else
        echo -e "${GREEN}${BOLD}All clear.${NC}"
        exit 0
    fi
}

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
init
print_banner

check_ports
check_firewall
check_ssh
check_failed_logins
check_updates
check_update_age
check_permissions
check_sudo_users
check_fail2ban
check_wireguard
check_failed_units
check_oom
check_memory
check_load
check_temperatures
check_uptime
check_timesync
check_docker
check_disk_space
check_journal
check_smart

show_summary
