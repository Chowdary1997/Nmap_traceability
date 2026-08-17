#!/usr/bin/env bash
#
# nmap-recon.sh — Automated Nmap Reconnaissance & Consolidated Reporting
#
# =============================================================================
#  LEGAL / ETHICAL NOTICE
#  This script performs active network reconnaissance. Only run it against
#  systems, networks, or URLs you OWN or for which you hold EXPLICIT WRITTEN
#  AUTHORIZATION to test (e.g. a signed penetration-testing engagement or a
#  bug-bounty program's in-scope assets). Unauthorized scanning may violate
#  laws such as the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse
#  Act, or equivalent legislation elsewhere, even if no damage is caused.
#  This script gathers information only — it does not exploit, brute-force,
#  or attack anything. You are solely responsible for how you use it.
# =============================================================================
#
# USAGE:
#   ./nmap-recon.sh -t <target> [options]
#
# OPTIONS:
#   -t, --target <target>        Target IP, hostname, or URL (required)
#   -o, --output <dir>           Output directory (default: auto-generated)
#   -p, --ports <range>          Port range, e.g. 1-1000 (default: 1-65535)
#   -u, --udp                    Also run a top-100 UDP scan (slow, needs root)
#   -v, --vuln                   Also run NSE 'vuln' (+ 'vulners' if installed)
#                                 scripts and build a severity-sorted CVE triage
#                                 table (detection only, but slower/noisier and
#                                 needs internet — opt-in)
#   --vuln-intensity <level>      'normal' (default) or 'high'. 'high' raises
#                                 --version-intensity to 9 and the NSE script
#                                 timeout to 5m for deeper CVE matching — only
#                                 takes effect together with -v/--vuln.
#   -H, --hard                   Shortcut for -v --vuln-intensity high
#   -6, --ipv6                   Resolve and scan the target over IPv6
#   --timing <0-5>                Nmap timing template, T0 (slowest/stealthiest)
#                                 to T5 (fastest/noisiest). Default: 4
#   --no-whois                   Skip WHOIS / DNS reconnaissance phase
#   --no-auto-install             Don't auto-install missing dependencies —
#                                 just warn and skip the phases that need them
#   -y, --yes-i-am-authorized    Skip the interactive authorization prompt
#                                 (you are still asserting you are authorized)
#   -h, --help                   Show this help
#
# EXAMPLES:
#   ./nmap-recon.sh -t example.com
#   sudo ./nmap-recon.sh -t https://www.domain.com -p 1-1000 -u -v -y --timing 4
#   sudo ./nmap-recon.sh -t 2001:db8::1 -6 --timing 3
#   sudo ./nmap-recon.sh -t https://www.domain.com -p 1-65535 -u -v -y --timing 4
#   sudo ./nmap-recon.sh -t example.com -H -y                 # thorough CVE scan
#   sudo nmap -sU -p 1-65535 -T4 --reason -oA ./udp_full_onwardgroup onwardgroup.com
#
# OUTPUT (written under -o/--output, default ./nmap_recon_<target>_<timestamp>/):
#   consolidated_report.txt   Full human-readable report, all phases + a
#                             "CONSOLIDATED SUMMARY" section (IP, open ports,
#                             proxy/CDN in front of the target, domain DNS
#                             expiry, registrant email if not privacy-redacted,
#                             hosting org & country).
#   summary.csv               The consolidated summary above, one field per row.
#   ports.csv                 One row per discovered port: port,protocol,state,
#                             service,product,version.
#   raw/                      Raw nmap .nmap/.xml/.gnmap per phase, WHOIS dumps,
#                             DNS records, and captured HTTP headers.
#   report.html                Optional pretty HTML (needs xsltproc).
#
# NOTES ON THE NEW FIELDS:
#   - Proxy/CDN detection is a passive check of HTTP response headers (and the
#     hosting org name) against known Cloudflare/Akamai/Fastly/etc. signatures.
#     A miss doesn't prove there's no proxy, only that no known signature hit.
#   - Registrant email is frequently redacted by registrars for privacy (GDPR
#     and similar rules) — "not disclosed" is a normal, expected result, not
#     a script bug.
#   - On first run the script checks for nmap/whois/dig/curl/python3/xsltproc
#     and auto-installs anything missing via apt/dnf/yum/pacman/brew (uses
#     sudo automatically if not already root). Pass --no-auto-install to
#     disable this and just get a warning + skipped phases instead.
#   - CVE table empty every time with -v? The 'vulners' NSE script needs a
#     service/version probe (-sV) in the same nmap invocation to know what to
#     match CVEs against — this is now always included in Phase 7. The script
#     also now auto-installs 'vulners' itself (it isn't bundled with nmap) the
#     same way it auto-installs other dependencies. Use -H/--hard or
#     --vuln-intensity high for deeper version fingerprinting and more time
#     per script when you need the most thorough CVE match possible.
# -----------------------------------------------------------------------------

set -uo pipefail

# ---------------------------- Defaults --------------------------------------
TARGET=""
OUTDIR=""
PORTS="1-65535"
DO_UDP=false
DO_VULN=false
DO_WHOIS=true
IPV6=false
TIMING="4"
AUTHORIZED_FLAG=false
AUTO_INSTALL=true
VULN_INTENSITY="normal"
TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
SCRIPT_START_EPOCH="$(date +%s)"
COMMANDS_RUN=()   # audit trail of every nmap/recon command actually executed

# ---------------------------- Colors -----------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ---------------------------- Helpers ----------------------------------------
banner() {
    echo -e "${CYAN}${BOLD}"
    cat <<'EOF'
 _   _ __  __    _    ____        ____  _____ ____ ___  _   _
| \ | |  \/  |  / \  |  _ \      |  _ \| ____/ ___/ _ \| \ | |
|  \| | |\/| | / _ \ | |_) |_____| |_) |  _|| |  | | | |  \| |
| |\  | |  | |/ ___ \|  __/_____|  _ <| |__| |__| |_| | |\  |
|_| \_|_|  |_/_/   \_\_|         |_| \_\_____\____\___/|_| \_|
EOF
    echo -e "${NC}${BOLD}Automated Nmap Reconnaissance & Consolidated Reporting${NC}"
    echo "--------------------------------------------------------------"
}

usage() { sed -n '2,83p' "$0" | sed 's/^# \{0,1\}//'; }

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; }

section_header() {
    local title="$1"
    {
        echo ""
        echo "================================================================================"
        echo " $title"
        echo "================================================================================"
        echo ""
    } >> "$REPORT_FILE"
}

require_cmd() { command -v "$1" >/dev/null 2>&1; }

# Pulls the first matching "Label: value" line out of a WHOIS dump.
# $1 = file to search, $2 = extended-regex of label alternatives, anchored to line start.
extract_whois_field() {
    local file="$1" pattern="$2"
    [[ -f "$file" ]] || return 0
    grep -iE "$pattern" "$file" 2>/dev/null | head -n1 | sed -E 's/^[^:]+:[[:space:]]*//' | tr -d '\r'
}

# Best-effort reverse-proxy / CDN / WAF fingerprinting from HTTP response headers
# plus the hosting org name pulled from the IP WHOIS record. Passive only —
# no active bypass or evasion attempts.
detect_proxy_cdn() {
    local headers=""
    if require_cmd curl; then
        headers="$(curl -sk -m 8 -D - -o /dev/null "https://$TARGET/" 2>/dev/null)"
        [[ -z "$headers" ]] && headers="$(curl -sk -m 8 -D - -o /dev/null "http://$TARGET/" 2>/dev/null)"
    fi
    echo "$headers" > "$RAW_DIR/proxy_headers.txt" 2>/dev/null

    local combined
    combined="$(tr '[:upper:]' '[:lower:]' <<< "$headers $IP_ORG")"
    case "$combined" in
        *cloudflare*)             echo "Cloudflare" ;;
        *akamai*)                 echo "Akamai" ;;
        *fastly*)                 echo "Fastly" ;;
        *incapsula*|*imperva*)    echo "Imperva / Incapsula" ;;
        *sucuri*)                 echo "Sucuri" ;;
        *cloudfront*)             echo "Amazon CloudFront" ;;
        *azurefd*|*azure*)        echo "Azure Front Door" ;;
        *"google frontend"*|*ghs*) echo "Google Cloud / Cloud CDN" ;;
        *) echo "" ;;
    esac
}

# Runs a command, tees its output into the report, and logs it for the audit trail
run_and_log() {
    local desc="$1"; shift
    COMMANDS_RUN+=("$*")
    echo "\$ $*" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    "$@" >> "$REPORT_FILE" 2>&1
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "[NOTE] '$desc' exited with status $rc (non-fatal, continuing)." >> "$REPORT_FILE"
    fi
    return $rc
}

run_nmap_with_fallback() {
    local label="$1"
    shift

    local cmd=("$@")
    local rc=0

    "${cmd[@]}" > /dev/null 2>&1
    rc=$?

    if [[ $rc -eq 139 ]]; then
        warn "$label crashed with a segmentation fault (exit 139)."
        echo "[NOTE] '$label' crashed with a segmentation fault (exit 139); retrying without the high-risk vuln script set." >> "$REPORT_FILE"
    fi

    return $rc
}

# Writes ports.csv (from the nmap XML, or a best-effort text fallback) and
# summary.csv (the one-row consolidated overview) into $OUTDIR.
generate_csv_reports() {
    local xml_file=""
    [[ -f "$RAW_DIR/04_deep_scan.xml" ]] && xml_file="$RAW_DIR/04_deep_scan.xml"
    [[ -z "$xml_file" && -f "$RAW_DIR/03_port_scan.xml" ]] && xml_file="$RAW_DIR/03_port_scan.xml"

    PORTS_CSV="$OUTDIR/ports.csv"
    echo "port,protocol,state,service,product,version" > "$PORTS_CSV"

    if [[ -n "$xml_file" && "$HAVE_PYTHON3" == true ]]; then
        python3 - "$xml_file" "$PORTS_CSV" <<'PYEOF'
import sys, csv
import xml.etree.ElementTree as ET

xml_file, csv_file = sys.argv[1], sys.argv[2]
try:
    root = ET.parse(xml_file).getroot()
except Exception:
    sys.exit(0)

rows = []
for host in root.findall("host"):
    ports_el = host.find("ports")
    if ports_el is None:
        continue
    for port in ports_el.findall("port"):
        state_el = port.find("state")
        service_el = port.find("service")
        rows.append([
            port.get("portid", ""),
            port.get("protocol", ""),
            state_el.get("state", "") if state_el is not None else "",
            service_el.get("name", "") if service_el is not None else "",
            service_el.get("product", "") if service_el is not None else "",
            service_el.get("version", "") if service_el is not None else "",
        ])

with open(csv_file, "a", newline="") as f:
    csv.writer(f).writerows(rows)
PYEOF
    elif [[ -n "$OPEN_PORTS" ]]; then
        # No python3 available — best-effort parse of the human-readable .nmap output.
        local nmap_txt="$RAW_DIR/03_port_scan.nmap"
        [[ -f "$RAW_DIR/04_deep_scan.nmap" ]] && nmap_txt="$RAW_DIR/04_deep_scan.nmap"
        if [[ -f "$nmap_txt" ]]; then
            grep -oP '^\d+/(tcp|udp)\s+\S+\s+\S+' "$nmap_txt" 2>/dev/null \
                | awk '{split($1,a,"/"); print a[1]","a[2]","$2","$3",,"}' >> "$PORTS_CSV"
        fi
        echo "[NOTE] python3 not found — ports.csv built from text output; product/version columns are blank. Install python3 for a fuller CSV." >> "$REPORT_FILE"
    fi

    SUMMARY_CSV="$OUTDIR/summary.csv"
    {
        echo "field,value"
        echo "target,\"$TARGET\""
        echo "resolved_ip,\"$RESOLVED_IP\""
        echo "scan_date,\"$(date)\""
        echo "open_ports,\"${OPEN_PORTS:-none found}\""
        echo "proxy_cdn_detected,\"${PROXY_DETECTED:-none detected}\""
        echo "domain_dns_expiry,\"${DOMAIN_EXPIRY:-not found / no whois}\""
        echo "registrant_email,\"${REGISTRANT_EMAIL:-not disclosed (redacted or no whois)}\""
        echo "registrant_organization,\"${REGISTRANT_ORG:-not found}\""
        echo "hosting_org,\"${IP_ORG:-not found}\""
        echo "hosting_country,\"${IP_COUNTRY:-not found}\""
    } > "$SUMMARY_CSV"

    ok "CSV reports written: $PORTS_CSV, $SUMMARY_CSV"
}

# Maps a command name to the correct package name for the detected package
# manager (package names for the same tool differ across distros).
pkg_name_for() {
    local cmd="$1" mgr="$2"
    case "$cmd:$mgr" in
        dig:apt)             echo "dnsutils" ;;
        dig:dnf|dig:yum)     echo "bind-utils" ;;
        dig:pacman)          echo "bind" ;;
        dig:brew)            echo "bind" ;;
        xsltproc:dnf|xsltproc:yum|xsltproc:pacman|xsltproc:brew)
                              echo "libxslt" ;;
        *)                   echo "$cmd" ;;
    esac
}

# Detects the system package manager, then installs whichever of
# nmap/whois/dig/curl/python3/xsltproc are missing. Safe to call even if
# everything is already installed (it's a no-op in that case).
install_missing_dependencies() {
    local pkg_manager; pkg_manager="$(detect_pkg_manager)"

    local needed_cmds=(nmap whois dig curl python3 xsltproc)
    local missing_cmds=() missing_pkgs=() c
    for c in "${needed_cmds[@]}"; do
        require_cmd "$c" || { missing_cmds+=("$c"); missing_pkgs+=("$(pkg_name_for "$c" "$pkg_manager")"); }
    done

    if [[ ${#missing_cmds[@]} -eq 0 ]]; then
        ok "All dependencies already installed (nmap, whois, dig, curl, python3, xsltproc)."
        return 0
    fi

    info "Missing: ${missing_cmds[*]}"

    if [[ -z "$pkg_manager" ]]; then
        warn "No supported package manager found (apt/dnf/yum/pacman/brew)."
        warn "Install these manually, then re-run: ${missing_cmds[*]}"
        return 1
    fi

    if [[ $EUID -ne 0 && "$pkg_manager" != "brew" ]] && ! require_cmd sudo; then
        warn "Not root and 'sudo' not found — cannot auto-install. Install manually: ${missing_pkgs[*]}"
        return 1
    fi

    info "Installing missing dependencies via $pkg_manager: ${missing_pkgs[*]}"
    pm_install "$pkg_manager" "${missing_pkgs[@]}"
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        warn "Automatic install failed (exit $rc). Continuing anyway — phases needing"
        warn "the missing tools will be skipped with a [NOTE] in the report."
    else
        ok "Dependency install finished."
    fi
    return $rc
}

# Detects the system package manager once. Empty string if none found.
detect_pkg_manager() {
    if require_cmd apt-get; then echo "apt"
    elif require_cmd dnf; then echo "dnf"
    elif require_cmd yum; then echo "yum"
    elif require_cmd pacman; then echo "pacman"
    elif require_cmd brew; then echo "brew"
    else echo ""
    fi
}

# Installs one or more packages with the given package manager, using sudo
# automatically when not already root (brew refuses to run as root, so it's
# never sudo'd). Returns the installer's exit status.
pm_install() {
    local pkg_manager="$1"; shift
    local pkgs=("$@")
    [[ ${#pkgs[@]} -eq 0 || -z "$pkg_manager" ]] && return 1

    local sudo_cmd=""
    if [[ $EUID -ne 0 && "$pkg_manager" != "brew" ]]; then
        require_cmd sudo && sudo_cmd="sudo"
    fi

    case "$pkg_manager" in
        apt)    $sudo_cmd apt-get update -y && $sudo_cmd apt-get install -y "${pkgs[@]}" ;;
        dnf)    $sudo_cmd dnf install -y "${pkgs[@]}" ;;
        yum)    $sudo_cmd yum install -y "${pkgs[@]}" ;;
        pacman) $sudo_cmd pacman -Sy --noconfirm "${pkgs[@]}" ;;
        brew)   brew install "${pkgs[@]}" ;;
        *)      return 1 ;;
    esac
}

# Tries a handful of common install locations for nmap's NSE scripts
# directory (varies by OS/package manager).
find_nmap_scripts_dir() {
    local candidates=(
        "/usr/share/nmap/scripts"
        "/usr/local/share/nmap/scripts"
        "/opt/homebrew/share/nmap/scripts"
    )
    local d
    for d in "${candidates[@]}"; do
        [[ -d "$d" ]] && { echo "$d"; return 0; }
    done
    echo "/usr/share/nmap/scripts"   # fall back to the common Linux default
}

# Reliable check for whether the 'vulners' NSE script is actually installed.
# NOTE: `nmap --script-help vulners` is NOT a safe check on its own — nmap
# exits 0 and just prints "Could not load 'vulners.nse'" to stdout when the
# script is missing, so a naive exit-code check always reports "installed"
# even when it isn't. We check the file directly instead.
have_vulners_script() {
    local d
    for d in "$(find_nmap_scripts_dir)" "/usr/share/nmap/scripts" "/usr/local/share/nmap/scripts" "/opt/homebrew/share/nmap/scripts"; do
        [[ -f "$d/vulners.nse" || -f "$d/vulners/vulners.nse" ]] && return 0
    done
    return 1
}

# Auto-installs the 'vulners' NSE script (not bundled with nmap — it's a
# separate community script that cross-references detected service versions
# against the vulners.com CVE database). No-op if already installed.
install_vulners_script() {
    have_vulners_script && return 0   # already installed

    if [[ "$AUTO_INSTALL" != true ]]; then
        return 1   # caller prints the manual-install instructions
    fi

    if ! require_cmd git; then
        local pkg_manager; pkg_manager="$(detect_pkg_manager)"
        if [[ -z "$pkg_manager" ]]; then
            warn "git not found and no supported package manager detected — can't auto-install 'vulners'."
            return 1
        fi
        info "Installing git (needed to fetch the 'vulners' NSE script)..."
        pm_install "$pkg_manager" git >/dev/null 2>&1
        require_cmd git || { warn "git install failed — can't auto-install 'vulners'."; return 1; }
    fi

    local scripts_dir; scripts_dir="$(find_nmap_scripts_dir)"
    local sudo_cmd=""
    [[ $EUID -ne 0 ]] && require_cmd sudo && sudo_cmd="sudo"

    info "Installing 'vulners' NSE script into $scripts_dir/vulners ..."
    if [[ -d "$scripts_dir/vulners" ]]; then
        $sudo_cmd git -C "$scripts_dir/vulners" pull --ff-only >/dev/null 2>&1
    else
        $sudo_cmd mkdir -p "$scripts_dir" 2>/dev/null
        $sudo_cmd git clone --depth 1 https://github.com/vulnersCom/nmap-vulners.git "$scripts_dir/vulners" >/dev/null 2>&1
    fi
    $sudo_cmd nmap --script-updatedb >/dev/null 2>&1

    if have_vulners_script; then
        ok "'vulners' NSE script installed — CVE/CVSS results will now populate."
        return 0
    else
        warn "Could not auto-install 'vulners' (no internet access, or git/permissions issue)."
        return 1
    fi
}

cleanup_on_interrupt() {
    echo ""
    warn "Scan interrupted by user. Partial results (if any) are in: $OUTDIR"
    exit 130
}
trap cleanup_on_interrupt INT TERM

# ---------------------------- Argument parsing --------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)               TARGET="$2"; shift 2 ;;
        -o|--output)                OUTDIR="$2"; shift 2 ;;
        -p|--ports)                  PORTS="$2"; shift 2 ;;
        -u|--udp)                  DO_UDP=true; shift ;;
        -v|--vuln)                 DO_VULN=true; shift ;;
        --vuln-intensity)           VULN_INTENSITY="$2"; shift 2 ;;
        -H|--hard)                 DO_VULN=true; VULN_INTENSITY="high"; shift ;;
        -6|--ipv6)                 IPV6=true; shift ;;
        --timing)                   TIMING="$2"; shift 2 ;;
        --no-whois)               DO_WHOIS=false; shift ;;
        --no-auto-install)         AUTO_INSTALL=false; shift ;;
        -y|--yes-i-am-authorized) AUTHORIZED_FLAG=true; shift ;;
        -h|--help)                 banner; usage; exit 0 ;;
        *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
done

banner

if [[ -z "$TARGET" ]]; then
    err "No target specified."
    usage
    exit 1
fi

if ! [[ "$TIMING" =~ ^[0-5]$ ]]; then
    err "Invalid --timing value: '$TIMING' (must be an integer 0-5)."
    exit 1
fi

if ! [[ "$VULN_INTENSITY" == "normal" || "$VULN_INTENSITY" == "high" ]]; then
    err "Invalid --vuln-intensity value: '$VULN_INTENSITY' (must be 'normal' or 'high')."
    exit 1
fi

if ! [[ "$PORTS" =~ ^[[:alnum:],:*-]+$ ]]; then
    err "Invalid port specification: '$PORTS'"
    err "Examples: 1-1000   22,80,443   1-100,8000-9000   U:53,T:80"
    exit 1
fi

# Strip protocol scheme, path, and trailing slash if a URL was given
CLEAN_TARGET="$TARGET"
CLEAN_TARGET="${CLEAN_TARGET#http://}"
CLEAN_TARGET="${CLEAN_TARGET#https://}"
CLEAN_TARGET="${CLEAN_TARGET%%/*}"

# Strip a trailing :port suffix — but NOT for IPv6 literals, which contain
# multiple colons of their own (e.g. 2001:db8::1). Bracketed form
# [2001:db8::1]:8443 is unwrapped explicitly.
if [[ "$CLEAN_TARGET" == \[*\]:* ]]; then
    CLEAN_TARGET="${CLEAN_TARGET#\[}"
    CLEAN_TARGET="${CLEAN_TARGET%%\]:*}"
elif [[ "$(tr -dc ':' <<< "$CLEAN_TARGET" | wc -c)" -le 1 ]]; then
    CLEAN_TARGET="${CLEAN_TARGET%%:*}"
fi

if [[ "$CLEAN_TARGET" == *:* ]]; then
    IPV6=true   # target contains multiple colons — treat as an IPv6 literal
fi

if [[ "$CLEAN_TARGET" != "$TARGET" ]]; then
    info "Interpreted '$TARGET' as host: $CLEAN_TARGET"
fi
TARGET="$CLEAN_TARGET"

NMAP_V6=()
[[ "$IPV6" == true ]] && NMAP_V6=(-6)

# ---------------------------- Authorization gate -------------------------------
echo ""
warn "You are about to run active reconnaissance scans against: ${BOLD}$TARGET${NC}"
warn "This includes port scans, service/version probing, OS fingerprinting,"
warn "default/vuln NSE scripts, and traceroute — all detectable on the network."
echo ""

if [[ "$AUTHORIZED_FLAG" != true ]]; then
    read -r -p "Do you have EXPLICIT WRITTEN AUTHORIZATION to scan this target? (type 'yes' to continue): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        err "Authorization not confirmed. Aborting."
        exit 1
    fi
fi

# ---------------------------- Dependency checks & auto-install --------------------
IS_ROOT=false
[[ $EUID -eq 0 ]] && IS_ROOT=true

if [[ "$AUTO_INSTALL" == true ]]; then
    info "Checking dependencies (nmap, whois, dig, curl, python3, xsltproc)..."
    install_missing_dependencies
else
    info "Skipping auto-install (--no-auto-install). Checking what's already present..."
fi

if ! require_cmd nmap; then
    err "nmap is not installed and auto-install did not succeed."
    err "Install it manually, e.g.: sudo apt install nmap    (Debian/Ubuntu)"
    err "                            sudo dnf install nmap    (Fedora/RHEL)"
    err "                            brew install nmap        (macOS)"
    exit 1
fi

HAVE_XSLTPROC=false; require_cmd xsltproc && HAVE_XSLTPROC=true
HAVE_WHOIS=false;    require_cmd whois    && HAVE_WHOIS=true
HAVE_DIG=false;      require_cmd dig      && HAVE_DIG=true
HAVE_HOST=false;     require_cmd host     && HAVE_HOST=true
HAVE_CURL=false;     require_cmd curl     && HAVE_CURL=true
HAVE_PYTHON3=false;  require_cmd python3  && HAVE_PYTHON3=true

if [[ "$HAVE_CURL" != true ]]; then
    warn "curl not found — proxy/CDN header fingerprinting will be skipped."
fi

if [[ "$IS_ROOT" != true ]]; then
    warn "Not running as root. OS detection (-O) and SYN scans (-sS) need root."
    warn "Falling back to TCP connect scan (-sT) and skipping OS detection."
    warn "For a full scan, re-run with: sudo $0 -t $TARGET"
fi

# ---------------------------- Target resolution ---------------------------------
if [[ "$IPV6" == true ]]; then
    RESOLVED_IP="$(getent ahostsv6 "$TARGET" 2>/dev/null | awk '{print $1}' | head -n1)"
    if [[ -z "$RESOLVED_IP" && "$HAVE_DIG" == true ]]; then
        RESOLVED_IP="$(dig +short AAAA "$TARGET" 2>/dev/null | head -n1)"
    fi
    if [[ -z "$RESOLVED_IP" ]]; then
        # getent/dig may not resolve on all systems; fall back to nmap's own -sL resolution
        RESOLVED_IP="$(nmap -6 -sL -n "$TARGET" 2>/dev/null | awk '/Nmap scan report/{print $NF}' | tr -d '()' | head -n1)"
    fi
else
    RESOLVED_IP="$(getent hosts "$TARGET" 2>/dev/null | awk '{print $1}' | head -n1)"
    if [[ -z "$RESOLVED_IP" ]]; then
        # getent may not resolve on all systems; fall back to nmap's own -sL resolution
        RESOLVED_IP="$(nmap -sL -n "$TARGET" 2>/dev/null | awk '/Nmap scan report/{print $NF}' | tr -d '()' | head -n1)"
    fi
fi
if [[ -z "$RESOLVED_IP" ]]; then
    err "Could not resolve '$TARGET' to a$([[ "$IPV6" == true ]] && echo 'n IPv6' || echo 'n IPv4') address. Check the hostname/URL and try again."
    [[ "$IPV6" == true ]] && err "If the target only has an IPv4 address, drop -6/--ipv6."
    exit 1
fi
ok "Target resolves to: $RESOLVED_IP"

# ---------------------------- Output setup ---------------------------------------
if [[ -z "$OUTDIR" ]]; then
    OUTDIR="./nmap_recon_${TARGET//[^a-zA-Z0-9._-]/_}_${TIMESTAMP}"
fi
if [[ -d "$OUTDIR" && -n "$(ls -A "$OUTDIR" 2>/dev/null)" ]]; then
    warn "Output directory '$OUTDIR' already exists and is not empty."
    warn "Files with matching names (report, raw/*) will be overwritten."
fi
mkdir -p "$OUTDIR"
REPORT_FILE="$OUTDIR/consolidated_report.txt"
RAW_DIR="$OUTDIR/raw"
mkdir -p "$RAW_DIR"

{
    echo "================================================================================"
    echo " NMAP RECONNAISSANCE REPORT"
    echo "================================================================================"
    echo " Target:          $TARGET"
    echo " Resolved IP:     $RESOLVED_IP"
    echo " IP version:      $([[ "$IPV6" == true ]] && echo IPv6 || echo IPv4)"
    echo " Scan started:    $(date)"
    echo " Nmap version:    $(nmap --version 2>/dev/null | head -n1)"
    echo " Run as root:     $IS_ROOT"
    echo " Port range:      $PORTS"
    echo " Timing template: T$TIMING"
    echo " UDP scan:        $DO_UDP"
    echo " Vuln scan:       $DO_VULN"
    echo " WHOIS/DNS phase: $DO_WHOIS"
    echo ""
    echo " AUTHORIZATION: The operator confirmed explicit authorization to test"
    echo " this target prior to the scan being run."
    echo "================================================================================"
} > "$REPORT_FILE"

ok "Output directory: $OUTDIR"
ok "Consolidated report: $REPORT_FILE"
echo ""

TOTAL_PHASES=8

# ---------------------------- Phase 1: DNS, WHOIS & PROXY/CDN --------------------
info "Phase 1/${TOTAL_PHASES}: DNS, WHOIS & proxy/CDN reconnaissance..."
section_header "PHASE 1: DNS, WHOIS & PROXY/CDN RECONNAISSANCE"

WHOIS_TARGET_FILE="$RAW_DIR/01_whois_target.txt"
WHOIS_IP_FILE="$RAW_DIR/01_whois_ip.txt"
DOMAIN_EXPIRY=""; REGISTRANT_EMAIL=""; REGISTRANT_ORG=""; IP_ORG=""; IP_COUNTRY=""; PROXY_DETECTED=""

if [[ "$DO_WHOIS" == true ]]; then
    if [[ "$HAVE_DIG" == true ]]; then
        for rtype in A AAAA MX NS TXT SOA CNAME; do
            echo "--- DNS $rtype records ---" >> "$REPORT_FILE"
            dig +noall +answer "$TARGET" "$rtype" | tee -a "$REPORT_FILE" >> "$RAW_DIR/01_dns_records.txt" 2>&1
            echo "" >> "$REPORT_FILE"
        done
        COMMANDS_RUN+=("dig $TARGET {A,AAAA,MX,NS,TXT,SOA,CNAME}")
    elif [[ "$HAVE_HOST" == true ]]; then
        run_and_log "host lookup" host -a "$TARGET"
    else
        echo "[NOTE] Neither 'dig' nor 'host' found — DNS record lookup skipped." >> "$REPORT_FILE"
    fi

    if [[ "$HAVE_WHOIS" == true ]]; then
        echo "--- WHOIS ($TARGET) ---" >> "$REPORT_FILE"
        whois "$TARGET" > "$WHOIS_TARGET_FILE" 2>&1
        cat "$WHOIS_TARGET_FILE" >> "$REPORT_FILE"
        COMMANDS_RUN+=("whois $TARGET")

        # Domain registration expiry — label differs by registry/registrar.
        DOMAIN_EXPIRY="$(extract_whois_field "$WHOIS_TARGET_FILE" '^(Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|paid-till)')"
        # Registrant / admin / tech contact email — most gTLD registrars redact
        # this for privacy (GDPR etc.) since 2018, so "not disclosed" is expected.
        REGISTRANT_EMAIL="$(extract_whois_field "$WHOIS_TARGET_FILE" '^(Registrant Email|Admin Email|Tech Email)')"
        REGISTRANT_ORG="$(extract_whois_field "$WHOIS_TARGET_FILE" '^(Registrant Organization|Registrant Org)')"

        if [[ "$RESOLVED_IP" != "$TARGET" ]]; then
            echo "--- WHOIS ($RESOLVED_IP) — network/ASN ownership ---" >> "$REPORT_FILE"
            whois "$RESOLVED_IP" > "$WHOIS_IP_FILE" 2>&1
            cat "$WHOIS_IP_FILE" >> "$REPORT_FILE"
            COMMANDS_RUN+=("whois $RESOLVED_IP")

            # Hosting org / netblock owner + country — field names vary between
            # RIRs (ARIN uses OrgName, RIPE/APNIC use organisation/descr+country).
            IP_ORG="$(extract_whois_field "$WHOIS_IP_FILE" '^(OrgName|Organization|organisation|org-name|netname)')"
            IP_COUNTRY="$(extract_whois_field "$WHOIS_IP_FILE" '^(Country|country)')"
        fi
    else
        echo "[NOTE] 'whois' not installed — skipping registrar/ASN lookup, DNS expiry and registrant email. Install with: sudo apt install whois" >> "$REPORT_FILE"
    fi
    ok "DNS/WHOIS recon complete."
else
    echo "[SKIPPED] --no-whois was specified." >> "$REPORT_FILE"
    info "Skipped (--no-whois)."
fi

# --- Proxy / CDN / WAF fingerprinting (passive header check, no bypass attempts) ---
echo "" >> "$REPORT_FILE"
echo "--- Proxy / CDN / WAF fingerprint ---" >> "$REPORT_FILE"
if [[ "$HAVE_CURL" == true ]]; then
    PROXY_DETECTED="$(detect_proxy_cdn)"
    COMMANDS_RUN+=("curl -sk -D - -o /dev/null https://$TARGET/")
    if [[ -n "$PROXY_DETECTED" ]]; then
        echo "Detected: $PROXY_DETECTED (based on response headers / hosting org name)" >> "$REPORT_FILE"
        ok "Proxy/CDN in front of target: $PROXY_DETECTED"
    else
        echo "No known reverse proxy/CDN/WAF signature detected in response headers or hosting org name." >> "$REPORT_FILE"
        echo "(This does not guarantee the target is unproxied — only that no known signature matched.)" >> "$REPORT_FILE"
        info "No known proxy/CDN signature detected."
    fi
    echo "Raw response headers saved to: $RAW_DIR/proxy_headers.txt" >> "$REPORT_FILE"
else
    echo "[NOTE] 'curl' not installed — proxy/CDN header check skipped. Install with: sudo apt install curl" >> "$REPORT_FILE"
fi

# ---------------------------- Phase 2: Host Discovery -----------------------------
info "Phase 2/${TOTAL_PHASES}: Host discovery..."
section_header "PHASE 2: HOST DISCOVERY (nmap -sn)"
CMD=(nmap "${NMAP_V6[@]}" -sn -PE -PP -PS21,22,25,80,443,3389 -PA80,443 --reason -oA "$RAW_DIR/02_host_discovery" "$TARGET")
COMMANDS_RUN+=("${CMD[*]}")
"${CMD[@]}" > /dev/null 2>&1
cat "$RAW_DIR/02_host_discovery.nmap" >> "$REPORT_FILE" 2>/dev/null
ok "Host discovery complete."

# ---------------------------- Phase 3: Port Scan -----------------------------------
info "Phase 3/${TOTAL_PHASES}: Full port scan (this can take a while for large ranges)..."
section_header "PHASE 3: PORT SCAN (ports $PORTS)"

if [[ "$IS_ROOT" == true ]]; then SCAN_TYPE=(-sS); else SCAN_TYPE=(-sT); fi

# -Pn: treat the host as up and skip nmap's own pre-scan ping probe. Phase 2
# already performed host discovery separately, and re-probing here means a
# host that merely blocks ICMP/ping (but has open ports) would otherwise be
# skipped entirely as "down".
CMD=(nmap "${NMAP_V6[@]}" "${SCAN_TYPE[@]}" -Pn -p "$PORTS" -T"$TIMING" --reason -oA "$RAW_DIR/03_port_scan" "$TARGET")
COMMANDS_RUN+=("${CMD[*]}")
"${CMD[@]}" > /dev/null 2>&1
cat "$RAW_DIR/03_port_scan.nmap" >> "$REPORT_FILE" 2>/dev/null

# Extract open ports as a comma-separated list for follow-up scans
OPEN_PORTS="$(grep -oP '^\d+(?=/(tcp|udp)\s+open)' "$RAW_DIR/03_port_scan.nmap" 2>/dev/null | paste -sd, -)"

if [[ -z "$OPEN_PORTS" ]]; then
    warn "No open TCP ports found in range $PORTS. Deep-dive phases will be skipped."
else
    ok "Open ports found: $OPEN_PORTS"
fi

# ---------------------------- Phase 4: Service/Version + Default Scripts + OS ------
if [[ -n "$OPEN_PORTS" ]]; then
    info "Phase 4/${TOTAL_PHASES}: Service/version detection, default NSE scripts, OS detection, traceroute..."
    section_header "PHASE 4: SERVICE VERSIONS, DEFAULT SCRIPTS, OS DETECTION & TRACEROUTE"

    if [[ "$IS_ROOT" == true ]]; then
        CMD=(nmap "${NMAP_V6[@]}" -sV -sC -O --traceroute --version-intensity 5 -Pn --reason -p "$OPEN_PORTS" -T"$TIMING" -oA "$RAW_DIR/04_deep_scan" "$TARGET")
    else
        CMD=(nmap "${NMAP_V6[@]}" -sV -sC --traceroute --version-intensity 5 -Pn --reason -p "$OPEN_PORTS" -T"$TIMING" -oA "$RAW_DIR/04_deep_scan" "$TARGET")
    fi
    COMMANDS_RUN+=("${CMD[*]}")
    "${CMD[@]}" > /dev/null 2>&1
    [[ "$IS_ROOT" != true ]] && echo "[NOTE] OS detection (-O) skipped — not running as root." >> "$REPORT_FILE"
    cat "$RAW_DIR/04_deep_scan.nmap" >> "$REPORT_FILE" 2>/dev/null
    ok "Deep scan complete."
else
    section_header "PHASE 4: SKIPPED (no open ports detected)"
fi

# ---------------------------- Phase 5: SSL/TLS inspection -------------------------
info "Phase 5/${TOTAL_PHASES}: SSL/TLS certificate & cipher inspection..."
section_header "PHASE 5: SSL/TLS INSPECTION"
SSL_CANDIDATE_PORTS="443,465,563,636,853,989,990,992,993,994,995,8443,9443"
if [[ -n "$OPEN_PORTS" ]]; then
    OPEN_PORTS_SORTED="$(echo "$OPEN_PORTS" | tr ',' '\n' | sort -n | paste -sd, -)"
    SSL_PORTS_FOUND="$(comm -12 <(echo "$OPEN_PORTS_SORTED" | tr ',' '\n' | sort -n) <(echo "$SSL_CANDIDATE_PORTS" | tr ',' '\n' | sort -n) | paste -sd, -)"
else
    SSL_PORTS_FOUND=""
fi

if [[ -n "$SSL_PORTS_FOUND" ]]; then
    CMD=(nmap "${NMAP_V6[@]}" --script ssl-cert,ssl-enum-ciphers -p "$SSL_PORTS_FOUND" -T"$TIMING" -oA "$RAW_DIR/05_ssl_scan" "$TARGET")
    COMMANDS_RUN+=("${CMD[*]}")
    "${CMD[@]}" > /dev/null 2>&1
    cat "$RAW_DIR/05_ssl_scan.nmap" >> "$REPORT_FILE" 2>/dev/null
    ok "SSL/TLS inspection complete on port(s): $SSL_PORTS_FOUND"
else
    echo "[NOTE] No common SSL/TLS ports found open — skipping." >> "$REPORT_FILE"
    info "No common SSL/TLS ports open — skipped."
fi

# ---------------------------- Phase 6: UDP scan (optional) ------------------------
if [[ "$DO_UDP" == true ]]; then
    info "Phase 6/${TOTAL_PHASES}: UDP scan (top 100 ports, this is slow)..."
    section_header "PHASE 6: UDP SCAN (top 100 ports)"
    if [[ "$IS_ROOT" == true ]]; then
        CMD=(nmap "${NMAP_V6[@]}" -sU --top-ports 100 -T"$TIMING" --reason -oA "$RAW_DIR/06_udp_scan" "$TARGET")
        COMMANDS_RUN+=("${CMD[*]}")
        "${CMD[@]}" > /dev/null 2>&1
        cat "$RAW_DIR/06_udp_scan.nmap" >> "$REPORT_FILE" 2>/dev/null
        ok "UDP scan complete."
    else
        warn "UDP scan requires root. Skipping."
        echo "[NOTE] UDP scan skipped: requires root privileges." >> "$REPORT_FILE"
    fi
else
    section_header "PHASE 6: SKIPPED (use -u/--udp to enable)"
    info "Phase 6/${TOTAL_PHASES}: UDP scan skipped (use -u/--udp to enable)."
fi

# ---------------------------- Phase 7: Extended safe NSE + optional vuln ----------
# NOTE: the 'vulners' script needs a service/version probe (-sV) to have run
# in the SAME invocation to know what product/version to match CVEs against —
# without it, 'vulners' silently returns nothing no matter what target you
# scan. This phase always runs -sV for that reason.
if [[ "$DO_VULN" == true ]]; then
    install_vulners_script
fi

HAVE_VULNERS_SCRIPT=false
if [[ "$DO_VULN" == true ]] && nmap --script-help vulners >/dev/null 2>&1; then
    HAVE_VULNERS_SCRIPT=true
fi

# --vuln-intensity high: deeper version fingerprinting + more time per script,
# for better CVE matching at the cost of a slower, noisier scan.
if [[ "$VULN_INTENSITY" == "high" ]]; then
    NSE_VERSION_INTENSITY=9
    NSE_SCRIPT_TIMEOUT="5m"
else
    NSE_VERSION_INTENSITY=7
    NSE_SCRIPT_TIMEOUT="2m"
fi

if [[ -n "$OPEN_PORTS" ]]; then
    SCRIPT_SET="default,safe"
    if [[ "$DO_VULN" == true ]]; then
        if [[ "$HAVE_VULNERS_SCRIPT" == true ]]; then
            SCRIPT_SET="default,safe,vuln,vulners"
        else
            SCRIPT_SET="default,safe,vuln"
        fi
    fi

    info "Phase 7/${TOTAL_PHASES}: Extended NSE scripts ($SCRIPT_SET, vuln-intensity=$VULN_INTENSITY)..."
    section_header "PHASE 7: EXTENDED NSE SCRIPTS (vuln-intensity: $VULN_INTENSITY)"

    if [[ "$DO_VULN" == true ]]; then
        warn "Running 'vuln'$([[ "$HAVE_VULNERS_SCRIPT" == true ]] && echo " + 'vulners'") scripts — these actively probe for known"
        warn "vulnerabilities$([[ "$HAVE_VULNERS_SCRIPT" == true ]] && echo " and cross-reference service versions against the vulners.com CVE database"). Detection only, no exploitation, but"
        warn "noisier/slower than default scripts."
        if [[ "$HAVE_VULNERS_SCRIPT" != true ]]; then
            warn "'vulners' NSE script could not be installed (offline, or no git/permissions)."
            warn "Install it manually with:"
            warn "  sudo git clone https://github.com/vulnersCom/nmap-vulners.git $(find_nmap_scripts_dir)/vulners"
            warn "  sudo nmap --script-updatedb"
            echo "[NOTE] 'vulners' script not installed — continuing with 'vuln' category scripts only." >> "$REPORT_FILE"
        fi
    fi

    CMD=(nmap "${NMAP_V6[@]}" -sV --version-intensity "$NSE_VERSION_INTENSITY" --script "$SCRIPT_SET" --script-timeout "$NSE_SCRIPT_TIMEOUT" -p "$OPEN_PORTS" -T"$TIMING" --reason -oA "$RAW_DIR/07_nse_extended" "$TARGET")
    COMMANDS_RUN+=("${CMD[*]}")

    scan_rc=0
    run_nmap_with_fallback "Extended NSE scripts" "${CMD[@]}"
    scan_rc=$?

    if [[ $scan_rc -ne 0 ]]; then
        if [[ "$DO_VULN" == true && "$SCRIPT_SET" != "default,safe" ]]; then
            warn "Retrying the extended NSE scan without the high-risk 'vuln'/'vulners' category after a segfault or failure."
            SCRIPT_SET="default,safe"
            CMD=(nmap "${NMAP_V6[@]}" -sV --version-intensity "$NSE_VERSION_INTENSITY" --script "$SCRIPT_SET" --script-timeout "$NSE_SCRIPT_TIMEOUT" -p "$OPEN_PORTS" -T"$TIMING" --reason -oA "$RAW_DIR/07_nse_extended" "$TARGET")
            COMMANDS_RUN+=("${CMD[*]}")
            run_nmap_with_fallback "Extended NSE scripts (safe fallback)" "${CMD[@]}"
            scan_rc=$?
            if [[ $scan_rc -ne 0 ]]; then
                warn "Extended NSE scan still failed after falling back to the safe default script set."
                echo "[NOTE] Extended NSE scan failed after a segfault and safe fallback; see raw output for details." >> "$REPORT_FILE"
            fi
        else
            warn "Extended NSE scan failed with exit status $scan_rc; skipping detailed script output."
            echo "[NOTE] Extended NSE scan failed; see raw output for details." >> "$REPORT_FILE"
        fi
    fi

    if [[ -f "$RAW_DIR/07_nse_extended.nmap" ]]; then
        cat "$RAW_DIR/07_nse_extended.nmap" >> "$REPORT_FILE" 2>/dev/null
        ok "Extended NSE scan complete."
    else
        warn "No extended NSE output was written; the scan may have crashed or been skipped."
    fi
else
    section_header "PHASE 7: SKIPPED (no open ports detected)"
fi

# ---------------------------- Phase 7.5: Vulnerability triage summary -------------
VULN_SUMMARY_FILE="$RAW_DIR/vuln_summary.tmp"
: > "$VULN_SUMMARY_FILE"

if [[ "$DO_VULN" == true && -f "$RAW_DIR/07_nse_extended.nmap" ]]; then
    info "Building severity-sorted vulnerability triage summary..."

    # 1) CVE + CVSS pairs from the 'vulners' script (format: CVE-YYYY-NNNNN <score> <url>)
    grep -oP 'CVE-\d{4}-\d+\s+\d+(\.\d+)?\s+\S+' "$RAW_DIR/07_nse_extended.nmap" 2>/dev/null \
        | awk '{print $2, $1, $3}' | sort -rn -k1,1 | uniq \
        | awk '{printf "| %-5s | %-16s | %s |\n", $1, $2, $3}' >> "$VULN_SUMMARY_FILE"

    # 2) Confirmed "VULNERABLE" findings from the 'vuln' category scripts (e.g. smb-vuln-ms17-010)
    CONFIRMED="$(awk '
        /^\| [a-z0-9_-]+-vuln|^\| .*-vuln/ { script=$0 }
        /State: VULNERABLE/ { print script "  ->  " $0 }
    ' "$RAW_DIR/07_nse_extended.nmap" 2>/dev/null)"

    {
        section_header "VULNERABILITY TRIAGE SUMMARY (sorted by CVSS, highest first)"
        if [[ -s "$VULN_SUMMARY_FILE" ]]; then
            echo "| CVSS  | CVE              | Reference |"
            echo "|-------|------------------|-----------|"
            cat "$VULN_SUMMARY_FILE"
        elif [[ "$HAVE_VULNERS_SCRIPT" != true ]]; then
            echo "The 'vulners' script was not installed, so no CVSS-scored CVE table"
            echo "could be built. See the [NOTE] above for install instructions."
        else
            echo "No CVE matches returned by the 'vulners' script (no internet access,"
            echo "no version-matched entries in the database, or no open ports scanned)."
        fi
        echo ""
        if [[ -n "$CONFIRMED" ]]; then
            echo "Confirmed VULNERABLE findings from targeted 'vuln' scripts:"
            echo ""
            echo "$CONFIRMED"
        else
            echo "No 'vuln' category script reported a confirmed VULNERABLE state."
        fi
        echo ""
        echo "NOTE: CVSS scores reflect the generic severity of the CVE, not this"
        echo "specific target's exposure — verify exploitability and context (patch"
        echo "level, mitigating controls, reachability) before treating as confirmed."
    } >> "$REPORT_FILE"
    ok "Vulnerability triage summary added to report."
elif [[ "$DO_VULN" != true ]]; then
    section_header "VULNERABILITY TRIAGE SUMMARY: SKIPPED (run with -v/--vuln to enable)"
fi
rm -f "$VULN_SUMMARY_FILE"

# ---------------------------- Phase 8: Summary, CSV & optional HTML ---------------
info "Phase 8/${TOTAL_PHASES}: Building consolidated summary, CSV reports..."
section_header "CONSOLIDATED SUMMARY"

{
    echo "Target:                 $TARGET"
    echo "Resolved IP address:    $RESOLVED_IP"
    echo "Scan duration:          $(( $(date +%s) - SCRIPT_START_EPOCH )) seconds"
    if [[ -n "$OPEN_PORTS" ]]; then
        echo "Open ports:             $OPEN_PORTS"
    else
        echo "Open ports:             none found in range $PORTS"
    fi
    echo "SSL/TLS ports:          ${SSL_PORTS_FOUND:-none}"
    echo "Proxy/CDN detected:     ${PROXY_DETECTED:-none detected}"
    echo "Domain DNS expiry:      ${DOMAIN_EXPIRY:-not found / no whois run}"
    echo "Registrant email:       ${REGISTRANT_EMAIL:-not disclosed (redacted for privacy or no whois run)}"
    echo "Registrant organization:${REGISTRANT_ORG:-not found}"
    echo "Hosting org (IP WHOIS): ${IP_ORG:-not found}"
    echo "Hosting country:        ${IP_COUNTRY:-not found}"
    echo ""
    echo "Raw nmap output:        $RAW_DIR/"
    echo "  - .nmap  (human-readable)"
    echo "  - .xml   (machine-readable)"
    echo "  - .gnmap (grepable)"
} >> "$REPORT_FILE"

generate_csv_reports
{
    echo ""
    echo "CSV reports:"
    echo "  - $PORTS_CSV    (one row per port: port,protocol,state,service,product,version)"
    echo "  - $SUMMARY_CSV  (one row per field: the consolidated summary above, machine-readable)"
} >> "$REPORT_FILE"

section_header "APPENDIX: COMMANDS EXECUTED (AUDIT TRAIL)"
for c in "${COMMANDS_RUN[@]}"; do
    echo "\$ $c" >> "$REPORT_FILE"
done

# Optional pretty HTML report from the deep-scan XML, if xsltproc + nmap.xsl available
if [[ "$HAVE_XSLTPROC" == true && -f "$RAW_DIR/04_deep_scan.xml" ]]; then
    if xsltproc "$RAW_DIR/04_deep_scan.xml" -o "$OUTDIR/report.html" 2>/dev/null; then
        ok "HTML report generated: $OUTDIR/report.html"
    fi
fi

echo "" >> "$REPORT_FILE"
echo "Scan finished: $(date)" >> "$REPORT_FILE"

echo ""
ok "All phases complete."
ok "Consolidated report: $REPORT_FILE"
ok "Ports CSV:            $PORTS_CSV"
ok "Summary CSV:          $SUMMARY_CSV"
ok "Raw scan files:       $RAW_DIR/"
[[ -f "$OUTDIR/report.html" ]] && ok "HTML report:          $OUTDIR/report.html"
echo ""
echo -e "${BOLD}Quick findings:${NC}"
echo "  IP address:        $RESOLVED_IP"
echo "  Open ports:        ${OPEN_PORTS:-none found}"
echo "  Proxy/CDN:         ${PROXY_DETECTED:-none detected}"
echo "  Domain DNS expiry: ${DOMAIN_EXPIRY:-not found / no whois run}"
echo "  Registrant email:  ${REGISTRANT_EMAIL:-not disclosed (redacted or no whois run)}"
echo "  Hosting org/country: ${IP_ORG:-not found} / ${IP_COUNTRY:-not found}"
echo ""
info "Remember: only use this against targets you are explicitly authorized to test."
