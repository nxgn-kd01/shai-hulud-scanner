#!/bin/bash

# Shai Hulud 2.0 Scanner
# Detects indicators of compromise from the Shai Hulud 2.0 npm supply chain attack
# Based on DataDog Security Labs IOC list
# https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0

set -e

VERSION="1.0.0"
SCAN_DIR="${1:-.}"
REPORT_FILE="shai-hulud-scan-report.txt"
CRITICAL_ISSUES=0
WARNING_ISSUES=0
INFO_ISSUES=0

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_critical() {
    echo -e "${RED}🚨 CRITICAL: $1${NC}"
    ((CRITICAL_ISSUES++))
}

print_warning() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
    ((WARNING_ISSUES++))
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
    ((INFO_ISSUES++))
}

# Start report
{
    echo "======================================"
    echo "Shai Hulud 2.0 Security Scan Report"
    echo "======================================"
    echo "Scan Date: $(date)"
    echo "Scan Directory: $(realpath "$SCAN_DIR")"
    echo "Scanner Version: $VERSION"
    echo ""
} > "$REPORT_FILE"

print_header "Shai Hulud 2.0 Scanner v${VERSION}"
echo "Scanning directory: $(realpath "$SCAN_DIR")"
echo ""

# Check 1: Malicious Files
print_header "1. Scanning for Malicious Files"
{
    echo "======================================"
    echo "1. MALICIOUS FILE SCAN"
    echo "======================================"
    echo ""
    echo "Checking for:"
    echo "  - setup_bun.js (malicious preinstall script)"
    echo "  - bun_environment.js (obfuscated payload)"
    echo ""
} >> "$REPORT_FILE"

MALICIOUS_FILES=$(find "$SCAN_DIR" -type f \( -name "setup_bun.js" -o -name "bun_environment.js" \) 2>/dev/null || true)

if [ -n "$MALICIOUS_FILES" ]; then
    print_critical "Malicious files detected!"
    echo "$MALICIOUS_FILES"
    echo "RESULT: CRITICAL - Malicious files found:" >> "$REPORT_FILE"
    echo "$MALICIOUS_FILES" >> "$REPORT_FILE"
else
    print_success "No malicious files found"
    echo "RESULT: PASS - No malicious files detected" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# Check 2: File Hash Verification
print_header "2. Checking File Hashes"
{
    echo "======================================"
    echo "2. FILE HASH VERIFICATION"
    echo "======================================"
    echo ""
    echo "Checking for known malicious file hashes:"
    echo "  setup_bun.js: a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
    echo "  bun_environment.js (6 known variants)"
    echo ""
} >> "$REPORT_FILE"

SUSPICIOUS_HASHES=0
if command -v shasum >/dev/null 2>&1; then
    while IFS= read -r -d '' file; do
        hash=$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')
        case "$hash" in
            "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"|"62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"|"cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd"|"f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068")
                print_critical "Malicious file hash detected: $file"
                echo "CRITICAL: $file (hash: $hash)" >> "$REPORT_FILE"
                ((SUSPICIOUS_HASHES++))
                ;;
        esac
    done < <(find "$SCAN_DIR" -type f \( -name "*.js" -o -name "*.ts" \) -print0 2>/dev/null)

    if [ $SUSPICIOUS_HASHES -eq 0 ]; then
        print_success "No known malicious file hashes detected"
        echo "RESULT: PASS - No malicious hashes found" >> "$REPORT_FILE"
    fi
else
    print_info "shasum not available - skipping hash verification"
    echo "RESULT: SKIPPED - shasum not available" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# Check 3: Suspicious preinstall scripts
print_header "3. Checking package.json for Suspicious Scripts"
{
    echo "======================================"
    echo "3. PACKAGE.JSON SCRIPT ANALYSIS"
    echo "======================================"
    echo ""
} >> "$REPORT_FILE"

SUSPICIOUS_SCRIPTS=0
while IFS= read -r -d '' pkg_file; do
    if grep -q '"preinstall"' "$pkg_file" 2>/dev/null; then
        print_warning "preinstall script found in: $pkg_file"
        echo "WARNING: preinstall script in $pkg_file" >> "$REPORT_FILE"
        grep -A 2 '"preinstall"' "$pkg_file" >> "$REPORT_FILE" 2>/dev/null || true
        ((SUSPICIOUS_SCRIPTS++))
    fi

    if grep -qi "setup_bun\|bun_environment" "$pkg_file" 2>/dev/null; then
        print_critical "Suspicious bun references in: $pkg_file"
        echo "CRITICAL: Suspicious bun references in $pkg_file" >> "$REPORT_FILE"
        grep -i "setup_bun\|bun_environment" "$pkg_file" >> "$REPORT_FILE" 2>/dev/null || true
        ((SUSPICIOUS_SCRIPTS++))
    fi
done < <(find "$SCAN_DIR" -name "package.json" -print0 2>/dev/null)

if [ $SUSPICIOUS_SCRIPTS -eq 0 ]; then
    print_success "No suspicious scripts found"
    echo "RESULT: PASS - No suspicious scripts detected" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# Check 4: Compromised Package Ecosystems
print_header "4. Checking for Compromised Package Ecosystems"
{
    echo "======================================"
    echo "4. COMPROMISED PACKAGE ECOSYSTEM SCAN"
    echo "======================================"
    echo ""
    echo "Checking for packages from affected ecosystems:"
    echo "  - @asyncapi/* (~60 compromised packages)"
    echo "  - @voiceflow/* (~90 compromised packages)"
    echo "  - posthog-* (~80 compromised packages)"
    echo "  - @ensdomains/* (~40 compromised packages)"
    echo "  - quickswap-* (~10 compromised packages)"
    echo "  - zapier-* (~15 compromised packages)"
    echo ""
} >> "$REPORT_FILE"

AFFECTED_PACKAGES=0
while IFS= read -r -d '' pkg_file; do
    pkg_name=$(basename "$(dirname "$pkg_file")")
    matches=$(grep -E "@asyncapi|@voiceflow|posthog|@ensdomains|quickswap|zapier" "$pkg_file" 2>/dev/null || true)
    if [ -n "$matches" ]; then
        print_warning "Affected ecosystem packages found in: $pkg_name"
        echo "WARNING: Affected packages in $pkg_name:" >> "$REPORT_FILE"
        echo "$matches" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        ((AFFECTED_PACKAGES++))
    fi
done < <(find "$SCAN_DIR" -name "package.json" -print0 2>/dev/null)

if [ $AFFECTED_PACKAGES -eq 0 ]; then
    print_success "No packages from compromised ecosystems found"
    echo "RESULT: PASS - No affected ecosystem packages detected" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# Check 5: TruffleHog Detection
print_header "5. Scanning for TruffleHog"
{
    echo "======================================"
    echo "5. TRUFFLLEHOG DETECTION"
    echo "======================================"
    echo ""
    echo "Checking for TruffleHog secret scanning tool (used by malware)"
    echo ""
} >> "$REPORT_FILE"

TRUFFLEHOG_FILES=$(find "$SCAN_DIR" -type f -iname "*trufflehog*" 2>/dev/null || true)
if [ -n "$TRUFFLEHOG_FILES" ]; then
    print_warning "TruffleHog files detected"
    echo "$TRUFFLEHOG_FILES"
    echo "WARNING: TruffleHog files found:" >> "$REPORT_FILE"
    echo "$TRUFFLEHOG_FILES" >> "$REPORT_FILE"
else
    print_success "No TruffleHog installations found"
    echo "RESULT: PASS - No TruffleHog detected" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# Check 6: Recent package.json modifications
print_header "6. Analyzing Recent package.json Changes"
{
    echo "======================================"
    echo "6. RECENT PACKAGE.JSON MODIFICATIONS"
    echo "======================================"
    echo ""
    echo "Checking for suspicious modifications in last 30 days"
    echo ""
} >> "$REPORT_FILE"

if command -v git >/dev/null 2>&1; then
    SUSPICIOUS_CHANGES=0
    while IFS= read -r -d '' pkg_file; do
        pkg_dir=$(dirname "$pkg_file")
        if [ -d "$pkg_dir/.git" ]; then
            cd "$pkg_dir"
            recent=$(git log --since="30 days ago" --oneline --follow -- package.json 2>/dev/null | head -5 || true)
            if [ -n "$recent" ]; then
                pkg_name=$(basename "$pkg_dir")
                print_info "Recent changes in $pkg_name:"
                echo "$recent"
                echo "INFO: Recent changes in $pkg_name:" >> "$REPORT_FILE"
                echo "$recent" >> "$REPORT_FILE"
                echo "" >> "$REPORT_FILE"
            fi
        fi
    done < <(find "$SCAN_DIR" -name "package.json" -print0 2>/dev/null)

    if [ $INFO_ISSUES -eq 0 ]; then
        print_success "No recent package.json modifications"
        echo "RESULT: No recent modifications detected" >> "$REPORT_FILE"
    fi
else
    print_info "Git not available - skipping change analysis"
    echo "RESULT: SKIPPED - Git not available" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# Check 7: GitHub Repository Patterns (if gh CLI available)
print_header "7. Checking GitHub Repository Patterns"
{
    echo "======================================"
    echo "7. GITHUB REPOSITORY PATTERN ANALYSIS"
    echo "======================================"
    echo ""
} >> "$REPORT_FILE"

if command -v gh >/dev/null 2>&1; then
    print_info "Checking GitHub repositories for suspicious patterns..."

    gh repo list --limit 100 --json name,description > /tmp/gh_repos_scan.json 2>/dev/null || true

    # Check for suspicious descriptions
    if grep -qi "sha1-hulud\|second coming" /tmp/gh_repos_scan.json 2>/dev/null; then
        print_critical "Suspicious repository descriptions found!"
        grep -i "sha1-hulud\|second coming" /tmp/gh_repos_scan.json >> "$REPORT_FILE"
    else
        print_success "No suspicious repository descriptions"
        echo "RESULT: PASS - No suspicious descriptions" >> "$REPORT_FILE"
    fi

    # Check for suspicious 18-char alphanumeric repo names
    if grep -E '"name":"[0-9a-z]{18}"' /tmp/gh_repos_scan.json >/dev/null 2>&1; then
        print_warning "Suspicious repository name pattern detected"
        grep -E '"name":"[0-9a-z]{18}"' /tmp/gh_repos_scan.json >> "$REPORT_FILE"
    else
        print_success "No suspicious repository names"
    fi

    rm -f /tmp/gh_repos_scan.json
else
    print_info "GitHub CLI not available - skipping GitHub scan"
    echo "RESULT: SKIPPED - GitHub CLI not available" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# Generate Summary
print_header "Scan Summary"
{
    echo "======================================"
    echo "SCAN SUMMARY"
    echo "======================================"
    echo ""
    echo "Critical Issues: $CRITICAL_ISSUES"
    echo "Warnings: $WARNING_ISSUES"
    echo "Info Items: $INFO_ISSUES"
    echo ""
} >> "$REPORT_FILE"

echo ""
echo "Critical Issues: $CRITICAL_ISSUES"
echo "Warnings: $WARNING_ISSUES"
echo "Info Items: $INFO_ISSUES"
echo ""

if [ $CRITICAL_ISSUES -gt 0 ]; then
    {
        echo "======================================"
        echo "⚠️  ACTION REQUIRED"
        echo "======================================"
        echo ""
        echo "CRITICAL security issues detected!"
        echo ""
        echo "⚠️  ⚠️  ⚠️  IMMEDIATE ACTION REQUIRED ⚠️  ⚠️  ⚠️"
        echo ""
        echo "📖 FOLLOW THE REMEDIATION GUIDE:"
        echo "   https://github.com/nxgn-kd01/shai-hulud-scanner/blob/main/REMEDIATION.md"
        echo ""
        echo "Quick actions (detailed steps in REMEDIATION.md):"
        echo "1. Isolate affected systems (stop deployments)"
        echo "2. Rotate ALL credentials immediately:"
        echo "   - npm tokens: npm token revoke --all"
        echo "   - GitHub tokens: https://github.com/settings/tokens"
        echo "   - AWS/GCP/Azure credentials"
        echo "   - All API keys and service tokens"
        echo "3. Remove malicious files identified above"
        echo "4. Review all recent package.json changes"
        echo "5. Scan for exfiltrated secrets using git history"
        echo "6. Report to npm security: security@npmjs.com"
        echo ""
        echo "📋 Complete Incident Response Checklist:"
        echo "   See REMEDIATION.md for full step-by-step guide"
        echo ""
        echo "References:"
        echo "  - Remediation Guide: https://github.com/nxgn-kd01/shai-hulud-scanner/blob/main/REMEDIATION.md"
        echo "  - DataDog Analysis: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/"
        echo "  - IOC List: https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0"
        echo "  - npm Security: security@npmjs.com"
        echo ""
    } >> "$REPORT_FILE"

    print_critical "CRITICAL ISSUES FOUND - Review report: $REPORT_FILE"
    exit 1
elif [ $WARNING_ISSUES -gt 0 ]; then
    {
        echo "======================================"
        echo "⚠️  WARNINGS DETECTED"
        echo "======================================"
        echo ""
        echo "Please review warnings above and verify legitimacy."
        echo ""
    } >> "$REPORT_FILE"

    print_warning "Warnings detected - Review report: $REPORT_FILE"
    exit 0
else
    {
        echo "======================================"
        echo "✅ ALL CLEAR"
        echo "======================================"
        echo ""
        echo "No indicators of Shai Hulud 2.0 compromise detected."
        echo ""
        echo "Recommendations:"
        echo "  - Continue monitoring dependencies before installation"
        echo "  - Review package.json changes in pull requests"
        echo "  - Run periodic scans with this tool"
        echo ""
    } >> "$REPORT_FILE"

    print_success "All clear! No indicators of compromise found."
    print_info "Detailed report saved to: $REPORT_FILE"
    exit 0
fi
