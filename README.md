# Shai Hulud 2.0 Scanner

🛡️ **Detect indicators of compromise from the Shai Hulud 2.0 npm supply chain attack**

A comprehensive security scanner to detect malicious code and patterns from the Shai Hulud 2.0 worm that compromised 796+ npm packages in November 2025.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚨 About Shai Hulud 2.0

Shai Hulud 2.0 is one of the fastest-spreading npm supply chain attacks ever observed. The automated worm:

- Hijacked **796+ unique npm packages** (1,092+ total versions)
- Stole credentials (npm tokens, GitHub tokens, cloud credentials)
- Created malicious GitHub repositories
- Exfiltrated secrets using TruffleHog
- Spread automatically to maintainer's other packages

**Timeline:** Active November 2025
**Vector:** Stolen npm credentials → automated package hijacking → credential harvesting loop

## 📋 What This Scanner Checks

This tool performs 7 comprehensive security checks:

### 1. **Malicious File Detection** 🔴 Critical
- `setup_bun.js` - Malicious preinstall script
- `bun_environment.js` - Obfuscated payload (6 known variants)

### 2. **File Hash Verification** 🔴 Critical
Validates files against known malicious SHA-256 hashes:
- `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a` (setup_bun.js)
- 6 known hashes for bun_environment.js variants

### 3. **Suspicious Script Analysis** 🟡 Warning
- Detects suspicious `preinstall` scripts in package.json
- Identifies references to setup_bun or bun_environment
- Flags unexpected script modifications

### 4. **Compromised Package Ecosystems** 🟡 Warning
Checks for packages from affected ecosystems:
- `@asyncapi/*` (~60 compromised packages)
- `@voiceflow/*` (~90 compromised packages)
- `posthog-*` (~80 compromised packages)
- `@ensdomains/*` (~40 compromised packages)
- `quickswap-*` (~10 compromised packages)
- `zapier-*` (~15 compromised packages)

### 5. **TruffleHog Detection** 🟡 Warning
- Scans for TruffleHog secret scanning tool
- Used by malware for credential harvesting

### 6. **Recent Modifications Analysis** 🔵 Info
- Reviews package.json changes in last 30 days
- Identifies suspicious patch version bumps
- Helps spot unexpected modifications

### 7. **GitHub Repository Patterns** 🟡 Warning
- Detects repos with description: "Sha1-Hulud: The Second Coming."
- Identifies suspicious 18-character lowercase alphanumeric repo names
- Flags unusual repository creation patterns

## 🚀 Getting Started

### Prerequisites

**Required:**
- macOS or Linux (Bash 4.0+)
- `find` command (pre-installed)

**Optional (recommended for full scanning):**
- `git` - For analyzing modification history
- `gh` (GitHub CLI) - For scanning GitHub repositories
- `shasum` or `sha256sum` - For file hash verification (usually pre-installed)

### Step 1: Get the Scanner

**Option A: Clone (Recommended for users)**

```bash
# Clone the repository
git clone https://github.com/nxgn-kd01/shai-hulud-scanner.git
cd shai-hulud-scanner

# Make script executable
chmod +x scan.sh
```

**Option B: Fork (Recommended for contributors)**

```bash
# Fork on GitHub (click "Fork" button on repository page)
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/shai-hulud-scanner.git
cd shai-hulud-scanner

# Make script executable
chmod +x scan.sh

# Add upstream remote to stay updated
git remote add upstream https://github.com/nxgn-kd01/shai-hulud-scanner.git
```

**Option C: Quick Download (No git required)**

```bash
# Download and run directly
curl -sSL https://raw.githubusercontent.com/nxgn-kd01/shai-hulud-scanner/main/scan.sh -o scan.sh
chmod +x scan.sh
./scan.sh /path/to/your/project
```

### Step 2: Setup GitHub CLI (Optional but Recommended)

To scan your GitHub repositories for suspicious patterns, you'll need the GitHub CLI:

**Install GitHub CLI:**

```bash
# macOS
brew install gh

# Linux (Debian/Ubuntu)
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh

# Linux (RHEL/Fedora)
sudo dnf install gh
```

**Authenticate with GitHub:**

```bash
# Login to GitHub
gh auth login

# Follow the prompts:
# 1. Select "GitHub.com"
# 2. Select "HTTPS" or "SSH" (HTTPS recommended)
# 3. Select "Login with a web browser"
# 4. Copy the one-time code shown
# 5. Press Enter to open browser
# 6. Paste code and authorize

# Verify authentication
gh auth status
```

### Step 3: Run Your First Scan

**Scan a Local Project:**

```bash
# Scan the current directory
./scan.sh

# Scan a specific project
./scan.sh /path/to/your/project

# Example: Scan your Node.js project
./scan.sh ~/code/my-app
```

**Scan Multiple Projects:**

```bash
# Scan all projects in a directory
for dir in ~/code/*/; do
    echo "===================="
    echo "Scanning: $(basename $dir)"
    echo "===================="
    ./scan.sh "$dir"
    echo ""
done
```

**What Happens During a Scan:**

1. 🔍 Searches for malicious files (`setup_bun.js`, `bun_environment.js`)
2. 🔐 Verifies file hashes against known malware
3. 📦 Checks `package.json` for suspicious scripts
4. 🌐 Scans dependencies for compromised packages
5. 🔨 Looks for TruffleHog secret scanner
6. 📅 Analyzes recent `package.json` modifications
7. 🐙 Checks your GitHub repos for suspicious patterns (if `gh` authenticated)

### Step 4: Review the Results

**Console Output:**

The scanner displays color-coded results:
- 🚨 **RED (Critical)** - Immediate action required, malware detected
- ⚠️ **YELLOW (Warning)** - Suspicious patterns, review recommended
- ✅ **GREEN (Success)** - Check passed, no issues
- ℹ️ **BLUE (Info)** - Informational findings

**Detailed Report:**

A full report is saved to `shai-hulud-scan-report.txt` in the current directory:

```bash
# View the report
cat shai-hulud-scan-report.txt

# Or open in your editor
code shai-hulud-scan-report.txt
```

### Step 5: Scan Remote Repositories

**Scan GitHub Repos Without Cloning:**

```bash
# List your repos
gh repo list --limit 100

# Clone and scan a specific repo
gh repo clone YOUR_ORG/repo-name /tmp/scan-temp
./scan.sh /tmp/scan-temp
rm -rf /tmp/scan-temp

# Or create a helper script
cat > scan-remote.sh <<'EOF'
#!/bin/bash
REPO=$1
TEMP_DIR=$(mktemp -d)
echo "Cloning $REPO to temporary directory..."
gh repo clone "$REPO" "$TEMP_DIR"
echo "Scanning..."
./scan.sh "$TEMP_DIR"
echo "Cleaning up..."
rm -rf "$TEMP_DIR"
EOF
chmod +x scan-remote.sh

# Use it:
./scan-remote.sh YOUR_USERNAME/repo-name
```

### Common Issues & Solutions

**Issue: "Permission denied"**
```bash
# Make script executable
chmod +x scan.sh
```

**Issue: "gh: command not found"**
```bash
# Install GitHub CLI (see Step 2)
# Or skip GitHub repo scanning (other checks will still run)
```

**Issue: "shasum: command not found"**
```bash
# Install coreutils (usually pre-installed on macOS)
# Linux:
sudo apt-get install coreutils  # Debian/Ubuntu
sudo yum install coreutils       # RHEL/CentOS

# Or use sha256sum instead (scanner auto-detects)
```

**Issue: Scan shows "INFO" items but you want details**
```bash
# View the full report file
less shai-hulud-scan-report.txt

# Or use grep to find specific issues
grep -A 5 "WARNING\|CRITICAL" shai-hulud-scan-report.txt
```

## 📖 Usage

### Basic Scan

Scan the current directory:

```bash
./scan.sh
```

### Scan Specific Directory

```bash
./scan.sh /path/to/your/project
```

### Scan Multiple Projects

```bash
# Scan all projects in a parent directory
for dir in /Users/username/code/*/; do
    echo "Scanning $dir"
    ./scan.sh "$dir"
done
```

### CI/CD Integration

**Quick Integration:**

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  shai-hulud-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Shai Hulud Scanner
        run: |
          curl -sSL https://raw.githubusercontent.com/nxgn-kd01/shai-hulud-scanner/main/scan.sh | bash -s .
```

**Full Example Workflow:**

See `examples/github-actions-workflow.yml` for a complete workflow with:
- Artifact uploads
- PR comments with scan results
- Automatic issue creation on detection
- Scheduled daily scans

## 📊 Output

### Console Output

The scanner provides color-coded results:

- 🚨 **RED (Critical):** Immediate action required
- ⚠️ **YELLOW (Warning):** Review recommended
- ✅ **GREEN (Success):** Check passed
- ℹ️ **BLUE (Info):** Informational findings

### Report File

A detailed report is saved to `shai-hulud-scan-report.txt` containing:

- Scan metadata (date, directory, version)
- Detailed findings for each check
- Recommended actions if issues found
- References to security resources

### Exit Codes

- `0` - No issues found or warnings only
- `1` - Critical issues detected

## 🎯 Example Output

```
=== Shai Hulud 2.0 Scanner v1.0.0 ===
Scanning directory: /Users/username/project

=== 1. Scanning for Malicious Files ===
✅ No malicious files found

=== 2. Checking File Hashes ===
✅ No known malicious file hashes detected

=== 3. Checking package.json for Suspicious Scripts ===
✅ No suspicious scripts found

=== 4. Checking for Compromised Package Ecosystems ===
✅ No packages from compromised ecosystems found

=== 5. Scanning for TruffleHog ===
✅ No TruffleHog installations found

=== 6. Analyzing Recent package.json Changes ===
✅ No recent package.json modifications

=== 7. Checking GitHub Repository Patterns ===
✅ No suspicious repository descriptions
✅ No suspicious repository names

=== Scan Summary ===

Critical Issues: 0
Warnings: 0
Info Items: 0

✅ All clear! No indicators of compromise found.
ℹ️  Detailed report saved to: shai-hulud-scan-report.txt
```

## 🔧 Troubleshooting

### "shasum: command not found"

Install shasum (usually part of `coreutils`):

```bash
# macOS (built-in)
# Linux
sudo apt-get install coreutils  # Debian/Ubuntu
sudo yum install coreutils       # RHEL/CentOS
```

### "gh: command not found"

Install GitHub CLI:

```bash
# macOS
brew install gh

# Linux
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update
sudo apt install gh

# Authenticate
gh auth login
```

## 🛡️ What To Do If Compromise Is Detected

**⚠️ CRITICAL: If the scanner detects issues, follow our comprehensive remediation guide immediately.**

### 📖 Complete Incident Response Guide

**Read the full guide:** [REMEDIATION.md](REMEDIATION.md)

The guide includes:
- ✅ Immediate response steps (first 15 minutes)
- ✅ Complete credential rotation procedures (npm, GitHub, AWS, GCP, Azure, etc.)
- ✅ Code cleanup instructions
- ✅ Investigation and forensics procedures
- ✅ Disclosure and reporting requirements
- ✅ Post-incident hardening measures
- ✅ Recovery checklist

### Quick Response (First 15 Minutes)

1. **Isolate Affected Systems**
   ```bash
   # Stop deployments immediately
   # Move compromised code to quarantine
   mkdir ~/quarantine-$(date +%Y%m%d)
   mv /path/to/compromised-project ~/quarantine-$(date +%Y%m%d)/
   ```

2. **Rotate ALL Credentials Immediately**
   ```bash
   # npm tokens
   npm token revoke --all

   # GitHub tokens
   gh auth logout && gh auth login

   # AWS/GCP/Azure - see REMEDIATION.md for full instructions
   ```

3. **Remove Malicious Code**
   ```bash
   find . -name "setup_bun.js" -delete
   find . -name "bun_environment.js" -delete
   git add -A && git commit -m "SECURITY: Remove malicious files"
   ```

4. **Report the Incident**
   - npm security: security@npmjs.com
   - GitHub security: security@github.com
   - Follow disclosure guidelines in REMEDIATION.md

5. **Follow Complete Guide**
   - See [REMEDIATION.md](REMEDIATION.md) for detailed step-by-step instructions
   - Use the recovery checklist to track progress
   - Document everything for post-mortem

### For Warnings

If you get warnings (not critical issues):

1. **Review the scan report**
   ```bash
   cat shai-hulud-scan-report.txt
   ```

2. **Verify legitimacy** of flagged items
3. **Update dependencies** if needed: `npm audit && npm update`
4. **Re-run scanner** to confirm: `./scan.sh .`

### Need Help?

- **Detailed Guide:** [REMEDIATION.md](REMEDIATION.md) - Complete incident response procedures
- **Community:** [GitHub Discussions](https://github.com/nxgn-kd01/shai-hulud-scanner/discussions)
- **Professional IR:** If severe, consider engaging professional incident response
- **CISA:** Report to https://www.cisa.gov/report

## 📚 Resources

### Official IOC Sources

- **DataDog IOC Repository:** [github.com/DataDog/indicators-of-compromise](https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0)
- **DataDog Analysis:** [securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- **Consolidated IOC List:** 1,000+ compromised packages tracked

### Community Tools

**Shai Hulud 2.0 Detection:**
- [Shai-Hulud-2.0-Detector](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector) - GitHub Action with SARIF support
- [sha1-hulud-scanner](https://github.com/sivanagendravepada/sha1-hulud-scanner) - npm package scanner

**Related Vulnerability Scanners:**
- [react2shell-scanner](https://github.com/nxgn-kd01/react2shell-scanner) - Detect CVE-2025-55182 (React2Shell) RCE vulnerability in React Server Components

### Security Best Practices

- [npm Security Best Practices](https://docs.npmjs.com/security-best-practices)
- [OWASP Supply Chain Security](https://owasp.org/www-project-supply-chain-security/)
- [GitHub Security Advisories](https://github.com/advisories)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -m 'Add new detection'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

### Ideas for Contributions

- [ ] Add support for additional IOC sources
- [ ] Implement JSON output format
- [ ] Add Docker container support
- [ ] Create npm package version
- [ ] Add integration tests
- [ ] Support for other package managers (pip, cargo, etc.)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided "as is" for security research and defensive purposes only. While we make every effort to keep the IOC list current, new variants may emerge. Always:

- Keep the scanner updated
- Follow official security advisories
- Report suspected compromises to npm security
- Maintain defense-in-depth security practices

## 🙏 Acknowledgments

- **DataDog Security Labs** for comprehensive IOC research and analysis
- **npm Security Team** for rapid response
- Community security researchers: Koi.ai, StepSecurity, ReversingLabs, HelixGuard, SocketDev, Wiz

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/nxgn-kd01/shai-hulud-scanner/issues)
- **Security:** Report vulnerabilities privately to security@yourdomain.com
- **Discussions:** [GitHub Discussions](https://github.com/nxgn-kd01/shai-hulud-scanner/discussions)

---

**Stay Safe! 🛡️**

Remember to run this scanner:
- ✅ Before `npm install` operations
- ✅ Before merging dependency updates
- ✅ Regularly in CI/CD pipelines
- ✅ After inheriting or acquiring projects
