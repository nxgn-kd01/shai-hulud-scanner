# Incident Response & Remediation Guide

**⚠️ If the scanner detected CRITICAL issues, follow this guide immediately.**

This document provides step-by-step instructions for responding to Shai Hulud 2.0 compromise detection.

## 🚨 Immediate Response (First 15 Minutes)

### Step 1: Isolate Affected Systems

**Stop all deployments and builds:**
```bash
# Cancel any running CI/CD pipelines
# GitHub Actions: Cancel running workflows
# Jenkins: Abort running builds

# If code is already deployed:
# - Do NOT tear down production yet (may need for forensics)
# - Block new deploys
```

**Quarantine compromised code:**
```bash
# Move affected directories
mkdir ~/quarantine-$(date +%Y%m%d)
mv /path/to/compromised-project ~/quarantine-$(date +%Y%m%d)/

# Or create a git branch for investigation
cd /path/to/compromised-project
git checkout -b incident-response-$(date +%Y%m%d)
git add .
git commit -m "SECURITY: Quarantine for incident response"
```

### Step 2: Assess Scope

**Review the scan report:**
```bash
cat shai-hulud-scan-report.txt

# Identify what was detected:
# - Malicious files? (setup_bun.js, bun_environment.js)
# - File hashes matched? (known malware)
# - Suspicious scripts? (preinstall hooks)
# - Compromised packages? (AsyncAPI, Voiceflow, etc.)
```

**Check when compromise occurred:**
```bash
cd /path/to/compromised-project

# Find when malicious files were added
git log --all --full-history -- "*setup_bun.js" "*bun_environment.js"

# Check package.json modification history
git log --all -p -- package.json | less

# Identify the commit that introduced the compromise
git log --since="30 days ago" --oneline
```

**Document everything:**
```bash
# Create incident log
cat > incident-log-$(date +%Y%m%d-%H%M).txt <<EOF
SECURITY INCIDENT LOG
=====================
Date: $(date)
Detected by: Shai Hulud 2.0 Scanner
Project: $(pwd)

FINDINGS:
$(cat shai-hulud-scan-report.txt)

TIMELINE:
$(git log --since="30 days ago" --oneline)

EOF
```

### Step 3: Immediately Rotate ALL Credentials

**The malware exfiltrates credentials. Assume ALL are compromised.**

## 🔐 Credential Rotation (Critical - Do Immediately)

### npm Tokens

```bash
# List all npm tokens
npm token list

# Revoke ALL tokens
npm token revoke --all

# Generate new token
npm token create --read-only  # For reading packages
npm token create              # For publishing (if needed)

# Update CI/CD with new token
# GitHub: Settings → Secrets → Update NPM_TOKEN
# Jenkins: Credentials → Update npm token
```

**Where npm tokens might be stored:**
- `~/.npmrc` - Remove old tokens
- CI/CD secrets (GitHub Actions, Jenkins, CircleCI, etc.)
- Team password managers
- Environment variables

### GitHub Tokens

```bash
# Revoke existing tokens
# Go to: https://github.com/settings/tokens
# Click "Delete" on all tokens

# For GitHub CLI:
gh auth logout
gh auth login  # Creates new token

# For personal access tokens:
# GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
# Delete all tokens
# Generate new tokens with minimum required scopes
```

**Check for unauthorized GitHub activity:**
```bash
# Review recent activity
gh api user/events | grep -A 5 "PushEvent\|CreateEvent"

# Check for suspicious repos
gh repo list --limit 100 --json name,description,createdAt

# Look for repos matching pattern: [0-9a-z]{18}
# Look for description: "Sha1-Hulud: The Second Coming."
```

**Delete suspicious repositories:**
```bash
# If you find malicious repos
gh repo delete OWNER/suspicious-repo-name --yes

# Review and delete repos created recently that you don't recognize
```

### Cloud Provider Credentials

**AWS:**
```bash
# Rotate access keys (CRITICAL)
aws iam list-access-keys
aws iam create-access-key
aws iam delete-access-key --access-key-id OLD_KEY_ID

# Review recent activity
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin
```

**Google Cloud:**
```bash
# List service account keys
gcloud iam service-accounts keys list --iam-account=SERVICE_ACCOUNT_EMAIL

# Delete old keys
gcloud iam service-accounts keys delete KEY_ID --iam-account=SERVICE_ACCOUNT_EMAIL

# Create new key
gcloud iam service-accounts keys create ~/new-key.json --iam-account=SERVICE_ACCOUNT_EMAIL

# Review audit logs
gcloud logging read "protoPayload.methodName=google.iam.admin.v1.CreateServiceAccountKey" --limit 50
```

**Azure:**
```bash
# Reset credentials
az ad sp credential reset --id SERVICE_PRINCIPAL_ID

# Review activity logs
az monitor activity-log list --start-time 2025-11-01 --end-time 2025-12-02
```

**Cloudflare:**
```bash
# API Tokens: https://dash.cloudflare.com/profile/api-tokens
# Roll all tokens

# Review audit logs
# Cloudflare Dashboard → Audit Logs → Check for suspicious activity
```

### Other Services

Rotate credentials for:
- ✅ Docker Hub
- ✅ Slack webhooks/tokens
- ✅ SendGrid/email service API keys
- ✅ Payment processors (Stripe, PayPal)
- ✅ Database credentials
- ✅ CDN tokens
- ✅ Monitoring services (Datadog, Sentry)
- ✅ Any service with API keys in your project

## 🧹 Code Cleanup

### Remove Malicious Files

```bash
cd /path/to/compromised-project

# Remove malicious files
find . -name "setup_bun.js" -delete
find . -name "bun_environment.js" -delete

# Verify they're gone
find . -name "*bun*.js"

# Commit removal
git add -A
git commit -m "SECURITY: Remove malicious Shai Hulud files"
```

### Clean package.json

```bash
# Review package.json for suspicious changes
git diff HEAD~5 package.json

# Look for:
# - New "preinstall" or "postinstall" scripts
# - References to setup_bun or bun_environment
# - Unexpected dependency additions
# - Version bumps without changelog entries

# If found, revert to clean version:
git checkout CLEAN_COMMIT_HASH -- package.json

# Or manually remove suspicious entries:
# Edit package.json and remove:
# - Suspicious scripts
# - Unknown dependencies
# - Malicious hooks
```

### Remove Compromised Packages

```bash
# If scanner detected compromised packages (AsyncAPI, Voiceflow, etc.)

# Remove the package
npm uninstall @asyncapi/parser  # Example

# Check if you actually need it
# If yes, wait for patched version or find alternative

# Update package-lock.json
rm package-lock.json
npm install
```

### Verify No Backdoors Remain

```bash
# Search for any remaining malicious code
grep -r "setup_bun\|bun_environment" .
grep -r "sha1-hulud\|sha1hulud" . -i

# Check for base64 encoded payloads
grep -r "eval.*atob\|eval.*Buffer.from.*base64" . --include="*.js" --include="*.ts"

# Look for suspicious network calls
grep -r "fetch.*metadata\|axios.*169.254.169.254" . --include="*.js" --include="*.ts"

# Run scanner again to verify
/path/to/shai-hulud-scanner/scan.sh .
```

## 🔍 Investigation & Forensics

### Determine Attack Timeline

```bash
# When was the malicious code introduced?
git log --all --full-history --source --oneline -- "*setup_bun*" "*bun_environment*"

# Who made the commit? (May be your account if compromised)
git log --all --format="%H %an %ae %ai" -- package.json

# What else changed in that timeframe?
git log --since="DATE_OF_COMPROMISE" --oneline --all

# Were there any deployments?
git log --grep="deploy\|release" --since="DATE_OF_COMPROMISE"
```

### Check for Exfiltrated Secrets

**Scan git history for exposed secrets:**

```bash
# Install TruffleHog (ironically, the same tool the malware uses)
# Use it for forensics to see what secrets may have been exposed

# Option 1: Use gitleaks
brew install gitleaks
gitleaks detect --source . --report-path gitleaks-report.json

# Option 2: Use trufflehog
docker run --rm -v "$(pwd):/repo" trufflesecurity/trufflehog:latest filesystem /repo

# Review the findings to understand what credentials may have been stolen
```

### Check Production Systems

```bash
# Were malicious files deployed to production?
ssh production-server
find /var/www/app -name "setup_bun.js" -o -name "bun_environment.js"

# Check application logs for suspicious activity
tail -f /var/log/app/access.log | grep -i "metadata\|169.254"

# Check for unauthorized access
grep -i "authentication\|login" /var/log/auth.log
```

### Review Access Logs

**GitHub:**
```bash
# Check for unauthorized repository access
# GitHub → Settings → Security log

# Look for:
# - Personal access token created/used
# - SSH keys added
# - OAuth applications authorized
# - Repository created (especially 18-char alphanumeric names)
```

**npm:**
```bash
# Check npm publish history
npm view YOUR_PACKAGE versions

# Check if any unauthorized versions were published
npm info YOUR_PACKAGE time

# If unauthorized versions exist:
npm unpublish YOUR_PACKAGE@BAD_VERSION
```

## 📢 Disclosure & Reporting

### Report to npm Security

```bash
# Email npm security team
# To: security@npmjs.com
# Subject: Shai Hulud 2.0 Compromise - [YOUR_PACKAGE_NAME]
```

**Include:**
- Package name(s) affected
- Versions compromised
- Timeline of compromise
- Evidence (scan reports, git commits)
- Actions taken

### Report to GitHub Security

```bash
# Report suspicious repositories
# Email: security@github.com

# Or use GitHub's security vulnerability reporting:
gh api /repos/OWNER/REPO/security-advisories
```

### Notify Users (If You Published Packages)

**If you maintain public packages that were compromised:**

```markdown
# Post security advisory

⚠️ SECURITY ADVISORY: Shai Hulud 2.0 Compromise

We have discovered that versions X.Y.Z of [package-name] were compromised
by the Shai Hulud 2.0 supply chain attack.

AFFECTED VERSIONS:
- [package-name]@X.Y.Z (published DATE)

IMMEDIATE ACTIONS:
1. Update to version X.Y.Z+1 (patched)
2. Rotate all credentials
3. Review applications for signs of compromise

TIMELINE:
- [DATE]: Compromise detected
- [DATE]: Malicious versions unpublished
- [DATE]: Patched version released

For more information:
- [Link to incident report]
- Contact: security@yourproject.com
```

### Create Public Incident Report

```markdown
# incident-report-public.md

## Shai Hulud 2.0 Compromise Incident Report

**Date of Detection:** 2025-12-02
**Attack Vector:** Shai Hulud 2.0 npm supply chain attack
**Status:** Resolved

### Summary
On [DATE], we detected indicators of compromise from the Shai Hulud 2.0
attack in [PROJECT_NAME]. Immediate action was taken to contain the incident.

### Impact
- [Describe what was affected]
- [What data/credentials may have been exposed]
- [What systems were affected]

### Response Actions Taken
- All credentials rotated
- Malicious code removed
- Security scan implemented
- Monitoring enhanced

### Prevention Measures Implemented
- Mandatory security scans before deployment
- Dependency lock with verification
- Multi-factor authentication enforced
- Security training for team

### Timeline
- [DATE TIME]: Compromise introduced
- [DATE TIME]: Detected by Shai Hulud scanner
- [DATE TIME]: Incident response initiated
- [DATE TIME]: Credentials rotated
- [DATE TIME]: Malicious code removed
- [DATE TIME]: Systems verified clean
- [DATE TIME]: Incident resolved

### Lessons Learned
- [What went well]
- [What could be improved]
- [Changes to prevent future incidents]
```

## 🛡️ Post-Incident Hardening

### Enable Multi-Factor Authentication

```bash
# GitHub: Settings → Password and authentication → Two-factor authentication
# npm: npm profile enable-2fa
# Cloud providers: Enable MFA for all accounts
```

### Implement Security Scanning

**Add to CI/CD:**
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Shai Hulud Scanner
        run: |
          curl -sSL https://raw.githubusercontent.com/nxgn-kd01/shai-hulud-scanner/main/scan.sh -o scan.sh
          chmod +x scan.sh
          ./scan.sh .
```

**Add pre-commit hook:**
```bash
# .git/hooks/pre-commit
#!/bin/bash
/path/to/shai-hulud-scanner/scan.sh . || exit 1
```

### Lock Down Dependencies

```bash
# Use package-lock.json and verify integrity
npm ci  # Instead of npm install

# Pin exact versions in package.json
# Instead of: "express": "^4.18.0"
# Use:        "express": "4.18.2"

# Verify checksums
npm audit signatures
```

### Implement Least Privilege

- Limit who can publish to npm
- Use scoped tokens with minimal permissions
- Rotate tokens regularly (90 days)
- Remove unused access

### Monitor for Threats

```bash
# Regular security scans
0 2 * * * /path/to/shai-hulud-scanner/scan.sh /path/to/projects

# Subscribe to security advisories
# - npm security advisories
# - GitHub security advisories
# - DataDog Security Labs
```

## 📚 Additional Resources

### Official Sources

- **DataDog Shai Hulud 2.0 Analysis:**
  https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/

- **DataDog IOC Repository:**
  https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0

- **npm Security Best Practices:**
  https://docs.npmjs.com/security-best-practices

- **npm Security Team:**
  security@npmjs.com

- **GitHub Security:**
  https://docs.github.com/en/code-security

### Incident Response Guides

- **NIST Cybersecurity Framework:**
  https://www.nist.gov/cyberframework

- **SANS Incident Response:**
  https://www.sans.org/white-papers/incident-response/

- **OWASP Incident Response:**
  https://owasp.org/www-community/Incident_Response_Cheat_Sheet

### Supply Chain Security

- **SLSA Framework:**
  https://slsa.dev/

- **CISA Software Supply Chain:**
  https://www.cisa.gov/software-supply-chain-security

- **OpenSSF Best Practices:**
  https://openssf.org/resources/guides/

## 💬 Need Help?

### Community Support

- **GitHub Discussions:** [Scanner discussions]
- **Security Community:** r/netsec, security.stackexchange.com

### Professional Incident Response

If compromise is severe or you need expert help:

- **Cybersecurity & Infrastructure Security Agency (CISA):** https://www.cisa.gov/report
- **Professional IR Firms:** Consider engaging professional incident response
- **Your Cloud Provider:** Contact AWS/GCP/Azure security teams

## ✅ Recovery Checklist

Use this checklist to track your incident response:

**Immediate Response:**
- [ ] Isolated affected systems
- [ ] Assessed scope of compromise
- [ ] Created incident log

**Credential Rotation:**
- [ ] Revoked all npm tokens
- [ ] Revoked all GitHub tokens
- [ ] Rotated AWS/GCP/Azure credentials
- [ ] Rotated Cloudflare API tokens
- [ ] Rotated all other service credentials

**Code Cleanup:**
- [ ] Removed malicious files
- [ ] Cleaned package.json
- [ ] Removed compromised packages
- [ ] Verified no backdoors remain
- [ ] Re-ran scanner (clean results)

**Investigation:**
- [ ] Determined attack timeline
- [ ] Identified compromised credentials
- [ ] Checked production systems
- [ ] Reviewed access logs
- [ ] Created incident report

**Disclosure:**
- [ ] Reported to npm security
- [ ] Reported to GitHub security
- [ ] Notified affected users
- [ ] Published incident report

**Hardening:**
- [ ] Enabled MFA everywhere
- [ ] Added security scanning to CI/CD
- [ ] Implemented pre-commit hooks
- [ ] Locked down dependencies
- [ ] Implemented least privilege
- [ ] Set up monitoring

**Verification:**
- [ ] Re-scan all projects (clean)
- [ ] Verify credentials work
- [ ] Test deployments
- [ ] Monitor for 30 days

---

**Remember:** Quick action saves time and limits damage. Follow this guide systematically, and don't skip steps even if you think they don't apply.

**Document everything** - you'll need it for the post-mortem and to prevent future incidents.
