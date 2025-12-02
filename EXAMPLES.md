# Usage Examples

Real-world examples of using the Shai Hulud Scanner in different scenarios.

## 🏠 Scanning Your Local Projects

### Example 1: Quick Scan of Current Project

```bash
cd ~/code/my-nodejs-app
/path/to/shai-hulud-scanner/scan.sh .
```

**Output:**
```
=== Shai Hulud 2.0 Scanner v1.0.0 ===
Scanning directory: /Users/username/code/my-nodejs-app

=== 1. Scanning for Malicious Files ===
✅ No malicious files found

=== 2. Checking File Hashes ===
✅ No known malicious file hashes detected

[... more checks ...]

=== Scan Summary ===
Critical Issues: 0
Warnings: 0
Info Items: 0

✅ All clear! No indicators of compromise found.
```

### Example 2: Scan Multiple Projects

**Scan all projects in a directory:**

```bash
#!/bin/bash
# save as: scan-all-projects.sh

SCANNER="/path/to/shai-hulud-scanner/scan.sh"
PROJECT_DIR="$HOME/code"

echo "Scanning all projects in $PROJECT_DIR"
echo "======================================"

for dir in "$PROJECT_DIR"/*/; do
    project_name=$(basename "$dir")

    # Skip non-Node.js projects
    if [ ! -f "$dir/package.json" ]; then
        echo "⏭️  Skipping $project_name (no package.json)"
        continue
    fi

    echo ""
    echo "🔍 Scanning: $project_name"
    echo "--------------------"

    $SCANNER "$dir" > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo "✅ $project_name - CLEAN"
    else
        echo "🚨 $project_name - ISSUES FOUND! Review shai-hulud-scan-report.txt"
    fi
done

echo ""
echo "======================================"
echo "Scan complete!"
```

### Example 3: Scan Before Deployment

**Pre-deployment security check:**

```bash
#!/bin/bash
# Add to your deployment script

echo "🛡️  Running security scan before deployment..."

if /path/to/shai-hulud-scanner/scan.sh .; then
    echo "✅ Security scan passed - proceeding with deployment"
    # Your deployment commands here
    npm run build
    npm run deploy
else
    echo "🚨 Security scan failed - DEPLOYMENT ABORTED"
    echo "Review shai-hulud-scan-report.txt for details"
    exit 1
fi
```

## 🐙 Scanning GitHub Repositories

### Example 4: Scan Your Own Repos

```bash
# List your repositories
gh repo list --limit 100

# Scan a specific repo
./scan-remote.sh YOUR_USERNAME/repo-name

# Or scan multiple repos
for repo in $(gh repo list --json name --jq '.[].name' --limit 10); do
    echo "Scanning $repo..."
    ./scan-remote.sh YOUR_USERNAME/$repo
    echo ""
done
```

### Example 5: Scan Before Forking/Cloning

**Before adding a dependency, scan it:**

```bash
#!/bin/bash
# Check a package's GitHub repo before using it

PACKAGE_NAME="$1"

if [ -z "$PACKAGE_NAME" ]; then
    echo "Usage: $0 package-name"
    exit 1
fi

echo "🔍 Looking up $PACKAGE_NAME on npm..."

# Get GitHub repo URL from npm
REPO_URL=$(npm view "$PACKAGE_NAME" repository.url 2>/dev/null | sed 's/git+https:\/\/github.com\///' | sed 's/.git$//')

if [ -z "$REPO_URL" ]; then
    echo "❌ Could not find GitHub repository for $PACKAGE_NAME"
    exit 1
fi

echo "📦 Repository: $REPO_URL"
echo ""

# Scan the repository
./scan-remote.sh "$REPO_URL"
```

**Usage:**
```bash
chmod +x check-package.sh
./check-package.sh express
./check-package.sh @asyncapi/parser  # Check potentially affected package
```

### Example 6: Scan Organization Repos

```bash
#!/bin/bash
# Scan all repos in an organization

ORG="YOUR_ORGANIZATION"

echo "🏢 Scanning all repositories in $ORG organization"
echo "=================================================="

# Get all repo names
repos=$(gh repo list "$ORG" --limit 100 --json name --jq '.[].name')

# Create results directory
mkdir -p scan-results
cd scan-results

# Scan each repo
for repo in $repos; do
    echo ""
    echo "🔍 Scanning: $ORG/$repo"
    echo "--------------------"

    ../scan-remote.sh "$ORG/$repo" > "${repo}-scan.log" 2>&1

    if [ $? -eq 0 ]; then
        echo "✅ $repo - CLEAN"
    else
        echo "🚨 $repo - ISSUES FOUND! Check ${repo}-scan.log"
    fi
done

echo ""
echo "=================================================="
echo "Results saved in: $(pwd)"
```

## 🔄 CI/CD Integration Examples

### Example 7: GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Shai Hulud Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

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

      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-report
          path: shai-hulud-scan-report.txt
```

### Example 8: Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "🛡️  Running Shai Hulud security scan..."

if /path/to/shai-hulud-scanner/scan.sh . > /dev/null 2>&1; then
    echo "✅ Security scan passed"
    exit 0
else
    echo "🚨 Security scan failed!"
    echo ""
    echo "Critical security issues detected."
    echo "Review: shai-hulud-scan-report.txt"
    echo ""
    echo "To bypass this check (NOT recommended):"
    echo "  git commit --no-verify"
    exit 1
fi
```

**Install:**
```bash
# Copy to your project
cp /path/to/shai-hulud-scanner/examples/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

### Example 9: Jenkins Pipeline

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    curl -sSL https://raw.githubusercontent.com/nxgn-kd01/shai-hulud-scanner/main/scan.sh -o scan.sh
                    chmod +x scan.sh
                    ./scan.sh .
                '''
            }
        }

        stage('Build') {
            when {
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                sh 'npm ci'
                sh 'npm run build'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'shai-hulud-scan-report.txt', fingerprint: true
        }
        failure {
            emailext (
                subject: "Security Scan Failed: ${env.JOB_NAME}",
                body: "Shai Hulud scanner detected security issues. Review attached report.",
                attachmentsPattern: 'shai-hulud-scan-report.txt'
            )
        }
    }
}
```

## 📊 Batch Scanning & Reporting

### Example 10: Generate Security Report for All Projects

```bash
#!/bin/bash
# generate-security-report.sh

SCANNER="/path/to/shai-hulud-scanner/scan.sh"
REPORT_DIR="security-reports-$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"

echo "📊 Generating Security Report"
echo "=============================="
echo "Date: $(date)"
echo ""

# Summary counters
TOTAL=0
CLEAN=0
WARNINGS=0
CRITICAL=0

for dir in ~/code/*/; do
    [ ! -f "$dir/package.json" ] && continue

    project=$(basename "$dir")
    ((TOTAL++))

    echo "Scanning: $project"

    $SCANNER "$dir" > "$REPORT_DIR/${project}.txt" 2>&1

    case $? in
        0)
            echo "  ✅ Clean"
            ((CLEAN++))
            ;;
        1)
            if grep -q "CRITICAL" "$REPORT_DIR/${project}.txt"; then
                echo "  🚨 CRITICAL ISSUES"
                ((CRITICAL++))
            else
                echo "  ⚠️  Warnings"
                ((WARNINGS++))
            fi
            ;;
    esac
done

# Generate summary
cat > "$REPORT_DIR/SUMMARY.txt" <<EOF
Security Scan Summary
=====================
Date: $(date)
Scanner: Shai Hulud 2.0 v1.0.0

Results:
--------
Total Projects: $TOTAL
Clean:          $CLEAN ($(( CLEAN * 100 / TOTAL ))%)
Warnings:       $WARNINGS ($(( WARNINGS * 100 / TOTAL ))%)
Critical:       $CRITICAL ($(( CRITICAL * 100 / TOTAL ))%)

Reports saved to: $REPORT_DIR/

Critical Issues Projects:
EOF

if [ $CRITICAL -gt 0 ]; then
    for report in "$REPORT_DIR"/*.txt; do
        if grep -q "CRITICAL" "$report"; then
            basename "$report" .txt >> "$REPORT_DIR/SUMMARY.txt"
        fi
    done
else
    echo "None" >> "$REPORT_DIR/SUMMARY.txt"
fi

cat "$REPORT_DIR/SUMMARY.txt"

echo ""
echo "Full reports available in: $REPORT_DIR/"
```

## 🔔 Notification Examples

### Example 11: Slack Notification

```bash
#!/bin/bash
# scan-and-notify-slack.sh

SCANNER="/path/to/shai-hulud-scanner/scan.sh"
SLACK_WEBHOOK="YOUR_SLACK_WEBHOOK_URL"

$SCANNER "$1"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 1 ]; then
    # Critical issues found
    MESSAGE="🚨 *CRITICAL* Security Issues Detected!\n\nProject: $1\n\nShai Hulud 2.0 indicators found. Immediate action required!"

    curl -X POST "$SLACK_WEBHOOK" \
        -H 'Content-Type: application/json' \
        -d "{\"text\": \"$MESSAGE\"}"
elif [ $EXIT_CODE -eq 0 ]; then
    # All clear
    MESSAGE="✅ Security scan passed for: $1"

    curl -X POST "$SLACK_WEBHOOK" \
        -H 'Content-Type: application/json' \
        -d "{\"text\": \"$MESSAGE\"}"
fi
```

### Example 12: Email Alert

```bash
#!/bin/bash
# scan-and-email.sh

SCANNER="/path/to/shai-hulud-scanner/scan.sh"
PROJECT="$1"
ADMIN_EMAIL="security@yourcompany.com"

$SCANNER "$PROJECT"

if [ $? -eq 1 ]; then
    # Send email alert
    mail -s "🚨 Security Alert: Shai Hulud Detected in $PROJECT" "$ADMIN_EMAIL" < shai-hulud-scan-report.txt
fi
```

## 🎯 Real-World Scenarios

### Scenario: New Team Member Onboarding

```bash
# onboarding-security-check.sh
#!/bin/bash

echo "Welcome! Running security scan on your local projects..."
echo ""

# Install scanner
git clone https://github.com/nxgn-kd01/shai-hulud-scanner.git ~/security-tools/shai-hulud-scanner

# Scan all projects
for dir in ~/code/*/; do
    ~/security-tools/shai-hulud-scanner/scan.sh "$dir"
done

echo ""
echo "Security scan complete!"
echo "If any issues were found, contact security@company.com"
```

### Scenario: Vendor Code Audit

```bash
# Before accepting vendor-provided code
./scan-remote.sh vendor-org/vendor-project

# Or for local code drop
unzip vendor-code.zip -d /tmp/vendor-code
./scan.sh /tmp/vendor-code
```

### Scenario: Open Source Contribution Review

```bash
# Before merging external PR
gh pr checkout 123
./scan.sh .

if [ $? -eq 0 ]; then
    echo "✅ Security check passed - safe to review"
else
    echo "🚨 Security issues in PR - request changes"
fi
```

---

**Need more examples?** Open an issue or contribute your use case!
