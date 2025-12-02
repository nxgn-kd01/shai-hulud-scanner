#!/bin/bash

# Scan Remote Repository
# Clones a GitHub repo to temporary directory, scans it, then cleans up

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 OWNER/REPO-NAME"
    echo ""
    echo "Examples:"
    echo "  $0 nodejs/node"
    echo "  $0 facebook/react"
    echo "  $0 YOUR_USERNAME/your-repo"
    echo ""
    echo "Note: Requires GitHub CLI (gh) to be installed and authenticated"
    echo "Run: gh auth login"
    exit 1
fi

REPO=$1
TEMP_DIR=$(mktemp -d)

echo "🔍 Scanning remote repository: $REPO"
echo "📁 Creating temporary directory: $TEMP_DIR"
echo ""

# Check if gh is installed
if ! command -v gh &> /dev/null; then
    echo "❌ Error: GitHub CLI (gh) is not installed"
    echo ""
    echo "Install with:"
    echo "  macOS:  brew install gh"
    echo "  Linux:  See https://cli.github.com/manual/installation"
    echo ""
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ Error: Not authenticated with GitHub"
    echo ""
    echo "Run: gh auth login"
    echo ""
    exit 1
fi

# Clone repository
echo "📥 Cloning repository..."
if ! gh repo clone "$REPO" "$TEMP_DIR" 2>&1; then
    echo "❌ Error: Failed to clone repository"
    echo "   Check if the repository exists and you have access"
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo "✅ Repository cloned"
echo ""

# Run scanner
echo "🛡️  Running Shai Hulud 2.0 Scanner..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

./scan.sh "$TEMP_DIR"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧹 Cleaning up temporary directory..."
rm -rf "$TEMP_DIR"

echo "✅ Scan complete!"
