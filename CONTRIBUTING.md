# Contributing to Shai Hulud Scanner

Thank you for your interest in contributing to the Shai Hulud Scanner! This tool helps protect the npm ecosystem from supply chain attacks, and your contributions make a difference.

## 🎯 Ways to Contribute

### 1. Report Bugs or False Positives
- Use [GitHub Issues](https://github.com/nxgn-kd01/shai-hulud-scanner/issues)
- Include scanner version, operating system, and steps to reproduce
- For false positives, include the specific package/file flagged

### 2. Add New IOCs
- Submit pull requests with newly discovered indicators
- Include source/reference for the IOC
- Update documentation with detection details

### 3. Improve Detection Logic
- Enhance existing checks
- Add new detection patterns
- Optimize performance

### 4. Documentation
- Fix typos or clarify instructions
- Add examples or use cases
- Translate documentation

### 5. Testing
- Test on different operating systems
- Verify detection accuracy
- Add integration tests

## 🚀 Getting Started

### Prerequisites

- Bash 4.0+
- Git
- Basic command line experience

### Setup Development Environment

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/YOUR_USERNAME/shai-hulud-scanner.git
cd shai-hulud-scanner

# Create a branch for your changes
git checkout -b feature/your-feature-name

# Make the script executable
chmod +x scan.sh

# Test your changes
./scan.sh /path/to/test/directory
```

## 📝 Development Guidelines

### Code Style

**Shell Script Best Practices:**

```bash
# Use meaningful variable names
MALICIOUS_FILES=$(find ...)  # Good
x=$(find ...)                 # Bad

# Add comments for complex logic
# Check for suspicious preinstall scripts that may execute malicious code
if grep -q '"preinstall"' "$pkg_file"; then
    # ...
fi

# Handle errors appropriately
set -e  # Exit on error

# Quote variables to prevent word splitting
echo "$VARIABLE"  # Good
echo $VARIABLE    # Bad

# Use functions for reusable code
print_critical() {
    echo -e "${RED}🚨 CRITICAL: $1${NC}"
    ((CRITICAL_ISSUES++))
}
```

### Testing Your Changes

**Manual Testing:**

```bash
# Create test directory with known patterns
mkdir -p test/malicious
echo "malicious content" > test/malicious/setup_bun.js

# Run scanner
./scan.sh test/

# Verify detection
cat shai-hulud-scan-report.txt
```

**Test Cases to Cover:**

1. **True Positives:** Should detect known malicious patterns
2. **True Negatives:** Should not flag legitimate code
3. **Edge Cases:** Empty directories, permission errors, missing tools
4. **Performance:** Large repositories (1000+ files)

### Commit Message Format

Use clear, descriptive commit messages:

```
type: brief description

Detailed explanation of changes (if needed)

Fixes #123
```

**Types:**
- `feat`: New feature or detection
- `fix`: Bug fix or false positive correction
- `docs`: Documentation updates
- `test`: Add or update tests
- `refactor`: Code restructuring
- `perf`: Performance improvements

**Examples:**

```
feat: add detection for malicious postinstall scripts

- Scan for postinstall in package.json
- Flag suspicious script patterns
- Update report format

Closes #45

fix: reduce false positives in AsyncAPI detection

The previous pattern was too broad and flagged legitimate @asyncapi
packages. Updated to only flag specific compromised versions.

Fixes #67
```

## 🔍 Adding New Detections

### Step 1: Research the IOC

- Verify with official sources (DataDog, npm security, etc.)
- Document the attack vector
- Identify unique fingerprints

### Step 2: Implement Detection

Add your check to `scan.sh`:

```bash
# Check X: Your New Detection
print_header "X. Checking for New Threat"
{
    echo "======================================"
    echo "X. NEW THREAT DETECTION"
    echo "======================================"
    echo ""
    echo "Checking for: [describe what you're looking for]"
    echo ""
} >> "$REPORT_FILE"

# Your detection logic here
THREAT_COUNT=0
# ... scanning code ...

if [ $THREAT_COUNT -gt 0 ]; then
    print_critical "New threat detected!"
    echo "CRITICAL: Details..." >> "$REPORT_FILE"
else
    print_success "No new threats found"
    echo "RESULT: PASS" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"
```

### Step 3: Update Documentation

- Add to README "What This Scanner Checks" section
- Document the IOC source
- Provide remediation steps

### Step 4: Test Thoroughly

- Test with true positives (known malicious samples)
- Test with true negatives (legitimate code)
- Verify report output

## 📋 Pull Request Process

### Before Submitting

- [ ] Test your changes on multiple operating systems (if possible)
- [ ] Update README if adding new features
- [ ] Add comments to complex code
- [ ] Verify no false positives introduced
- [ ] Check that all existing tests still pass

### Submitting PR

1. **Create Pull Request**
   - Use a clear, descriptive title
   - Reference related issues
   - Explain what changed and why

2. **PR Description Template**

   ```markdown
   ## Description
   [Brief description of changes]

   ## Type of Change
   - [ ] Bug fix (false positive/negative)
   - [ ] New feature (detection method)
   - [ ] Documentation update
   - [ ] Performance improvement

   ## Testing
   [How you tested your changes]

   ## Checklist
   - [ ] Code follows project style guidelines
   - [ ] Self-review completed
   - [ ] Documentation updated
   - [ ] Tested on multiple scenarios
   - [ ] No new warnings introduced

   ## Related Issues
   Closes #[issue number]
   ```

3. **Respond to Review**
   - Address feedback promptly
   - Make requested changes
   - Ask questions if unclear

### After Approval

- Maintainers will merge your PR
- Your contribution will be credited
- Thank you! 🎉

## 🛡️ Security Considerations

### Reporting Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email: security@yourdomain.com
2. Include detailed description
3. Provide steps to reproduce
4. Suggest a fix if possible

We will respond within 48 hours and work with you on a fix.

### Handling Sensitive Data

- Never commit actual malware samples
- Use file hashes instead of full payloads
- Sanitize any example output
- Don't include real credentials or tokens

## 📚 Resources

### IOC Sources

- [DataDog IOC Repository](https://github.com/DataDog/indicators-of-compromise)
- [npm Security Advisories](https://www.npmjs.com/advisories)
- [GitHub Security Advisories](https://github.com/advisories)

### Shell Scripting

- [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
- [ShellCheck](https://www.shellcheck.net/) - Shell script linter
- [Bash Guide](https://mywiki.wooledge.org/BashGuide)

### Security Research

- [OWASP Supply Chain Security](https://owasp.org/www-project-supply-chain-security/)
- [npm Security Best Practices](https://docs.npmjs.com/security-best-practices)

## 💬 Communication

### Getting Help

- **Questions:** [GitHub Discussions](https://github.com/nxgn-kd01/shai-hulud-scanner/discussions)
- **Bugs:** [GitHub Issues](https://github.com/nxgn-kd01/shai-hulud-scanner/issues)
- **Chat:** [Join our Discord](#) (if applicable)

### Code of Conduct

We are committed to providing a welcoming and inclusive environment:

- Be respectful and considerate
- Welcome newcomers and help them learn
- Focus on what is best for the community
- Show empathy towards others
- Accept constructive criticism gracefully

Unacceptable behavior:
- Harassment or discriminatory language
- Personal attacks or trolling
- Publishing others' private information
- Other conduct inappropriate in a professional setting

## 🎖️ Recognition

Contributors will be recognized in:
- README.md acknowledgments section
- Release notes for significant contributions
- GitHub contributors page

Thank you for making the npm ecosystem safer! 🛡️

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.
