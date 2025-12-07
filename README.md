# react2shell-guard

Security scanner for **CVE-2025-55182** - a critical (CVSS 10.0) unauthenticated Remote Code Execution vulnerability in React Server Components.

> **⚠️ DISCLAIMER**
>
> This is a **security scanner**, NOT an exploit tool. It is designed to help developers and security teams identify vulnerable dependencies in their projects.
>
> This is a **community-driven open source project** provided "AS IS" without warranty of any kind, express or implied. The authors and contributors are not responsible for any damages or security incidents arising from the use of this tool.
>
> **Use at your own risk and responsibility.** Always verify findings manually and follow your organization's security policies. If you discover any issues, bugs, or have suggestions, please [contribute back](CONTRIBUTING.md) to help improve the project for everyone.

> **🤝 CONTRIBUTORS WANTED**
>
> This project is **actively looking for testers and contributors**! Whether you want to report bugs, suggest features, improve documentation, or submit code - all contributions are welcome. Check out our [Contributing Guide](CONTRIBUTING.md) to get started.

## Acknowledgments

This project exists to help the community respond to CVE-2025-55182. We acknowledge and thank:

- **[Lachlan Davidson](https://github.com/lachlan2k)** ([react2shell.com](https://react2shell.com/)) - For discovering and responsibly disclosing the React Server Components vulnerability (CVE-2025-55182) on November 29th, 2025. The security community owes him gratitude for his diligence in identifying this critical flaw and working with the React and Next.js teams to ensure patches were available. His efforts have helped protect countless applications and users worldwide. See his [original PoC](https://github.com/lachlan2k/React2Shell-CVE-2025-55182-original-poc) for technical details.

## Quick Start

### 1. Instant Scan (No Installation)

The fastest way to check if your project is vulnerable:

```bash
npx react2shell-guard .
```

That's it! This will scan your current directory and show results immediately.

### 2. Scan a Specific Project

```bash
npx react2shell-guard /path/to/your/project
```

### 3. Auto-Fix Vulnerabilities

Found vulnerabilities? Fix them automatically:

```bash
# Preview what will be changed
npx react2shell-guard fix --dry-run

# Apply fixes
npx react2shell-guard fix

# Apply fixes and reinstall dependencies
npx react2shell-guard fix --install
```

### 4. Scan Live URLs

Check if a deployed application is vulnerable:

```bash
npx react2shell-guard scan-url https://your-app.com
```

### 5. Verify Patch Was Applied

Confirm your deployed fix is working:

```bash
npx react2shell-guard verify-patch https://your-app.com
```

### 6. Scan Container Images

Check if your Docker images contain vulnerable packages:

```bash
npx react2shell-guard scan-image myapp:latest
```

### 7. Create Fix PR (GitHub)

Automatically create a GitHub PR to fix vulnerabilities:

```bash
npx react2shell-guard create-pr --dry-run  # Preview
npx react2shell-guard create-pr            # Create PR
```

---

## What is CVE-2025-55182?

On November 29th, 2025, security researcher Lachlan Davidson discovered and responsibly disclosed a critical vulnerability in React Server Components. The flaw exists in how React decodes payloads sent to React Server Function endpoints, allowing unauthenticated attackers to achieve remote code execution on affected servers without any user interaction.

CVE-2025-55182 is rated CVSS 10.0 (Critical) and affects React Server Components (RSC) and frameworks using the RSC "Flight" protocol.

**Affected Packages:**
- `react-server-dom-webpack` 19.0.0, 19.1.0-19.1.1, 19.2.0
- `react-server-dom-parcel` (same versions)
- `react-server-dom-turbopack` (same versions)
- `next` 15.0.0-15.0.4, 15.1.0-15.1.8, 15.2.0-15.2.5, 15.3.0-15.3.5, 15.4.0-15.4.7, 15.5.0-15.5.6, 16.0.0-16.0.6

**More Information:**
- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Wiz Research](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)

---

## Installation (Optional)

For frequent use, install globally:

```bash
npm install -g react2shell-guard
```

Then use without `npx`:

```bash
react2shell-guard .
```

---

## Usage Guide

### Basic Scanning

```bash
# Scan current directory
react2shell-guard .

# Scan specific directory
react2shell-guard /path/to/project

# Scan and ignore certain paths
react2shell-guard . --ignore-path "examples/**" "test/**"
```

### Output Formats

```bash
# Human-readable text (default)
react2shell-guard .

# JSON output (for scripting)
react2shell-guard . --json

# SARIF output (for GitHub Security tab)
react2shell-guard . --sarif

# HTML report (standalone, shareable)
react2shell-guard . --html report.html
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--json` | Output results as JSON |
| `--sarif` | Output results as SARIF 2.1.0 |
| `--html <file>` | Generate standalone HTML report |
| `--no-exit-on-vuln` | Don't exit with code 1 when vulnerabilities found |
| `--ignore-path <patterns>` | Paths to ignore (e.g., `examples/**`) |
| `--debug` | Enable debug output |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities found |
| `1` | Vulnerabilities detected |
| `2+` | Fatal error |

## Live URL Scanning

Scan live endpoints to detect if they are vulnerable:

```bash
# Scan a single URL
react2shell-guard scan-url https://example.com

# Batch scan from a file (one URL per line)
react2shell-guard scan-url urls.txt --list

# With options
react2shell-guard scan-url https://example.com --timeout 5000 --json
```

### How Live URL Scanning Works

The scanner uses **passive fingerprinting** to detect vulnerable React Server Components endpoints without exploiting the vulnerability:

1. **Probe Request**: Sends a crafted POST request simulating an RSC Server Action call with a minimal payload:
   - Uses `multipart/form-data` content type with RSC-like data structure
   - Includes `Next-Action` header to trigger Server Action processing

2. **Response Analysis**: Analyzes the HTTP response for vulnerability signatures:
   - Checks for HTTP 500 status code (error response)
   - Matches response body against RSC Flight protocol error patterns:
     - `^[0-9]+:E{` - RSC Flight protocol error format
     - `"digest":"...RSC` - RSC digest in error responses
     - `ReactServerComponentsError` - React error class names
     - `text/x-component.*error` - Component error content type

3. **Non-Destructive**: This is purely a detection mechanism - it does **not** execute any malicious payload or exploit the vulnerability. The probe uses benign data that triggers error responses on vulnerable servers but causes no harm.

> **Note**: A positive detection means the server is running a vulnerable version and returned an RSC-specific error signature. It does NOT mean the server was exploited.

### URL Scanner Options

| Option | Description |
|--------|-------------|
| `--list` | Treat target as a file containing URLs |
| `--threads <n>` | Number of concurrent threads (default: 10) |
| `--timeout <ms>` | Request timeout in milliseconds (default: 10000) |
| `--json` | Output results as JSON |
| `--skip-ssl-verify` | Skip SSL certificate verification |
| `--verbose` | Show all results including non-vulnerable hosts |

## Patch Verification

Verify if a target has been patched against the vulnerability:

```bash
# Verify patch status (runs multiple scans for accuracy)
react2shell-guard verify-patch https://example.com

# With JSON output
react2shell-guard verify-patch https://example.com --json
```

### How Patch Verification Works

Patch verification performs **multiple consecutive scans** (default: 3) with brief delays between them to ensure accurate detection:

1. **Multiple Probes**: Runs the same passive fingerprinting check 3 times with 500ms delays
2. **Confidence Scoring**:
   - **High confidence**: 2+ successful scans with consistent results
   - **Medium confidence**: 1 successful scan with conclusive result
   - **Low confidence**: All scans failed or inconclusive results
3. **Result Classification**:
   - **PATCHED**: No vulnerability signatures detected across all successful scans
   - **VULNERABLE**: Vulnerability signature detected in one or more scans
   - **Inconclusive**: Mixed results or all scans failed

This multi-scan approach reduces false positives from transient network issues and provides higher confidence in the patch status.

### Verification Options

| Option | Description |
|--------|-------------|
| `--timeout <ms>` | Request timeout in milliseconds (default: 10000) |
| `--json` | Output results as JSON |
| `--skip-ssl-verify` | Skip SSL certificate verification |

## Container Image Scanning

Scan Docker/OCI container images for vulnerable packages:

```bash
# Scan a local or remote image
react2shell-guard scan-image myapp:latest

# Scan from a registry
react2shell-guard scan-image registry.example.com/myapp:v1.0

# Skip pulling (use local image only)
react2shell-guard scan-image myapp:latest --skip-pull

# With JSON output
react2shell-guard scan-image myapp:latest --json

# With SARIF output
react2shell-guard scan-image myapp:latest --sarif
```

### Container Scanner Options

| Option | Description |
|--------|-------------|
| `--timeout <ms>` | Operation timeout in milliseconds (default: 120000) |
| `--skip-pull` | Skip pulling image from registry (use local only) |
| `--json` | Output results as JSON |
| `--sarif` | Output results as SARIF 2.1.0 |
| `--no-exit-on-vuln` | Don't exit with code 1 when vulnerabilities found |
| `--debug` | Enable debug output |

**Requirements:**
- Docker must be installed and running
- Sufficient disk space for image extraction

## Vercel Deployment Integration

Block vulnerable deployments before they reach production:

```bash
# Run as part of your build command
react2shell-guard vercel-check

# In package.json
{
  "scripts": {
    "vercel-build": "react2shell-guard vercel-check && next build"
  }
}

# Or in vercel.json
{
  "buildCommand": "npx react2shell-guard vercel-check && npm run build"
}
```

### Vercel Check Options

| Option | Description |
|--------|-------------|
| `--no-fail` | Warn but do not fail the build on vulnerabilities |
| `--ignore-path <patterns>` | Paths to ignore (glob patterns) |
| `--debug` | Enable debug output |

## GitHub PR Automation

Automatically create a pull request to fix vulnerabilities:

```bash
# Preview what will be done
react2shell-guard create-pr --dry-run

# Create branch and PR
react2shell-guard create-pr

# Create branch but don't push/create PR
react2shell-guard create-pr --no-push

# Custom branch name
react2shell-guard create-pr --branch fix/security-update
```

### Create PR Options

| Option | Description |
|--------|-------------|
| `--branch <name>` | Branch name for the fix (default: `fix/cve-2025-55182`) |
| `--dry-run` | Show what would be done without making changes |
| `--no-push` | Create branch and commits but do not push or create PR |

**Requirements:**
- [GitHub CLI (gh)](https://cli.github.com/) must be installed and authenticated
- Must be in a git repository with a remote

## Example Output

```
react2shell-guard - CVE-2025-55182 Scanner
──────────────────────────────────────────────────

Scanned 1 project(s)

✗ my-app [VULNERABLE]
  Path: /path/to/my-app
  Framework: nextjs v15.2.1
  App Router: Yes (RSC enabled)

  Vulnerabilities found:
    - react-server-dom-webpack @ 19.1.0
      Upgrade to: 19.1.2
      Advisory: https://react.dev/blog/2025/12/03/...
    - next @ 15.2.1
      Upgrade to: 15.2.6
      Advisory: https://react.dev/blog/2025/12/03/...

──────────────────────────────────────────────────
VULNERABLE - Action required!
Upgrade affected packages to patched versions immediately.
```

## GitHub Actions Integration

> **Note:** We actively release new versions with improved detection patterns and fixes. Use `@v1` for stable releases or `@latest` for the newest version.

### GitHub Marketplace Action

The easiest way to integrate is using our official GitHub Action:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan for CVE-2025-55182
        uses: gensecaihq/react2shell-scanner@v1
        with:
          path: '.'
          fail-on-vuln: true
```

### Full-Featured Setup (SARIF + PR Comments)

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write    # For SARIF upload
      pull-requests: write      # For PR comments

    steps:
      - uses: actions/checkout@v4

      - name: Scan for CVE-2025-55182
        uses: gensecaihq/react2shell-scanner@v1
        with:
          path: '.'
          format: sarif
          fail-on-vuln: true
          upload-sarif: true        # Upload to GitHub Security tab
          add-pr-comment: true      # Comment on PRs with results
          ignore-paths: 'examples/**,test/fixtures/**'
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `scan-type` | Type of scan: `repo`, `sbom`, `container` | `repo` |
| `format` | Output format: `text`, `json`, `sarif` | `text` |
| `fail-on-vuln` | Fail if vulnerabilities found | `true` |
| `upload-sarif` | Upload SARIF to GitHub Security | `false` |
| `add-pr-comment` | Add PR comment with results | `false` |
| `ignore-paths` | Comma-separated paths to ignore | `''` |
| `sbom-file` | SBOM file path (when scan-type is sbom) | `''` |
| `container-image` | Docker image (when scan-type is container) | `''` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `vulnerable` | Whether vulnerabilities were found (`true`/`false`) |
| `findings-count` | Number of vulnerable packages |
| `scan-result` | Full scan result (JSON format) |
| `sarif-file` | Path to SARIF output file |

### Scan Container Images

```yaml
- name: Scan Docker image
  uses: gensecaihq/react2shell-scanner@v1
  with:
    scan-type: container
    container-image: myapp:latest
```

### Scan SBOM Files

```yaml
- name: Scan SBOM
  uses: gensecaihq/react2shell-scanner@v1
  with:
    scan-type: sbom
    sbom-file: sbom.json
```

### Manual CLI Usage

If you prefer to use the CLI directly:

```yaml
- name: Setup Node.js
  uses: actions/setup-node@v4
  with:
    node-version: '20'

- name: Scan for vulnerabilities
  run: npx react2shell-guard@latest .
```

## Supported Package Managers

react2shell-guard automatically detects and parses lockfiles from:

- **npm** - `package-lock.json` (v2 and v3 formats)
- **pnpm** - `pnpm-lock.yaml`
- **yarn** - `yarn.lock` (Classic and Berry formats)

## Features

- **Fast scanning** - Analyzes lockfiles directly, no need to install dependencies
- **Monorepo support** - Automatically discovers and scans all projects
- **Framework detection** - Identifies Next.js and App Router usage
- **Multiple output formats** - Text, JSON, SARIF, and HTML reports
- **CI/CD ready** - Exit codes and GitHub Actions integration
- **Zero network calls** - Works completely offline
- **Auto-fix** - Automatically update vulnerable dependencies
- **Pre-commit hooks** - Block commits with vulnerable dependencies
- **SBOM scanning** - Scan CycloneDX SBOM files
- **MCP integration** - AI assistant support via Model Context Protocol
- **Runtime protection** - Express.js/Next.js middleware for defense-in-depth
- **Live URL scanning** - Scan deployed applications for vulnerabilities
- **Container scanning** - Scan Docker/OCI images for vulnerable packages
- **Vercel integration** - Block vulnerable deployments before production
- **GitHub PR automation** - Auto-create fix PRs with one command

## Auto-Fix Vulnerabilities

Automatically update your `package.json` to use patched versions:

```bash
# Preview changes (dry run)
react2shell-guard fix --dry-run

# Apply fixes
react2shell-guard fix

# Apply fixes and run npm/pnpm/yarn install
react2shell-guard fix --install
```

## Pre-Commit Hooks

Install git hooks to prevent committing vulnerable dependencies:

```bash
# Auto-detect hook framework and install
react2shell-guard init-hooks

# Preview what would be installed
react2shell-guard init-hooks --dry-run

# Force specific hook type
react2shell-guard init-hooks --hook-type husky
react2shell-guard init-hooks --hook-type lefthook
react2shell-guard init-hooks --hook-type standalone
```

**Supported hook frameworks:**
- **Husky** - Appends to `.husky/pre-commit`
- **Lefthook** - Creates/updates `lefthook.yml`
- **Standalone** - Creates `.git/hooks/pre-commit`

The hook will block commits when `package.json` contains vulnerable dependencies and suggest running `react2shell-guard fix` to remediate.

## SBOM Scanning

Scan CycloneDX SBOM files for vulnerabilities:

```bash
# Scan a CycloneDX SBOM
react2shell-guard scan-sbom bom.json

# With JSON output
react2shell-guard scan-sbom bom.json --json

# With SARIF output
react2shell-guard scan-sbom bom.json --sarif
```

## MCP Server (AI Assistant Integration)

Start the Model Context Protocol server for AI assistant integration:

```bash
react2shell-guard mcp-server
```

**Available MCP tools:**
- `scan_repo` - Scan a repository for vulnerabilities
- `scan_sbom` - Scan a CycloneDX SBOM file

**Configure with MCP-compatible clients** (example configuration):
```json
{
  "mcpServers": {
    "react2shell-guard": {
      "command": "npx",
      "args": ["react2shell-guard", "mcp-server"]
    }
  }
}
```

## Runtime Protection Middleware

Defense-in-depth middleware that detects and blocks CVE-2025-55182 exploit attempts at runtime.

### Express.js

```typescript
import express from 'express';
import { createExpressMiddleware } from 'react2shell-guard/middleware';

const app = express();

// Add raw body parser for RSC payloads
app.use(express.raw({ type: 'text/x-component' }));
app.use(express.json());

// Add protection middleware
app.use(createExpressMiddleware({
  action: 'block',  // 'block' | 'log' | 'alert'
  onAlert: (result, req) => {
    // Send to your alerting system (Slack, PagerDuty, etc.)
    console.error('CVE-2025-55182 exploit attempt:', result);
  },
  skipPaths: ['/health', '/metrics'],
}));
```

### Next.js

```typescript
// middleware.ts
import { withReact2ShellGuard } from 'react2shell-guard/middleware';

export const middleware = withReact2ShellGuard({
  action: 'block',
  rscEndpointsOnly: true,  // Only check RSC endpoints (recommended)
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

**Detected patterns:**
- Serialized function injection
- Prototype pollution attempts
- Malformed module references
- Server action tampering
- Encoded malicious payloads
- RSC streaming format abuse

## API Usage

```typescript
import { scan } from 'react2shell-guard';

const result = scan({
  path: '/path/to/project',
  ignorePaths: ['examples/**'],
  debug: false,
});

console.log(result.vulnerable); // boolean
console.log(result.projects);   // ProjectResult[]
```

## JSON Output Schema

```json
{
  "cve": "CVE-2025-55182",
  "vulnerable": true,
  "scanTime": "2025-12-04T10:30:00Z",
  "projects": [
    {
      "name": "my-app",
      "path": "/path/to/my-app",
      "framework": {
        "type": "nextjs",
        "version": "15.2.1",
        "appRouterDetected": true
      },
      "findings": [
        {
          "package": "react-server-dom-webpack",
          "currentVersion": "19.1.0",
          "fixedVersion": "19.1.2",
          "severity": "critical",
          "advisoryUrl": "https://..."
        }
      ],
      "vulnerable": true
    }
  ],
  "errors": []
}
```

## Remediation

**Automatic fix (recommended):**
```bash
react2shell-guard fix --install
```

**Manual upgrade - React packages:**
```bash
npm install react-server-dom-webpack@19.1.2  # or 19.0.1, 19.2.1
```

**Manual upgrade - Next.js:**
```bash
npm install next@15.2.6  # or other patched version for your release line
```

**Fixed Next.js versions by release line:**
- 15.0.x → 15.0.5
- 15.1.x → 15.1.9
- 15.2.x → 15.2.6
- 15.3.x → 15.3.6
- 15.4.x → 15.4.8
- 15.5.x → 15.5.7
- 16.0.x → 16.0.7

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run in development mode
npm run dev
```

## License

MIT
