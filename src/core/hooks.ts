/**
 * Git Pre-Commit Hook Integration
 * Generates and installs pre-commit hooks to prevent vulnerable dependencies
 */

import { existsSync, mkdirSync, writeFileSync, chmodSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface InitHooksOptions {
  projectPath: string;
  hookType?: 'husky' | 'lefthook' | 'simple-git-hooks' | 'standalone';
  dryRun?: boolean;
}

export interface InitHooksResult {
  success: boolean;
  hookType: string;
  hookPath: string;
  message: string;
  errors: string[];
}

const PRE_COMMIT_SCRIPT = `#!/bin/sh
# react2shell-guard pre-commit hook
# Prevents commits with CVE-2025-55182 vulnerable dependencies

# Check if package.json is being committed
if git diff --cached --name-only | grep -q "package.json"; then
  echo "Checking for CVE-2025-55182 vulnerabilities..."

  # Run the scanner on staged package.json files
  npx react2shell-guard scan --json > /tmp/react2shell-guard-result.json 2>/dev/null

  if [ $? -eq 1 ]; then
    echo ""
    echo "\\033[31m╔══════════════════════════════════════════════════════════════╗\\033[0m"
    echo "\\033[31m║  COMMIT BLOCKED: CVE-2025-55182 Vulnerability Detected!      ║\\033[0m"
    echo "\\033[31m╚══════════════════════════════════════════════════════════════╝\\033[0m"
    echo ""
    echo "Your package.json contains vulnerable dependencies."
    echo ""
    echo "Run 'npx react2shell-guard fix' to automatically update to safe versions."
    echo "Or run 'npx react2shell-guard scan' for details."
    echo ""
    echo "To bypass this check (not recommended), use: git commit --no-verify"
    echo ""
    rm -f /tmp/react2shell-guard-result.json
    exit 1
  fi

  rm -f /tmp/react2shell-guard-result.json
  echo "\\033[32m✓ No CVE-2025-55182 vulnerabilities found\\033[0m"
fi

exit 0
`;

const HUSKY_SCRIPT = `npx react2shell-guard scan --json > /dev/null 2>&1

if [ $? -eq 1 ]; then
  echo ""
  echo "\\033[31m╔══════════════════════════════════════════════════════════════╗\\033[0m"
  echo "\\033[31m║  COMMIT BLOCKED: CVE-2025-55182 Vulnerability Detected!      ║\\033[0m"
  echo "\\033[31m╚══════════════════════════════════════════════════════════════╝\\033[0m"
  echo ""
  echo "Run 'npx react2shell-guard fix' to automatically fix."
  echo "Or run 'npx react2shell-guard scan' for details."
  echo ""
  exit 1
fi
`;

const LEFTHOOK_CONFIG = `pre-commit:
  commands:
    react2shell-guard:
      glob: "package.json"
      run: npx react2shell-guard scan
      fail_text: "CVE-2025-55182 vulnerability detected! Run 'npx react2shell-guard fix' to remediate."
`;

/**
 * Detect which hook framework is installed
 */
function detectHookFramework(projectPath: string): 'husky' | 'lefthook' | 'simple-git-hooks' | 'standalone' {
  const packageJsonPath = join(projectPath, 'package.json');

  if (existsSync(packageJsonPath)) {
    try {
      const content = readFileSync(packageJsonPath, 'utf-8');
      const pkg = JSON.parse(content);

      // Check devDependencies
      const devDeps = pkg.devDependencies || {};
      const deps = pkg.dependencies || {};
      const allDeps = { ...deps, ...devDeps };

      if (allDeps['husky']) return 'husky';
      if (allDeps['lefthook']) return 'lefthook';
      if (allDeps['simple-git-hooks']) return 'simple-git-hooks';
    } catch {
      // Ignore parse errors
    }
  }

  // Check for existing hook directories
  if (existsSync(join(projectPath, '.husky'))) return 'husky';
  if (existsSync(join(projectPath, 'lefthook.yml')) || existsSync(join(projectPath, '.lefthook.yml'))) return 'lefthook';

  return 'standalone';
}

/**
 * Install pre-commit hook for Husky
 */
function installHuskyHook(projectPath: string, dryRun: boolean): InitHooksResult {
  const huskyDir = join(projectPath, '.husky');
  const hookPath = join(huskyDir, 'pre-commit');

  const result: InitHooksResult = {
    success: false,
    hookType: 'husky',
    hookPath,
    message: '',
    errors: [],
  };

  if (!existsSync(huskyDir)) {
    result.errors.push('.husky directory not found. Run "npx husky init" first.');
    return result;
  }

  // Check if pre-commit already exists
  let content = HUSKY_SCRIPT;
  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, 'utf-8');
    if (existing.includes('react2shell-guard')) {
      result.success = true;
      result.message = 'react2shell-guard hook already installed in .husky/pre-commit';
      return result;
    }
    // Append to existing hook
    content = existing.trimEnd() + '\n\n# react2shell-guard CVE check\n' + HUSKY_SCRIPT;
  }

  if (!dryRun) {
    writeFileSync(hookPath, content, 'utf-8');
    chmodSync(hookPath, 0o755);
  }

  result.success = true;
  result.message = dryRun
    ? `Would install hook to ${hookPath}`
    : `Installed react2shell-guard hook to ${hookPath}`;

  return result;
}

/**
 * Install pre-commit hook for Lefthook
 */
function installLefthookHook(projectPath: string, dryRun: boolean): InitHooksResult {
  const configPath = existsSync(join(projectPath, 'lefthook.yml'))
    ? join(projectPath, 'lefthook.yml')
    : join(projectPath, '.lefthook.yml');

  const result: InitHooksResult = {
    success: false,
    hookType: 'lefthook',
    hookPath: configPath,
    message: '',
    errors: [],
  };

  if (!existsSync(configPath)) {
    // Create new lefthook config
    if (!dryRun) {
      writeFileSync(join(projectPath, 'lefthook.yml'), LEFTHOOK_CONFIG, 'utf-8');
    }
    result.success = true;
    result.hookPath = join(projectPath, 'lefthook.yml');
    result.message = dryRun
      ? 'Would create lefthook.yml with react2shell-guard hook'
      : 'Created lefthook.yml with react2shell-guard hook';
    return result;
  }

  // Check if already configured
  const existing = readFileSync(configPath, 'utf-8');
  if (existing.includes('react2shell-guard')) {
    result.success = true;
    result.message = 'react2shell-guard already configured in lefthook';
    return result;
  }

  // Append to existing config
  const newContent = existing.trimEnd() + '\n\n' + LEFTHOOK_CONFIG;

  if (!dryRun) {
    writeFileSync(configPath, newContent, 'utf-8');
  }

  result.success = true;
  result.message = dryRun
    ? `Would add react2shell-guard hook to ${configPath}`
    : `Added react2shell-guard hook to ${configPath}`;

  return result;
}

/**
 * Install standalone Git hook
 */
function installStandaloneHook(projectPath: string, dryRun: boolean): InitHooksResult {
  const gitDir = join(projectPath, '.git');
  const hooksDir = join(gitDir, 'hooks');
  const hookPath = join(hooksDir, 'pre-commit');

  const result: InitHooksResult = {
    success: false,
    hookType: 'standalone',
    hookPath,
    message: '',
    errors: [],
  };

  if (!existsSync(gitDir)) {
    result.errors.push('Not a git repository. Run "git init" first.');
    return result;
  }

  // Create hooks directory if needed
  if (!existsSync(hooksDir) && !dryRun) {
    mkdirSync(hooksDir, { recursive: true });
  }

  // Check if pre-commit already exists
  let content = PRE_COMMIT_SCRIPT;
  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, 'utf-8');
    if (existing.includes('react2shell-guard')) {
      result.success = true;
      result.message = 'react2shell-guard hook already installed';
      return result;
    }
    // Backup and replace
    if (!dryRun) {
      writeFileSync(hookPath + '.backup', existing, 'utf-8');
    }
    result.message = `Backed up existing hook to ${hookPath}.backup`;
  }

  if (!dryRun) {
    writeFileSync(hookPath, content, 'utf-8');
    chmodSync(hookPath, 0o755);
  }

  result.success = true;
  result.message = dryRun
    ? `Would install hook to ${hookPath}`
    : `Installed react2shell-guard hook to ${hookPath}`;

  return result;
}

/**
 * Initialize pre-commit hooks
 */
export function initHooks(options: InitHooksOptions): InitHooksResult {
  const { projectPath, hookType, dryRun = false } = options;

  // Auto-detect or use specified hook type
  const detectedType = hookType || detectHookFramework(projectPath);

  switch (detectedType) {
    case 'husky':
      return installHuskyHook(projectPath, dryRun);
    case 'lefthook':
      return installLefthookHook(projectPath, dryRun);
    case 'simple-git-hooks':
      // For simple-git-hooks, recommend manual setup
      return {
        success: false,
        hookType: 'simple-git-hooks',
        hookPath: '',
        message: '',
        errors: [
          'simple-git-hooks detected. Add this to your package.json:',
          '"simple-git-hooks": { "pre-commit": "npx react2shell-guard scan" }',
          'Then run: npx simple-git-hooks',
        ],
      };
    default:
      return installStandaloneHook(projectPath, dryRun);
  }
}

/**
 * Check if hooks are installed
 */
export function checkHooksInstalled(projectPath: string): boolean {
  const gitHookPath = join(projectPath, '.git', 'hooks', 'pre-commit');
  const huskyHookPath = join(projectPath, '.husky', 'pre-commit');
  const lefthookPath = join(projectPath, 'lefthook.yml');
  const lefthookAltPath = join(projectPath, '.lefthook.yml');

  const paths = [gitHookPath, huskyHookPath, lefthookPath, lefthookAltPath];

  for (const path of paths) {
    if (existsSync(path)) {
      try {
        const content = readFileSync(path, 'utf-8');
        if (content.includes('react2shell-guard')) {
          return true;
        }
      } catch {
        // Ignore read errors
      }
    }
  }

  return false;
}
