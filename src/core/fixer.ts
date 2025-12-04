/**
 * Auto-fix module for updating vulnerable dependencies
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import type { Finding, PackageJson } from './types.js';

export interface FixResult {
  success: boolean;
  updatedPackages: Array<{
    package: string;
    from: string;
    to: string;
  }>;
  errors: string[];
  packageJsonPath: string;
}

export interface FixOptions {
  projectPath: string;
  findings: Finding[];
  dryRun?: boolean;
  install?: boolean;
}

/**
 * Detect which package manager is being used
 */
function detectPackageManager(projectPath: string): 'npm' | 'pnpm' | 'yarn' {
  if (existsSync(join(projectPath, 'pnpm-lock.yaml'))) {
    return 'pnpm';
  }
  if (existsSync(join(projectPath, 'yarn.lock'))) {
    return 'yarn';
  }
  return 'npm';
}

/**
 * Update package.json with fixed versions
 */
export function fixVulnerabilities(options: FixOptions): FixResult {
  const { projectPath, findings, dryRun = false, install = false } = options;
  const packageJsonPath = join(projectPath, 'package.json');

  const result: FixResult = {
    success: false,
    updatedPackages: [],
    errors: [],
    packageJsonPath,
  };

  if (!existsSync(packageJsonPath)) {
    result.errors.push(`package.json not found at ${packageJsonPath}`);
    return result;
  }

  if (findings.length === 0) {
    result.success = true;
    return result;
  }

  try {
    const content = readFileSync(packageJsonPath, 'utf-8');
    const packageJson = JSON.parse(content) as PackageJson;

    // Track which packages we update
    const updates: Array<{ package: string; from: string; to: string }> = [];

    // Update dependencies
    for (const finding of findings) {
      const { package: pkgName, currentVersion, fixedVersion } = finding;

      // Check in dependencies
      if (packageJson.dependencies?.[pkgName]) {
        const currentRange = packageJson.dependencies[pkgName];
        // Preserve prefix (^, ~, etc) if present
        const prefix = currentRange.match(/^[\^~>=<]*/)?.[0] || '^';
        const newRange = `${prefix}${fixedVersion}`;

        if (!dryRun) {
          packageJson.dependencies[pkgName] = newRange;
        }

        updates.push({
          package: pkgName,
          from: currentRange,
          to: newRange,
        });
      }

      // Check in devDependencies
      if (packageJson.devDependencies?.[pkgName]) {
        const currentRange = packageJson.devDependencies[pkgName];
        const prefix = currentRange.match(/^[\^~>=<]*/)?.[0] || '^';
        const newRange = `${prefix}${fixedVersion}`;

        if (!dryRun) {
          packageJson.devDependencies[pkgName] = newRange;
        }

        updates.push({
          package: pkgName,
          from: currentRange,
          to: newRange,
        });
      }
    }

    result.updatedPackages = updates;

    // Write updated package.json
    if (!dryRun && updates.length > 0) {
      const updatedContent = JSON.stringify(packageJson, null, 2) + '\n';
      writeFileSync(packageJsonPath, updatedContent, 'utf-8');
    }

    // Run package manager install if requested
    if (install && !dryRun && updates.length > 0) {
      const pm = detectPackageManager(projectPath);
      const installCmd = pm === 'npm' ? 'npm install' : pm === 'pnpm' ? 'pnpm install' : 'yarn install';

      try {
        execSync(installCmd, {
          cwd: projectPath,
          stdio: 'inherit',
        });
      } catch (error) {
        result.errors.push(`Failed to run ${installCmd}: ${error}`);
      }
    }

    result.success = result.errors.length === 0;
    return result;

  } catch (error) {
    result.errors.push(`Failed to process package.json: ${error}`);
    return result;
  }
}

/**
 * Generate a summary of the fix for PR description
 */
export function generateFixSummary(result: FixResult): string {
  const lines: string[] = [
    '## Security Fix: CVE-2025-55182',
    '',
    'This update fixes a critical Remote Code Execution vulnerability in React Server Components.',
    '',
    '### Updated Packages',
    '',
  ];

  for (const update of result.updatedPackages) {
    lines.push(`- \`${update.package}\`: ${update.from} → ${update.to}`);
  }

  lines.push('');
  lines.push('### References');
  lines.push('');
  lines.push('- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)');
  lines.push('- [CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)');

  return lines.join('\n');
}
