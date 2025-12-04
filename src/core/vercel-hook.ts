/**
 * Vercel Deployment Hook for CVE-2025-55182
 *
 * Pre-deployment vulnerability check that can block vulnerable builds.
 * Use as a build command or in vercel.json configuration.
 */

import { scan } from './scanner.js';
import type { ScanResult } from './types.js';

export interface VercelHookOptions {
  /** Path to scan (default: current directory) */
  path?: string;
  /** Fail the build if vulnerabilities found (default: true) */
  failOnVulnerable?: boolean;
  /** Paths to ignore */
  ignorePaths?: string[];
  /** Enable debug output */
  debug?: boolean;
}

export interface VercelHookResult {
  passed: boolean;
  result: ScanResult;
  message: string;
}

/**
 * Run the Vercel pre-deployment check
 *
 * Usage in package.json:
 * ```json
 * {
 *   "scripts": {
 *     "vercel-build": "react2shell-guard vercel-check && next build"
 *   }
 * }
 * ```
 *
 * Or in vercel.json:
 * ```json
 * {
 *   "buildCommand": "npx react2shell-guard vercel-check && npm run build"
 * }
 * ```
 */
export function runVercelCheck(options: VercelHookOptions = {}): VercelHookResult {
  const {
    path = process.cwd(),
    failOnVulnerable = true,
    ignorePaths = [],
    debug = false,
  } = options;

  if (debug) {
    console.log('[react2shell-guard] Running Vercel pre-deployment check...');
    console.log('[react2shell-guard] Path:', path);
  }

  const result = scan({
    path,
    ignorePaths,
    debug,
  });

  if (result.vulnerable) {
    const vulnCount = result.projects.reduce((sum, p) => sum + p.findings.length, 0);
    const message = `CVE-2025-55182: Found ${vulnCount} vulnerable package(s) in ${result.projects.filter(p => p.vulnerable).length} project(s). ` +
      'Run "npx react2shell-guard fix --install" to remediate before deploying.';

    if (failOnVulnerable) {
      return {
        passed: false,
        result,
        message,
      };
    }

    // Warn but don't fail
    console.warn('[react2shell-guard] WARNING:', message);
    return {
      passed: true,
      result,
      message: 'WARNING: ' + message,
    };
  }

  const message = 'CVE-2025-55182: No vulnerabilities detected. Safe to deploy.';
  if (debug) {
    console.log('[react2shell-guard]', message);
  }

  return {
    passed: true,
    result,
    message,
  };
}

/**
 * Format output for Vercel build logs
 */
export function formatVercelOutput(hookResult: VercelHookResult): string {
  const lines: string[] = [];
  const { result, passed, message } = hookResult;

  lines.push('');
  lines.push('╔══════════════════════════════════════════════════╗');
  lines.push('║  react2shell-guard - Vercel Security Check       ║');
  lines.push('╚══════════════════════════════════════════════════╝');
  lines.push('');

  if (!passed) {
    lines.push('❌ DEPLOYMENT BLOCKED - Vulnerabilities Detected');
    lines.push('');
    lines.push('The following packages are vulnerable to CVE-2025-55182:');
    lines.push('');

    for (const project of result.projects) {
      if (!project.vulnerable) continue;

      lines.push('  Project: ' + project.name);
      for (const finding of project.findings) {
        lines.push('    • ' + finding.package + ' @ ' + finding.currentVersion);
        lines.push('      → Upgrade to ' + finding.fixedVersion);
      }
      lines.push('');
    }

    lines.push('To fix, run:');
    lines.push('  npx react2shell-guard fix --install');
    lines.push('');
    lines.push('Then commit the changes and redeploy.');
  } else if (result.vulnerable) {
    lines.push('⚠️  WARNING - Vulnerabilities Detected (non-blocking)');
    lines.push('');
    lines.push(message);
  } else {
    lines.push('✅ PASSED - No CVE-2025-55182 vulnerabilities found');
    lines.push('');
    lines.push('Scanned ' + result.projects.length + ' project(s)');
  }

  lines.push('');
  lines.push('══════════════════════════════════════════════════');

  return lines.join('\n');
}
